using System.Collections.ObjectModel;
using Avalonia.Threading;
using Hubris.Control;
using Hubris.Desktop.Services;

namespace Hubris.Desktop.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly HubDiscovery _discovery;
    private readonly HubLauncher _launcher;
    private HubViewModel? _selectedHub;
    private bool _showConfig = true;
    private bool _showCatalog;

    public MainViewModel(HubDiscovery discovery, HubLauncher launcher)
    {
        _discovery = discovery;
        _launcher = launcher;
        Config = new ConfigViewModel(launcher);
        Config.ReloadRunningHubs = async signIn =>
        {
            var hubs = Hubs.ToArray();
            foreach (var h in hubs) await h.ReloadConfigAsync();
            // One hub runs the browser login (commands on one connection are handled in order, so the bridge exists by then);
            // the token lands in the shared store and SignedIn tells the rest.
            if (signIn is not null && hubs.Length > 0) await hubs[0].SignInAsync(signIn);
            return hubs.Length;
        };
        ShowConfigCommand = new RelayCommand(() => { SelectedHub = null; ShowCatalog = false; ShowConfig = true; });
        ShowCatalogCommand = new RelayCommand(() => { SelectedHub = null; ShowConfig = false; ShowCatalog = true; });
        RescanCommand = new AsyncCommand(() => _discovery.RescanAsync());
        AsyncCommand.Failed += ex => Dispatcher.UIThread.Post(() =>
        {
            if (SelectedHub is { } hub) hub.ReportError(ex.Message); else Config.ReportError(ex.Message);
        });
        Hubs.CollectionChanged += (_, _) => { Raise(nameof(HasHubs)); Raise(nameof(NoHubs)); RaisePending(); };
    }

    public ObservableCollection<HubViewModel> Hubs { get; } = new();
    public ConfigViewModel Config { get; }
    public string RuntimeDir => _discovery.RuntimeDir;
    public bool HasHubs => Hubs.Count > 0;
    public bool NoHubs => Hubs.Count == 0;
    public int PendingTotal { get { int n = 0; foreach (var h in Hubs) n += h.PendingCount; return n; } }
    public bool HasPending => PendingTotal > 0;

    public HubViewModel? SelectedHub
    {
        get => _selectedHub;
        set
        {
            if (!Set(ref _selectedHub, value)) return;
            if (value is not null) { ShowConfig = false; ShowCatalog = false; }
            Raise(nameof(ShowHub));
        }
    }

    public bool ShowConfig { get => _showConfig; private set { if (Set(ref _showConfig, value)) Raise(nameof(ShowHub)); } }
    /// <summary>The "Known servers" page: catalog and registry search, adds bridges straight into config.json.</summary>
    public bool ShowCatalog { get => _showCatalog; private set { if (Set(ref _showCatalog, value)) Raise(nameof(ShowHub)); } }
    public bool ShowHub => !_showConfig && !_showCatalog && _selectedHub is not null;

    public RelayCommand ShowConfigCommand { get; }
    public RelayCommand ShowCatalogCommand { get; }
    public AsyncCommand RescanCommand { get; }

    public void Start()
    {
        _discovery.HubConnected += OnHubConnected;
        _discovery.HubDisconnected += OnHubDisconnected;
        _discovery.Start();
    }

    private void OnHubConnected(HubClient client)
    {
        // The read loop starts after this returns (HubDiscovery calls client.Start()), so hello and replayed approvals are not lost.
        client.MessageReceived += OnMessage;
        Dispatcher.UIThread.Post(() =>
        {
            var vm = new HubViewModel(client);
            vm.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(HubViewModel.PendingCount)) RaisePending(); };
            vm.SignedIn += (from, bridge) => { foreach (var other in Hubs.ToArray()) if (!ReferenceEquals(other, from)) _ = other.RefreshBridgeAsync(bridge); };
            Hubs.Add(vm);
        });
    }

    private void OnHubDisconnected(HubClient client)
    {
        client.MessageReceived -= OnMessage;
        Dispatcher.UIThread.Post(() =>
        {
            for (int i = Hubs.Count - 1; i >= 0; i--)
            {
                if (Hubs[i].Pid != client.Pid) continue;
                var vm = Hubs[i];
                bool wasSelected = ReferenceEquals(_selectedHub, vm); // the ListBox clears the selection during RemoveAt
                vm.MarkDisconnected();
                Hubs.RemoveAt(i);
                if (wasSelected) { SelectedHub = null; ShowCatalog = false; ShowConfig = true; }
            }
        });
    }

    private void OnMessage(HubClient client, ControlMessage msg)
    {
        Dispatcher.UIThread.Post(() =>
        {
            foreach (var h in Hubs)
                if (h.Pid == client.Pid) { h.Handle(msg); break; }
            if (msg.Type is ControlTypes.ApprovalRequest or ControlTypes.ApprovalResolved) RaisePending();
        });
    }

    private void RaisePending() { Raise(nameof(PendingTotal)); Raise(nameof(HasPending)); }

    public void Dispose()
    {
        _discovery.HubConnected -= OnHubConnected;
        _discovery.HubDisconnected -= OnHubDisconnected;
        _launcher.Dispose();
        _ = _discovery.DisposeAsync();
    }
}

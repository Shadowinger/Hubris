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

    public MainViewModel(HubDiscovery discovery, HubLauncher launcher)
    {
        _discovery = discovery;
        _launcher = launcher;
        Config = new ConfigViewModel(launcher);
        ShowConfigCommand = new RelayCommand(() => { SelectedHub = null; ShowConfig = true; });
        RescanCommand = new AsyncCommand(() => _discovery.RescanAsync());
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
            if (value is not null) ShowConfig = false;
            Raise(nameof(ShowHub));
        }
    }

    public bool ShowConfig { get => _showConfig; private set { if (Set(ref _showConfig, value)) Raise(nameof(ShowHub)); } }
    public bool ShowHub => !_showConfig && _selectedHub is not null;

    public RelayCommand ShowConfigCommand { get; }
    public AsyncCommand RescanCommand { get; }

    public void Start()
    {
        _discovery.HubConnected += OnHubConnected;
        _discovery.HubDisconnected += OnHubDisconnected;
        _discovery.Start();
    }

    private void OnHubConnected(HubClient client)
    {
        client.MessageReceived += OnMessage;
        // The hub's hello may already have passed before we subscribed; ask again, ReplaceTools makes it idempotent.
        _ = client.RequestToolsAsync();
        _ = client.RequestStatusAsync();
        Dispatcher.UIThread.Post(() =>
        {
            var vm = new HubViewModel(client);
            vm.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(HubViewModel.PendingCount)) RaisePending(); };
            Hubs.Add(vm);
            if (_selectedHub is null && ShowConfig && Hubs.Count == 1) { /* keep configurator until the user picks */ }
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
                vm.MarkDisconnected();
                Hubs.RemoveAt(i);
                if (ReferenceEquals(_selectedHub, vm)) { SelectedHub = null; ShowConfig = true; }
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

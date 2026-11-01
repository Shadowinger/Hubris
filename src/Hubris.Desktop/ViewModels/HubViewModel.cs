using System.Collections.ObjectModel;
using System.Text.Encodings.Web;
using System.Text.Json;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using Avalonia.Threading;
using Hubris.Control;
using Hubris.Desktop.Services;

namespace Hubris.Desktop.ViewModels;

public sealed class HubViewModel : ObservableObject
{
    private const int MaxEvents = 500;
    private readonly HubClient _client;
    private readonly DispatcherTimer _tick;

    private string _mode = "Safe";
    private bool _isBypass;
    private bool _isConnected = true;
    private string _clientName = "";
    private string _uptime = "–";
    private string _rss = "–";
    private string _heap = "–";
    private string _cache = "–";
    private long _blocked, _dlp;
    private int _toolCount, _bridgeCount, _clients, _cacheSize, _cacheCapacity;
    private string _toolFilter = "";
    private EventRow? _selectedEvent;

    public HubViewModel(HubClient client)
    {
        _client = client;
        Pid = client.Pid;
        Cwd = client.Descriptor.Cwd;
        IsCompact = client.Descriptor.Compact;
        Version = client.Descriptor.Version;
        _clientName = client.Descriptor.Client ?? "";
        _mode = client.Descriptor.Mode;
        _isBypass = _mode == "Bypass";

        SetSafeCommand = new AsyncCommand(() => _client.SetModeAsync("safe"));
        SetBypassCommand = new AsyncCommand(() => _client.SetModeAsync("bypass"));
        ClearCacheCommand = new AsyncCommand(() => _client.ClearCacheAsync());
        ClearEventsCommand = new RelayCommand(() => Events.Clear());
        ShutdownCommand = new AsyncCommand(() => _client.ShutdownHubAsync());
        RefreshCommand = new AsyncCommand(() => _client.RequestStatusAsync());

        _tick = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background, (_, _) => Tick());
        _tick.Start();
    }

    // ---------------------------------------------------------------- identity
    public int Pid { get; }
    public string Cwd { get; }
    public bool IsCompact { get; }
    public string Version { get; }
    public string Title => string.IsNullOrEmpty(ClientName) ? $"pid {Pid}" : ClientName;
    public string Subtitle => $"pid {Pid} · {Fmt.Trim(Cwd, 48)}";
    public string ClientName { get => _clientName; private set { if (Set(ref _clientName, value)) { Raise(nameof(Title)); } } }
    public bool IsConnected { get => _isConnected; private set => Set(ref _isConnected, value); }

    // ---------------------------------------------------------------- mode
    public string Mode { get => _mode; private set { if (Set(ref _mode, value)) { Raise(nameof(IsSafe)); Raise(nameof(ModeBrush)); } } }
    public bool IsSafe => _mode == "Safe";
    public IBrush ModeBrush => IsSafe ? Palette.Ok : Palette.Warn;

    /// <summary>Two-way bound to the toggle; the setter sends the command, the event confirms it.</summary>
    public bool IsBypass
    {
        get => _isBypass;
        set
        {
            if (!Set(ref _isBypass, value)) return;
            _ = _client.SetModeAsync(value ? "bypass" : "safe");
        }
    }

    // ---------------------------------------------------------------- status
    public string Uptime { get => _uptime; private set => Set(ref _uptime, value); }
    public string Rss { get => _rss; private set => Set(ref _rss, value); }
    public string Heap { get => _heap; private set => Set(ref _heap, value); }
    public string Cache { get => _cache; private set => Set(ref _cache, value); }
    public long Blocked { get => _blocked; private set => Set(ref _blocked, value); }
    public long Dlp { get => _dlp; private set => Set(ref _dlp, value); }
    public int ToolCount { get => _toolCount; private set => Set(ref _toolCount, value); }
    public int BridgeCount { get => _bridgeCount; private set => Set(ref _bridgeCount, value); }
    public int Clients { get => _clients; private set => Set(ref _clients, value); }
    public string CacheFill => $"{_cacheSize}/{_cacheCapacity}";

    // ---------------------------------------------------------------- collections
    public ObservableCollection<ApprovalViewModel> Approvals { get; } = new();
    public bool HasApprovals => Approvals.Count > 0;
    public int PendingCount => Approvals.Count;
    public ObservableCollection<EventRow> Events { get; } = new();
    public EventRow? SelectedEvent { get => _selectedEvent; set => Set(ref _selectedEvent, value); }
    public ObservableCollection<ToolRow> Tools { get; } = new();
    public ObservableCollection<ToolRow> FilteredTools { get; } = new();
    public string ToolFilter { get => _toolFilter; set { if (Set(ref _toolFilter, value)) ApplyToolFilter(); } }

    // ---------------------------------------------------------------- commands
    public AsyncCommand SetSafeCommand { get; }
    public AsyncCommand SetBypassCommand { get; }
    public AsyncCommand ClearCacheCommand { get; }
    public RelayCommand ClearEventsCommand { get; }
    public AsyncCommand ShutdownCommand { get; }
    public AsyncCommand RefreshCommand { get; }

    // ---------------------------------------------------------------- inbound (UI thread)
    public void Handle(ControlMessage m)
    {
        switch (m.Type)
        {
            case ControlTypes.Hello:
                ApplyStatus(m);
                if (m.Tools is not null) ReplaceTools(m.Tools);
                break;
            case ControlTypes.Status:
                ApplyStatus(m);
                break;
            case ControlTypes.ModeChanged:
                if (m.Mode is not null) { Mode = m.Mode; _isBypass = m.Mode == "Bypass"; Raise(nameof(IsBypass)); }
                break;
            case ControlTypes.ToolsChanged:
                if (m.Tools is not null) ReplaceTools(m.Tools);
                break;
            case ControlTypes.ToolCall:
                AddEvent(EventRow.FromToolCall(m));
                break;
            case ControlTypes.ApprovalRequest:
                if (m.ApprovalId is not null && !Approvals.Any(a => a.Id == m.ApprovalId))
                {
                    var a = new ApprovalViewModel(m, id => _client.ApproveAsync(id), id => _client.DenyAsync(id));
                    Approvals.Insert(0, a);
                    AddEvent(EventRow.FromApprovalRequest(m));
                    RaiseApprovals();
                }
                break;
            case ControlTypes.ApprovalResolved:
                for (int i = Approvals.Count - 1; i >= 0; i--)
                    if (Approvals[i].Id == m.ApprovalId) Approvals.RemoveAt(i);
                RaiseApprovals();
                break;
            case ControlTypes.Log:
                AddEvent(EventRow.FromLog(m));
                break;
            case ControlTypes.Ack:
                if (m.Ok == false) AddEvent(EventRow.Error($"command failed: {m.Error}"));
                break;
        }
    }

    public void MarkDisconnected()
    {
        IsConnected = false;
        _tick.Stop();
        foreach (var a in Approvals) a.Expire();
        Approvals.Clear();
        RaiseApprovals();
        AddEvent(EventRow.Error("hub disconnected"));
    }

    private void ApplyStatus(ControlMessage m)
    {
        if (m.Mode is not null) { Mode = m.Mode; _isBypass = m.Mode == "Bypass"; Raise(nameof(IsBypass)); }
        if (m.Client is not null) ClientName = m.Client;
        Uptime = Fmt.Duration(m.UptimeSec);
        Rss = Fmt.Bytes(m.RssBytes);
        Heap = Fmt.Bytes(m.HeapBytes);
        Cache = $"{m.CacheHits ?? 0} hit / {m.CacheMisses ?? 0} miss";
        _cacheSize = m.CacheSize ?? 0; _cacheCapacity = m.CacheCapacity ?? 0; Raise(nameof(CacheFill));
        Blocked = m.Blocked ?? 0;
        Dlp = m.DlpRedactions ?? 0;
        ToolCount = m.ToolCount ?? 0;
        BridgeCount = m.BridgeCount ?? 0;
        Clients = m.Clients ?? 0;
    }

    private void ReplaceTools(List<ToolInfo> tools)
    {
        Tools.Clear();
        foreach (var t in tools) Tools.Add(new ToolRow(t, name => _client.RevealAsync(name)));
        ApplyToolFilter();
    }

    private void ApplyToolFilter()
    {
        FilteredTools.Clear();
        string f = _toolFilter.Trim();
        foreach (var t in Tools)
            if (f.Length == 0 || t.Name.Contains(f, StringComparison.OrdinalIgnoreCase) || t.Description.Contains(f, StringComparison.OrdinalIgnoreCase))
                FilteredTools.Add(t);
    }

    private void AddEvent(EventRow row)
    {
        Events.Insert(0, row);
        while (Events.Count > MaxEvents) Events.RemoveAt(Events.Count - 1);
    }

    private void RaiseApprovals() { Raise(nameof(HasApprovals)); Raise(nameof(PendingCount)); }

    private void Tick()
    {
        foreach (var a in Approvals) a.Tick();
    }
}

public static class Palette
{
    public static readonly IBrush Ok = new ImmutableSolidColorBrush(Color.Parse("#3FB950"));
    public static readonly IBrush Warn = new ImmutableSolidColorBrush(Color.Parse("#D29922"));
    public static readonly IBrush Error = new ImmutableSolidColorBrush(Color.Parse("#F85149"));
    public static readonly IBrush Info = new ImmutableSolidColorBrush(Color.Parse("#58A6FF"));
    public static readonly IBrush Muted = new ImmutableSolidColorBrush(Color.Parse("#8B949E"));
    public static readonly IBrush Purple = new ImmutableSolidColorBrush(Color.Parse("#BC8CFF"));
}

public sealed class ApprovalViewModel : ObservableObject
{
    // Display only: keep '&', '<', non-ASCII readable instead of \uXXXX escapes.
    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly DateTime _deadline;
    private string _remaining = "";
    private bool _busy;

    public ApprovalViewModel(ControlMessage m, Func<string, Task> approve, Func<string, Task> deny)
    {
        Id = m.ApprovalId ?? "";
        Tool = m.Tool ?? "";
        Risk = m.Risk ?? "";
        Reason = m.Reason ?? "";
        ArgsJson = m.Args is null ? "(no arguments)" : m.Args.ToJsonString(PrettyJson);
        RequestedAt = Fmt.LocalTime(m.Timestamp);
        var requested = DateTime.TryParse(m.Timestamp, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var dt) ? dt.ToUniversalTime() : DateTime.UtcNow;
        _deadline = requested.AddSeconds(m.TimeoutSec ?? 120);
        ApproveCommand = new AsyncCommand(async () => { Busy = true; await approve(Id); }, () => !_busy);
        DenyCommand = new AsyncCommand(async () => { Busy = true; await deny(Id); }, () => !_busy);
        Tick();
    }

    public string Id { get; }
    public string Tool { get; }
    public string Risk { get; }
    public string Reason { get; }
    public string ArgsJson { get; }
    public string RequestedAt { get; }
    public string Remaining { get => _remaining; private set => Set(ref _remaining, value); }
    public bool Busy { get => _busy; private set { if (Set(ref _busy, value)) { ApproveCommand.RaiseCanExecuteChanged(); DenyCommand.RaiseCanExecuteChanged(); } } }
    public AsyncCommand ApproveCommand { get; }
    public AsyncCommand DenyCommand { get; }

    public void Tick()
    {
        var left = _deadline - DateTime.UtcNow;
        Remaining = left <= TimeSpan.Zero ? "expiring…" : $"{(int)left.TotalSeconds}s left";
    }

    public void Expire() => Busy = true;
}

public sealed class EventRow
{
    private static readonly JsonSerializerOptions CompactJson = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public string Time { get; init; } = "";
    public string Tool { get; init; } = "";
    public string Outcome { get; init; } = "";
    public string Risk { get; init; } = "";
    public string Duration { get; init; } = "";
    public string Args { get; init; } = "";
    public string Preview { get; init; } = "";
    public IBrush OutcomeBrush { get; init; } = Palette.Muted;
    public string Detail => string.IsNullOrEmpty(Args) ? Preview : $"args: {Args}\n\n{Preview}";

    public static EventRow FromToolCall(ControlMessage m)
    {
        string outcome = m.Outcome ?? "";
        return new EventRow
        {
            Time = Fmt.LocalTime(m.Timestamp),
            Tool = m.Tool ?? "",
            Outcome = outcome,
            Risk = m.Risk ?? "",
            Duration = Fmt.Ms(m.DurationMs),
            Args = m.Args?.ToJsonString(CompactJson) ?? "",
            Preview = m.Preview ?? "",
            OutcomeBrush = outcome switch
            {
                "ok" or "cached" => Palette.Ok,
                "approved" => Palette.Info,
                "blocked" or "denied" or "timeout" => Palette.Error,
                "error" or "cancelled" => Palette.Warn,
                _ => Palette.Muted,
            },
        };
    }

    public static EventRow FromApprovalRequest(ControlMessage m) => new()
    {
        Time = Fmt.LocalTime(m.Timestamp),
        Tool = m.Tool ?? "",
        Outcome = "awaiting approval",
        Risk = m.Risk ?? "",
        Args = m.Args?.ToJsonString(CompactJson) ?? "",
        Preview = m.Reason ?? "",
        OutcomeBrush = Palette.Purple,
    };

    public static EventRow FromLog(ControlMessage m) => new()
    {
        Time = Fmt.LocalTime(m.Timestamp),
        Tool = "log",
        Outcome = m.Level ?? "info",
        Preview = m.Text ?? "",
        OutcomeBrush = Palette.Muted,
    };

    public static EventRow Error(string text) => new()
    {
        Time = Fmt.LocalTime(null),
        Tool = "desktop",
        Outcome = "error",
        Preview = text,
        OutcomeBrush = Palette.Error,
    };
}

public sealed class ToolRow : ObservableObject
{
    public ToolRow(ToolInfo t, Func<string, Task> reveal)
    {
        Name = t.Name;
        Description = t.Description;
        Risk = t.Risk;
        Pinned = t.Pinned;
        Visible = t.Visible;
        Bridge = t.Bridge ?? "";
        RevealCommand = new AsyncCommand(() => reveal(Name), () => !Visible);
    }

    public string Name { get; }
    public string Description { get; }
    public string Risk { get; }
    public bool Pinned { get; }
    public bool Visible { get; }
    public string Bridge { get; }
    public bool IsBridged => Bridge.Length > 0;
    public string VisibilityText => Pinned ? "pinned" : Visible ? "unlocked" : "on-demand";
    public IBrush RiskBrush => Risk switch { "ReadOnly" => Palette.Ok, "Mutating" => Palette.Warn, _ => Palette.Error };
    public AsyncCommand RevealCommand { get; }
}

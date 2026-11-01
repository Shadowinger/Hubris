using System.Collections.ObjectModel;
using System.Text.Encodings.Web;
using System.Text.Json;
using Avalonia.Threading;
using Hubris.Control;
using Hubris.Engine;
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
    private int _toolCount, _bridgeCount, _bridgesRunning, _clients, _cacheSize, _cacheCapacity;
    private string _toolFilter = "";
    private EventRow? _selectedEvent;
    private int _activeTools, _activeTokens, _totalTokens;

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
    /// <summary>The hub process predates this desktop build (started before the client was restarted).</summary>
    public bool IsOutdated => !string.Equals(Version, HubRuntime.Version, StringComparison.Ordinal);
    public string OutdatedHint => $"Hub runs Hubris {Version}, this app is {HubRuntime.Version}: restart the MCP client to pick up the new binary.";
    public string Subtitle => $"pid {Pid} · {Fmt.Trim(Cwd, 48)}";
    public string ClientName { get => _clientName; private set { if (Set(ref _clientName, value)) { Raise(nameof(Title)); } } }
    public bool IsConnected { get => _isConnected; private set => Set(ref _isConnected, value); }

    // ---------------------------------------------------------------- mode
    public string Mode { get => _mode; private set { if (Set(ref _mode, value)) Raise(nameof(IsSafe)); } }
    public bool IsSafe => _mode == "Safe";

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
    public int BridgeCount { get => _bridgeCount; private set { if (Set(ref _bridgeCount, value)) Raise(nameof(BridgesText)); } }
    public int BridgesRunning { get => _bridgesRunning; private set { if (Set(ref _bridgesRunning, value)) Raise(nameof(BridgesText)); } }
    public string BridgesText => _bridgeCount == 0 ? "0" : $"{_bridgeCount} · {_bridgesRunning} running";
    public int Clients { get => _clients; private set => Set(ref _clients, value); }
    public string CacheFill => $"{_cacheSize} cached · {_cacheCapacity} bridges";

    // ---------------------------------------------------------------- context meter
    public int ActiveTools => _activeTools;
    public int ActiveTokens => _activeTokens;
    public int TotalTokens => _totalTokens;
    public int SavedPercent => _totalTokens == 0 ? 0 : (int)Math.Round(100.0 * (_totalTokens - _activeTokens) / _totalTokens);
    public string ContextMeter => $"Active in context: {_activeTools} / {ToolCount} tools  (~{_activeTokens} tokens | {SavedPercent}% saved)";
    public string ContextTile => $"~{_activeTokens} tok";
    public string ContextTileSub => $"{_activeTools}/{ToolCount} tools · {SavedPercent}% saved";
    public string SavedText => $"{SavedPercent}% saved";
    public bool SavedGood => SavedPercent >= 50;
    public bool SavedSome => SavedPercent is > 0 and < 50;

    private void ApplyContext(int? active, int? activeTok, int? totalTok)
    {
        if (active is null && activeTok is null && totalTok is null) return;
        _activeTools = active ?? _activeTools;
        _activeTokens = activeTok ?? _activeTokens;
        _totalTokens = totalTok ?? _totalTokens;
        Raise(nameof(ActiveTools)); Raise(nameof(ActiveTokens)); Raise(nameof(TotalTokens)); Raise(nameof(SavedPercent));
        Raise(nameof(ContextMeter)); Raise(nameof(ContextTile)); Raise(nameof(ContextTileSub)); Raise(nameof(SavedText)); Raise(nameof(SavedGood)); Raise(nameof(SavedSome));
    }

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
                    var a = new ApprovalViewModel(m, (id, remember) => _client.ApproveAsync(id, remember), (id, remember) => _client.DenyAsync(id, remember));
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
                if (m.Ok == false)
                    AddEvent(EventRow.Error(m.Error is { } e && e.StartsWith("unknown command", StringComparison.Ordinal)
                        ? $"{e} — this hub is an older Hubris build ({Version}); restart the MCP client"
                        : $"command failed: {m.Error}"));
                else if (m.Bridges is { Count: > 0 } b) AddEvent(EventRow.Info($"bridges added: {string.Join(", ", b)}"));
                break;
            case ControlTypes.BridgesChanged:
                break; // tools_changed follows and refreshes the list
        }
    }

    public Task ReloadConfigAsync() => _client.ReloadConfigAsync();

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
        BridgesRunning = m.BridgesRunning ?? 0;
        Clients = m.Clients ?? 0;
        ApplyContext(m.ActiveTools, m.ActiveTokens, m.TotalTokens);
    }

    private void ReplaceTools(List<ToolInfo> tools)
    {
        Tools.Clear();
        int active = 0, activeTok = 0, totalTok = 0;
        foreach (var t in tools)
        {
            Tools.Add(new ToolRow(t, IsCompact, name => _client.RevealAsync(name), name => _client.LockAsync(name), name => _client.ForgetAsync(name)));
            totalTok += t.Tokens;
            if (t.Visible) { active++; activeTok += t.Tokens; }
        }
        ToolCount = tools.Count;
        ApplyContext(active, activeTok, totalTok);
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

public sealed class ApprovalViewModel : ObservableObject
{
    // Display only: keep '&', '<', non-ASCII readable instead of \uXXXX escapes.
    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly DateTime _deadline;
    private string _remaining = "";
    private bool _busy;

    public ApprovalViewModel(ControlMessage m, Func<string, bool, Task> approve, Func<string, bool, Task> deny)
    {
        Id = m.ApprovalId ?? "";
        Tool = m.Tool ?? "";
        Risk = m.Risk ?? "";
        Reason = m.Reason ?? "";
        ArgsJson = m.Args is null ? "(no arguments)" : m.Args.ToJsonString(PrettyJson);
        RequestedAt = Fmt.LocalTime(m.Timestamp);
        var requested = DateTime.TryParse(m.Timestamp, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var dt) ? dt.ToUniversalTime() : DateTime.UtcNow;
        _deadline = requested.AddSeconds(m.TimeoutSec ?? 120);
        ApproveCommand = new AsyncCommand(async () => { Busy = true; await approve(Id, Remember); }, () => !_busy);
        DenyCommand = new AsyncCommand(async () => { Busy = true; await deny(Id, Remember); }, () => !_busy);
        Tick();
    }

    public string Id { get; }
    /// <summary>Two-way bound to the "Remember for this session" checkbox; read when Approve/Deny fires.</summary>
    public bool Remember { get; set; }
    public string Tool { get; }
    public string Risk { get; }
    public bool IsReadOnly => Risk == "ReadOnly";
    public bool IsMutating => Risk == "Mutating";
    public bool IsDestructive => Risk == "Destructive";
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
    /// <summary>Pill tone, consumed by the view as style classes (ok / warn / danger / indigo; none = neutral).</summary>
    public string Tone { get; init; } = "";
    public bool ToneOk => Tone == "ok";
    public bool ToneWarn => Tone == "warn";
    public bool ToneDanger => Tone == "danger";
    public bool ToneIndigo => Tone == "indigo";
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
            Tone = outcome switch
            {
                "ok" or "cached" => "ok",
                "approved" => "indigo",
                "blocked" or "denied" or "timeout" => "danger",
                "error" or "cancelled" => "warn",
                _ => "",
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
        Tone = "indigo",
    };

    public static EventRow FromLog(ControlMessage m) => new()
    {
        Time = Fmt.LocalTime(m.Timestamp),
        Tool = "log",
        Outcome = m.Level ?? "info",
        Preview = m.Text ?? "",
    };

    public static EventRow Info(string text) => new()
    {
        Time = Fmt.LocalTime(null),
        Tool = "desktop",
        Outcome = "info",
        Preview = text,
    };

    public static EventRow Error(string text) => new()
    {
        Time = Fmt.LocalTime(null),
        Tool = "desktop",
        Outcome = "error",
        Preview = text,
        Tone = "danger",
    };
}

public sealed class ToolRow : ObservableObject
{
    public ToolRow(ToolInfo t, bool hubCompact, Func<string, Task> reveal, Func<string, Task> lockTool, Func<string, Task> forget)
    {
        Name = t.Name;
        Description = t.Description;
        Risk = t.Risk;
        Pinned = t.Pinned;
        Visible = t.Visible;
        Unlocked = t.Unlocked;
        Tokens = t.Tokens;
        Bridge = t.Bridge ?? "";
        Decision = t.Decision ?? "";
        // Only compact hubs hide anything, so only there does (un)locking change the client's context.
        CanUnlock = hubCompact && !Visible;
        CanLock = hubCompact && Unlocked && !Pinned;
        RevealCommand = new AsyncCommand(() => reveal(Name), () => CanUnlock);
        LockCommand = new AsyncCommand(() => lockTool(Name), () => CanLock);
        ForgetCommand = new AsyncCommand(() => forget(Name), () => HasDecision);
    }

    public string Name { get; }
    public string Description { get; }
    public string Risk { get; }
    public bool Pinned { get; }
    public bool Visible { get; }
    public bool Unlocked { get; }
    public int Tokens { get; }
    public string TokensText => $"~{Tokens} tok";
    public string Bridge { get; }
    public bool IsBridged => Bridge.Length > 0;
    public bool CanUnlock { get; }
    public bool CanLock { get; }
    public string VisibilityText => Pinned ? "pinned" : Unlocked ? "unlocked" : Visible ? "listed" : "on-demand";
    public bool IsReadOnly => Risk == "ReadOnly";
    public bool IsMutating => Risk == "Mutating";
    public bool IsDestructive => Risk == "Destructive";
    public bool StateIndigo => !Pinned && Unlocked;
    public string Decision { get; }
    public bool HasDecision => Decision.Length > 0;
    public bool DecisionAlways => Decision == "always";
    public bool DecisionNever => Decision == "never";
    public AsyncCommand RevealCommand { get; }
    public AsyncCommand LockCommand { get; }
    public AsyncCommand ForgetCommand { get; }
}

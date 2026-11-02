using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Caching;
using Hubris.Engine;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Transport;

namespace Hubris.Control;

/// <summary>
/// Glue between the running hub and connected UIs: owns the socket server and the approval gate,
/// answers UI commands against the registry/security/cache, and publishes status and call events.
/// </summary>
public sealed class ControlHub : IAsyncDisposable
{
    private readonly HubRuntime _rt;
    private readonly ToolRegistry _registry;
    private readonly SecurityInterceptor _security;
    private readonly BridgeHost _bridgeHost;
    private readonly TimeSpan _approvalTimeout;
    private readonly CancellationTokenSource _lifetime = new();
    private Task? _statusLoop;
    private int _disposed;

    public ControlHub(HubRuntime runtime, ToolRegistry registry, SecurityInterceptor security, TimeSpan approvalTimeout)
    {
        _rt = runtime;
        _registry = registry;
        _security = security;
        _bridgeHost = new BridgeHost(runtime, registry);
        _approvalTimeout = approvalTimeout;
        Approvals = new ApprovalGate();
        Server = new ControlServer(HubrisPaths.SocketPath(Environment.ProcessId), OnCommandAsync, OnConnectedAsync);
        Approvals.Requested += p => Server.Broadcast(ApprovalRequestMessage(p));
        // Nobody left to click Approve: fail the waiting calls now instead of after the full timeout.
        Server.ClientCountChanged += n => { if (n == 0) Approvals.CancelAll(); };
        Approvals.Resolved += (p, d) => Server.Broadcast(new ControlMessage
        {
            Type = ControlTypes.ApprovalResolved,
            Timestamp = DateTime.UtcNow.ToString("O"),
            ApprovalId = p.Id,
            Tool = p.Tool,
            Decision = ApprovalGate.DecisionText(d),
        });
    }

    public ApprovalGate Approvals { get; }
    public ControlServer Server { get; }
    public TimeSpan ApprovalTimeout => _approvalTimeout;
    public bool HasClients => Server.HasClients;
    public string? ClientName { get; set; }
    public DateTime StartedAt { get; } = DateTime.UtcNow;

    /// <summary>Set by the router: pushes notifications/tools/list_changed to the MCP client.</summary>
    public Func<ValueTask>? NotifyToolsChanged { get; set; }
    /// <summary>Set by Program: initiates graceful shutdown.</summary>
    public Action? RequestShutdown { get; set; }
    /// <summary>Set by the router: swaps a bridge's registered tools and notifies the client.</summary>
    public Func<McpBridge, List<ToolDefinition>, Task>? ReplaceBridgeTools { get; set; }
    /// <summary>Set by the router: a newly added bridge needs its events hooked up.</summary>
    public Action<McpBridge>? BridgeAdded { get; set; }

    // ------------------------------------------------------------------ lifecycle

    public void Start()
    {
        Server.Start();
        WriteDescriptor();
        if (_rt.Auth is { } auth) auth.Changed += () => { if (Server.HasClients) Server.Broadcast(OAuthMessage(ControlTypes.OAuthChanged)); };
        _statusLoop = Task.Run(() => StatusLoopAsync(_lifetime.Token), CancellationToken.None);
    }

    private ControlMessage OAuthMessage(string type)
    {
        var m = ControlMessage.Of(type);
        m.Auth = _rt.Auth?.Infos() ?? new List<AuthInfo>();
        return m;
    }

    private async Task StatusLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                if (Server.HasClients) await Server.BroadcastAsync(BuildStatus()).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log.Warn($"status loop: {ex.Message}"); }
    }

    public void WriteDescriptor()
    {
        try
        {
            var d = new HubDescriptor
            {
                Pid = Environment.ProcessId,
                Socket = Server.SocketPath,
                Cwd = Environment.CurrentDirectory,
                StartedAt = StartedAt.ToString("O"),
                Version = HubRuntime.Version,
                Mode = ModeNames.ToText(_security.Mode),
                Compact = _rt.CompactContext,
                Client = ClientName,
            };
            string path = HubrisPaths.DescriptorPath(Environment.ProcessId);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string tmp = path + ".tmp";
            File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(d, ControlJsonContext.Default.HubDescriptor));
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Warn($"descriptor write failed: {ex.Message}");
        }
    }

    // ------------------------------------------------------------------ outbound events

    public Task<ApprovalDecision> RequestApprovalAsync(string tool, ToolRiskLevel risk, string reason, JsonObject? args, CancellationToken ct)
        => Approvals.RequestAsync(tool, risk, reason, args, _approvalTimeout, ct);

    public void EmitToolCall(string callId, string tool, ToolRiskLevel risk, string outcome, double durationMs, JsonObject? args, CallToolResult? result)
    {
        if (!Server.HasClients) return;
        Server.Broadcast(new ControlMessage
        {
            Type = ControlTypes.ToolCall,
            Timestamp = DateTime.UtcNow.ToString("O"),
            Id = callId,
            Tool = tool,
            Risk = ModeNames.ToText(risk),
            Outcome = outcome,
            DurationMs = Math.Round(durationMs, 2),
            Args = args?.DeepClone(),
            Preview = Preview(result),
        });
    }

    public void EmitToolsChanged()
    {
        if (!Server.HasClients) return;
        Server.Broadcast(ToolsChangedMessage());
    }

    /// <summary>Awaited variant so a command's ack never overtakes the tools_changed it caused.</summary>
    public ValueTask EmitToolsChangedAsync() => Server.HasClients ? Server.BroadcastAsync(ToolsChangedMessage()) : ValueTask.CompletedTask;

    private ControlMessage ToolsChangedMessage() => new() { Type = ControlTypes.ToolsChanged, Timestamp = DateTime.UtcNow.ToString("O"), Tools = ToolInfos() };

    /// <summary>Tool list stamped with each tool's remembered Safe-mode decision for UI pills.</summary>
    private List<ToolInfo> ToolInfos()
    {
        var list = _registry.ToolInfos();
        foreach (var t in list)
            t.Decision = _security.DecisionFor(t.Name) switch { true => "always", false => "never", _ => null };
        return list;
    }

    private List<ToolDecision> DecisionList()
    {
        var list = new List<ToolDecision>();
        foreach (var kv in _security.Decisions) list.Add(new ToolDecision { Tool = kv.Key, Allow = kv.Value });
        list.Sort(static (a, b) => string.CompareOrdinal(a.Tool, b.Tool));
        return list;
    }

    private static string? Preview(CallToolResult? result)
    {
        if (result is null) return null;
        foreach (var block in result.Content)
        {
            if (block.Text is { Length: > 0 } t)
                return t.Length > 600 ? string.Concat(t.AsSpan(0, 600), "…") : t;
        }
        return result.Content.Count == 0 ? string.Empty : $"[{result.Content[0].Type} content]";
    }

    private ControlMessage ApprovalRequestMessage(PendingApproval p) => new()
    {
        Type = ControlTypes.ApprovalRequest,
        Timestamp = p.RequestedAt.ToString("O"),
        ApprovalId = p.Id,
        Tool = p.Tool,
        Risk = ModeNames.ToText(p.Risk),
        Reason = p.Reason,
        Args = p.Arguments?.DeepClone(),
        TimeoutSec = p.Timeout.TotalSeconds,
    };

    // ------------------------------------------------------------------ status

    public ControlMessage BuildStatus()
    {
        var m = ControlMessage.Of(ControlTypes.Status);
        FillStatus(m);
        return m;
    }

    private void FillStatus(ControlMessage m)
    {
        m.Pid = Environment.ProcessId;
        m.Version = HubRuntime.Version;
        m.Mode = ModeNames.ToText(_security.Mode);
        m.Compact = _rt.CompactContext;
        m.Cwd = Environment.CurrentDirectory;
        m.Client = ClientName;
        m.StartedAt = StartedAt.ToString("O");
        m.UptimeSec = Math.Round(_rt.Uptime.Elapsed.TotalSeconds, 1);
        m.RssBytes = Environment.WorkingSet;
        m.HeapBytes = GC.GetTotalMemory(false);
        m.CacheHits = _rt.ToolCache?.Hits ?? 0;
        m.CacheMisses = _rt.ToolCache?.Misses ?? 0;
        m.CacheSize = _rt.ToolCache?.Count ?? 0;
        m.CacheCapacity = _rt.BridgeCount;
        m.BridgesRunning = _rt.BridgesRunning;
        m.Blocked = _security.BlockedCount;
        m.DlpRedactions = DlpSanitizer.RedactionCount;
        m.ToolCount = _registry.Count;
        m.BridgeCount = _rt.BridgeCount;
        m.PendingApprovals = Approvals.Count;
        m.Clients = Server.ClientCount;
        var ctx = _registry.GetContextStats();
        m.ActiveTools = ctx.ActiveTools;
        m.ActiveTokens = ctx.ActiveTokens;
        m.TotalTokens = ctx.TotalTokens;
        m.Decisions = DecisionList();
        if (_rt.Auth is { Count: > 0 } auth) m.Auth = auth.Infos();
    }

    private ControlMessage BuildHello()
    {
        var m = ControlMessage.Of(ControlTypes.Hello);
        FillStatus(m);
        m.Tools = ToolInfos();
        return m;
    }

    // ------------------------------------------------------------------ inbound

    private async ValueTask OnConnectedAsync(ControlClient client)
    {
        await client.SendAsync(BuildHello()).ConfigureAwait(false);
        foreach (var p in Approvals.Pending)
            await client.SendAsync(ApprovalRequestMessage(p)).ConfigureAwait(false);
    }

    private async ValueTask OnCommandAsync(ControlClient client, ControlMessage cmd)
    {
        var ack = new ControlMessage { Type = ControlTypes.Ack, ReqId = cmd.ReqId, Ok = true, Timestamp = DateTime.UtcNow.ToString("O") };
        try
        {
            switch (cmd.Type)
            {
                case ControlTypes.GetStatus:
                    await client.SendAsync(BuildStatus()).ConfigureAwait(false);
                    break;

                case ControlTypes.ListTools:
                    await client.SendAsync(new ControlMessage { Type = ControlTypes.ToolsChanged, Timestamp = DateTime.UtcNow.ToString("O"), Tools = ToolInfos(), ReqId = cmd.ReqId }).ConfigureAwait(false);
                    return;

                case ControlTypes.ListDecisions:
                    await client.SendAsync(new ControlMessage { Type = ControlTypes.Status, Timestamp = DateTime.UtcNow.ToString("O"), Decisions = DecisionList(), ReqId = cmd.ReqId }).ConfigureAwait(false);
                    return;

                case ControlTypes.SetMode:
                    if (!ModeNames.TryParseMode(cmd.Mode, out var mode)) { Fail(ack, $"unknown mode '{cmd.Mode}'"); break; }
                    if (_security.Mode != mode)
                    {
                        _security.Mode = mode;
                        Log.Info($"mode switched to {ModeNames.ToText(mode)} by control client {client.Id}");
                        WriteDescriptor();
                        await Server.BroadcastAsync(new ControlMessage { Type = ControlTypes.ModeChanged, Timestamp = DateTime.UtcNow.ToString("O"), Mode = ModeNames.ToText(mode) }).ConfigureAwait(false);
                    }
                    break;

                case ControlTypes.Approve:
                case ControlTypes.Deny:
                    if (string.IsNullOrEmpty(cmd.ApprovalId)) { Fail(ack, "approvalId required"); break; }
                    bool approve = cmd.Type == ControlTypes.Approve;
                    // Record the remembered decision before Resolve removes the pending entry we read the tool name from.
                    if (cmd.Remember == true && Approvals.TryGet(cmd.ApprovalId, out var pending))
                    {
                        _security.Remember(pending.Tool, approve);
                        await EmitToolsChangedAsync().ConfigureAwait(false);
                    }
                    if (!Approvals.Resolve(cmd.ApprovalId, approve)) Fail(ack, $"no pending approval '{cmd.ApprovalId}'");
                    break;

                case ControlTypes.Forget:
                    if (string.IsNullOrEmpty(cmd.Tool)) { Fail(ack, "tool required"); break; }
                    if (_security.Forget(cmd.Tool))
                    {
                        Log.Info($"forgot remembered decision for '{cmd.Tool}' (control client {client.Id})");
                        await EmitToolsChangedAsync().ConfigureAwait(false);
                    }
                    break;

                case ControlTypes.Reveal:
                    if (string.IsNullOrEmpty(cmd.Tool)) { Fail(ack, "tool required"); break; }
                    if (!_registry.TryGet(cmd.Tool, out _)) { Fail(ack, $"unknown tool '{cmd.Tool}'"); break; }
                    if (_registry.Unlock(cmd.Tool))
                    {
                        if (NotifyToolsChanged is { } notify) await notify().ConfigureAwait(false);
                        await EmitToolsChangedAsync().ConfigureAwait(false);
                    }
                    break;

                case ControlTypes.Lock:
                    if (string.IsNullOrEmpty(cmd.Tool)) { Fail(ack, "tool required"); break; }
                    if (!_registry.TryGet(cmd.Tool, out var lockTarget)) { Fail(ack, $"unknown tool '{cmd.Tool}'"); break; }
                    if (lockTarget.Pinned) { Fail(ack, $"'{cmd.Tool}' is pinned and cannot be locked"); break; }
                    if (_registry.Lock(cmd.Tool))
                    {
                        Log.Info($"'{cmd.Tool}' locked by control client {client.Id}");
                        if (NotifyToolsChanged is { } notifyLock) await notifyLock().ConfigureAwait(false);
                        await EmitToolsChangedAsync().ConfigureAwait(false);
                    }
                    break;

                case ControlTypes.ClearCache:
                    await RefreshBridgesAsync().ConfigureAwait(false);
                    break;

                case ControlTypes.ReloadConfig:
                {
                    // Bridges added to ~/.hubris/config.json (by the desktop import) join the running hub without a restart.
                    var (fresh, stale) = _bridgeHost.DiffConfig();
                    var added = new List<string>();
                    foreach (var spec in fresh)
                    {
                        var bridge = await _bridgeHost.AddAsync(spec, _lifetime.Token).ConfigureAwait(false);
                        if (bridge is null) continue;
                        BridgeAdded?.Invoke(bridge);
                        added.Add(bridge.Name);
                    }
                    ack.Bridges = added;
                    if (stale.Count > 0) { ack.BridgesStale = stale; Log.Warn($"config changed for running bridge(s) {string.Join(", ", stale)}; takes effect at the next hub start"); }
                    if (added.Count > 0)
                    {
                        Log.Info($"config reload added {added.Count} bridge(s): {string.Join(", ", added)}");
                        if (NotifyToolsChanged is { } notifyReload) await notifyReload().ConfigureAwait(false);
                        await EmitToolsChangedAsync().ConfigureAwait(false);
                    }
                    break;
                }

                case ControlTypes.OAuthStatus:
                    var st = OAuthMessage(ControlTypes.Status);
                    st.ReqId = cmd.ReqId;
                    await client.SendAsync(st).ConfigureAwait(false);
                    return;

                case ControlTypes.OAuthStart:
                case ControlTypes.OAuthRevoke:
                {
                    if (string.IsNullOrEmpty(cmd.Bridge)) { Fail(ack, "bridge required"); break; }
                    if (_rt.Auth is null || !_rt.Auth.TryGet(cmd.Bridge, out var provider)) { Fail(ack, $"bridge '{cmd.Bridge}' has no auth block"); break; }
                    if (cmd.Type == ControlTypes.OAuthRevoke) { provider.Revoke(); break; }
                    if (provider.State == "pending") { Fail(ack, "login already in progress"); break; }
                    // The browser round trip takes as long as the user does; the ack says it started, oauth_changed says how it ended.
                    string bridgeName = cmd.Bridge;
                    _ = Task.Run(async () =>
                    {
                        try { await provider.LoginAsync(_lifetime.Token).ConfigureAwait(false); }
                        catch (Hubris.Auth.OAuthException) { return; /* logged and carried in the state */ }
                        // Signed in: the bridge that was waiting (or whose tools are stale) is listed now.
                        foreach (var b in _rt.Bridges)
                            if (b.Name == bridgeName) await RefreshBridgeAsync(b).ConfigureAwait(false);
                    }, CancellationToken.None);
                    ack.Text = "browser opened";
                    break;
                }

                case ControlTypes.CacheMaintain:
                    if (_rt.ToolCache is { } tc) tc.Maintain(); else Fail(ack, "tool cache is disabled");
                    break;

                case ControlTypes.Shutdown:
                    Log.Info($"shutdown requested by control client {client.Id}");
                    RequestShutdown?.Invoke();
                    break;

                default:
                    Fail(ack, $"unknown command '{cmd.Type}'");
                    break;
            }
        }
        catch (Exception ex)
        {
            Fail(ack, ex.Message);
        }
        await client.SendAsync(ack).ConfigureAwait(false);
    }

    /// <summary>Drops this hub's cache entries, (re)starts every bridge, lists its tools again and recaches them.</summary>
    private async Task RefreshBridgesAsync()
    {
        foreach (var bridge in _rt.Bridges) await RefreshBridgeAsync(bridge).ConfigureAwait(false);
    }

    private async Task RefreshBridgeAsync(McpBridge bridge)
    {
        _rt.ToolCache?.Invalidate(bridge.Name);
        if (bridge.IsStarted && !bridge.IsAlive && !bridge.CanRestart)
        {
            Log.Warn($"bridge '{bridge.Name}' has exited; restart the hub to bring it back");
            return;
        }
        try
        {
            var tools = await bridge.StartAsync(_lifetime.Token).ConfigureAwait(false);
            if (ReplaceBridgeTools is { } replace) await replace(bridge, tools).ConfigureAwait(false);
            _bridgeHost.Cache(bridge, tools);
        }
        catch (Exception ex)
        {
            Log.Warn($"bridge '{bridge.Name}' refresh failed: {ex.Message}");
        }
    }

    private static void Fail(ControlMessage ack, string error)
    {
        ack.Ok = false;
        ack.Error = error;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        _lifetime.Cancel();
        Approvals.CancelAll();
        if (_statusLoop is not null) { try { await _statusLoop.ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"status loop: {ex.Message}"); } }
        await Server.DisposeAsync().ConfigureAwait(false);
        try { File.Delete(HubrisPaths.DescriptorPath(Environment.ProcessId)); } catch (Exception ex) { Log.Debug($"descriptor delete: {ex.Message}"); }
        _lifetime.Dispose();
    }
}

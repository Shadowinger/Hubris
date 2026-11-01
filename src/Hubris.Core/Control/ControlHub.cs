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
    private readonly FastLruCache _cache;
    private readonly TimeSpan _approvalTimeout;
    private readonly CancellationTokenSource _lifetime = new();
    private Task? _statusLoop;
    private int _disposed;

    public ControlHub(HubRuntime runtime, ToolRegistry registry, SecurityInterceptor security, FastLruCache cache, TimeSpan approvalTimeout)
    {
        _rt = runtime;
        _registry = registry;
        _security = security;
        _cache = cache;
        _approvalTimeout = approvalTimeout;
        Approvals = new ApprovalGate();
        Server = new ControlServer(HubrisPaths.SocketPath(Environment.ProcessId), OnCommandAsync, OnConnectedAsync);
        Approvals.Requested += p => Server.Broadcast(ApprovalRequestMessage(p));
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

    // ------------------------------------------------------------------ lifecycle

    public void Start()
    {
        Server.Start();
        WriteDescriptor();
        _statusLoop = Task.Run(() => StatusLoopAsync(_lifetime.Token), CancellationToken.None);
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

    private ControlMessage ToolsChangedMessage() => new() { Type = ControlTypes.ToolsChanged, Timestamp = DateTime.UtcNow.ToString("O"), Tools = _registry.ToolInfos() };

    public void EmitLog(string level, string text)
    {
        if (!Server.HasClients) return;
        Server.Broadcast(new ControlMessage { Type = ControlTypes.Log, Timestamp = DateTime.UtcNow.ToString("O"), Level = level, Text = text });
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
        m.CacheHits = _cache.Hits;
        m.CacheMisses = _cache.Misses;
        m.CacheSize = _cache.Count;
        m.CacheCapacity = _cache.Capacity;
        m.Blocked = _security.BlockedCount;
        m.DlpRedactions = DlpSanitizer.RedactionCount;
        m.ToolCount = _registry.Count;
        m.BridgeCount = _rt.BridgeCount;
        m.PendingApprovals = Approvals.Count;
        m.Clients = Server.ClientCount;
    }

    private ControlMessage BuildHello()
    {
        var m = ControlMessage.Of(ControlTypes.Hello);
        FillStatus(m);
        m.Tools = _registry.ToolInfos();
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
                    await client.SendAsync(new ControlMessage { Type = ControlTypes.ToolsChanged, Timestamp = DateTime.UtcNow.ToString("O"), Tools = _registry.ToolInfos(), ReqId = cmd.ReqId }).ConfigureAwait(false);
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
                    if (!Approvals.Resolve(cmd.ApprovalId, cmd.Type == ControlTypes.Approve)) Fail(ack, $"no pending approval '{cmd.ApprovalId}'");
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

                case ControlTypes.ClearCache:
                    _cache.Clear();
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

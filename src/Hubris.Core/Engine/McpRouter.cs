using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Control;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Tools;
using Hubris.Transport;

namespace Hubris.Engine;

/// <summary>Dispatches JSON-RPC methods; one Task per request so slow tools never block ping.</summary>
public sealed class McpRouter
{
    private readonly StdioTransport _transport;
    private readonly ToolRegistry _registry;
    private readonly SecurityInterceptor _security;
    private readonly HubRuntime _runtime;
    private readonly List<ExternalMcpBridge> _bridges;
    private readonly ControlHub? _control;
    private readonly ConcurrentDictionary<RpcId, CancellationTokenSource> _inflight = new();
    private readonly CancellationTokenSource _shutdown = new();
    private volatile bool _initialized;
    private long _callSeq;

    public McpRouter(StdioTransport transport, ToolRegistry registry, SecurityInterceptor security, HubRuntime runtime, List<ExternalMcpBridge> bridges, ControlHub? control = null)
    {
        _transport = transport;
        _registry = registry;
        _security = security;
        _runtime = runtime;
        _bridges = bridges;
        _control = control;
        foreach (var b in bridges) { b.ToolsChanged += OnBridgeToolsChanged; b.Exited += OnBridgeExited; }

        if (registry.TryGet(ExecuteToolMetaTool.ToolName, out var proxy) && proxy is ExecuteToolMetaTool exec)
            exec.Invoker = (name, args, ct) => InvokeToolAsync(name, args, ct, viaProxy: true);

        if (control is not null)
        {
            control.NotifyToolsChanged = () => _initialized ? SendToolsListChangedAsync() : ValueTask.CompletedTask;
            control.ReplaceBridgeTools = ReplaceBridgeToolsAsync;
            control.BridgeAdded = b => { b.ToolsChanged += OnBridgeToolsChanged; b.Exited += OnBridgeExited; };
        }
    }

    public bool Initialized => _initialized;

    // ------------------------------------------------------------------ entry

    public ValueTask HandleAsync(JsonRpcMessage msg)
    {
        if (msg.Method is null)
        {
            Log.Debug($"ignoring response/stray frame id={msg.Id}");
            return ValueTask.CompletedTask;
        }

        if (msg.Id.IsNone)
            return HandleNotificationAsync(msg);

        var cts = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
        if (!_inflight.TryAdd(msg.Id, cts))
        {
            cts.Dispose();
            return _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.InvalidRequest, $"Duplicate in-flight request id {msg.Id}");
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await DispatchAsync(msg, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                if (!_shutdown.IsCancellationRequested)
                    await SafeSendErrorAsync(msg.Id, JsonRpcErrorCodes.RequestCancelled, "Request cancelled").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log.Error($"{msg.Method} id={msg.Id} failed: {ex}");
                await SafeSendErrorAsync(msg.Id, JsonRpcErrorCodes.InternalError, $"{ex.GetType().Name}: {ex.Message}").ConfigureAwait(false);
            }
            finally
            {
                _inflight.TryRemove(msg.Id, out _);
                cts.Dispose();
            }
        }, CancellationToken.None);

        return ValueTask.CompletedTask;
    }

    private ValueTask HandleNotificationAsync(JsonRpcMessage msg)
    {
        switch (msg.Method)
        {
            case "notifications/initialized":
                _initialized = true;
                Log.Debug("client initialized");
                break;
            case "notifications/cancelled":
                CancelledParams? p = null;
                try { if (msg.Params is not null) p = JsonSerializer.Deserialize(msg.Params, McpJsonContext.Default.CancelledParams); }
                catch (JsonException ex) { Log.Warn($"ignoring malformed notifications/cancelled: {ex.Message}"); }
                if (p is not null && _inflight.TryGetValue(p.RequestId, out var cts))
                {
                    Log.Debug($"cancelling {p.RequestId}: {p.Reason}");
                    try { cts.Cancel(); } catch (ObjectDisposedException) { }
                }
                break;
            default:
                Log.Debug($"notification {msg.Method} ignored");
                break;
        }
        return ValueTask.CompletedTask;
    }

    // ------------------------------------------------------------------ dispatch

    private async Task DispatchAsync(JsonRpcMessage msg, CancellationToken ct)
    {
        switch (msg.Method)
        {
            case "initialize":
                await HandleInitializeAsync(msg, ct).ConfigureAwait(false);
                break;
            case "ping":
                await _transport.SendResultAsync(msg.Id, new EmptyResult(), McpJsonContext.Default.EmptyResult, ct).ConfigureAwait(false);
                break;
            case "tools/list":
                await _transport.SendResultAsync(msg.Id, new ListToolsResult { Tools = _registry.ListVisible() }, McpJsonContext.Default.ListToolsResult, ct).ConfigureAwait(false);
                break;
            case "tools/call":
                await HandleToolCallAsync(msg, ct).ConfigureAwait(false);
                break;
            case "resources/list":
                await _transport.SendResultAsync(msg.Id, new EmptyListResult { Resources = new List<JsonObject>() }, McpJsonContext.Default.EmptyListResult, ct).ConfigureAwait(false);
                break;
            case "prompts/list":
                await _transport.SendResultAsync(msg.Id, new EmptyListResult { Prompts = new List<JsonObject>() }, McpJsonContext.Default.EmptyListResult, ct).ConfigureAwait(false);
                break;
            default:
                await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.MethodNotFound, $"Method not found: {msg.Method}", null, ct).ConfigureAwait(false);
                break;
        }
    }

    private async Task HandleInitializeAsync(JsonRpcMessage msg, CancellationToken ct)
    {
        InitializeParams? p = null;
        if (msg.Params is not null)
        {
            try { p = JsonSerializer.Deserialize(msg.Params, McpJsonContext.Default.InitializeParams); }
            catch (JsonException ex)
            {
                await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.InvalidParams, $"Invalid initialize params: {ex.Message}", null, ct).ConfigureAwait(false);
                return;
            }
        }

        string version = McpProtocol.Negotiate(p?.ProtocolVersion);
        if (p?.ClientInfo is { } ci)
        {
            Log.Info($"client {ci.Name} {ci.Version} protocol={version}");
            if (_control is not null)
            {
                _control.ClientName = string.IsNullOrEmpty(ci.Version) ? ci.Name : $"{ci.Name} {ci.Version}";
                _control.WriteDescriptor();
            }
        }

        string modeText = ModeNames.ToText(_runtime.Mode);
        string instructions = _runtime.Mode == ExecutionMode.Safe
            ? $"Hubris runs in {modeText} mode: read-only tools execute immediately; mutating tools are scanned for destructive patterns and destructive tools are blocked. A blocked call either waits for the user to approve it in the Hubris desktop app or returns isError=true with a [SAFE MODE BLOCKED] message – in that case ask the user to approve it or to switch Hubris to Bypass mode."
            : $"Hubris runs in {modeText} mode: all tool calls execute without policy checks.";
        instructions += $" Use {SearchToolsMetaTool.ToolName} with keywords to discover additional tools; discovered tools are unlocked and can be called directly or through {ExecuteToolMetaTool.ToolName}.";
        if (_runtime.CompactContext)
            instructions += " Compact context is enabled: only core tools are listed until unlocked.";

        var result = new InitializeResult
        {
            ProtocolVersion = version,
            Capabilities = new ServerCapabilities { Tools = new ToolsCapability { ListChanged = true } },
            ServerInfo = new Implementation { Name = "Hubris", Version = HubRuntime.Version },
            Instructions = instructions,
        };
        await _transport.SendResultAsync(msg.Id, result, McpJsonContext.Default.InitializeResult, ct).ConfigureAwait(false);
    }

    private async Task HandleToolCallAsync(JsonRpcMessage msg, CancellationToken ct)
    {
        CallToolParams? p;
        try { p = msg.Params is null ? null : JsonSerializer.Deserialize(msg.Params, McpJsonContext.Default.CallToolParams); }
        catch (JsonException ex)
        {
            await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.InvalidParams, $"Invalid tools/call params: {ex.Message}", null, ct).ConfigureAwait(false);
            return;
        }
        if (p is null || string.IsNullOrEmpty(p.Name))
        {
            await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.InvalidParams, "tools/call requires 'name'", null, ct).ConfigureAwait(false);
            return;
        }

        CallToolResult result = await InvokeToolAsync(p.Name, p.Arguments, ct, viaProxy: false).ConfigureAwait(false);
        await _transport.SendResultAsync(msg.Id, result, McpJsonContext.Default.CallToolResult, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ the pipeline

    /// <summary>
    /// security → (approval) → cache → execute → DLP → cache store → events → unlock notifications.
    /// Shared by direct tools/call and by mcp_execute_tool, so the proxy cannot bypass policy.
    /// </summary>
    private async ValueTask<CallToolResult> InvokeToolAsync(string name, JsonObject? args, CancellationToken ct, bool viaProxy)
    {
        string callId = $"{Environment.ProcessId}-{Interlocked.Increment(ref _callSeq)}";

        if (!_registry.TryGet(name, out var tool))
            return CallToolResult.Error($"Unknown tool '{name}'. Use {SearchToolsMetaTool.ToolName} to discover available tools.");

        string outcome = "ok";
        bool bridged = tool is BridgedTool;
        var verdict = _security.Evaluate(tool.Name, tool.RiskLevel, args, bridged);
        if (!verdict.Allowed)
        {
            string reason = verdict.Reason ?? SecurityInterceptor.BlockedPrefix;
            if (_control is { HasClients: true })
            {
                Log.Info($"holding '{tool.Name}' for approval");
                ApprovalDecision decision = await _control.RequestApprovalAsync(tool.Name, tool.RiskLevel, reason, args, ct).ConfigureAwait(false);
                if (decision != ApprovalDecision.Approved)
                {
                    string why = decision switch
                    {
                        ApprovalDecision.Denied => "Denied by the user in the Hubris desktop app.",
                        ApprovalDecision.TimedOut => $"No decision within {_control.ApprovalTimeout.TotalSeconds:0}s.",
                        _ => "Request cancelled (UI disconnected or call aborted).",
                    };
                    var denied = CallToolResult.Error($"{reason} {why}");
                    _control.EmitToolCall(callId, tool.Name, tool.RiskLevel, ApprovalGate.DecisionText(decision), 0, args, denied);
                    return denied;
                }
                outcome = "approved";
                Log.Info($"'{tool.Name}' approved by user");
            }
            else
            {
                var blocked = CallToolResult.Error(reason);
                _control?.EmitToolCall(callId, tool.Name, tool.RiskLevel, "blocked", 0, args, blocked);
                return blocked;
            }
        }

        CallToolResult result;
        long t0 = System.Diagnostics.Stopwatch.GetTimestamp();
        try
        {
            result = await tool.ExecuteAsync(args, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _control?.EmitToolCall(callId, tool.Name, tool.RiskLevel, "cancelled", System.Diagnostics.Stopwatch.GetElapsedTime(t0).TotalMilliseconds, args, null);
            throw;
        }
        catch (Exception ex)
        {
            Log.Error($"tool {tool.Name} threw: {ex}");
            result = CallToolResult.Error($"{ex.GetType().Name}: {ex.Message}");
        }
        double ms = System.Diagnostics.Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
        Log.Debug($"{tool.Name} {(result.Failed ? "error" : "ok")} {ms:0.0}ms{(viaProxy ? " (via proxy)" : "")}");

        result = DlpSanitizer.Sanitize(result);

        if (result.Failed && outcome == "ok") outcome = "error";
        _control?.EmitToolCall(callId, tool.Name, tool.RiskLevel, outcome, ms, args, result);

        if (tool is IUnlockingTool { LastCallUnlocked: true })
        {
            await SendToolsListChangedAsync().ConfigureAwait(false);
            _control?.EmitToolsChanged();
        }

        return result;
    }

    private ValueTask SendToolsListChangedAsync()
        => _transport.SendNotificationAsync("notifications/tools/list_changed", null, _shutdown.Token);

    private async ValueTask SafeSendErrorAsync(RpcId id, int code, string message)
    {
        try { await _transport.SendErrorAsync(id, code, message).ConfigureAwait(false); }
        catch (Exception ex) { Log.Debug($"send error failed: {ex.Message}"); }
    }

    // ------------------------------------------------------------------ bridge events

    private void OnBridgeToolsChanged(ExternalMcpBridge bridge)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                var tools = await bridge.ListToolsAsync(_shutdown.Token).ConfigureAwait(false);
                await ReplaceBridgeToolsAsync(bridge, tools).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log.Warn($"bridge '{bridge.Name}' tool refresh failed: {ex.Message}");
            }
        }, CancellationToken.None);
    }

    /// <summary>A dead bridge must not keep advertising tools that can only fail.</summary>
    private void OnBridgeExited(ExternalMcpBridge bridge)
    {
        _ = Task.Run(() => ReplaceBridgeToolsAsync(bridge, []), CancellationToken.None);
    }

    /// <summary>Also used by the control hub after Clear cache re-lists a bridge.</summary>
    private async Task ReplaceBridgeToolsAsync(ExternalMcpBridge bridge, List<ToolDefinition> tools)
    {
        _registry.UnregisterWhere(t => t is BridgedTool bt && string.Equals(bt.BridgeName, bridge.Name, StringComparison.Ordinal));
        foreach (var def in tools) _registry.Register(new BridgedTool(bridge, def));
        Log.Info($"bridge '{bridge.Name}' now exposes {tools.Count} tool(s)");
        if (_initialized) await SendToolsListChangedAsync().ConfigureAwait(false);
        _control?.EmitToolsChanged();
    }

    // ------------------------------------------------------------------ shutdown

    /// <summary>Waits for in-flight requests to finish without cancelling them (stdin EOF path).</summary>
    public async Task DrainAsync(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!_inflight.IsEmpty && DateTime.UtcNow < deadline)
            await Task.Delay(10).ConfigureAwait(false);
        if (!_inflight.IsEmpty) Log.Warn($"drain timeout; {_inflight.Count} request(s) still in flight");
    }

    public async Task ShutdownAsync()
    {
        _shutdown.Cancel();
        foreach (var kv in _inflight)
        {
            try { kv.Value.Cancel(); } catch (ObjectDisposedException) { }
        }

        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (!_inflight.IsEmpty && DateTime.UtcNow < deadline)
            await Task.Delay(20).ConfigureAwait(false);

        foreach (var b in _bridges) { b.ToolsChanged -= OnBridgeToolsChanged; b.Exited -= OnBridgeExited; }
    }
}

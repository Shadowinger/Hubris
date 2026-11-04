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
    private readonly IEnumerable<McpBridge> _bridges;
    private readonly ControlHub? _control;
    private readonly ConcurrentDictionary<RpcId, CancellationTokenSource> _inflight = new();
    private readonly CancellationTokenSource _shutdown = new();
    private volatile bool _initialized;
    private long _callSeq;

    public McpRouter(StdioTransport transport, ToolRegistry registry, SecurityInterceptor security, HubRuntime runtime, IEnumerable<McpBridge> bridges, ControlHub? control = null)
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
            {
                var all = new ListResourcesResult();
                foreach (var kv in _runtime.Extras) all.Resources.AddRange(kv.Value.Resources);
                await _transport.SendResultAsync(msg.Id, all, McpJsonContext.Default.ListResourcesResult, ct).ConfigureAwait(false);
                break;
            }
            case "resources/templates/list":
            {
                var all = new ListResourceTemplatesResult();
                foreach (var kv in _runtime.Extras) all.ResourceTemplates.AddRange(kv.Value.ResourceTemplates);
                await _transport.SendResultAsync(msg.Id, all, McpJsonContext.Default.ListResourceTemplatesResult, ct).ConfigureAwait(false);
                break;
            }
            case "resources/read":
                await HandleResourceReadAsync(msg, ct).ConfigureAwait(false);
                break;
            case "prompts/list":
            {
                // Prompt names get the bridge prefix like tools do, so prompts/get can find the owner.
                var all = new ListPromptsResult();
                foreach (var kv in _runtime.Extras)
                    foreach (var p in kv.Value.Prompts)
                    {
                        var copy = (JsonObject)p.DeepClone();
                        copy["name"] = kv.Key + "__" + (p["name"]?.GetValue<string>() ?? "");
                        all.Prompts.Add(copy);
                    }
                await _transport.SendResultAsync(msg.Id, all, McpJsonContext.Default.ListPromptsResult, ct).ConfigureAwait(false);
                break;
            }
            case "prompts/get":
                await HandlePromptGetAsync(msg, ct).ConfigureAwait(false);
                break;
            default:
                await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.MethodNotFound, $"Method not found: {msg.Method}", null, ct).ConfigureAwait(false);
                break;
        }
    }

    /// <summary>The bridge that listed the URI, else the one whose template prefix (up to the first '{') matches.</summary>
    private McpBridge? OwnerOfResource(string uri)
    {
        foreach (var kv in _runtime.Extras)
            foreach (var r in kv.Value.Resources)
                if (r["uri"] is JsonValue v && v.TryGetValue<string>(out var u) && u == uri) return _runtime.Bridge(kv.Key);
        McpBridge? best = null;
        int bestLen = -1;
        foreach (var kv in _runtime.Extras)
            foreach (var t in kv.Value.ResourceTemplates)
            {
                if (t["uriTemplate"] is not JsonValue v || !v.TryGetValue<string>(out var tpl)) continue;
                int brace = tpl.IndexOf('{');
                string prefix = brace < 0 ? tpl : tpl[..brace];
                if (prefix.Length > bestLen && uri.StartsWith(prefix, StringComparison.Ordinal)) { best = _runtime.Bridge(kv.Key); bestLen = prefix.Length; }
            }
        return best;
    }

    private async Task HandleResourceReadAsync(JsonRpcMessage msg, CancellationToken ct)
    {
        string? uri = msg.Params?["uri"] is JsonValue v && v.TryGetValue<string>(out var u) ? u : null;
        if (string.IsNullOrEmpty(uri))
        {
            await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.InvalidParams, "resources/read requires 'uri'", null, ct).ConfigureAwait(false);
            return;
        }
        var bridge = OwnerOfResource(uri);
        if (bridge is null)
        {
            await _transport.SendErrorAsync(msg.Id, -32002, $"Resource not found: {uri}", null, ct).ConfigureAwait(false);
            return;
        }
        JsonNode? result;
        try { result = await bridge.ReadResourceAsync(uri, ct).ConfigureAwait(false); }
        catch (McpBridgeException ex) { await _transport.SendErrorAsync(msg.Id, ex.Code, ex.Message, null, ct).ConfigureAwait(false); return; }
        catch (Exception ex) when (ex is TimeoutException or HttpRequestException or IOException)
        { await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.InternalError, $"bridge '{bridge.Name}': {ex.Message}", null, ct).ConfigureAwait(false); return; }

        // Same DLP as tool results: the model must not see secrets through a resource either.
        if (result is JsonObject o && o["contents"] is JsonArray contents)
            foreach (var c in contents)
                if (c is JsonObject co && co["text"] is JsonValue tv && tv.TryGetValue<string>(out var text) && text.Length > 0)
                {
                    string clean = DlpSanitizer.Sanitize(text);
                    if (!ReferenceEquals(clean, text)) co["text"] = clean;
                }
        await _transport.SendResultAsync(msg.Id, result ?? new JsonObject(), McpJsonContext.Default.JsonNode, ct).ConfigureAwait(false);
    }

    private async Task HandlePromptGetAsync(JsonRpcMessage msg, CancellationToken ct)
    {
        string? name = msg.Params?["name"] is JsonValue v && v.TryGetValue<string>(out var n) ? n : null;
        int sep = name?.IndexOf("__", StringComparison.Ordinal) ?? -1;
        var bridge = sep > 0 ? _runtime.Bridge(name![..sep]) : null;
        if (bridge is null)
        {
            await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.InvalidParams, $"Unknown prompt '{name}'; prompts/list gives the names", null, ct).ConfigureAwait(false);
            return;
        }
        var args = msg.Params?["arguments"] as JsonObject;
        JsonNode? result;
        try { result = await bridge.GetPromptAsync(name![(sep + 2)..], args, ct).ConfigureAwait(false); }
        catch (McpBridgeException ex) { await _transport.SendErrorAsync(msg.Id, ex.Code, ex.Message, null, ct).ConfigureAwait(false); return; }
        catch (Exception ex) when (ex is TimeoutException or HttpRequestException or IOException)
        { await _transport.SendErrorAsync(msg.Id, JsonRpcErrorCodes.InternalError, $"bridge '{bridge.Name}': {ex.Message}", null, ct).ConfigureAwait(false); return; }
        await _transport.SendResultAsync(msg.Id, result ?? new JsonObject(), McpJsonContext.Default.JsonNode, ct).ConfigureAwait(false);
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
        instructions += $" Use {SearchToolsMetaTool.ToolName} with keywords to discover additional tools; discovered tools are unlocked and can be called directly or through {ExecuteToolMetaTool.ToolName}. Resources and prompts of the bridged servers are listed as-is (prompt names carry the bridge prefix).";
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

            // A remembered session decision short-circuits the gate (Bypass never reaches here: Evaluate returns Ok).
            bool? remembered = _security.DecisionFor(tool.Name);
            if (remembered == true && verdict.PatternHit)
            {
                Log.Info($"'{tool.Name}' is remembered as allowed, but the arguments hit a destructive pattern: asking");
                remembered = null;
            }
            if (remembered == false)
            {
                var denied = CallToolResult.Error($"{reason} Denied for this session.");
                _control?.EmitToolCall(callId, tool.Name, tool.RiskLevel, "denied", 0, args, denied);
                return denied;
            }
            if (remembered == true)
            {
                outcome = "approved";
                Log.Info($"'{tool.Name}' auto-approved (remembered for this session)");
            }
            else if (_control is { HasClients: true })
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
        int unlockedBefore = _registry.UnlockedCount; // per call, not a flag on the shared tool instance: parallel searches must each notify
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

        if (tool is IUnlockingTool && _registry.UnlockedCount != unlockedBefore)
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

    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    /// <summary>Re-lists after list_changed (and after the first lazy start): one refresh at a time so an older list never lands last.</summary>
    private void OnBridgeToolsChanged(McpBridge bridge)
    {
        _ = Task.Run(async () =>
        {
            await _refreshLock.WaitAsync(_shutdown.Token).ConfigureAwait(false);
            try
            {
                var tools = await bridge.ListToolsAsync(_shutdown.Token).ConfigureAwait(false);
                string fresh = JsonSerializer.Serialize(tools, McpJsonContext.Default.ListToolDefinition);
                string current = JsonSerializer.Serialize(_registry.DefinitionsOf(bridge.Name), McpJsonContext.Default.ListToolDefinition);
                if (!string.Equals(fresh, current, StringComparison.Ordinal))
                    await ReplaceBridgeToolsAsync(bridge, tools).ConfigureAwait(false);
                BridgeHost.Cache(_runtime, bridge, tools); // the cache must say what the server last said, for every other hub too
                if (await BridgeHost.RefreshExtrasAsync(_runtime, bridge, _shutdown.Token).ConfigureAwait(false) && _initialized)
                {
                    await _transport.SendNotificationAsync("notifications/resources/list_changed", null, _shutdown.Token).ConfigureAwait(false);
                    await _transport.SendNotificationAsync("notifications/prompts/list_changed", null, _shutdown.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Log.Warn($"bridge '{bridge.Name}' tool refresh failed: {ex.Message}");
            }
            finally
            {
                _refreshLock.Release();
            }
        }, CancellationToken.None);
    }

    /// <summary>A dead bridge must not keep advertising tools that can only fail.</summary>
    private void OnBridgeExited(McpBridge bridge)
    {
        _ = Task.Run(() => ReplaceBridgeToolsAsync(bridge, []), CancellationToken.None);
    }

    /// <summary>Also used by the control hub after Clear cache re-lists a bridge.</summary>
    private async Task ReplaceBridgeToolsAsync(McpBridge bridge, List<ToolDefinition> tools)
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

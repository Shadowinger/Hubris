using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using McpHub.Caching;
using McpHub.Protocol;
using McpHub.Security;
using McpHub.Tools;
using McpHub.Transport;

namespace McpHub.Engine;

/// <summary>Dispatches JSON-RPC methods; one Task per request so slow tools never block ping.</summary>
public sealed class McpRouter
{
    private readonly StdioTransport _transport;
    private readonly ToolRegistry _registry;
    private readonly SecurityInterceptor _security;
    private readonly FastLruCache _cache;
    private readonly HubRuntime _runtime;
    private readonly List<ExternalMcpBridge> _bridges;
    private readonly ConcurrentDictionary<RpcId, CancellationTokenSource> _inflight = new();
    private readonly CancellationTokenSource _shutdown = new();
    private volatile bool _initialized;

    public McpRouter(StdioTransport transport, ToolRegistry registry, SecurityInterceptor security, FastLruCache cache, HubRuntime runtime, List<ExternalMcpBridge> bridges)
    {
        _transport = transport;
        _registry = registry;
        _security = security;
        _cache = cache;
        _runtime = runtime;
        _bridges = bridges;
        foreach (var b in bridges) b.ToolsChanged += OnBridgeToolsChanged;
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
                if (msg.Params is not null)
                {
                    var p = JsonSerializer.Deserialize(msg.Params, McpJsonContext.Default.CancelledParams);
                    if (p is not null && _inflight.TryGetValue(p.RequestId, out var cts))
                    {
                        Log.Debug($"cancelling {p.RequestId}: {p.Reason}");
                        try { cts.Cancel(); } catch (ObjectDisposedException) { }
                    }
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
        if (p?.ClientInfo is { } ci) Log.Info($"client {ci.Name} {ci.Version} protocol={version}");

        string modeText = ModeNames.ToText(_runtime.Mode);
        string instructions = _runtime.Mode == ExecutionMode.Safe
            ? $"McpHub runs in {modeText} mode: read-only tools execute immediately; mutating tools are scanned for destructive patterns and destructive tools are blocked. A blocked call returns isError=true with a [SAFE MODE BLOCKED] message – ask the user to confirm or to restart McpHub with --mode=bypass."
            : $"McpHub runs in {modeText} mode: all tool calls execute without policy checks.";
        if (_runtime.CompactContext)
            instructions += $" Compact context is enabled: only core tools are listed. Call {SearchToolsMetaTool.ToolName} with keywords to discover and unlock additional tools.";

        var result = new InitializeResult
        {
            ProtocolVersion = version,
            Capabilities = new ServerCapabilities { Tools = new ToolsCapability { ListChanged = true } },
            ServerInfo = new Implementation { Name = "McpHub", Version = HubRuntime.Version },
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

        if (!_registry.TryGet(p.Name, out var tool))
        {
            await SendToolResultAsync(msg.Id, CallToolResult.Error($"Unknown tool '{p.Name}'. Use {SearchToolsMetaTool.ToolName} to discover available tools."), ct).ConfigureAwait(false);
            return;
        }

        var verdict = _security.Evaluate(tool.Name, tool.RiskLevel, p.Arguments);
        if (!verdict.Allowed)
        {
            await SendToolResultAsync(msg.Id, CallToolResult.Error(verdict.Reason ?? SecurityInterceptor.BlockedPrefix), ct).ConfigureAwait(false);
            return;
        }

        bool isMeta = tool is SearchToolsMetaTool;
        bool cacheable = tool.RiskLevel == ToolRiskLevel.ReadOnly && !isMeta;
        FastLruCache.CacheKey key = default;
        if (cacheable)
        {
            key = FastLruCache.ComputeKey(tool.Name, p.Arguments);
            if (_cache.TryGet(in key, out var cached) && cached is not null)
            {
                Log.Debug($"cache hit {tool.Name}");
                await SendToolResultAsync(msg.Id, cached, ct).ConfigureAwait(false);
                return;
            }
        }

        CallToolResult result;
        long t0 = System.Diagnostics.Stopwatch.GetTimestamp();
        try
        {
            result = await tool.ExecuteAsync(p.Arguments, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Error($"tool {tool.Name} threw: {ex}");
            result = CallToolResult.Error($"{ex.GetType().Name}: {ex.Message}");
        }
        double ms = System.Diagnostics.Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
        Log.Debug($"{tool.Name} {(result.Failed ? "error" : "ok")} {ms:0.0}ms");

        result = DlpSanitizer.Sanitize(result);

        if (cacheable && !result.Failed)
            _cache.Set(in key, result);

        await SendToolResultAsync(msg.Id, result, ct).ConfigureAwait(false);

        if (isMeta && tool is SearchToolsMetaTool meta && meta.LastCallRevealed)
            await _transport.SendNotificationAsync("notifications/tools/list_changed", null, ct).ConfigureAwait(false);
    }

    private ValueTask SendToolResultAsync(RpcId id, CallToolResult result, CancellationToken ct)
        => _transport.SendResultAsync(id, result, McpJsonContext.Default.CallToolResult, ct);

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
                _registry.UnregisterWhere(t => t is IBridgedTool bt && string.Equals(bt.BridgeName, bridge.Name, StringComparison.Ordinal));
                foreach (var def in tools) _registry.Register(new BridgedTool(bridge, def));
                Log.Info($"bridge '{bridge.Name}' tools refreshed: {tools.Count}");
                if (_initialized)
                    await _transport.SendNotificationAsync("notifications/tools/list_changed", null, _shutdown.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log.Warn($"bridge '{bridge.Name}' tool refresh failed: {ex.Message}");
            }
        }, CancellationToken.None);
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

        foreach (var b in _bridges) b.ToolsChanged -= OnBridgeToolsChanged;
    }
}

using System.Text.Json;
using Hubris.Caching;
using Hubris.Cli;
using Hubris.Config;
using Hubris.Protocol;
using Hubris.Transport;

namespace Hubris.Engine;

/// <summary>Brings a bridge into the hub: cache hit → tools registered without a process or connection, miss → start, list, cache.</summary>
public sealed class BridgeHost
{
    private readonly HubRuntime _rt;
    private readonly ToolRegistry _registry;

    public BridgeHost(HubRuntime runtime, ToolRegistry registry)
    {
        _rt = runtime;
        _registry = registry;
    }

    public async Task<McpBridge?> AddAsync(BridgeSpec spec, CancellationToken ct)
    {
        McpBridge bridge;
        try { bridge = McpBridge.Create(spec, _rt.Auth); }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            Log.Warn($"bridge '{spec.Name}' skipped: {ex.Message}");
            return null;
        }

        var cachedTools = _rt.ToolCache?.TryGet(spec.Name, bridge.ConfigHash);
        if (cachedTools is not null)
        {
            foreach (var def in cachedTools) _registry.Register(new BridgedTool(bridge, def));
            if (_rt.ToolCache?.TryGetExtras(spec.Name, bridge.ConfigHash) is { } cachedExtras) _rt.Extras[spec.Name] = cachedExtras;
            _rt.Bridges.Enqueue(bridge);
            Log.Info($"bridge '{spec.Name}' exposes {cachedTools.Count} tool(s) from cache; {(spec.IsRemote ? "not connected yet" : "process not started")}");
            return bridge;
        }

        try
        {
            var tools = await bridge.StartAsync(ct).ConfigureAwait(false);
            foreach (var def in tools) _registry.Register(new BridgedTool(bridge, def));
            _rt.Bridges.Enqueue(bridge);
            Log.Info($"bridge '{spec.Name}' exposes {tools.Count} tool(s)" + (bridge.ServerInfo is { } si ? $" ({si.Name} {si.Version})" : string.Empty));
            Cache(_rt, bridge, tools);
            await RefreshExtrasAsync(_rt, bridge, ct).ConfigureAwait(false);
            return bridge;
        }
        catch (NotSignedInException)
        {
            // Keep it, without tools: after Connect the control hub lists it (RefreshBridgeAsync).
            _rt.Bridges.Enqueue(bridge);
            Log.Warn($"bridge '{spec.Name}' waits for sign-in; its tools appear after Connect in the desktop app");
            return bridge;
        }
        catch (Exception ex)
        {
            Log.Warn($"bridge '{spec.Name}' failed to start: {ex.Message}");
            await bridge.DisposeAsync().ConfigureAwait(false);
            return null;
        }
    }

    /// <summary>Fetches the bridge's resources/templates/prompts, stores them for the client and the cache. Returns true when they changed.</summary>
    public static async Task<bool> RefreshExtrasAsync(HubRuntime rt, McpBridge bridge, CancellationToken ct)
    {
        BridgeExtras extras;
        try { extras = await bridge.FetchExtrasAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is McpBridgeException or TimeoutException or HttpRequestException or IOException)
        {
            Log.Warn($"bridge '{bridge.Name}' resources/prompts not listed: {ex.Message}");
            return false;
        }
        string fresh = JsonSerializer.Serialize(extras, McpJsonContext.Default.BridgeExtras);
        string before = rt.Extras.TryGetValue(bridge.Name, out var old) ? JsonSerializer.Serialize(old, McpJsonContext.Default.BridgeExtras) : "";
        rt.Extras[bridge.Name] = extras;
        rt.ToolCache?.PutExtras(bridge.Name, bridge.ConfigHash, extras);
        if (!extras.IsEmpty) Log.Info($"bridge '{bridge.Name}' offers {extras.Resources.Count} resource(s), {extras.ResourceTemplates.Count} template(s), {extras.Prompts.Count} prompt(s)");
        return !string.Equals(fresh, before, StringComparison.Ordinal);
    }

    public static void Cache(HubRuntime rt, McpBridge bridge, List<ToolDefinition> tools)
    {
        if (rt.ToolCache is not { } cache) return;
        int tokens = 0;
        foreach (var def in tools) tokens += ToolRegistry.EstimateTokens(new BridgedTool(bridge, def));
        cache.Put(bridge.Name, bridge.ConfigHash, tools, tokens);
    }

    /// <summary>Bridges from ~/.hubris/config.json that this hub does not run yet (by name), and names whose launch changed.</summary>
    public (List<BridgeSpec> New, List<string> Stale) DiffConfig()
    {
        var specs = HubrisConfigFile.ToSpecs(HubrisConfigFile.Load());
        var running = _rt.Bridges.ToArray();
        var fresh = new List<BridgeSpec>();
        var stale = new List<string>();
        foreach (var s in specs)
        {
            var b = Array.Find(running, x => x.Name == s.Name);
            if (b is null) { fresh.Add(s); continue; }
            if (b.ConfigHash != s.ConfigHash()) stale.Add(s.Name); // a changed launch only takes effect at the next hub start
        }
        return (fresh, stale);
    }
}

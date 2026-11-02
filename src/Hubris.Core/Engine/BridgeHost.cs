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
        try { bridge = McpBridge.Create(spec); }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            Log.Warn($"bridge '{spec.Name}' skipped: {ex.Message}");
            return null;
        }

        var cachedTools = _rt.ToolCache?.TryGet(spec.Name, bridge.ConfigHash);
        if (cachedTools is not null)
        {
            foreach (var def in cachedTools) _registry.Register(new BridgedTool(bridge, def));
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
            Cache(bridge, tools);
            return bridge;
        }
        catch (Exception ex)
        {
            Log.Warn($"bridge '{spec.Name}' failed to start: {ex.Message}");
            await bridge.DisposeAsync().ConfigureAwait(false);
            return null;
        }
    }

    public void Cache(McpBridge bridge, List<ToolDefinition> tools)
    {
        if (_rt.ToolCache is not { } cache) return;
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

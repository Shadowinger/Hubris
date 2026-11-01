using Hubris.Caching;
using Hubris.Cli;
using Hubris.Config;
using Hubris.Protocol;
using Hubris.Transport;

namespace Hubris.Engine;

/// <summary>Brings a bridge into the hub: cache hit → tools registered without a process, miss → spawn, list, cache.</summary>
public sealed class BridgeHost
{
    private readonly HubRuntime _rt;
    private readonly ToolRegistry _registry;

    public BridgeHost(HubRuntime runtime, ToolRegistry registry)
    {
        _rt = runtime;
        _registry = registry;
    }

    public async Task<ExternalMcpBridge?> AddAsync(BridgeSpec spec, CancellationToken ct)
    {
        var bridge = new ExternalMcpBridge(spec.Name, spec.Command, spec.Args, env: spec.Env);
        string hash = ToolCacheStore.ComputeHash(spec.Command, spec.Args, spec.Env?.Keys ?? []);

        var cachedTools = _rt.ToolCache?.TryGet(spec.Name, hash);
        if (cachedTools is not null)
        {
            foreach (var def in cachedTools) _registry.Register(new BridgedTool(bridge, def));
            _rt.Bridges.Add(bridge);
            Log.Info($"bridge '{spec.Name}' exposes {cachedTools.Count} tool(s) from cache; process not started");
            return bridge;
        }

        try
        {
            var tools = await bridge.StartAsync(ct).ConfigureAwait(false);
            foreach (var def in tools) _registry.Register(new BridgedTool(bridge, def));
            _rt.Bridges.Add(bridge);
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

    public void Cache(ExternalMcpBridge bridge, List<ToolDefinition> tools)
    {
        if (_rt.ToolCache is not { } cache) return;
        int tokens = 0;
        foreach (var def in tools) tokens += ToolRegistry.EstimateTokens(new BridgedTool(bridge, def));
        cache.Put(bridge.Name, ToolCacheStore.ComputeHash(bridge.Command, bridge.Args, bridge.Env.Keys), tools, tokens);
    }

    /// <summary>Bridges from ~/.hubris/config.json that this hub does not run yet (by name).</summary>
    public List<BridgeSpec> NewSpecsFromConfig()
    {
        var specs = HubrisConfigFile.ToSpecs(HubrisConfigFile.Load());
        specs.RemoveAll(s => _rt.Bridges.Exists(b => b.Name == s.Name));
        return specs;
    }
}

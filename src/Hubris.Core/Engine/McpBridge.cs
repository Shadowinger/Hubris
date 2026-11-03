using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Cli;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Tools;
using Hubris.Transport;

namespace Hubris.Engine;

public class McpBridgeException : Exception
{
    public McpBridgeException(int code, string message) : base(message) => Code = code;
    public int Code { get; }
}

/// <summary>The bridge has an auth block but no token yet: not a failure, the user has to press Connect.</summary>
public sealed class NotSignedInException : McpBridgeException
{
    public NotSignedInException(string bridge) : base(JsonRpcErrorCodes.InternalError, $"bridge '{bridge}' is not signed in: press Connect in the Hubris desktop app") { }
}

/// <summary>
/// One external MCP server seen from the hub: tools are listed through it and calls are forwarded to it.
/// The transport (child process over stdio, remote server over HTTP) is the subclass's business; the JSON-RPC
/// conversation above it is shared here.
/// </summary>
public abstract class McpBridge : IAsyncDisposable
{
    protected McpBridge(BridgeSpec spec)
    {
        Spec = spec;
        Name = spec.Name;
    }

    public BridgeSpec Spec { get; }
    public string Name { get; }
    /// <summary>Identity of the launch for the tool cache and for config diffs (command+args+env names, or url+transport+header names).</summary>
    public string ConfigHash => Spec.ConfigHash();
    /// <summary>What a log line should show: the command or the URL.</summary>
    public abstract string Launch { get; }
    /// <summary>False for a bridge registered from the tool cache that has not been needed yet.</summary>
    public abstract bool IsStarted { get; }
    public abstract bool IsAlive { get; }
    /// <summary>A bridge that can be brought back by <see cref="StartAsync"/> after it died (a remote session can; a dead child cannot).</summary>
    public virtual bool CanRestart => false;
    public Implementation? ServerInfo { get; protected set; }

    /// <summary>Raised when the server announces notifications/tools/list_changed.</summary>
    public event Action<McpBridge>? ToolsChanged;
    /// <summary>Raised when the server goes away on its own (not on dispose).</summary>
    public event Action<McpBridge>? Exited;

    protected void RaiseToolsChanged() => ToolsChanged?.Invoke(this);
    protected void RaiseExited() => Exited?.Invoke(this);

    /// <summary>Starts (or connects) the server, completes the MCP handshake and lists its tools.</summary>
    public async Task<List<ToolDefinition>> StartAsync(CancellationToken ct)
    {
        await EnsureStartedAsync(ct).ConfigureAwait(false);
        return await ListToolsAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Starts on first use; concurrent callers wait for the same start. No-op once started.</summary>
    public abstract Task EnsureStartedAsync(CancellationToken ct);

    protected abstract Task<JsonNode?> SendRequestAsync(string method, JsonNode? parameters, CancellationToken ct, TimeSpan timeout);

    public abstract ValueTask DisposeAsync();

    public async Task<List<ToolDefinition>> ListToolsAsync(CancellationToken ct)
    {
        var all = new List<ToolDefinition>();
        string? cursor = null;
        int pages = 0;
        do
        {
            JsonObject? p = cursor is null ? null : new JsonObject { ["cursor"] = cursor };
            JsonNode? node = await SendRequestAsync("tools/list", p, ct, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            if (node is null) break;
            var page = JsonSerializer.Deserialize(node, McpJsonContext.Default.ListToolsResult);
            if (page is null) break;
            all.AddRange(page.Tools);
            cursor = page.NextCursor;
        } while (cursor is not null && ++pages < 64);
        return all;
    }

    public async Task<CallToolResult> CallToolAsync(string remoteName, JsonObject? arguments, CancellationToken ct)
    {
        bool wasStarted = IsStarted;
        try { await EnsureStartedAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is McpBridgeException or System.ComponentModel.Win32Exception or TimeoutException
                                   or InvalidOperationException or HttpRequestException or IOException or UriFormatException)
        { return CallToolResult.Error($"Bridge '{Name}' could not start: {ex.Message}"); }

        // First real start of a bridge that was registered from the cache: let the router re-list in the background,
        // so a server whose tools changed since the cache entry is corrected on first use, not after the TTL.
        if (!wasStarted) RaiseToolsChanged();

        var p = new JsonObject { ["name"] = remoteName };
        if (arguments is not null) p["arguments"] = arguments.DeepClone();
        try
        {
            JsonNode? node = await SendRequestAsync("tools/call", p, ct, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
            if (node is null) return CallToolResult.Error($"Bridge '{Name}' returned an empty result for '{remoteName}'.");
            var result = JsonSerializer.Deserialize(node, McpJsonContext.Default.CallToolResult);
            return result ?? CallToolResult.Error($"Bridge '{Name}' returned an unparseable result for '{remoteName}'.");
        }
        catch (McpBridgeException ex) { return CallToolResult.Error($"Bridge '{Name}' error {ex.Code}: {ex.Message}"); }
        catch (TimeoutException) { return CallToolResult.Error($"Bridge '{Name}' timed out executing '{remoteName}'."); }
        catch (HttpRequestException ex) { return CallToolResult.Error($"Bridge '{Name}' unreachable: {ex.Message}"); }
    }

    protected static JsonObject InitializeParams() => new()
    {
        ["protocolVersion"] = McpProtocol.Latest,
        ["capabilities"] = new JsonObject(),
        ["clientInfo"] = new JsonObject { ["name"] = "Hubris", ["version"] = HubRuntime.Version },
    };

    /// <summary>Remembers serverInfo from an initialize result; returns the protocol version the server settled on.</summary>
    protected string ReadInitializeResult(JsonNode? result)
    {
        string version = McpProtocol.Latest;
        if (result is JsonObject io)
        {
            if (io["serverInfo"] is JsonObject si)
                ServerInfo = new Implementation
                {
                    Name = si["name"]?.GetValue<string>() ?? Name,
                    Version = si["version"]?.GetValue<string>() ?? "?",
                };
            if (io["protocolVersion"] is JsonValue pv && pv.TryGetValue<string>(out var v) && !string.IsNullOrWhiteSpace(v)) version = v;
        }
        return version;
    }

    protected static JsonNode? IdToNode(RpcId id) => id.Kind switch
    {
        RpcIdKind.Number => JsonValue.Create(id.Number),
        RpcIdKind.String => JsonValue.Create(id.Text),
        _ => null,
    };

    /// <summary>Builds the bridge a spec asks for; nothing is started here. An auth block wires the OAuth token in.</summary>
    public static McpBridge Create(BridgeSpec spec, Hubris.Auth.OAuthManager? auth = null)
    {
        var provider = spec.Auth is not null && auth is not null ? auth.GetOrCreate(spec) : null;
        if (spec.IsRemote)
            return new HttpMcpBridge(spec, provider is null ? null : new Hubris.Auth.OAuthDelegatingHandler(provider, HttpMcpBridge.DefaultHandler()));
        var bridge = new ExternalMcpBridge(spec);
        if (provider is not null)
        {
            if (provider.EnvName is null) Log.Warn($"bridge '{spec.Name}': auth.env (the variable that receives the token) is not set; the child gets no token");
            else bridge.TokenSource = provider.GetAccessTokenAsync;
        }
        return bridge;
    }
}

/// <summary>Registry-facing adapter for one remote tool.</summary>
public sealed class BridgedTool : IMcpTool
{
    private readonly McpBridge _bridge;
    private readonly string _remoteName;

    public BridgedTool(McpBridge bridge, ToolDefinition remote)
    {
        _bridge = bridge;
        _remoteName = remote.Name;
        Name = string.Concat(bridge.Name, "__", remote.Name);
        Description = string.IsNullOrWhiteSpace(remote.Description) ? $"Tool '{remote.Name}' from bridge '{bridge.Name}'." : remote.Description!;
        InputSchema = remote.InputSchema ?? new JsonObject { ["type"] = "object" };
        RiskLevel = remote.Annotations switch
        {
            { ReadOnlyHint: true } => ToolRiskLevel.ReadOnly,
            { DestructiveHint: true } => ToolRiskLevel.Destructive,
            _ => ToolRiskLevel.Mutating,
        };
    }

    public string BridgeName => _bridge.Name;
    public string Name { get; }
    public string Description { get; }
    public ToolRiskLevel RiskLevel { get; }
    public bool Pinned => false;
    public JsonObject InputSchema { get; }

    public async ValueTask<CallToolResult> ExecuteAsync(JsonObject? arguments, CancellationToken ct)
        => await _bridge.CallToolAsync(_remoteName, arguments, ct).ConfigureAwait(false);
}

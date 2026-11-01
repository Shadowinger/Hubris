using System.Diagnostics;
using System.IO.Pipelines;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Engine;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Tools;
using Hubris.Transport;

namespace Hubris.Tests;

/// <summary>Drives a real router over in-memory pipes exactly like a stdio client would.</summary>
internal sealed class HubHarness : IAsyncDisposable
{
    private readonly Pipe _toHub = new();
    private readonly Pipe _fromHub = new();
    private readonly StreamWriter _in;
    private readonly StreamReader _out;
    private readonly Task _loop;
    private readonly CancellationTokenSource _cts = new();
    private int _id;

    public ToolRegistry Registry { get; }
    public SecurityInterceptor Security { get; }
    public FakeTool Mutating { get; } = new("mut", ToolRiskLevel.Mutating);
    public FakeTool Hidden { get; } = new("hidden_tool", ToolRiskLevel.ReadOnly, pinned: false, description: "a hidden helper");

    public HubHarness(bool compact = true)
    {
        Registry = new ToolRegistry(compact);
        var security = new SecurityInterceptor(ExecutionMode.Safe);
        Security = security;
        var runtime = new HubRuntime { Uptime = Stopwatch.StartNew(), CompactContext = compact, Security = security, Registry = Registry };
        Registry.Register(new HubStatusTool(runtime));
        Registry.Register(new SearchToolsMetaTool(Registry));
        Registry.Register(new ExecuteToolMetaTool(Registry));
        Registry.Register(Mutating);
        Registry.Register(Hidden);

        var transport = new StdioTransport(_toHub.Reader.AsStream(), _fromHub.Writer.AsStream());
        var router = new McpRouter(transport, Registry, security, runtime, new List<ExternalMcpBridge>());
        _loop = transport.RunReadLoopAsync(router.HandleAsync, _cts.Token);
        _in = new StreamWriter(_toHub.Writer.AsStream()) { AutoFlush = true, NewLine = "\n" };
        _out = new StreamReader(_fromHub.Reader.AsStream());
    }

    public async Task SendRawAsync(string line) => await _in.WriteLineAsync(line);

    public async Task<JsonObject> ReadAsync()
    {
        var line = await _out.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
        return (JsonObject)JsonNode.Parse(line!)!;
    }

    /// <summary>Sends a request and returns its response, collecting notifications seen before it.</summary>
    public async Task<(JsonObject Response, List<string> Notifications)> CallAsync(string method, JsonNode? @params = null)
    {
        int id = ++_id;
        var req = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method };
        if (@params is not null) req["params"] = @params;
        await SendRawAsync(req.ToJsonString());
        var notes = new List<string>();
        while (true)
        {
            var m = await ReadAsync();
            if (m["method"] is { } n) { notes.Add(n.GetValue<string>()); continue; }
            if (m["id"]?.GetValue<int>() == id) return (m, notes);
        }
    }

    public async Task<JsonObject> ToolAsync(string name, JsonObject? args = null)
    {
        var p = new JsonObject { ["name"] = name };
        if (args is not null) p["arguments"] = args;
        var (r, _) = await CallAsync("tools/call", p);
        return (JsonObject)r["result"]!;
    }

    public async ValueTask DisposeAsync()
    {
        _in.Dispose();
        await _toHub.Writer.CompleteAsync();
        _cts.Cancel();
        try { await _loop.WaitAsync(TimeSpan.FromSeconds(5)); } catch (Exception) { }
    }
}

public class RouterTests
{
    [Fact]
    public async Task Cached_destructive_bridged_tool_is_gated_before_the_bridge_starts()
    {
        await using var hub = new HubHarness(compact: false);
        var bridge = new ExternalMcpBridge("py", "/nonexistent/server", []);
        var cachedDef = new ToolDefinition { Name = "nuke", Description = "from cache", InputSchema = new JsonObject { ["type"] = "object" }, Annotations = new ToolAnnotations { DestructiveHint = true } };
        hub.Registry.Register(new BridgedTool(bridge, cachedDef));

        var direct = await hub.ToolAsync("py__nuke", new JsonObject { ["x"] = 1 });
        Assert.True(direct["isError"]!.GetValue<bool>());
        Assert.StartsWith("[SAFE MODE BLOCKED]", direct["content"]![0]!["text"]!.GetValue<string>());

        var viaProxy = await hub.ToolAsync("mcp_execute_tool", new JsonObject { ["toolName"] = "py__nuke", ["arguments"] = new JsonObject() });
        Assert.True(viaProxy["isError"]!.GetValue<bool>());
        Assert.False(bridge.IsStarted); // nothing was spawned on the way to the verdict
    }

    [Fact]
    public async Task Initialize_ping_and_list_answer_with_matching_ids()
    {
        await using var hub = new HubHarness();
        var (init, _) = await hub.CallAsync("initialize", new JsonObject { ["protocolVersion"] = "2025-03-26" });
        Assert.Equal("2025-03-26", init["result"]!["protocolVersion"]!.GetValue<string>());
        Assert.Equal("Hubris", init["result"]!["serverInfo"]!["name"]!.GetValue<string>());
        var (ping, _) = await hub.CallAsync("ping");
        Assert.Equal("{}", ping["result"]!.ToJsonString());
        var (list, _) = await hub.CallAsync("tools/list");
        var names = list["result"]!["tools"]!.AsArray().Select(t => t!["name"]!.GetValue<string>()).ToList();
        Assert.Equal(["hub_status", "mcp_execute_tool", "mcp_search_tools"], names); // compact: hidden_tool and mut are not listed
    }

    [Fact]
    public async Task Malformed_cancel_notification_does_not_kill_the_loop()
    {
        await using var hub = new HubHarness();
        await hub.SendRawAsync("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":\"oops\"}");
        await hub.SendRawAsync("{not json");
        var err = await hub.ReadAsync();
        Assert.Equal(-32700, err["error"]!["code"]!.GetValue<int>());
        Assert.Null(err["id"]?.GetValue<string>());
        var (ping, _) = await hub.CallAsync("ping");
        Assert.NotNull(ping["result"]);
    }

    [Fact]
    public async Task Unknown_method_and_unknown_tool()
    {
        await using var hub = new HubHarness();
        var (r, _) = await hub.CallAsync("nope/method");
        Assert.Equal(-32601, r["error"]!["code"]!.GetValue<int>());
        var res = await hub.ToolAsync("ghost");
        Assert.True(res["isError"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Safe_mode_blocks_dangerous_arguments_without_a_ui()
    {
        await using var hub = new HubHarness();
        var res = await hub.ToolAsync("mut", new JsonObject { ["cmd"] = "rm -rf /" });
        Assert.True(res["isError"]!.GetValue<bool>());
        Assert.StartsWith("[SAFE MODE BLOCKED]", res["content"]![0]!["text"]!.GetValue<string>());
        Assert.Equal(0, hub.Mutating.Calls);
        var ok = await hub.ToolAsync("mut", new JsonObject { ["cmd"] = "ls" });
        Assert.Null(ok["isError"]);
        Assert.Equal(1, hub.Mutating.Calls);
    }

    [Fact]
    public async Task Remembered_allow_runs_a_blocked_tool_without_a_ui()
    {
        await using var hub = new HubHarness();
        hub.Security.Remember("mut", allow: true);
        var ok = await hub.ToolAsync("mut", new JsonObject { ["cmd"] = "rm -rf /" });
        Assert.Null(ok["isError"]);
        Assert.Equal(1, hub.Mutating.Calls);
    }

    [Fact]
    public async Task Remembered_deny_blocks_without_asking()
    {
        await using var hub = new HubHarness();
        hub.Security.Remember("mut", allow: false);
        var res = await hub.ToolAsync("mut", new JsonObject { ["cmd"] = "rm -rf /" });
        Assert.True(res["isError"]!.GetValue<bool>());
        Assert.Contains("denied for this session", res["content"]![0]!["text"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, hub.Mutating.Calls);
    }

    [Fact]
    public async Task Bypass_mode_ignores_remembered_decisions()
    {
        await using var hub = new HubHarness();
        hub.Security.Remember("mut", allow: false); // deny-listed...
        hub.Security.Mode = ExecutionMode.Bypass;   // ...but Bypass runs everything anyway
        var ok = await hub.ToolAsync("mut", new JsonObject { ["cmd"] = "rm -rf /" });
        Assert.Null(ok["isError"]);
        Assert.Equal(1, hub.Mutating.Calls);
    }

    [Fact]
    public async Task Search_unlocks_and_sends_list_changed()
    {
        await using var hub = new HubHarness();
        var p = new JsonObject { ["name"] = "mcp_search_tools", ["arguments"] = new JsonObject { ["query"] = "hidden helper" } };
        var (r, notes) = await hub.CallAsync("tools/call", p);
        Assert.Contains("hidden_tool", r["result"]!["content"]![0]!["text"]!.GetValue<string>());
        if (!notes.Contains("notifications/tools/list_changed"))
            Assert.Equal("notifications/tools/list_changed", (await hub.ReadAsync())["method"]!.GetValue<string>());
        var (list, _) = await hub.CallAsync("tools/list");
        Assert.Contains("hidden_tool", list["result"]!["tools"]!.AsArray().Select(t => t!["name"]!.GetValue<string>()));
    }

    [Fact]
    public async Task Execute_tool_proxies_through_policy_and_unlocks_target()
    {
        await using var hub = new HubHarness();
        var blocked = await hub.ToolAsync("mcp_execute_tool", new JsonObject { ["toolName"] = "mut", ["arguments"] = new JsonObject { ["cmd"] = "DROP TABLE x" } });
        Assert.True(blocked["isError"]!.GetValue<bool>());
        Assert.Equal(0, hub.Mutating.Calls);

        var self = await hub.ToolAsync("mcp_execute_tool", new JsonObject { ["toolName"] = "mcp_execute_tool" });
        Assert.Contains("cannot invoke itself", self["content"]![0]!["text"]!.GetValue<string>());

        var ok = await hub.ToolAsync("mcp_execute_tool", new JsonObject { ["toolName"] = "hidden_tool", ["arguments"] = new JsonObject { ["x"] = "1" } });
        Assert.Null(ok["isError"]);
        Assert.Equal("hidden_tool:{\"x\":\"1\"}", ok["content"]![0]!["text"]!.GetValue<string>());
        Assert.True(hub.Registry.IsUnlocked("hidden_tool"));
    }

    [Fact]
    public async Task Repeated_calls_always_execute()
    {
        await using var hub = new HubHarness(compact: false);
        await hub.ToolAsync("hidden_tool", new JsonObject { ["x"] = "same" });
        await hub.ToolAsync("hidden_tool", new JsonObject { ["x"] = "same" });
        Assert.Equal(2, hub.Hidden.Calls);
    }

    [Fact]
    public async Task Tool_output_is_passed_through_dlp()
    {
        await using var hub = new HubHarness(compact: false);
        hub.Hidden.Handler = _ => CallToolResult.Text("conn: Password=hunter2;");
        var res = await hub.ToolAsync("hidden_tool");
        Assert.Equal("conn: Password=***;", res["content"]![0]!["text"]!.GetValue<string>());
    }
}

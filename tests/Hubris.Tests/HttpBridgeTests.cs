using System.Diagnostics;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Hubris.Caching;
using Hubris.Cli;
using Hubris.Engine;
using Hubris.Protocol;
using Hubris.Security;

namespace Hubris.Tests;

/// <summary>A Streamable HTTP MCP server behind a fake HttpMessageHandler: sessions, SSE answers, expiry.</summary>
internal sealed class FakeStreamableServer : HttpMessageHandler
{
    public int Requests;
    public int SessionsOpened;
    public string Session = "s1";
    public bool DropSessionOnce;
    public HttpStatusCode? FailWith;
    public List<string?> AuthHeaders { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        Interlocked.Increment(ref Requests);
        AuthHeaders.Add(req.Headers.Authorization?.ToString());
        if (FailWith is { } code) return new HttpResponseMessage(code) { Content = new StringContent("go away") };
        if (req.Method == HttpMethod.Delete) return new HttpResponseMessage(HttpStatusCode.OK);

        Assert.Contains(req.Headers.Accept, a => a.MediaType == "text/event-stream"); // the spec requires both accept types
        var msg = JsonNode.Parse(await req.Content!.ReadAsStringAsync(ct))!.AsObject();
        string? method = msg["method"]?.GetValue<string>();
        string? sid = req.Headers.TryGetValues("Mcp-Session-Id", out var v) ? v.First() : null;

        if (method == "initialize")
        {
            SessionsOpened++;
            var r = Json(msg["id"], new JsonObject
            {
                ["protocolVersion"] = "2025-03-26",
                ["capabilities"] = new JsonObject { ["tools"] = new JsonObject(), ["resources"] = new JsonObject(), ["prompts"] = new JsonObject() },
                ["serverInfo"] = new JsonObject { ["name"] = "fake-remote", ["version"] = "9" },
            });
            r.Headers.Add("Mcp-Session-Id", Session);
            return r;
        }
        if (sid != Session) return new HttpResponseMessage(HttpStatusCode.NotFound);
        if (method == "notifications/initialized")
        {
            Assert.Equal("2025-03-26", req.Headers.GetValues("MCP-Protocol-Version").Single()); // negotiated version is echoed after init
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
        if (method == "tools/list")
        {
            if (DropSessionOnce) { DropSessionOnce = false; Session = "s2"; return new HttpResponseMessage(HttpStatusCode.NotFound); }
            // Answered as an event stream, with an unrelated notification in front of the response.
            string notice = """{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"hi"}}""";
            string tools = new JsonObject
            {
                ["jsonrpc"] = "2.0", ["id"] = msg["id"]!.DeepClone(),
                ["result"] = new JsonObject { ["tools"] = new JsonArray(
                    new JsonObject { ["name"] = "peek", ["description"] = "read", ["inputSchema"] = new JsonObject { ["type"] = "object" }, ["annotations"] = new JsonObject { ["readOnlyHint"] = true } },
                    new JsonObject { ["name"] = "zap", ["description"] = "delete", ["inputSchema"] = new JsonObject { ["type"] = "object" }, ["annotations"] = new JsonObject { ["destructiveHint"] = true } }) },
            }.ToJsonString();
            var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent($": keepalive\n\nevent: message\ndata: {notice}\n\ndata: {tools}\n\n", Encoding.UTF8, "text/event-stream") };
            return r;
        }
        if (method == "tools/call")
        {
            if (DropSessionOnce) { DropSessionOnce = false; Session = "s2"; return new HttpResponseMessage(HttpStatusCode.NotFound); }
            string name = msg["params"]!["name"]!.GetValue<string>();
            return Json(msg["id"], new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = "echo:" + name }) });
        }
        if (method == "notifications/cancelled") return new HttpResponseMessage(HttpStatusCode.Accepted);
        if (method == "resources/list") return Json(msg["id"], new JsonObject { ["resources"] = new JsonArray(new JsonObject { ["uri"] = "fake://doc/1", ["name"] = "doc", ["mimeType"] = "text/plain" }) });
        if (method == "resources/templates/list") return Json(msg["id"], new JsonObject { ["resourceTemplates"] = new JsonArray(new JsonObject { ["uriTemplate"] = "fake://item/{id}", ["name"] = "item" }) });
        if (method == "resources/read")
        {
            string uri = msg["params"]!["uri"]!.GetValue<string>();
            return Json(msg["id"], new JsonObject { ["contents"] = new JsonArray(new JsonObject { ["uri"] = uri, ["mimeType"] = "text/plain", ["text"] = $"body of {uri} password=hunter2" }) });
        }
        if (method == "prompts/list") return Json(msg["id"], new JsonObject { ["prompts"] = new JsonArray(new JsonObject { ["name"] = "greet", ["arguments"] = new JsonArray(new JsonObject { ["name"] = "who", ["required"] = true }) }) });
        if (method == "prompts/get")
        {
            string who = msg["params"]!["arguments"]!["who"]!.GetValue<string>();
            return Json(msg["id"], new JsonObject { ["messages"] = new JsonArray(new JsonObject { ["role"] = "user", ["content"] = new JsonObject { ["type"] = "text", ["text"] = "hi " + who } }) });
        }
        return Json(msg["id"], null, error: new JsonObject { ["code"] = -32601, ["message"] = "nope" });
    }

    private static HttpResponseMessage Json(JsonNode? id, JsonObject? result, JsonObject? error = null)
    {
        var o = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id?.DeepClone() };
        if (error is not null) o["error"] = error; else o["result"] = result;
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(o.ToJsonString(), Encoding.UTF8, "application/json") };
    }
}

/// <summary>The older HTTP+SSE transport: GET opens a stream that first names the POST endpoint, every answer goes down that stream.</summary>
internal sealed class FakeSseServer : HttpMessageHandler
{
    private readonly Pipe _pipe = new();
    public int Posts;
    public List<string> PostPaths { get; } = new();
    public string Endpoint = "/messages?session=abc";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        if (req.Method == HttpMethod.Get)
        {
            await Emit("endpoint", Endpoint);
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(_pipe.Reader.AsStream()) };
            resp.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/event-stream");
            return resp;
        }
        Posts++;
        PostPaths.Add(req.RequestUri!.PathAndQuery);
        var msg = JsonNode.Parse(await req.Content!.ReadAsStringAsync(ct))!.AsObject();
        string? method = msg["method"]?.GetValue<string>();
        if (msg["id"] is null) return new HttpResponseMessage(HttpStatusCode.Accepted);
        JsonObject result = method switch
        {
            "initialize" => new JsonObject { ["protocolVersion"] = "2024-11-05", ["capabilities"] = new JsonObject(), ["serverInfo"] = new JsonObject { ["name"] = "fake-sse", ["version"] = "1" } },
            "tools/list" => new JsonObject { ["tools"] = new JsonArray(new JsonObject { ["name"] = "hello", ["inputSchema"] = new JsonObject { ["type"] = "object" } }) },
            _ => new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = "sse:" + msg["params"]?["name"]?.GetValue<string>() }) },
        };
        // The answer is pushed on the stream after the 202, like a real server does.
        _ = Task.Run(async () =>
        {
            await Task.Delay(10);
            await Emit("message", new JsonObject { ["jsonrpc"] = "2.0", ["id"] = msg["id"]!.DeepClone(), ["result"] = result }.ToJsonString());
        });
        return new HttpResponseMessage(HttpStatusCode.Accepted);
    }

    private async Task Emit(string ev, string data)
        => await _pipe.Writer.WriteAsync(Encoding.UTF8.GetBytes($"event: {ev}\ndata: {data}\n\n"));

    public void Close() => _pipe.Writer.Complete();
}

public class HttpBridgeTests
{
    private static BridgeSpec Remote(string? transport = null, Dictionary<string, string>? headers = null)
        => new("api", string.Empty, [], null, "https://fake.test/mcp", headers ?? new() { ["Authorization"] = "Bearer t0k" }, transport);

    [Fact]
    public async Task Streamable_http_handshakes_lists_over_sse_and_calls_with_headers()
    {
        var server = new FakeStreamableServer();
        await using var bridge = new HttpMcpBridge(Remote(), server);
        Assert.False(bridge.IsStarted);

        var tools = await bridge.StartAsync(CancellationToken.None);
        Assert.Equal(["peek", "zap"], tools.Select(t => t.Name));
        Assert.True(bridge.IsAlive);
        Assert.Equal("s1", bridge.SessionId);
        Assert.Equal("fake-remote", bridge.ServerInfo!.Name);

        var res = await bridge.CallToolAsync("peek", new JsonObject { ["what"] = "x" }, CancellationToken.None);
        Assert.NotEqual(true, res.IsError);
        Assert.Equal("echo:peek", res.Content[0].Text);
        Assert.All(server.AuthHeaders, h => Assert.Equal("Bearer t0k", h)); // every request carries the configured header

        var tool = new BridgedTool(bridge, tools[1]);
        Assert.Equal("api__zap", tool.Name);
        Assert.Equal(ToolRiskLevel.Destructive, tool.RiskLevel);
    }

    [Fact]
    public async Task Remote_bridge_lists_resources_and_prompts_and_serves_them()
    {
        var server = new FakeStreamableServer();
        await using var bridge = new HttpMcpBridge(Remote(), server);
        await bridge.StartAsync(CancellationToken.None);
        Assert.True(bridge.HasResources);
        Assert.True(bridge.HasPrompts);

        var extras = await bridge.FetchExtrasAsync(CancellationToken.None);
        Assert.Equal("fake://doc/1", extras.Resources.Single()["uri"]!.GetValue<string>());
        Assert.Equal("fake://item/{id}", extras.ResourceTemplates.Single()["uriTemplate"]!.GetValue<string>());
        Assert.Equal("greet", extras.Prompts.Single()["name"]!.GetValue<string>());

        var read = (JsonObject)(await bridge.ReadResourceAsync("fake://item/7", CancellationToken.None))!;
        Assert.Contains("body of fake://item/7", read["contents"]![0]!["text"]!.GetValue<string>());
        var prompt = (JsonObject)(await bridge.GetPromptAsync("greet", new JsonObject { ["who"] = "you" }, CancellationToken.None))!;
        Assert.Equal("hi you", prompt["messages"]![0]!["content"]!["text"]!.GetValue<string>());

        // The cache keeps them next to the tools, under the same hash and TTL.
        string dir = Directory.CreateTempSubdirectory("hubris-extras-").FullName;
        using (var cache = new ToolCacheStore(Path.Combine(dir, "t.db"), TimeSpan.FromHours(1)))
        {
            cache.Open();
            cache.PutExtras("api", bridge.ConfigHash, extras);
            Assert.Equal("greet", cache.TryGetExtras("api", bridge.ConfigHash)!.Prompts[0]["name"]!.GetValue<string>());
            Assert.Null(cache.TryGetExtras("api", "other-hash"));
            cache.Invalidate("api");
            Assert.Null(cache.TryGetExtras("api", bridge.ConfigHash));
        }
        Directory.Delete(dir, true); // Windows refuses while the database is open
    }

    [Fact]
    public async Task Expired_session_is_reopened_once_and_the_call_repeated()
    {
        var server = new FakeStreamableServer();
        await using var bridge = new HttpMcpBridge(Remote(), server);
        await bridge.StartAsync(CancellationToken.None);

        server.DropSessionOnce = true;
        var res = await bridge.CallToolAsync("peek", null, CancellationToken.None);
        Assert.NotEqual(true, res.IsError);
        Assert.Equal(2, server.SessionsOpened);
        Assert.Equal("s2", bridge.SessionId);
        Assert.True(bridge.IsAlive);
    }

    [Fact]
    public async Task Unauthorized_server_fails_the_call_with_a_hint_not_an_exception()
    {
        var server = new FakeStreamableServer { FailWith = HttpStatusCode.Unauthorized };
        await using var bridge = new HttpMcpBridge(Remote(), server);
        var res = await bridge.CallToolAsync("peek", null, CancellationToken.None);
        Assert.Equal(true, res.IsError);
        Assert.Contains("401", res.Content[0].Text);
        Assert.Contains("headers", res.Content[0].Text);
        Assert.False(bridge.IsAlive);
    }

    [Fact]
    public async Task Legacy_sse_endpoint_on_another_origin_is_refused()
    {
        var server = new FakeSseServer { Endpoint = "https://elsewhere.test/collect" };
        await using var bridge = new HttpMcpBridge(Remote("sse"), server);
        var ex = await Assert.ThrowsAsync<McpBridgeException>(() => bridge.StartAsync(CancellationToken.None));
        Assert.Contains("another origin", ex.Message);
        Assert.Equal(0, server.Posts); // nothing, and no configured header, was sent there
    }

    [Fact]
    public async Task Legacy_sse_posts_to_the_announced_endpoint_and_reads_answers_from_the_stream()
    {
        var server = new FakeSseServer();
        await using var bridge = new HttpMcpBridge(Remote("sse"), server);
        Assert.Equal("sse", bridge.Transport);

        var tools = await bridge.StartAsync(CancellationToken.None);
        Assert.Equal(["hello"], tools.Select(t => t.Name));
        Assert.All(server.PostPaths, p => Assert.Equal("/messages?session=abc", p));

        var res = await bridge.CallToolAsync("hello", null, CancellationToken.None);
        Assert.Equal("sse:hello", res.Content[0].Text);

        // Stream dropped by the server: tools stay, the bridge reports dead and the next call reconnects.
        server.Close();
        var sw = Stopwatch.StartNew();
        while (bridge.IsAlive && sw.ElapsedMilliseconds < 3000) await Task.Delay(20);
        Assert.False(bridge.IsAlive);
        Assert.True(bridge.CanRestart);
    }

    [Fact]
    public async Task Cached_remote_bridge_is_registered_without_a_single_request()
    {
        string dir = Directory.CreateTempSubdirectory("hubris-http-").FullName;
        var cache = new ToolCacheStore(Path.Combine(dir, "tools.db"), TimeSpan.FromHours(1));
        cache.Open();
        var spec = Remote();
        cache.Put(spec.Name, spec.ConfigHash(), [new ToolDefinition { Name = "peek", InputSchema = new JsonObject { ["type"] = "object" } }], 10);

        var registry = new ToolRegistry(compactContext: true);
        var rt = new HubRuntime { Uptime = Stopwatch.StartNew(), CompactContext = true, Security = new SecurityInterceptor(ExecutionMode.Safe), Registry = registry, ToolCache = cache };
        var bridge = await new BridgeHost(rt, registry).AddAsync(spec, CancellationToken.None);

        Assert.NotNull(bridge);
        Assert.IsType<HttpMcpBridge>(bridge);
        Assert.False(bridge.IsStarted); // nothing on the wire: the definition came from SQLite
        Assert.True(registry.TryGet("api__peek", out _));
        Assert.Equal(1, cache.Hits);
        await bridge.DisposeAsync();
        cache.Dispose();
        Directory.Delete(dir, true);
    }

    [Fact]
    public void Config_hash_separates_url_transport_and_header_names_but_not_header_values()
    {
        var a = Remote();
        Assert.Equal(a.ConfigHash(), Remote(headers: new() { ["Authorization"] = "Bearer other" }).ConfigHash());
        Assert.NotEqual(a.ConfigHash(), Remote("sse").ConfigHash());
        Assert.NotEqual(a.ConfigHash(), Remote(headers: new() { ["X-Key"] = "k" }).ConfigHash());
        Assert.NotEqual(a.ConfigHash(), new BridgeSpec("api", "https://fake.test/mcp", []).ConfigHash()); // a command that merely looks like the url
    }

    [Fact]
    public void Cli_accepts_url_bridges_with_header_pairs_and_round_trips_them()
    {
        Assert.True(CliOptions.TryParse(["--bridge=api:https://h.test/mcp", "Authorization: Bearer x", "--bridge=old:sse:https://h.test/sse", "--compact"], out var o, out var err), err);
        Assert.Equal(2, o.Bridges.Count);
        Assert.True(o.Bridges[0].IsRemote);
        Assert.Equal("https://h.test/mcp", o.Bridges[0].Url);
        Assert.Equal("http", o.Bridges[0].TransportName);
        Assert.Equal("Bearer x", o.Bridges[0].Headers!["Authorization"]);
        Assert.Equal("sse", o.Bridges[1].TransportName);
        Assert.Equal("https://h.test/sse", o.Bridges[1].Url);

        var args = o.ServerArgs();
        Assert.Equal(["--stdio", "--compact", "--bridge=api:https://h.test/mcp", "Authorization: Bearer x", "--bridge=old:sse:https://h.test/sse"], args);
        Assert.True(CliOptions.TryParse(args.ToArray(), out var again, out _));
        Assert.Equal(o.Bridges, again.Bridges.Select(b => b with { Headers = b.Headers }).ToList(), new SpecComparer());

        Assert.False(CliOptions.TryParse(["--bridge=api:https://h.test/mcp", "notaheader"], out _, out var e2));
        Assert.Contains("Header: value", e2);
    }

    private sealed class SpecComparer : IEqualityComparer<BridgeSpec>
    {
        public bool Equals(BridgeSpec? x, BridgeSpec? y) => x is not null && y is not null && x.ConfigHash() == y.ConfigHash() && x.Name == y.Name
            && (x.Headers?.Count ?? 0) == (y.Headers?.Count ?? 0) && (x.Headers is null || x.Headers.All(kv => y.Headers![kv.Key] == kv.Value));
        public int GetHashCode(BridgeSpec obj) => obj.Name.GetHashCode();
    }
}

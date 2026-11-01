using System.Text.Json.Nodes;
using Hubris.Caching;
using Hubris.Cli;
using Hubris.Control;
using Hubris.Engine;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Tools;

namespace Hubris.Tests;

internal sealed class FakeTool : IMcpTool
{
    public FakeTool(string name, ToolRiskLevel risk = ToolRiskLevel.ReadOnly, bool pinned = false, string? description = null)
    {
        Name = name; RiskLevel = risk; Pinned = pinned; Description = description ?? $"fake tool {name}";
    }
    public string Name { get; }
    public string Description { get; }
    public ToolRiskLevel RiskLevel { get; }
    public bool Pinned { get; }
    public JsonObject InputSchema { get; } = SchemaBuilder.Object(("x", SchemaBuilder.String("x"), false));
    public int Calls;
    public Func<JsonObject?, CallToolResult>? Handler { get; set; }
    public ValueTask<CallToolResult> ExecuteAsync(JsonObject? arguments, CancellationToken ct)
    {
        Calls++;
        return ValueTask.FromResult(Handler?.Invoke(arguments) ?? CallToolResult.Text($"{Name}:{arguments?.ToJsonString()}"));
    }
}

public class ToolCacheStoreTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("hubris-cache-").FullName;
    private ToolCacheStore Open(TimeSpan? ttl = null)
    {
        var store = new ToolCacheStore(Path.Combine(_dir, "cache", "tools_cache.db"), ttl ?? TimeSpan.FromHours(24));
        store.Open();
        return store;
    }
    private static List<ToolDefinition> Tools(params string[] names)
        => names.Select(n => new ToolDefinition { Name = n, Description = "d", InputSchema = new JsonObject { ["type"] = "object" } }).ToList();

    [Fact]
    public void Hit_requires_same_hash_and_fresh_entry()
    {
        using var store = Open();
        string h = ToolCacheStore.ComputeHash("npx", ["-y", "srv"], ["TOKEN"]);
        Assert.Null(store.TryGet("fs", h));
        store.Put("fs", h, Tools("read", "write"), 123);
        var hit = store.TryGet("fs", h);
        Assert.NotNull(hit);
        Assert.Equal(["read", "write"], hit!.Select(t => t.Name));
        Assert.Null(store.TryGet("fs", ToolCacheStore.ComputeHash("npx", ["-y", "srv", "--extra"], ["TOKEN"])));
        Assert.Equal(1, store.Hits);
        Assert.Equal(2, store.Misses);
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void Hash_ignores_env_values_and_key_order()
    {
        Assert.Equal(ToolCacheStore.ComputeHash("c", ["a"], ["B", "A"]), ToolCacheStore.ComputeHash("c", ["a"], ["A", "B"]));
        Assert.NotEqual(ToolCacheStore.ComputeHash("c", ["a"], ["A"]), ToolCacheStore.ComputeHash("c", ["a"], ["A", "B"]));
    }

    [Fact]
    public void Entries_expire_and_can_be_invalidated()
    {
        using var expired = Open(TimeSpan.FromSeconds(-1));
        string h = ToolCacheStore.ComputeHash("c", [], []);
        expired.Put("x", h, Tools("t"), 1);
        Assert.Null(expired.TryGet("x", h));
        using var fresh = Open();
        Assert.NotNull(fresh.TryGet("x", h));
        Assert.Equal(1, fresh.Invalidate("x"));
        Assert.Null(fresh.TryGet("x", h));
    }

    [Fact]
    public void Two_processes_worth_of_stores_share_one_file()
    {
        using var a = Open();
        using var b = Open();
        string h = ToolCacheStore.ComputeHash("c", [], []);
        a.Put("x", h, Tools("t"), 1);
        Assert.NotNull(b.TryGet("x", h));           // reader sees the other connection's write (WAL)
        Assert.True(a.MaintainIfDue(TimeSpan.Zero));   // VACUUM while b holds an open connection
        Assert.True(b.MaintainIfDue(TimeSpan.Zero));   // and the other way round; a busy database must not throw
        b.Put("x", h, Tools("t", "u"), 2);
        Assert.Equal(2, a.TryGet("x", h)!.Count);
    }

    [Fact]
    public void Wal_mode_and_maintenance()
    {
        using var store = Open();
        Assert.True(store.MaintainIfDue(TimeSpan.FromDays(7)));
        Assert.False(store.MaintainIfDue(TimeSpan.FromDays(7)));
        Assert.True(File.Exists(Path.Combine(_dir, "cache", "tools_cache.db")));
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }
}

public class SchemaMinifierTests
{
    [Fact]
    public void Drops_noise_but_keeps_structure()
    {
        var schema = new JsonObject
        {
            ["$schema"] = "http://json-schema.org/draft-07/schema#",
            ["title"] = "X",
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["a"] = new JsonObject { ["type"] = "string", ["description"] = "", ["examples"] = new JsonArray("x") },
            },
            ["required"] = new JsonArray(),
            ["default"] = null,
        };
        string json = SchemaMinifier.Minify(schema).ToJsonString();
        Assert.Equal("{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"}}}", json);
    }
}

public class ToolRegistryTests
{
    private static ToolRegistry Compact()
    {
        var r = new ToolRegistry(compactContext: true);
        r.Register(new FakeTool("core", pinned: true));
        r.Register(new FakeTool("git_status", description: "git working tree status"));
        r.Register(new FakeTool("fs_read"));
        return r;
    }

    [Fact]
    public void Compact_lists_only_pinned_until_unlocked_and_lock_hides_again()
    {
        var r = Compact();
        Assert.Equal(["core"], r.ListVisible().Select(t => t.Name));
        Assert.True(r.Unlock("git_status"));
        Assert.False(r.Unlock("git_status"));
        Assert.Equal(["core", "git_status"], r.ListVisible().Select(t => t.Name));
        Assert.True(r.Lock("git_status"));
        Assert.Equal(["core"], r.ListVisible().Select(t => t.Name));
        Assert.False(r.Unlock("missing"));
    }

    [Fact]
    public void Context_stats_count_only_visible_tools()
    {
        var r = Compact();
        var s = r.GetContextStats();
        Assert.Equal(1, s.ActiveTools);
        Assert.Equal(3, s.TotalTools);
        Assert.True(s.ActiveTokens > 0 && s.ActiveTokens < s.TotalTokens);
        Assert.InRange(s.SavedPercent, 1, 99);
        Assert.All(r.ToolInfos(), t => Assert.True(t.Tokens > 0));
    }

    [Fact]
    public void Search_ranks_name_matches_first()
    {
        var r = Compact();
        var hits = r.Search("git status", 10);
        Assert.Equal("git_status", hits[0].Tool.Name);
        Assert.Empty(r.Search("zzz", 10));
    }

    [Fact]
    public void Unregister_forgets_tokens_and_unlock_state()
    {
        var r = Compact();
        r.Unlock("fs_read");
        Assert.Equal(1, r.UnregisterWhere(t => t.Name == "fs_read"));
        Assert.False(r.IsUnlocked("fs_read"));
        Assert.Equal(2, r.GetContextStats().TotalTools);
    }
}

public class ApprovalGateTests
{
    [Fact]
    public async Task Approve_and_deny_resolve_the_waiting_call()
    {
        var gate = new ApprovalGate();
        string? id = null;
        gate.Requested += p => id = p.Id;
        var t = gate.RequestAsync("x", ToolRiskLevel.Mutating, "r", null, TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.True(gate.Resolve(id!, approved: true));
        Assert.Equal(ApprovalDecision.Approved, await t);
        Assert.Equal(0, gate.Count);
        Assert.False(gate.Resolve(id!, approved: false));
    }

    [Fact]
    public async Task Timeout_and_cancel_all_fail_fast()
    {
        var gate = new ApprovalGate();
        Assert.Equal(ApprovalDecision.TimedOut, await gate.RequestAsync("x", ToolRiskLevel.Mutating, "r", null, TimeSpan.FromMilliseconds(30), CancellationToken.None));
        var pending = gate.RequestAsync("y", ToolRiskLevel.Mutating, "r", null, TimeSpan.FromSeconds(30), CancellationToken.None);
        gate.CancelAll();
        Assert.Equal(ApprovalDecision.Cancelled, await pending);
    }
}

public class FsReadHeadTests
{
    [Fact]
    public async Task Reads_n_lines_and_flags_more()
    {
        var r = new StringReader("a\r\nb\nc\nd");
        var (text, lines, more) = await FsReadHeadTool.ReadHeadAsync(r, 2, 400, CancellationToken.None);
        Assert.Equal("a\nb\n", text);
        Assert.Equal(2, lines);
        Assert.True(more);
    }

    [Fact]
    public async Task Last_line_without_newline_is_counted()
    {
        var (text, lines, more) = await FsReadHeadTool.ReadHeadAsync(new StringReader("a\nb"), 10, 400, CancellationToken.None);
        Assert.Equal("a\nb\n", text);
        Assert.Equal(2, lines);
        Assert.False(more);
    }

    [Fact]
    public async Task One_giant_line_is_cut_by_the_character_budget()
    {
        var r = new StringReader(new string('x', 5_000_000));
        var (text, lines, more) = await FsReadHeadTool.ReadHeadAsync(r, 3, 100, CancellationToken.None);
        Assert.True(text.Length <= 3 * 101 + 2, $"len {text.Length}");
        Assert.StartsWith(new string('x', 100) + "…", text);
        Assert.Equal(1, lines);
        Assert.True(more);
    }
}

public class CliOptionsTests
{
    [Fact]
    public void Bridge_keeps_child_flags_and_stops_at_own_options()
    {
        Assert.True(CliOptions.TryParse(["--bridge=fs:npx", "-y", "server-fs", "--allowed", "/x", "--compact", "--bridge", "gh:gh-mcp", "--mode=bypass"], out var o, out var err), err);
        Assert.Equal(2, o.Bridges.Count);
        Assert.Equal(["-y", "server-fs", "--allowed", "/x"], o.Bridges[0].Args);
        Assert.True(o.Compact);
        Assert.Equal(ExecutionMode.Bypass, o.Mode);
        Assert.Equal(["--stdio", "--mode=bypass", "--compact", "--bridge=fs:npx", "-y", "server-fs", "--allowed", "/x", "--bridge=gh:gh-mcp"], o.ServerArgs());
    }

    [Theory]
    [InlineData("--mode=yolo")]
    [InlineData("--bridge=nocolon")]
    [InlineData("--approval-timeout=0")]
    [InlineData("--cache-ttl=0")]
    [InlineData("--whatever")]
    public void Invalid_options_are_rejected(string arg)
    {
        Assert.False(CliOptions.TryParse([arg], out _, out var err));
        Assert.NotNull(err);
    }
}

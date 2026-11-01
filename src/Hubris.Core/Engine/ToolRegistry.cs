using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Caching;
using Hubris.Control;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Tools;
using Hubris.Transport;

namespace Hubris.Engine;

/// <summary>Shared process-wide state handed to tools by constructor (pure DI).</summary>
public sealed class HubRuntime
{
    public required Stopwatch Uptime { get; init; }
    /// <summary>Live mode; the interceptor owns it so the control channel can flip it at runtime.</summary>
    public ExecutionMode Mode => Security.Mode;
    public ControlHub? Control { get; set; }
    public required bool CompactContext { get; init; }
    public required SecurityInterceptor Security { get; init; }
    public ToolRegistry Registry { get; set; } = null!;
    public ToolCacheStore? ToolCache { get; init; }
    public List<ExternalMcpBridge> Bridges { get; } = new();
    public int BridgeCount => Bridges.Count;
    public int BridgesRunning { get { int n = 0; foreach (var b in Bridges) if (b.IsAlive) n++; return n; } }
    public const string Version = "1.0.0";
}

public sealed class ToolRegistry
{
    private readonly ConcurrentDictionary<string, IMcpTool> _tools = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _unlocked = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, int> _tokens = new(StringComparer.Ordinal);

    public ToolRegistry(bool compactContext)
    {
        CompactContext = compactContext;
    }

    public bool CompactContext { get; }
    public int Count => _tools.Count;

    public int PinnedCount
    {
        get { int n = 0; foreach (var t in _tools.Values) if (t.Pinned) n++; return n; }
    }

    public int BridgedCount
    {
        get { int n = 0; foreach (var t in _tools.Values) if (t is BridgedTool) n++; return n; }
    }

    public IEnumerable<IMcpTool> All => _tools.Values;

    public void Register(IMcpTool tool)
    {
        if (!_tools.TryAdd(tool.Name, tool))
        {
            Log.Warn($"duplicate tool '{tool.Name}' – replacing previous registration");
            _tools[tool.Name] = tool;
        }
        _tokens[tool.Name] = EstimateTokens(tool); // definitions never change after registration
    }

    public int UnregisterWhere(Func<IMcpTool, bool> predicate)
    {
        int removed = 0;
        foreach (var kv in _tools)
        {
            if (!predicate(kv.Value) || !_tools.TryRemove(kv)) continue;
            _tokens.TryRemove(kv.Key, out _);
            _unlocked.TryRemove(kv.Key, out _);
            removed++;
        }
        return removed;
    }

    public int TokensOf(IMcpTool tool) => _tokens.TryGetValue(tool.Name, out int t) ? t : EstimateTokens(tool);

    public bool TryGet(string name, out IMcpTool tool) => _tools.TryGetValue(name, out tool!);

    /// <summary>Marks an on-demand tool as unlocked for the rest of the session. Returns true if newly unlocked.</summary>
    public bool Unlock(string name) => _tools.ContainsKey(name) && _unlocked.TryAdd(name, 0);

    public bool IsUnlocked(string name) => _unlocked.ContainsKey(name);

    /// <summary>Hides an unlocked on-demand tool again (compact mode). Returns true if it was unlocked.</summary>
    public bool Lock(string name) => _unlocked.TryRemove(name, out _);

    /// <summary>Rough prompt cost of one tool definition as the client sees it: UTF-8 bytes of the minified JSON / 4.</summary>
    public static int EstimateTokens(IMcpTool tool)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(ToDefinition(tool), McpJsonContext.Default.ToolDefinition);
        return Math.Max(1, (bytes.Length + 3) / 4);
    }

    public readonly record struct ContextStats(int ActiveTools, int TotalTools, int ActiveTokens, int TotalTokens)
    {
        public int SavedPercent => TotalTokens == 0 ? 0 : (int)Math.Round(100.0 * (TotalTokens - ActiveTokens) / TotalTokens);
        public override string ToString() => $"{ActiveTools}/{TotalTools} tools ~{ActiveTokens} tok ({SavedPercent}% saved)";
    }

    public ContextStats GetContextStats()
    {
        int active = 0, total = 0, activeTok = 0, totalTok = 0;
        foreach (var tool in _tools.Values)
        {
            int tok = TokensOf(tool);
            total++; totalTok += tok;
            if (IsVisible(tool)) { active++; activeTok += tok; }
        }
        return new ContextStats(active, total, activeTok, totalTok);
    }

    public bool IsVisible(IMcpTool tool) => !CompactContext || tool.Pinned || _unlocked.ContainsKey(tool.Name);

    public List<ToolInfo> ToolInfos()
    {
        var list = new List<ToolInfo>(_tools.Count);
        foreach (var tool in _tools.Values)
        {
            list.Add(new ToolInfo
            {
                Name = tool.Name,
                Description = tool.Description,
                Risk = ModeNames.ToText(tool.RiskLevel),
                Pinned = tool.Pinned,
                Visible = IsVisible(tool),
                Unlocked = _unlocked.ContainsKey(tool.Name),
                Tokens = TokensOf(tool),
                Bridge = tool is BridgedTool bt ? bt.BridgeName : null,
            });
        }
        list.Sort(static (a, b) => string.CompareOrdinal(a.Name, b.Name));
        return list;
    }

    public List<ToolDefinition> ListVisible()
    {
        var list = new List<ToolDefinition>(_tools.Count);
        foreach (var tool in _tools.Values)
            if (IsVisible(tool)) list.Add(ToDefinition(tool));
        list.Sort(static (a, b) => string.CompareOrdinal(a.Name, b.Name));
        return list;
    }

    public static ToolDefinition ToDefinition(IMcpTool tool) => new()
    {
        Name = tool.Name,
        Description = tool.Description,
        InputSchema = SchemaMinifier.Minify(tool.InputSchema),
        Annotations = new ToolAnnotations
        {
            ReadOnlyHint = tool.RiskLevel == ToolRiskLevel.ReadOnly ? true : null,
            DestructiveHint = tool.RiskLevel == ToolRiskLevel.Destructive ? true : (tool.RiskLevel == ToolRiskLevel.ReadOnly ? false : null),
        },
    };

    public readonly record struct SearchHit(IMcpTool Tool, int Score);

    public List<SearchHit> Search(string query, int limit)
    {
        var tokens = Tokenize(query);
        var hits = new List<SearchHit>();
        if (tokens.Count == 0) return hits;

        foreach (var tool in _tools.Values)
        {
            string name = tool.Name.ToLowerInvariant();
            string desc = tool.Description.ToLowerInvariant();
            var nameTokens = Tokenize(name);
            int score = 0;
            foreach (var tok in tokens)
            {
                if (nameTokens.Contains(tok)) score += 3;
                else if (name.Contains(tok, StringComparison.Ordinal)) score += 2;
                if (desc.Contains(tok, StringComparison.Ordinal)) score += 1;
            }
            if (score > 0) hits.Add(new SearchHit(tool, score));
        }

        hits.Sort(static (a, b) =>
        {
            int c = b.Score.CompareTo(a.Score);
            return c != 0 ? c : string.CompareOrdinal(a.Tool.Name, b.Tool.Name);
        });
        if (hits.Count > limit) hits.RemoveRange(limit, hits.Count - limit);
        return hits;
    }

    private static HashSet<string> Tokenize(string text)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        int start = -1;
        for (int i = 0; i <= text.Length; i++)
        {
            bool sep = i == text.Length || !char.IsLetterOrDigit(text[i]);
            if (!sep) { if (start < 0) start = i; continue; }
            if (start >= 0)
            {
                set.Add(text.AsSpan(start, i - start).ToString().ToLowerInvariant());
                start = -1;
            }
        }
        return set;
    }
}

/// <summary>Strips schema noise (nulls, empty containers, documentation-only keys) before it costs tokens.</summary>
public static class SchemaMinifier
{
    private static readonly string[] DroppedKeys = ["$schema", "$id", "$comment", "title", "examples", "example", "deprecated", "readOnly", "writeOnly"];

    public static JsonObject Minify(JsonObject schema)
    {
        var result = MinifyNode(schema) as JsonObject;
        return result ?? new JsonObject { ["type"] = "object" };
    }

    private static JsonNode? MinifyNode(JsonNode? node)
    {
        switch (node)
        {
            case null:
                return null;
            case JsonObject obj:
            {
                var copy = new JsonObject();
                foreach (var kv in obj)
                {
                    if (IsDropped(kv.Key)) continue;
                    var child = MinifyNode(kv.Value);
                    if (child is null) continue;
                    if (child is JsonObject co && co.Count == 0 && !string.Equals(kv.Key, "properties", StringComparison.Ordinal)) continue;
                    if (child is JsonArray ca && ca.Count == 0) continue;
                    if (child is JsonValue cv && string.Equals(kv.Key, "description", StringComparison.Ordinal)
                        && cv.TryGetValue<string>(out var s) && s.Length == 0) continue;
                    copy[kv.Key] = child;
                }
                return copy;
            }
            case JsonArray arr:
            {
                var copy = new JsonArray();
                foreach (var item in arr)
                {
                    var child = MinifyNode(item);
                    if (child is not null) copy.Add(child);
                }
                return copy;
            }
            default:
                return node.DeepClone();
        }
    }

    private static bool IsDropped(string key)
    {
        foreach (var k in DroppedKeys)
            if (string.Equals(k, key, StringComparison.Ordinal)) return true;
        return false;
    }
}

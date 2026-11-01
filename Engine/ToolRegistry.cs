using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Hubris.Caching;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Tools;
using Hubris.Transport;

namespace Hubris.Engine;

/// <summary>Shared process-wide state handed to tools by constructor (pure DI).</summary>
public sealed class HubRuntime
{
    public required Stopwatch Uptime { get; init; }
    public required ExecutionMode Mode { get; init; }
    public required bool CompactContext { get; init; }
    public required FastLruCache Cache { get; init; }
    public required SecurityInterceptor Security { get; init; }
    public ToolRegistry Registry { get; set; } = null!;
    public int BridgeCount { get; set; }
    public const string Version = "1.0.0";
}

public sealed class ToolRegistry
{
    private readonly ConcurrentDictionary<string, IMcpTool> _tools = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _revealed = new(StringComparer.Ordinal);

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
        get { int n = 0; foreach (var t in _tools.Values) if (t is IBridgedTool) n++; return n; }
    }

    public IEnumerable<IMcpTool> All => _tools.Values;

    public void Register(IMcpTool tool)
    {
        if (!_tools.TryAdd(tool.Name, tool))
        {
            Log.Warn($"duplicate tool '{tool.Name}' – replacing previous registration");
            _tools[tool.Name] = tool;
        }
    }

    public bool Unregister(string name) => _tools.TryRemove(name, out _);

    public int UnregisterWhere(Func<IMcpTool, bool> predicate)
    {
        int removed = 0;
        foreach (var kv in _tools)
            if (predicate(kv.Value) && _tools.TryRemove(kv)) removed++;
        return removed;
    }

    public bool TryGet(string name, out IMcpTool tool) => _tools.TryGetValue(name, out tool!);

    /// <summary>Marks an on-demand tool as visible for the rest of the session. Returns true if newly revealed.</summary>
    public bool Reveal(string name) => _tools.ContainsKey(name) && _revealed.TryAdd(name, 0);

    public bool IsVisible(IMcpTool tool) => !CompactContext || tool.Pinned || _revealed.ContainsKey(tool.Name);

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

/// <summary>Marker so the registry can count/replace bridged tools without reflection.</summary>
public interface IBridgedTool : IMcpTool
{
    string BridgeName { get; }
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

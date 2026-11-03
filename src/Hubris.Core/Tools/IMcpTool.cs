using System.Text.Json.Nodes;
using Hubris.Protocol;
using Hubris.Security;

namespace Hubris.Tools;

public interface IMcpTool
{
    string Name { get; }
    string Description { get; }
    ToolRiskLevel RiskLevel { get; }
    /// <summary>Pinned tools are always listed; others are on-demand in compact mode.</summary>
    bool Pinned { get; }
    JsonObject InputSchema { get; }
    ValueTask<CallToolResult> ExecuteAsync(JsonObject? arguments, CancellationToken ct);
}

/// <summary>Reflection-free JSON-schema literals.</summary>
public static class SchemaBuilder
{
    public static JsonObject Object(params ReadOnlySpan<(string Name, JsonObject Prop, bool Required)> props)
    {
        var properties = new JsonObject();
        var required = new JsonArray();
        foreach (var (name, prop, req) in props)
        {
            properties[name] = prop;
            if (req) required.Add((JsonNode?)JsonValue.Create(name));
        }
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = properties,
        };
        if (required.Count > 0) schema["required"] = required;
        schema["additionalProperties"] = false;
        return schema;
    }

    public static JsonObject String(string description) => new()
    {
        ["type"] = "string",
        ["description"] = description,
    };

    public static JsonObject Integer(string description, long? min = null, long? max = null, long? @default = null)
    {
        var o = new JsonObject
        {
            ["type"] = "integer",
            ["description"] = description,
        };
        if (min is { } lo) o["minimum"] = lo;
        if (max is { } hi) o["maximum"] = hi;
        if (@default is { } d) o["default"] = d;
        return o;
    }

}

/// <summary>Tolerant argument access: accepts numbers written as strings and vice versa.</summary>
public static class ArgReader
{
    public static string? GetString(JsonObject? args, string name, string? fallback = null)
    {
        if (args is null || !args.TryGetPropertyValue(name, out var node) || node is null) return fallback;
        if (node is JsonValue v)
        {
            if (v.TryGetValue<string>(out var s)) return s;
            if (v.TryGetValue<long>(out var l)) return l.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (v.TryGetValue<double>(out var d)) return d.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (v.TryGetValue<bool>(out var b)) return b ? "true" : "false";
        }
        return node.ToJsonString();
    }

    public static int GetInt(JsonObject? args, string name, int fallback)
    {
        if (args is null || !args.TryGetPropertyValue(name, out var node) || node is not JsonValue v) return fallback;
        if (v.TryGetValue<long>(out var l)) return (int)Math.Clamp(l, int.MinValue, int.MaxValue);
        if (v.TryGetValue<double>(out var d)) return (int)Math.Clamp(d, int.MinValue, int.MaxValue);
        if (v.TryGetValue<string>(out var s) && int.TryParse(s, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed)) return parsed;
        return fallback;
    }

}

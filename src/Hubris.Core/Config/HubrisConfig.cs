using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Hubris.Cli;
using Hubris.Control;
using Hubris.Transport;

namespace Hubris.Config;

public sealed class BridgeConfig
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("command")] public string Command { get; set; } = string.Empty;
    [JsonPropertyName("args")] public List<string> Args { get; set; } = new();
    [JsonPropertyName("env")] public Dictionary<string, string>? Env { get; set; }
    /// <summary>Remote server: its endpoint. <see cref="Command"/> is then empty.</summary>
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("headers")] public Dictionary<string, string>? Headers { get; set; }
    /// <summary>"http" (Streamable HTTP, default for a url) or "sse".</summary>
    [JsonPropertyName("transport")] public string? Transport { get; set; }
    [JsonPropertyName("source")] public string? Source { get; set; }

    public bool IsRemote => !string.IsNullOrWhiteSpace(Url);

    /// <summary>Env and header values may say <c>${NAME}</c>; those are read from the hub's environment at start.</summary>
    public BridgeSpec ToSpec() => new(Name, Command ?? string.Empty, Args, EnvExpander.Expand(Env), Url, EnvExpander.Expand(Headers), Transport);
}

public static class EnvExpander
{
    public static Dictionary<string, string>? Expand(Dictionary<string, string>? values)
    {
        if (values is null || values.Count == 0) return values;
        var result = new Dictionary<string, string>(values.Count, values.Comparer);
        foreach (var kv in values) result[kv.Key] = Expand(kv.Value);
        return result;
    }

    public static string Expand(string value)
    {
        int start = value.IndexOf("${", StringComparison.Ordinal);
        if (start < 0) return value;
        var sb = new System.Text.StringBuilder(value.Length);
        int pos = 0;
        while (start >= 0)
        {
            int end = value.IndexOf('}', start + 2);
            if (end < 0) break;
            sb.Append(value, pos, start - pos);
            string name = value[(start + 2)..end];
            sb.Append(Environment.GetEnvironmentVariable(name) ?? value[start..(end + 1)]); // unknown: left as written
            pos = end + 1;
            start = value.IndexOf("${", pos, StringComparison.Ordinal);
        }
        sb.Append(value, pos, value.Length - pos);
        return sb.ToString();
    }
}

/// <summary>~/.hubris/config.json – the one place bridges live; clients only point at the Hubris binary.</summary>
public sealed class HubrisConfig
{
    [JsonPropertyName("bridges")] public List<BridgeConfig> Bridges { get; set; } = new();
}

[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(HubrisConfig))]
[JsonSerializable(typeof(BridgeConfig))]
[JsonSerializable(typeof(McpSnapshot))]
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(Dictionary<string, JsonObject>))]
public sealed partial class ConfigJsonContext : JsonSerializerContext
{
}

public static class HubrisConfigFile
{
    public static HubrisConfig Load(string? path = null)
    {
        path ??= HubrisPaths.ConfigPath;
        if (!File.Exists(path)) return new HubrisConfig();
        using var fs = File.OpenRead(path);
        if (fs.Length == 0) return new HubrisConfig();
        return JsonSerializer.Deserialize(fs, ConfigJsonContext.Default.HubrisConfig) ?? new HubrisConfig();
    }

    /// <summary>Atomic write, previous file kept as .bak, mode 0600 because imported env blocks carry API keys.</summary>
    public static void Save(HubrisConfig config, string? path = null)
    {
        path ??= HubrisPaths.ConfigPath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (File.Exists(path)) File.Copy(path, path + ".bak", overwrite: true);
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(config, ConfigJsonContext.Default.HubrisConfig));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(tmp, path, overwrite: true);
        Log.Info($"config written: {path} ({config.Bridges.Count} bridge(s))");
    }

    public static List<BridgeSpec> ToSpecs(HubrisConfig config)
    {
        var list = new List<BridgeSpec>(config.Bridges.Count);
        foreach (var b in config.Bridges)
            if (!string.IsNullOrWhiteSpace(b.Name) && (!string.IsNullOrWhiteSpace(b.Command) || b.IsRemote)) list.Add(b.ToSpec());
        return list;
    }
}

using System.Text.Json;
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
    [JsonPropertyName("source")] public string? Source { get; set; }

    public BridgeSpec ToSpec() => new(Name, Command, Args, Env);
}

/// <summary>~/.hubris/config.json – the one place bridges live; clients only point at the Hubris binary.</summary>
public sealed class HubrisConfig
{
    [JsonPropertyName("bridges")] public List<BridgeConfig> Bridges { get; set; } = new();
}

[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(HubrisConfig))]
[JsonSerializable(typeof(BridgeConfig))]
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
            if (!string.IsNullOrWhiteSpace(b.Name) && !string.IsNullOrWhiteSpace(b.Command)) list.Add(b.ToSpec());
        return list;
    }
}

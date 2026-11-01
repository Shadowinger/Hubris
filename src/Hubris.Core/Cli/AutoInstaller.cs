using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Transport;

namespace Hubris.Cli;

/// <summary>Registers this binary in VS Code (.vscode/mcp.json) or Claude Desktop config with a safe merge.</summary>
public static class AutoInstaller
{
    public const string ServerKey = "hubris";

    public static int InstallVsCode(string workspaceDir, string? exe, IReadOnlyList<string> serverArgs)
    {
        if (string.IsNullOrEmpty(exe)) { Log.Error("server executable path is unknown"); return 1; }

        string path = Path.Combine(workspaceDir, ".vscode", "mcp.json");
        var entry = new JsonObject
        {
            ["type"] = "stdio",
            ["command"] = exe,
            ["args"] = ToArray(serverArgs),
        };
        return MergeServerEntry(path, "servers", entry) ? 0 : 1;
    }

    public static int InstallClaude(string? exe, IReadOnlyList<string> serverArgs)
    {
        if (string.IsNullOrEmpty(exe)) { Log.Error("server executable path is unknown"); return 1; }

        string? path = ClaudeConfigPath();
        if (path is null) { Log.Error("unsupported OS for Claude Desktop auto-config"); return 1; }

        var entry = new JsonObject
        {
            ["command"] = exe,
            ["args"] = ToArray(serverArgs),
        };
        return MergeServerEntry(path, "mcpServers", entry) ? 0 : 1;
    }

    public static string? ClaudeConfigPath()
    {
        if (OperatingSystem.IsWindows())
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return string.IsNullOrEmpty(appData) ? null : Path.Combine(appData, "Claude", "claude_desktop_config.json");
        }
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home)) home = Environment.GetEnvironmentVariable("HOME") ?? string.Empty;
        if (string.IsNullOrEmpty(home)) return null;
        if (OperatingSystem.IsMacOS())
            return Path.Combine(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
        string xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") ?? Path.Combine(home, ".config");
        return Path.Combine(xdg, "Claude", "claude_desktop_config.json");
    }

    private static JsonArray ToArray(IReadOnlyList<string> values)
    {
        var arr = new JsonArray();
        foreach (var v in values) arr.Add((JsonNode?)JsonValue.Create(v));
        return arr;
    }

    private static readonly JsonDocumentOptions LenientDoc = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private static bool MergeServerEntry(string path, string rootKey, JsonObject entry)
    {
        try
        {
            string dir = Path.GetDirectoryName(path)!;
            Directory.CreateDirectory(dir);

            JsonObject root;
            if (File.Exists(path))
            {
                // JsonNode cannot preserve comments (VS Code's mcp.json is JSONC), so the original is always kept.
                File.Copy(path, path + ".bak", overwrite: true);
                Log.Info($"previous config kept at {path}.bak");

                JsonNode? parsed = null;
                try
                {
                    using var fs = File.OpenRead(path);
                    if (fs.Length > 0) parsed = JsonNode.Parse(fs, nodeOptions: null, LenientDoc);
                }
                catch (JsonException ex)
                {
                    Log.Warn($"{path} is not valid JSON ({ex.Message}); starting from an empty document");
                }
                root = parsed as JsonObject ?? new JsonObject();
            }
            else
            {
                root = new JsonObject();
            }

            if (root[rootKey] is not JsonObject servers)
            {
                servers = new JsonObject();
                root[rootKey] = servers;
            }

            bool replaced = servers.ContainsKey(ServerKey);
            servers[ServerKey] = entry;

            string tmp = path + ".tmp-" + Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true }))
            {
                root.WriteTo(w);
                w.Flush();
                fs.WriteByte((byte)'\n');
            }
            File.Move(tmp, path, overwrite: true);

            Log.Info($"{(replaced ? "updated" : "added")} '{ServerKey}' in {path}");
            Log.Info($"command: {entry["command"]?.GetValue<string>()} {string.Join(' ', ArgsOf(entry))}");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Error($"failed to write {path}: {ex.Message}");
            return false;
        }
    }

    private static IEnumerable<string> ArgsOf(JsonObject entry)
    {
        if (entry["args"] is JsonArray arr)
            foreach (var n in arr)
                if (n is JsonValue v && v.TryGetValue<string>(out var s)) yield return s;
    }
}

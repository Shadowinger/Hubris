using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Transport;

namespace Hubris.Config;

/// <summary>Where an MCP client keeps its server list and how that file is shaped.</summary>
public sealed record ClientKind(string Id, string Name, string RootKey, bool Writable);

public sealed class DetectedServer
{
    public required string Name { get; init; }
    public required string Command { get; init; }
    public List<string> Args { get; init; } = new();
    public Dictionary<string, string> Env { get; init; } = new();
}

public sealed class DetectedClient
{
    public required ClientKind Kind { get; init; }
    public required string Path { get; init; }
    public List<DetectedServer> Servers { get; init; } = new();
    /// <summary>An entry already launches Hubris (it is skipped from <see cref="Servers"/>).</summary>
    public bool HubrisPresent { get; init; }
    /// <summary>Hubris is the only entry: nothing left to import.</summary>
    public bool IsGateway => HubrisPresent && Servers.Count == 0;
}

public static class ClientConfigScanner
{
    public static readonly ClientKind ClaudeDesktop = new("claude-desktop", "Claude Desktop", "mcpServers", Writable: true);
    public static readonly ClientKind ClaudeCode = new("claude-code", "Claude Code", "mcpServers", Writable: true);
    public static readonly ClientKind Cursor = new("cursor", "Cursor", "mcpServers", Writable: true);
    public static readonly ClientKind Windsurf = new("windsurf", "Windsurf", "mcpServers", Writable: true);
    public static readonly ClientKind VsCodeWorkspace = new("vscode", "VS Code workspace", "servers", Writable: true);

    public static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>Candidate files for this OS. <paramref name="home"/> and <paramref name="appData"/> exist for tests.</summary>
    public static List<(ClientKind Kind, string Path)> KnownLocations(string? workspaceDir = null, string? home = null, string? appData = null)
    {
        home ??= Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var list = new List<(ClientKind, string)>
        {
            (ClaudeDesktop, ClaudeDesktopPath(home, appData)),
            (ClaudeCode, Path.Combine(home, ".claude.json")),
            (Cursor, Path.Combine(home, ".cursor", "mcp.json")),
            (Windsurf, Path.Combine(home, ".codeium", "windsurf", "mcp_config.json")),
        };
        if (!string.IsNullOrEmpty(workspaceDir)) list.Add((VsCodeWorkspace, Path.Combine(workspaceDir, ".vscode", "mcp.json")));
        return list;
    }

    public static string ClaudeDesktopPath(string home, string? appData = null)
    {
        if (OperatingSystem.IsWindows())
        {
            appData ??= Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appData, "Claude", "claude_desktop_config.json");
        }
        if (OperatingSystem.IsMacOS())
            return Path.Combine(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
        string xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") ?? Path.Combine(home, ".config");
        return Path.Combine(xdg, "Claude", "claude_desktop_config.json");
    }

    public static List<DetectedClient> Scan(string? workspaceDir = null, string? home = null, string? appData = null)
    {
        var found = new List<DetectedClient>();
        foreach (var (kind, path) in KnownLocations(workspaceDir, home, appData))
        {
            if (!File.Exists(path)) continue;
            try
            {
                var client = Parse(kind, path);
                if (client is not null) found.Add(client);
            }
            catch (JsonException ex)
            {
                Log.Warn($"{kind.Name} config {path} is not valid JSON: {ex.Message}");
            }
            catch (IOException ex)
            {
                Log.Warn($"{kind.Name} config {path} unreadable: {ex.Message}");
            }
        }
        return found;
    }

    public static DetectedClient? Parse(ClientKind kind, string path)
    {
        JsonNode? root;
        using (var fs = File.OpenRead(path))
            root = fs.Length == 0 ? null : JsonNode.Parse(fs, nodeOptions: null, Lenient);
        if (root is not JsonObject obj) return null;
        if (obj[kind.RootKey] is not JsonObject servers) return new DetectedClient { Kind = kind, Path = path };

        var list = new List<DetectedServer>();
        bool hubris = false;
        foreach (var kv in servers)
        {
            if (kv.Value is not JsonObject entry) continue;
            if (IsHubrisEntry(kv.Key, entry)) { hubris = true; continue; }
            string? command = entry["command"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(command)) continue; // remote (url/type sse) servers cannot be bridged over stdio
            var server = new DetectedServer { Name = kv.Key, Command = command };
            if (entry["args"] is JsonArray args)
                foreach (var a in args)
                    if (a is JsonValue v && v.TryGetValue<string>(out var s)) server.Args.Add(s);
            if (entry["env"] is JsonObject env)
                foreach (var e in env)
                    if (e.Value is JsonValue ev && ev.TryGetValue<string>(out var es)) server.Env[e.Key] = es;
            list.Add(server);
        }
        return new DetectedClient { Kind = kind, Path = path, Servers = list, HubrisPresent = hubris };
    }

    /// <summary>Loop guard: never import an entry that would make Hubris spawn itself.</summary>
    public static bool IsHubrisEntry(string key, JsonObject entry)
    {
        if (key.Contains("hubris", StringComparison.OrdinalIgnoreCase)) return true;
        string? command = entry["command"]?.GetValue<string>();
        if (command is not null)
        {
            string file = Path.GetFileNameWithoutExtension(command);
            if (string.Equals(file, "Hubris", StringComparison.OrdinalIgnoreCase)) return true;
            if (Environment.ProcessPath is { } self && string.Equals(Path.GetFullPath(command), Path.GetFullPath(self), StringComparison.Ordinal)) return true;
        }
        if (entry["args"] is JsonArray args)
            foreach (var a in args)
                if (a is JsonValue v && v.TryGetValue<string>(out var s) && s.Contains("hubris", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}

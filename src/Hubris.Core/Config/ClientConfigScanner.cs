using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Cli;
using Hubris.Transport;

namespace Hubris.Config;

/// <summary>Where an MCP client keeps its server list and how that file is shaped.</summary>
/// <param name="GlobalKindId">For a project-level file: the kind whose global config, once routed through Hubris, lets this file be emptied instead of pointing at Hubris again.</param>
public sealed record ClientKind(string Id, string Name, string RootKey, string? GlobalKindId = null)
{
    public bool IsProjectLevel => GlobalKindId is not null || Id == "vscode";
}

public sealed class DetectedServer
{
    public required string Name { get; init; }
    public required string Command { get; init; }
    public List<string> Args { get; init; } = new();
    public Dictionary<string, string> Env { get; init; } = new();
    /// <summary>Project path for a per-project entry in ~/.claude.json; empty for the global block.</summary>
    public string Scope { get; init; } = "";
}

public sealed class DetectedClient
{
    public required ClientKind Kind { get; init; }
    public required string Path { get; init; }
    public List<DetectedServer> Servers { get; init; } = new();
    /// <summary>An entry already launches Hubris (it is skipped from <see cref="Servers"/>).</summary>
    public bool HubrisPresent { get; init; }
    /// <summary>Per-project blocks in ~/.claude.json that still list servers.</summary>
    public int ProjectBlocksWithServers { get; init; }
    /// <summary>Nothing left to import: Hubris is the only entry, or the file is an emptied project config.</summary>
    public bool IsGateway => Servers.Count == 0 && (HubrisPresent || Kind.IsProjectLevel && Emptied);
    public bool Emptied { get; init; }
}

public static class ClientConfigScanner
{
    public static readonly ClientKind ClaudeDesktop = new("claude-desktop", "Claude Desktop", "mcpServers");
    public static readonly ClientKind ClaudeCode = new("claude-code", "Claude Code", "mcpServers");
    public static readonly ClientKind Cursor = new("cursor", "Cursor", "mcpServers");
    public static readonly ClientKind Windsurf = new("windsurf", "Windsurf", "mcpServers");
    public static readonly ClientKind VsCodeWorkspace = new("vscode", "VS Code workspace", "servers");
    public static readonly ClientKind ProjectMcp = new("project-mcp", "Claude Code project", "mcpServers", GlobalKindId: "claude-code");
    public static readonly ClientKind CursorProject = new("cursor-project", "Cursor project", "mcpServers", GlobalKindId: "cursor");

    public static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    private static readonly string[] SkippedDirs = ["node_modules", "bin", "obj", "dist", "build", "target", "vendor", ".git", ".hg", ".svn", "Library", ".Trash"];

    /// <summary>Candidate global files for this OS. <paramref name="home"/> and <paramref name="appData"/> exist for tests.</summary>
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
            if (File.Exists(path)) Try(found, kind, path);
        return found;
    }

    /// <summary>Walks <paramref name="root"/> (default depth 4) for project-level MCP configs; hidden and build folders are skipped.</summary>
    public static List<DetectedClient> ScanProjects(string root, int maxDepth = 4)
    {
        var found = new List<DetectedClient>();
        if (!Directory.Exists(root)) return found;
        Walk(root, 0);
        return found;

        void Walk(string dir, int depth)
        {
            Try(found, ProjectMcp, Path.Combine(dir, ".mcp.json"));
            Try(found, CursorProject, Path.Combine(dir, ".cursor", "mcp.json"));
            Try(found, VsCodeWorkspace, Path.Combine(dir, ".vscode", "mcp.json"));
            if (depth >= maxDepth) return;
            IEnumerable<string> subs;
            try { subs = Directory.EnumerateDirectories(dir); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }
            foreach (var sub in subs)
            {
                string name = Path.GetFileName(sub);
                if (name.StartsWith('.') || Array.IndexOf(SkippedDirs, name) >= 0) continue;
                Walk(sub, depth + 1);
            }
        }
    }

    private static void Try(List<DetectedClient> found, ClientKind kind, string path)
    {
        if (!File.Exists(path)) return;
        try
        {
            var client = Parse(kind, path);
            if (client is not null) found.Add(client);
        }
        catch (JsonException ex) { Log.Warn($"{kind.Name} config {path} is not valid JSON: {ex.Message}"); }
        catch (IOException ex) { Log.Warn($"{kind.Name} config {path} unreadable: {ex.Message}"); }
    }

    public static DetectedClient? Parse(ClientKind kind, string path)
    {
        JsonNode? root;
        using (var fs = File.OpenRead(path))
            root = fs.Length == 0 ? null : JsonNode.Parse(fs, nodeOptions: null, Lenient);
        if (root is not JsonObject obj) return null;

        var list = new List<DetectedServer>();
        bool hubris = false, emptied = false;
        if (obj[kind.RootKey] is JsonObject servers)
        {
            emptied = servers.Count == 0;
            ReadBlock(servers, "", list, ref hubris);
        }

        int projectBlocks = 0;
        if (kind == ClaudeCode && obj["projects"] is JsonObject projects)
        {
            // Per-project servers bypass the gateway just like global ones; import them too.
            foreach (var kv in projects)
            {
                if (kv.Value is not JsonObject project || project["mcpServers"] is not JsonObject block || block.Count == 0) continue;
                int before = list.Count;
                ReadBlock(block, kv.Key, list, ref hubris);
                if (list.Count > before) projectBlocks++;
            }
        }
        return new DetectedClient { Kind = kind, Path = path, Servers = list, HubrisPresent = hubris, ProjectBlocksWithServers = projectBlocks, Emptied = emptied };
    }

    private static void ReadBlock(JsonObject servers, string scope, List<DetectedServer> list, ref bool hubris)
    {
        foreach (var kv in servers)
        {
            if (kv.Value is not JsonObject entry) continue;
            if (IsHubrisEntry(kv.Key, entry))
            {
                hubris = true;
                // Bridges still passed as --bridge arguments to Hubris itself belong in config.json: offer them for import.
                list.AddRange(BridgesFromHubrisArgs(entry, scope));
                continue;
            }
            string? command = entry["command"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(command)) continue; // remote (url/type sse) servers cannot be bridged over stdio
            var server = new DetectedServer { Name = kv.Key, Command = command, Scope = scope };
            if (entry["args"] is JsonArray args)
                foreach (var a in args)
                    if (a is JsonValue v && v.TryGetValue<string>(out var s)) server.Args.Add(s);
            if (entry["env"] is JsonObject env)
                foreach (var e in env)
                    if (e.Value is JsonValue ev && ev.TryGetValue<string>(out var es)) server.Env[e.Key] = es;
            list.Add(server);
        }
    }

    private static IEnumerable<DetectedServer> BridgesFromHubrisArgs(JsonObject entry, string scope)
    {
        if (entry["args"] is not JsonArray args) yield break;
        var argv = new List<string>();
        foreach (var a in args)
            if (a is JsonValue v && v.TryGetValue<string>(out var s)) argv.Add(s);
        if (!CliOptions.TryParse(argv.ToArray(), out var opts, out _)) yield break;
        foreach (var b in opts.Bridges)
            yield return new DetectedServer { Name = b.Name, Command = b.Command, Args = new List<string>(b.Args), Scope = scope };
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

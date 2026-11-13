using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Hubris.Control;
using Hubris.Transport;

namespace Hubris.Config;

public sealed record ImportResult(List<string> Added, List<string> Skipped);

/// <summary>What a hijack replaced, keyed so Restore can put exactly those blocks back and nothing else.</summary>
public sealed class McpSnapshot
{
    [JsonPropertyName("file")] public string File { get; set; } = string.Empty;
    [JsonPropertyName("takenAt")] public string TakenAt { get; set; } = string.Empty;
    /// <summary>The root server block (`mcpServers` / `servers`) as it was.</summary>
    [JsonPropertyName("root")] public JsonObject? Root { get; set; }
    /// <summary>~/.claude.json only: original `projects[path].mcpServers` per project path.</summary>
    [JsonPropertyName("projects")] public Dictionary<string, JsonObject> Projects { get; set; } = new();
}

/// <summary>Imports a client's servers as Hubris bridges and (optionally) makes Hubris that client's only MCP server.</summary>
public static class ClientConfigHijacker
{
    public const string ServerKey = "hubris";
    public const int KeptBackups = 5;

    /// <summary>
    /// Adds every detected server as a bridge. The same launch (command + args) anywhere is one bridge; a name
    /// already taken by a different launch gets the project folder (or a number) as suffix.
    /// </summary>
    public static ImportResult Import(DetectedClient client, HubrisConfig config)
    {
        var added = new List<string>();
        var skipped = new List<string>();
        foreach (var s in client.Servers)
        {
            string name = SafeName(s.Name);
            if (config.Bridges.Exists(b => SameLaunch(b, s))) { skipped.Add(name); continue; }
            if (config.Bridges.Exists(b => string.Equals(b.Name, name, StringComparison.Ordinal)))
            {
                string scoped = s.Scope.Length > 0 ? SafeName(name + "-" + Path.GetFileName(s.Scope.TrimEnd('/', '\\'))) : name;
                if (scoped == name || config.Bridges.Exists(b => b.Name == scoped))
                {
                    int n = 2;
                    while (config.Bridges.Exists(b => b.Name == $"{name}-{n}")) n++;
                    scoped = $"{name}-{n}";
                }
                name = scoped;
            }
            config.Bridges.Add(new BridgeConfig
            {
                Name = name,
                Command = s.Command,
                Args = new List<string>(s.Args),
                Env = s.Env.Count == 0 ? null : new Dictionary<string, string>(s.Env),
                Url = s.Url,
                Headers = s.Headers.Count == 0 ? null : new Dictionary<string, string>(s.Headers),
                Transport = s.Transport,
                Source = s.Scope.Length > 0 ? $"{client.Kind.Id}:{s.Scope}" : client.Kind.Id,
            });
            added.Add(name);
        }
        return new ImportResult(added, skipped);
    }

    /// <summary>
    /// Backs the file up, snapshots the blocks it is about to replace, then rewrites the root server block to a
    /// single Hubris entry (or to {} when <paramref name="empty"/>) and clears every per-project block in ~/.claude.json.
    /// Everything else in the file is left byte-for-byte as JSON DOM round-trips it. Returns the file backup path.
    /// </summary>
    public static string Hijack(DetectedClient client, string exePath, IReadOnlyList<string> serverArgs, bool empty = false)
    {
        string backup = Backup(client.Path);
        JsonObject root;
        using (var fs = File.OpenRead(client.Path))
            root = (fs.Length == 0 ? null : JsonNode.Parse(fs, nodeOptions: null, ClientConfigScanner.Lenient)) as JsonObject ?? new JsonObject();

        var snapshot = new McpSnapshot { File = client.Path, TakenAt = DateTime.UtcNow.ToString("O") };
        snapshot.Root = root[client.Kind.RootKey] is JsonObject r ? (JsonObject)r.DeepClone() : null;

        JsonObject block = new();
        if (!empty)
        {
            var entry = new JsonObject { ["command"] = exePath, ["args"] = ToArray(serverArgs) };
            if (client.Kind.RootKey == "servers") entry.Insert(0, "type", "stdio"); // VS Code shape
            block[ServerKey] = entry;
        }
        root[client.Kind.RootKey] = block;

        if (client.Kind == ClientConfigScanner.ClaudeCode && root["projects"] is JsonObject projects)
        {
            foreach (var kv in projects)
            {
                if (kv.Value is not JsonObject project || project["mcpServers"] is not JsonObject servers || servers.Count == 0) continue;
                snapshot.Projects[kv.Key] = (JsonObject)servers.DeepClone();
                project["mcpServers"] = new JsonObject(); // no per-project server may spawn outside the gateway
            }
        }

        WriteAtomic(client.Path, root);
        SaveSnapshot(client, snapshot);
        Log.Info($"{client.Kind.Name}: {client.Path} now routes through Hubris ({snapshot.Projects.Count} project block(s) cleared, backup {backup})");
        return backup;
    }

    /// <summary>
    /// Puts the snapshotted blocks back into the *current* file, so history and state written since the hijack survive.
    /// Falls back to the newest whole-file backup when no snapshot exists. Returns what was used, or null.
    /// </summary>
    public static string? Restore(DetectedClient client)
    {
        string snapPath = SnapshotPath(client);
        if (File.Exists(snapPath))
        {
            McpSnapshot? snap;
            using (var fs = File.OpenRead(snapPath))
                snap = JsonSerializer.Deserialize(fs, ConfigJsonContext.Default.McpSnapshot);
            if (snap is not null && string.Equals(snap.File, client.Path, StringComparison.Ordinal))
            {
                JsonObject root;
                using (var fs = File.OpenRead(client.Path))
                    root = (fs.Length == 0 ? null : JsonNode.Parse(fs, nodeOptions: null, ClientConfigScanner.Lenient)) as JsonObject ?? new JsonObject();
                root[client.Kind.RootKey] = snap.Root?.DeepClone() ?? new JsonObject();
                if (snap.Projects.Count > 0)
                {
                    if (root["projects"] is not JsonObject projects) { projects = new JsonObject(); root["projects"] = projects; }
                    foreach (var kv in snap.Projects)
                    {
                        if (projects[kv.Key] is not JsonObject project) { project = new JsonObject(); projects[kv.Key] = project; }
                        project["mcpServers"] = kv.Value.DeepClone();
                    }
                }
                WriteAtomic(client.Path, root);
                File.Delete(snapPath);
                Log.Info($"{client.Kind.Name}: restored server blocks of {client.Path} from snapshot");
                return snapPath;
            }
        }

        string? latest = LatestBackup(client.Path);
        if (latest is null) return null;
        if (File.Exists(client.Path)) Backup(client.Path); // this replaces the whole file, state the client wrote since included: keep it, so one more Restore brings it back
        File.Copy(latest, client.Path, overwrite: true);
        Log.Info($"{client.Kind.Name}: restored {client.Path} from {latest}");
        return latest;
    }

    public static bool HasRestorePoint(string path) => File.Exists(SnapshotPathFor(path)) || LatestBackup(path) is not null;

    public static string? LatestBackup(string path) => Backups(path).FirstOrDefault();

    /// <summary>Whole-file backups of one client config, newest first (the name carries the time).</summary>
    private static List<string> Backups(string path)
    {
        string dir = HubrisPaths.BackupsDir;
        string prefix = Path.GetFileName(Path.ChangeExtension(SnapshotPathFor(path), null)) + ".bak-";
        var list = Directory.Exists(dir) ? Directory.EnumerateFiles(dir, prefix + "*").ToList() : [];
        list.Sort((a, b) => string.CompareOrdinal(b, a));
        return list;
    }

    /// <summary>Merges one server entry into a client config without touching the others (used by --install-*).</summary>
    public static bool MergeServerEntry(string path, string rootKey, string entryName, JsonObject entry)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            JsonObject root = new();
            if (File.Exists(path))
            {
                Backup(path);
                try
                {
                    using var fs = File.OpenRead(path);
                    if (fs.Length > 0) root = JsonNode.Parse(fs, nodeOptions: null, ClientConfigScanner.Lenient) as JsonObject ?? new JsonObject();
                }
                catch (JsonException ex)
                {
                    Log.Warn($"{path} is not valid JSON ({ex.Message}); starting from an empty document");
                }
            }
            if (root[rootKey] is not JsonObject servers) { servers = new JsonObject(); root[rootKey] = servers; }
            bool replaced = servers.ContainsKey(entryName);
            servers[entryName] = entry;
            WriteAtomic(path, root);
            Log.Info($"{(replaced ? "updated" : "added")} '{entryName}' in {path}");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Error($"failed to write {path}: {ex.Message}");
            return false;
        }
    }

    /// <summary>Whole-file copy under ~/.hubris/backups (never next to a project file, where git would pick it up), 0600 like the snapshot.</summary>
    public static string Backup(string path)
    {
        Directory.CreateDirectory(HubrisPaths.BackupsDir);
        string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff", System.Globalization.CultureInfo.InvariantCulture);
        string backup = System.IO.Path.ChangeExtension(SnapshotPathFor(path), null) + ".bak-" + stamp + ".json";
        File.Copy(path, backup, overwrite: true);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(backup, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        // ~/.claude.json runs to megabytes and carries secrets: the newest few are enough (the snapshot holds the original server list).
        foreach (string old in Backups(path).Skip(KeptBackups))
            try { File.Delete(old); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Log.Debug($"backup {old}: {ex.Message}"); }
        return backup;
    }

    // Claude Code's file keeps the spec'd name; other files get one snapshot each, named after their path.
    public static string SnapshotPath(DetectedClient client) => SnapshotPathFor(client.Path);

    public static string SnapshotPathFor(string path)
    {
        if (string.Equals(Path.GetFileName(path), ".claude.json", StringComparison.Ordinal))
            return Path.Combine(HubrisPaths.BackupsDir, "claude_mcp_snapshot.json");
        string safe = string.Concat(path.Select(c => char.IsLetterOrDigit(c) ? c : '_')).Trim('_');
        return Path.Combine(HubrisPaths.BackupsDir, safe + ".snapshot.json");
    }

    /// <summary>
    /// The first hijack holds the true original. A later hijack only adds what the user put into the client config
    /// since (new root entries, new project blocks), so Restore returns everything that ever bypassed the gateway.
    /// </summary>
    private static void SaveSnapshot(DetectedClient client, McpSnapshot snapshot)
    {
        string path = SnapshotPath(client);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (File.Exists(path))
        {
            McpSnapshot? existing = null;
            try { existing = JsonSerializer.Deserialize(File.ReadAllBytes(path), ConfigJsonContext.Default.McpSnapshot); }
            catch (JsonException ex) { Log.Warn($"snapshot {path} unreadable, replacing: {ex.Message}"); }
            if (existing is not null)
            {
                if (snapshot.Root is { } newRoot)
                {
                    existing.Root ??= new JsonObject();
                    foreach (var kv in newRoot)
                        if (!existing.Root.ContainsKey(kv.Key) && !IsHubrisEntryNode(kv.Key, kv.Value)) existing.Root[kv.Key] = kv.Value?.DeepClone();
                }
                foreach (var kv in snapshot.Projects)
                {
                    if (!existing.Projects.TryGetValue(kv.Key, out var block)) { existing.Projects[kv.Key] = kv.Value; continue; }
                    foreach (var entry in kv.Value)
                        if (!block.ContainsKey(entry.Key)) block[entry.Key] = entry.Value?.DeepClone();
                }
                snapshot = existing;
            }
        }
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(snapshot, ConfigJsonContext.Default.McpSnapshot));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite); // carries the imported env blocks
        File.Move(tmp, path, overwrite: true);
    }

    private static bool IsHubrisEntryNode(string key, JsonNode? node) => node is JsonObject o && ClientConfigScanner.IsHubrisEntry(key, o);

    private static void WriteAtomic(string path, JsonObject root)
    {
        // Dotfiles setups symlink these files; replacing the link with a plain file would be undone by the next sync.
        try { path = File.ResolveLinkTarget(path, returnFinalTarget: true)?.FullName ?? path; }
        catch (IOException ex) { Log.Debug($"link target of {path}: {ex.Message}"); }
        string tmp = path + ".tmp-" + Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true }))
        {
            root.WriteTo(w);
            w.Flush();
            fs.WriteByte((byte)'\n');
        }
        // A rename would replace a 0600 config (Claude Desktop's carries tokens) with a umask-default 0644 file.
        if (!OperatingSystem.IsWindows() && File.Exists(path)) File.SetUnixFileMode(tmp, File.GetUnixFileMode(path));
        File.Move(tmp, path, overwrite: true);
    }

    private static JsonArray ToArray(IReadOnlyList<string> values)
    {
        var arr = new JsonArray();
        foreach (var v in values) arr.Add((JsonNode?)JsonValue.Create(v));
        return arr;
    }

    private static bool SameLaunch(BridgeConfig b, DetectedServer s)
        => b.Command == s.Command && b.Args.SequenceEqual(s.Args) && SameEnv(b.Env, s.Env)
           && string.Equals(b.Url ?? "", s.Url ?? "", StringComparison.Ordinal) && SameEnv(b.Headers, s.Headers);

    private static bool SameEnv(Dictionary<string, string>? a, Dictionary<string, string> b)
    {
        if ((a?.Count ?? 0) != b.Count) return false;
        if (a is null) return true;
        foreach (var kv in a) if (!b.TryGetValue(kv.Key, out var v) || v != kv.Value) return false;
        return true;
    }

    private static string SafeName(string raw)
    {
        var chars = raw.Trim().Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-').ToArray();
        string name = new(chars);
        return name.Length == 0 ? "bridge" : name;
    }

}

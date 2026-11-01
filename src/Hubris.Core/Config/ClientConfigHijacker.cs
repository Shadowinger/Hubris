using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Transport;

namespace Hubris.Config;

public sealed record ImportResult(List<string> Added, List<string> Skipped);

/// <summary>Imports a client's servers as Hubris bridges and (optionally) makes Hubris that client's only MCP server.</summary>
public static class ClientConfigHijacker
{
    public const string ServerKey = "hubris";

    /// <summary>Adds every detected server as a bridge; a name clash with a different command gets a numeric suffix.</summary>
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
                int n = 2;
                while (config.Bridges.Exists(b => b.Name == $"{name}-{n}")) n++;
                name = $"{name}-{n}";
            }
            config.Bridges.Add(new BridgeConfig
            {
                Name = name,
                Command = s.Command,
                Args = new List<string>(s.Args),
                Env = s.Env.Count == 0 ? null : new Dictionary<string, string>(s.Env),
                Source = client.Kind.Id,
            });
            added.Add(name);
        }
        return new ImportResult(added, skipped);
    }

    /// <summary>Backs the file up, then rewrites its server block to a single Hubris entry. Returns the backup path.</summary>
    public static string Hijack(DetectedClient client, string exePath, IReadOnlyList<string> serverArgs)
    {
        string backup = Backup(client.Path);
        JsonObject root;
        using (var fs = File.OpenRead(client.Path))
            root = (fs.Length == 0 ? null : JsonNode.Parse(fs, nodeOptions: null, ClientConfigScanner.Lenient)) as JsonObject ?? new JsonObject();

        var entry = new JsonObject { ["command"] = exePath, ["args"] = ToArray(serverArgs) };
        if (client.Kind.RootKey == "servers") entry.Insert(0, "type", "stdio"); // VS Code shape
        // Only the root-level block is replaced; ~/.claude.json keeps its projects, history and everything else.
        root[client.Kind.RootKey] = new JsonObject { [ServerKey] = entry };
        WriteAtomic(client.Path, root);
        Log.Info($"{client.Kind.Name}: {client.Path} now routes through Hubris (backup {backup})");
        return backup;
    }

    /// <summary>Puts the newest Hubris backup back. Returns the backup used, or null when there is none.</summary>
    public static string? Restore(DetectedClient client)
    {
        string? latest = LatestBackup(client.Path);
        if (latest is null) return null;
        File.Copy(latest, client.Path, overwrite: true);
        Log.Info($"{client.Kind.Name}: restored {client.Path} from {latest}");
        return latest;
    }

    public static string? LatestBackup(string path)
    {
        string dir = Path.GetDirectoryName(path)!;
        string prefix = Path.GetFileName(path) + ".hubris.bak-";
        if (!Directory.Exists(dir)) return null;
        string? best = null;
        foreach (var f in Directory.EnumerateFiles(dir, prefix + "*"))
            if (best is null || string.CompareOrdinal(f, best) > 0) best = f;
        return best;
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

    public static string Backup(string path)
    {
        string backup = path + ".hubris.bak-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture);
        File.Copy(path, backup, overwrite: true);
        return backup;
    }

    private static void WriteAtomic(string path, JsonObject root)
    {
        string tmp = path + ".tmp-" + Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true }))
        {
            root.WriteTo(w);
            w.Flush();
            fs.WriteByte((byte)'\n');
        }
        File.Move(tmp, path, overwrite: true);
    }

    private static JsonArray ToArray(IReadOnlyList<string> values)
    {
        var arr = new JsonArray();
        foreach (var v in values) arr.Add((JsonNode?)JsonValue.Create(v));
        return arr;
    }

    private static bool SameLaunch(BridgeConfig b, DetectedServer s)
        => b.Command == s.Command && b.Args.SequenceEqual(s.Args);

    private static string SafeName(string raw)
    {
        var chars = raw.Trim().Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-').ToArray();
        string name = new(chars);
        return name.Length == 0 ? "bridge" : name;
    }
}

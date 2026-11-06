using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Hubris.Protocol;
using Hubris.Transport;

namespace Hubris.Caching;

/// <summary>
/// Tool definitions per bridge, persisted in SQLite so a hub can list a bridge's tools without spawning it.
/// Keyed by bridge name; an entry is valid only while its config hash matches and its age is under the TTL.
/// One connection per hub process; WAL lets several hubs and the desktop share the file.
/// </summary>
public sealed class ToolCacheStore : IDisposable
{
    private readonly string _path;
    private readonly TimeSpan _ttl;
    private readonly object _gate = new();
    private SqliteConnection? _db;
    private long _hits, _misses;

    public ToolCacheStore(string path, TimeSpan ttl)
    {
        _path = path;
        _ttl = ttl;
    }

    public string Path => _path;
    public TimeSpan Ttl => _ttl;
    public long Hits => Interlocked.Read(ref _hits);
    public long Misses => Interlocked.Read(ref _misses);

    public void Open()
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_path)!);
        var db = new SqliteConnection($"Data Source={_path};Pooling=False"); // one connection per hub; pooling only keeps the file locked after Dispose (Windows)
        db.Open();
        Exec(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=2000;");
        Exec(db, """
            CREATE TABLE IF NOT EXISTS bridge_cache(
                bridge_name    TEXT PRIMARY KEY,
                config_hash    TEXT NOT NULL,
                tools_json     TEXT NOT NULL,
                token_estimate INTEGER NOT NULL,
                updated_at     INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS bridge_extras(
                bridge_name    TEXT PRIMARY KEY,
                config_hash    TEXT NOT NULL,
                extras_json    TEXT NOT NULL,
                updated_at     INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """);
        _db = db;
    }

    /// <summary>SHA-256 over command, arguments and the *names* of environment variables (values may rotate).</summary>
    public static string ComputeHash(string command, IReadOnlyList<string> args, IEnumerable<string> envKeys)
    {
        var sb = new StringBuilder(command.Length + 64);
        sb.Append(command).Append('\0');
        foreach (var a in args) sb.Append(a).Append('\0');
        var keys = envKeys.ToList();
        keys.Sort(StringComparer.Ordinal);
        foreach (var k in keys) sb.Append(k).Append('\0');
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }

    public List<ToolDefinition>? TryGet(string bridgeName, string configHash)
    {
        lock (_gate)
        {
            var db = Require();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "SELECT config_hash, tools_json, updated_at FROM bridge_cache WHERE bridge_name = $n";
            cmd.Parameters.AddWithValue("$n", bridgeName);
            using var r = cmd.ExecuteReader();
            if (r.Read())
            {
                bool fresh = string.Equals(r.GetString(0), configHash, StringComparison.Ordinal)
                             && DateTimeOffset.UtcNow.ToUnixTimeSeconds() - r.GetInt64(2) <= (long)_ttl.TotalSeconds;
                if (fresh)
                {
                    try
                    {
                        var tools = JsonSerializer.Deserialize(r.GetString(1), McpJsonContext.Default.ListToolDefinition);
                        if (tools is not null) { Interlocked.Increment(ref _hits); return tools; }
                    }
                    catch (JsonException ex) { Log.Warn($"tool cache entry for '{bridgeName}' unreadable: {ex.Message}"); }
                }
            }
            Interlocked.Increment(ref _misses);
            return null;
        }
    }

    public void Put(string bridgeName, string configHash, List<ToolDefinition> tools, int tokenEstimate)
    {
        lock (_gate)
        {
            var db = Require();
            using var cmd = db.CreateCommand();
            cmd.CommandText = """
                INSERT INTO bridge_cache(bridge_name, config_hash, tools_json, token_estimate, updated_at)
                VALUES ($n, $h, $j, $t, $u)
                ON CONFLICT(bridge_name) DO UPDATE SET config_hash = $h, tools_json = $j, token_estimate = $t, updated_at = $u
                """;
            cmd.Parameters.AddWithValue("$n", bridgeName);
            cmd.Parameters.AddWithValue("$h", configHash);
            cmd.Parameters.AddWithValue("$j", JsonSerializer.Serialize(tools, McpJsonContext.Default.ListToolDefinition));
            cmd.Parameters.AddWithValue("$t", tokenEstimate);
            cmd.Parameters.AddWithValue("$u", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            cmd.ExecuteNonQuery();
        }
    }

    public int Invalidate(string bridgeName)
    {
        lock (_gate)
        {
            using var cmd = Require().CreateCommand();
            cmd.CommandText = "DELETE FROM bridge_cache WHERE bridge_name = $n; DELETE FROM bridge_extras WHERE bridge_name = $n";
            cmd.Parameters.AddWithValue("$n", bridgeName);
            return cmd.ExecuteNonQuery();
        }
    }

    /// <summary>Resources, templates and prompts of a bridge, valid under the same hash and TTL rules as its tools.</summary>
    public BridgeExtras? TryGetExtras(string bridgeName, string configHash)
    {
        lock (_gate)
        {
            using var cmd = Require().CreateCommand();
            cmd.CommandText = "SELECT config_hash, extras_json, updated_at FROM bridge_extras WHERE bridge_name = $n";
            cmd.Parameters.AddWithValue("$n", bridgeName);
            using var r = cmd.ExecuteReader();
            if (!r.Read()) return null;
            bool fresh = string.Equals(r.GetString(0), configHash, StringComparison.Ordinal)
                         && DateTimeOffset.UtcNow.ToUnixTimeSeconds() - r.GetInt64(2) <= (long)_ttl.TotalSeconds;
            if (!fresh) return null;
            try { return JsonSerializer.Deserialize(r.GetString(1), McpJsonContext.Default.BridgeExtras); }
            catch (JsonException ex) { Log.Warn($"extras cache entry for '{bridgeName}' unreadable: {ex.Message}"); return null; }
        }
    }

    public void PutExtras(string bridgeName, string configHash, BridgeExtras extras)
    {
        lock (_gate)
        {
            using var cmd = Require().CreateCommand();
            cmd.CommandText = """
                INSERT INTO bridge_extras(bridge_name, config_hash, extras_json, updated_at) VALUES ($n, $h, $j, $u)
                ON CONFLICT(bridge_name) DO UPDATE SET config_hash = $h, extras_json = $j, updated_at = $u
                """;
            cmd.Parameters.AddWithValue("$n", bridgeName);
            cmd.Parameters.AddWithValue("$h", configHash);
            cmd.Parameters.AddWithValue("$j", JsonSerializer.Serialize(extras, McpJsonContext.Default.BridgeExtras));
            cmd.Parameters.AddWithValue("$u", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            cmd.ExecuteNonQuery();
        }
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                using var cmd = Require().CreateCommand();
                cmd.CommandText = "SELECT COUNT(*) FROM bridge_cache";
                return Convert.ToInt32(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
            }
        }
    }

    /// <summary>Runs VACUUM/ANALYZE/REINDEX when the last run is older than <paramref name="every"/>. Returns true if it ran.</summary>
    public bool MaintainIfDue(TimeSpan every)
    {
        lock (_gate)
        {
            try
            {
                var db = Require();
                long last = 0;
                using (var get = db.CreateCommand())
                {
                    get.CommandText = "SELECT value FROM meta WHERE key = 'last_maintenance'";
                    if (get.ExecuteScalar() is string s) long.TryParse(s, out last);
                }
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (now - last < (long)every.TotalSeconds) return false;
                MaintainLocked(db, now);
                return true;
            }
            catch (SqliteException ex)
            {
                // Another hub is vacuuming right now (Claude starts several at once); the cache itself is fine.
                Log.Warn($"tool cache maintenance skipped: {ex.Message}");
                return false;
            }
        }
    }

    public void Maintain()
    {
        lock (_gate) MaintainLocked(Require(), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    private static void MaintainLocked(SqliteConnection db, long now)
    {
        Exec(db, "VACUUM; ANALYZE; REINDEX;");
        using var set = db.CreateCommand();
        set.CommandText = "INSERT INTO meta(key, value) VALUES ('last_maintenance', $v) ON CONFLICT(key) DO UPDATE SET value = $v";
        set.Parameters.AddWithValue("$v", now.ToString(System.Globalization.CultureInfo.InvariantCulture));
        set.ExecuteNonQuery();
        Log.Info("tool cache maintenance done (VACUUM, ANALYZE, REINDEX)");
    }

    private static void Exec(SqliteConnection db, string sql)
    {
        using var cmd = db.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Require() => _db ?? throw new InvalidOperationException("ToolCacheStore is not open");

    public void Dispose()
    {
        lock (_gate)
        {
            _db?.Dispose();
            _db = null;
        }
    }
}

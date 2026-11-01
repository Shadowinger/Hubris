using System.Buffers;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using McpHub.Protocol;

namespace McpHub.Caching;

/// <summary>
/// Lock-free-read TTL cache keyed by FNV-1a(tool name + canonical argument JSON).
/// Eviction is approximate-LRU over a bounded set (capacity is small, a scan is sub-millisecond).
/// </summary>
public sealed class FastLruCache
{
    public readonly record struct CacheKey(ulong Hash, string Text);

    private sealed class Entry
    {
        public required string KeyText;
        public required CallToolResult Value;
        public long ExpiresAt;
        public long LastAccess;
    }

    private readonly ConcurrentDictionary<ulong, Entry> _map;
    private readonly int _capacity;
    private readonly long _ttlTicks;
    private long _hits;
    private long _misses;
    private int _evicting;

    public FastLruCache(int capacity = 256, TimeSpan? ttl = null)
    {
        _capacity = Math.Max(8, capacity);
        _ttlTicks = (ttl ?? TimeSpan.FromSeconds(60)).Ticks;
        _map = new ConcurrentDictionary<ulong, Entry>(Environment.ProcessorCount, _capacity * 2);
    }

    public long Hits => Interlocked.Read(ref _hits);
    public long Misses => Interlocked.Read(ref _misses);
    public int Count => _map.Count;
    public int Capacity => _capacity;

    // ------------------------------------------------------------------ key

    public static CacheKey ComputeKey(string toolName, JsonObject? arguments)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        Encoding.UTF8.GetBytes(toolName.AsSpan(), buffer);
        buffer.GetSpan(1)[0] = 0;
        buffer.Advance(1);
        if (arguments is not null)
        {
            using var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false, SkipValidation = true });
            arguments.WriteTo(w);
            w.Flush();
        }
        ReadOnlySpan<byte> span = buffer.WrittenSpan;
        return new CacheKey(Fnv1a64(span), Encoding.UTF8.GetString(span));
    }

    public static ulong Fnv1a64(ReadOnlySpan<byte> data)
    {
        const ulong offset = 14695981039346656037UL;
        const ulong prime = 1099511628211UL;
        ulong h = offset;
        foreach (byte b in data)
        {
            h ^= b;
            h *= prime;
        }
        return h;
    }

    // ------------------------------------------------------------------ ops

    public bool TryGet(in CacheKey key, out CallToolResult? value)
    {
        long now = DateTime.UtcNow.Ticks;
        if (_map.TryGetValue(key.Hash, out var e) && string.Equals(e.KeyText, key.Text, StringComparison.Ordinal))
        {
            if (Volatile.Read(ref e.ExpiresAt) > now)
            {
                Volatile.Write(ref e.LastAccess, now);
                Interlocked.Increment(ref _hits);
                value = e.Value;
                return true;
            }
            _map.TryRemove(new KeyValuePair<ulong, Entry>(key.Hash, e));
        }
        Interlocked.Increment(ref _misses);
        value = null;
        return false;
    }

    public void Set(in CacheKey key, CallToolResult value)
    {
        long now = DateTime.UtcNow.Ticks;
        var entry = new Entry
        {
            KeyText = key.Text,
            Value = value,
            ExpiresAt = now + _ttlTicks,
            LastAccess = now,
        };
        _map[key.Hash] = entry;
        if (_map.Count > _capacity) Evict(now);
    }

    public void Clear() => _map.Clear();

    private void Evict(long now)
    {
        if (Interlocked.Exchange(ref _evicting, 1) == 1) return;
        try
        {
            // Pass 1: drop expired.
            foreach (var kv in _map)
            {
                if (Volatile.Read(ref kv.Value.ExpiresAt) <= now)
                    _map.TryRemove(kv);
            }
            if (_map.Count <= _capacity) return;

            // Pass 2: drop the coldest ~12.5 % by last access.
            int toRemove = Math.Max(1, _capacity / 8) + (_map.Count - _capacity);
            var snapshot = new (long access, ulong key)[_map.Count];
            int n = 0;
            foreach (var kv in _map)
            {
                if (n >= snapshot.Length) break;
                snapshot[n++] = (Volatile.Read(ref kv.Value.LastAccess), kv.Key);
            }
            Array.Sort(snapshot, 0, n, AccessComparer.Instance);
            for (int i = 0; i < n && i < toRemove; i++)
                _map.TryRemove(snapshot[i].key, out _);
        }
        finally
        {
            Volatile.Write(ref _evicting, 0);
        }
    }

    private sealed class AccessComparer : IComparer<(long access, ulong key)>
    {
        public static readonly AccessComparer Instance = new();
        public int Compare((long access, ulong key) x, (long access, ulong key) y) => x.access.CompareTo(y.access);
    }
}

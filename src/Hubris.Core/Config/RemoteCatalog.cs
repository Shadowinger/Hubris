using System.Text.Json;
using System.Text.Json.Serialization;
using Hubris.Transport;

namespace Hubris.Config;

/// <summary>One known remote MCP server, from the bundled catalog or the public registry.</summary>
public sealed class CatalogServer
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("slug")] public string Slug { get; set; } = string.Empty;
    [JsonPropertyName("url")] public string Url { get; set; } = string.Empty;
    /// <summary>"http" or "sse".</summary>
    [JsonPropertyName("transport")] public string Transport { get; set; } = "http";
    [JsonPropertyName("category")] public string Category { get; set; } = string.Empty;
    [JsonPropertyName("description")] public string Description { get; set; } = string.Empty;
    /// <summary>"oauth" (browser sign-in through Hubris) or "none".</summary>
    [JsonPropertyName("auth")] public string Auth { get; set; } = "oauth";

    public BridgeConfig ToBridge(string? name = null) => new()
    {
        Name = name ?? Slug,
        Url = Url,
        Transport = Transport,
        Auth = Auth == "oauth" ? new BridgeAuthConfig() : null,
        Source = "catalog",
    };
}

public sealed class RemoteCatalog
{
    [JsonPropertyName("updated")] public string? Updated { get; set; }
    [JsonPropertyName("source")] public string? Source { get; set; }
    [JsonPropertyName("servers")] public List<CatalogServer> Servers { get; set; } = new();

    public static RemoteCatalog Load(Stream json) => JsonSerializer.Deserialize(json, CatalogJsonContext.Default.RemoteCatalog) ?? new RemoteCatalog();

    public static string Slug(string name)
    {
        var sb = new System.Text.StringBuilder(name.Length);
        foreach (char c in name.ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(c)) sb.Append(c);
            else if (sb.Length > 0 && sb[^1] != '-') sb.Append('-');
        }
        return sb.ToString().Trim('-') is { Length: > 0 } s ? s : "server";
    }

    public const string RegistryUrl = "https://registry.modelcontextprotocol.io/v0/servers";

    /// <summary>Live search in the public MCP registry; only entries with a remote endpoint come back, one per URL.</summary>
    public static async Task<List<CatalogServer>> SearchRegistryAsync(HttpClient http, string query, CancellationToken ct, int limit = 30)
    {
        string url = $"{RegistryUrl}?search={Uri.EscapeDataString(query)}&limit={limit}";
        await using var stream = await http.GetStreamAsync(url, ct).ConfigureAwait(false);
        var resp = await JsonSerializer.DeserializeAsync(stream, CatalogJsonContext.Default.RegistryResponse, ct).ConfigureAwait(false);
        return FromRegistry(resp);
    }

    public static List<CatalogServer> FromRegistry(RegistryResponse? resp)
    {
        var list = new List<CatalogServer>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in resp?.Servers ?? [])
        {
            var s = entry.Server;
            if (s?.Remotes is null) continue;
            foreach (var r in s.Remotes)
            {
                if (r.Url is null || !Uri.TryCreate(r.Url, UriKind.Absolute, out var u) || u.Scheme != "https" || !seen.Add(r.Url)) continue;
                string name = s.Title ?? s.Name ?? r.Url;
                list.Add(new CatalogServer
                {
                    Name = name, Slug = Slug(s.Name?.Split('/').Last() ?? name), Url = r.Url,
                    Transport = string.Equals(r.Type, "sse", StringComparison.OrdinalIgnoreCase) ? "sse" : "http",
                    Category = "registry", Description = s.Description ?? string.Empty, Auth = "oauth",
                });
            }
        }
        return list;
    }
}

// ---- registry.modelcontextprotocol.io/v0/servers (only the fields Hubris reads)
public sealed class RegistryResponse { [JsonPropertyName("servers")] public List<RegistryEntry>? Servers { get; set; } }
public sealed class RegistryEntry { [JsonPropertyName("server")] public RegistryServer? Server { get; set; } }
public sealed class RegistryServer
{
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("title")] public string? Title { get; set; }
    [JsonPropertyName("description")] public string? Description { get; set; }
    [JsonPropertyName("remotes")] public List<RegistryRemote>? Remotes { get; set; }
}
public sealed class RegistryRemote
{
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, WriteIndented = true)]
[JsonSerializable(typeof(RemoteCatalog))]
[JsonSerializable(typeof(RegistryResponse))]
public sealed partial class CatalogJsonContext : JsonSerializerContext
{
}

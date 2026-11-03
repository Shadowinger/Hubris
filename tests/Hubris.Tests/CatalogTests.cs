using System.Text;
using System.Text.Json;
using Hubris.Config;

namespace Hubris.Tests;

public class CatalogTests
{
    private static string RepoFile(string relative)
    {
        string dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "Hubris.slnx"))) dir = Path.GetDirectoryName(dir)!;
        return Path.Combine(dir!, relative);
    }

    [Fact]
    public void Bundled_catalog_is_well_formed()
    {
        using var s = File.OpenRead(RepoFile("catalog/remote-servers.json"));
        var cat = RemoteCatalog.Load(s);
        Assert.True(cat.Servers.Count >= 40, $"only {cat.Servers.Count} servers");
        Assert.Equal(cat.Servers.Count, cat.Servers.Select(x => x.Slug).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(cat.Servers.Count, cat.Servers.Select(x => x.Url).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var x in cat.Servers)
        {
            Assert.True(Uri.TryCreate(x.Url, UriKind.Absolute, out var u) && u.Scheme == "https", x.Name);
            Assert.Equal(RemoteCatalog.Slug(x.Name), x.Slug);
            Assert.Contains(x.Transport, new[] { "http", "sse" });
            Assert.Contains(x.Auth, new[] { "oauth", "none" });
            Assert.False(string.IsNullOrWhiteSpace(x.Category), x.Name);
        }
        var notion = cat.Servers.Single(x => x.Slug == "notion");
        var bridge = notion.ToBridge();
        Assert.Equal("https://mcp.notion.com/mcp", bridge.Url);
        Assert.NotNull(bridge.Auth);
        Assert.Equal("oauth", bridge.Auth.Type);
        Assert.Null(cat.Servers.Single(x => x.Slug == "deepwiki").ToBridge().Auth);
        Assert.Equal("sse", cat.Servers.Single(x => x.Slug == "salesloft").Transport);
    }

    [Theory]
    [InlineData("Atlassian MCP", "atlassian-mcp")]
    [InlineData("monday.com", "monday-com")]
    [InlineData("  Intuit QuickBooks  ", "intuit-quickbooks")]
    [InlineData("***", "server")]
    public void Slug_is_lowercase_ascii_with_single_dashes(string name, string slug) => Assert.Equal(slug, RemoteCatalog.Slug(name));

    [Fact]
    public void Registry_response_maps_remotes_and_drops_the_rest()
    {
        const string json = """
            {"servers":[
              {"server":{"name":"ai.smithery/smithery-notion","title":"Notion (Smithery)","description":"wrapper","remotes":[{"type":"streamable-http","url":"https://server.smithery.ai/@smithery/notion/mcp"}]}},
              {"server":{"name":"com.foreverworks/notion","description":"stdio only","remotes":[]}},
              {"server":{"name":"io.example/legacy","remotes":[{"type":"sse","url":"https://legacy.example.com/sse"},{"type":"sse","url":"https://legacy.example.com/sse"},{"type":"streamable-http","url":"http://insecure.example.com/mcp"}]}},
              {"server":{"name":"broken"}}
            ],"metadata":{"count":4}}
            """;
        var resp = JsonSerializer.Deserialize(Encoding.UTF8.GetBytes(json), CatalogJsonContext.Default.RegistryResponse);
        var list = RemoteCatalog.FromRegistry(resp);
        Assert.Equal(2, list.Count);
        Assert.Equal("Notion (Smithery)", list[0].Name);
        Assert.Equal("smithery-notion", list[0].Slug);
        Assert.Equal("http", list[0].Transport);
        Assert.Equal("io.example/legacy", list[1].Name);
        Assert.Equal("legacy", list[1].Slug);
        Assert.Equal("sse", list[1].Transport); // duplicate and plain-http remotes dropped
        Assert.All(list, x => Assert.Equal("oauth", x.Auth));
    }
}

using System.Text.Json.Nodes;
using Hubris.Config;

namespace Hubris.Tests;

public class ConfigTests : IDisposable
{
    private readonly string _home = Directory.CreateTempSubdirectory("hubris-home-").FullName;

    private string Write(string relative, string content)
    {
        string path = Path.Combine(_home, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Config_file_round_trips_and_keeps_a_backup()
    {
        string path = Path.Combine(_home, "cfg", "config.json");
        var cfg = new HubrisConfig();
        cfg.Bridges.Add(new BridgeConfig { Name = "fs", Command = "npx", Args = ["-y", "srv"], Env = new() { ["TOKEN"] = "x" } });
        HubrisConfigFile.Save(cfg, path);
        HubrisConfigFile.Save(cfg, path);
        Assert.True(File.Exists(path + ".bak"));
        var back = HubrisConfigFile.Load(path);
        Assert.Single(back.Bridges);
        Assert.Equal("x", back.Bridges[0].Env!["TOKEN"]);
        var spec = HubrisConfigFile.ToSpecs(back)[0];
        Assert.Equal(["-y", "srv"], spec.Args);
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        Assert.Empty(HubrisConfigFile.Load(Path.Combine(_home, "missing.json")).Bridges);
    }

    [Fact]
    public void Scanner_finds_clients_and_skips_hubris_entries()
    {
        Write(Path.GetRelativePath(_home, ClientConfigScanner.ClaudeDesktopPath(_home)), """
            {
              // JSONC is fine
              "mcpServers": {
                "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": { "GITHUB_TOKEN": "t" } },
                "hubris": { "command": "/opt/Hubris", "args": ["--stdio"] },
                "remote": { "url": "https://example.com/mcp" },
              }
            }
            """);
        Write(".claude.json", """{ "mcpServers": { "gw": { "command": "/Applications/Hubris.app/Contents/MacOS/Hubris", "args": ["--stdio"] }, "fs": { "command": "uvx", "args": ["mcp-fs"] } }, "projects": { "/x": { "mcpServers": { "p": { "command": "a" } } } }, "other": 1 }""");
        Write(Path.Combine(".cursor", "mcp.json"), """{ "mcpServers": { "only": { "command": "node", "args": ["srv.js", "--for-hubris"] } } }""");

        var clients = ClientConfigScanner.Scan(workspaceDir: null, home: _home, appData: _home);
        var desktop = Assert.Single(clients, c => c.Kind == ClientConfigScanner.ClaudeDesktop);
        Assert.Equal(["github"], desktop.Servers.Select(s => s.Name));
        Assert.True(desktop.HubrisPresent);
        Assert.False(desktop.IsGateway);
        Assert.Equal("t", desktop.Servers[0].Env["GITHUB_TOKEN"]);

        var code = Assert.Single(clients, c => c.Kind == ClientConfigScanner.ClaudeCode);
        Assert.Equal(["fs"], code.Servers.Select(s => s.Name)); // "gw" launches Hubris -> loop guard
        Assert.True(code.HubrisPresent);

        var cursor = Assert.Single(clients, c => c.Kind == ClientConfigScanner.Cursor);
        Assert.Empty(cursor.Servers); // arg mentions hubris -> guarded
        Assert.True(cursor.HubrisPresent);
    }

    [Fact]
    public void Import_merges_with_suffix_on_clash_and_hijack_restore_round_trip()
    {
        string path = Write(".claude.json", """{ "mcpServers": { "fs": { "command": "uvx", "args": ["mcp-fs"] }, "db": { "command": "npx", "args": ["db"] } }, "projects": { "/x": { "mcpServers": { "p": { "command": "a" } } } }, "keep": true }""");
        var client = ClientConfigScanner.Parse(ClientConfigScanner.ClaudeCode, path)!;

        var cfg = new HubrisConfig();
        cfg.Bridges.Add(new BridgeConfig { Name = "fs", Command = "node", Args = ["other"] });
        var result = ClientConfigHijacker.Import(client, cfg);
        Assert.Equal(["fs-2", "db"], result.Added);
        Assert.Equal(["fs", "fs-2", "db"], cfg.Bridges.Select(b => b.Name));
        var second = ClientConfigHijacker.Import(client, cfg); // idempotent
        Assert.Empty(second.Added);
        Assert.Equal(["fs", "db"], second.Skipped);
        Assert.Equal(3, cfg.Bridges.Count);

        string backup = ClientConfigHijacker.Hijack(client, "/opt/Hubris", ["--stdio", "--compact"]);
        Assert.True(File.Exists(backup));
        var root = (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;
        var servers = (JsonObject)root["mcpServers"]!;
        Assert.Equal(["hubris"], servers.Select(kv => kv.Key));
        Assert.Equal("/opt/Hubris", servers["hubris"]!["command"]!.GetValue<string>());
        Assert.NotNull(root["projects"]!["/x"]!["mcpServers"]!["p"]); // per-project block untouched
        Assert.True(root["keep"]!.GetValue<bool>());

        var after = ClientConfigScanner.Parse(ClientConfigScanner.ClaudeCode, path)!;
        Assert.True(after.IsGateway);

        Assert.Equal(backup, ClientConfigHijacker.Restore(client));
        var restored = ClientConfigScanner.Parse(ClientConfigScanner.ClaudeCode, path)!;
        Assert.Equal(["fs", "db"], restored.Servers.Select(s => s.Name));
    }

    [Fact]
    public void Vscode_hijack_uses_servers_key_and_stdio_type()
    {
        string path = Write(Path.Combine("ws", ".vscode", "mcp.json"), """{ "servers": { "a": { "type": "stdio", "command": "x" } } }""");
        var client = ClientConfigScanner.Parse(ClientConfigScanner.VsCodeWorkspace, path)!;
        ClientConfigHijacker.Hijack(client, "/opt/Hubris", ["--stdio"]);
        var root = (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;
        Assert.Equal("stdio", root["servers"]!["hubris"]!["type"]!.GetValue<string>());
        Assert.Null(root["servers"]!["a"]);
    }

    public void Dispose() { try { Directory.Delete(_home, true); } catch (IOException) { } }
}

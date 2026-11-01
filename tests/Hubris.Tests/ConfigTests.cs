using System.Text.Json.Nodes;
using Hubris.Config;

namespace Hubris.Tests;

public class ConfigTests : IDisposable
{
    private readonly string _home = Directory.CreateTempSubdirectory("hubris-home-").FullName;

    // Every snapshot/backup written by these tests must land in the temp home, never in ~/.hubris.
    public ConfigTests() => Environment.SetEnvironmentVariable("HUBRIS_HOME", _home);

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
                "hubris": { "command": "/opt/Hubris", "args": ["--stdio", "--compact", "--bridge=fs:npx", "-y", "server-fs", "/x"] },
                "remote": { "url": "https://example.com/mcp" },
              }
            }
            """);
        Write(".claude.json", """{ "mcpServers": { "gw": { "command": "/Applications/Hubris.app/Contents/MacOS/Hubris", "args": ["--stdio"] }, "fs": { "command": "uvx", "args": ["mcp-fs"] } }, "projects": { "/x": { "mcpServers": { "p": { "command": "a" } } } }, "other": 1 }""");
        Write(Path.Combine(".cursor", "mcp.json"), """{ "mcpServers": { "only": { "command": "node", "args": ["srv.js", "--for-hubris"] } } }""");

        var clients = ClientConfigScanner.Scan(workspaceDir: null, home: _home, appData: _home);
        var desktop = Assert.Single(clients, c => c.Kind == ClientConfigScanner.ClaudeDesktop);
        Assert.Equal(["github", "fs"], desktop.Servers.Select(s => s.Name)); // fs comes from hubris's own --bridge args
        Assert.Equal(["-y", "server-fs", "/x"], desktop.Servers[1].Args);
        Assert.True(desktop.HubrisPresent);
        Assert.False(desktop.IsGateway);
        Assert.Equal("t", desktop.Servers[0].Env["GITHUB_TOKEN"]);

        var code = Assert.Single(clients, c => c.Kind == ClientConfigScanner.ClaudeCode);
        Assert.Equal(["fs", "p"], code.Servers.Select(s => s.Name)); // "gw" launches Hubris -> loop guard; "p" comes from projects["/x"]
        Assert.True(code.HubrisPresent);

        var cursor = Assert.Single(clients, c => c.Kind == ClientConfigScanner.Cursor);
        Assert.Equal(["only"], cursor.Servers.Select(s => s.Name)); // "hubris" inside an argument is not the gateway
        Assert.False(cursor.HubrisPresent);
    }

    [Fact]
    public void Import_merges_with_suffix_on_clash_and_hijack_restore_round_trip()
    {
        string path = Write(".claude.json", """{ "mcpServers": { "fs": { "command": "uvx", "args": ["mcp-fs"] }, "db": { "command": "npx", "args": ["db"] } }, "projects": { "/x": { "mcpServers": { "p": { "command": "a" } } } }, "keep": true }""");
        var client = ClientConfigScanner.Parse(ClientConfigScanner.ClaudeCode, path)!;

        var cfg = new HubrisConfig();
        cfg.Bridges.Add(new BridgeConfig { Name = "fs", Command = "node", Args = ["other"] });
        var result = ClientConfigHijacker.Import(client, cfg);
        Assert.Equal(["fs-2", "db", "p"], result.Added);
        Assert.Equal(["fs", "fs-2", "db", "p"], cfg.Bridges.Select(b => b.Name));
        var second = ClientConfigHijacker.Import(client, cfg); // idempotent
        Assert.Empty(second.Added);
        Assert.Equal(["fs", "db", "p"], second.Skipped);
        Assert.Equal(4, cfg.Bridges.Count);

        string backup = ClientConfigHijacker.Hijack(client, "/opt/Hubris", ["--stdio", "--compact"]);
        Assert.True(File.Exists(backup));
        var root = (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;
        var servers = (JsonObject)root["mcpServers"]!;
        Assert.Equal(["hubris"], servers.Select(kv => kv.Key));
        Assert.Equal("/opt/Hubris", servers["hubris"]!["command"]!.GetValue<string>());
        Assert.Empty((JsonObject)root["projects"]!["/x"]!["mcpServers"]!); // full takeover: per-project block cleared
        Assert.True(root["keep"]!.GetValue<bool>());

        var after = ClientConfigScanner.Parse(ClientConfigScanner.ClaudeCode, path)!;
        Assert.True(after.IsGateway);

        Assert.EndsWith("claude_mcp_snapshot.json", ClientConfigHijacker.Restore(client)); // snapshot wins over the file backup
        var restored = ClientConfigScanner.Parse(ClientConfigScanner.ClaudeCode, path)!;
        Assert.Equal(["fs", "db", "p"], restored.Servers.Select(s => s.Name));
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

    [Fact]
    public void Deep_scan_dedupes_takes_over_projects_and_restores_surgically()
    {
        string path = Write(".claude.json", """
            {
              "mcpServers": { "fs": { "command": "uvx", "args": ["mcp-fs"] } },
              "projects": {
                "/w/alpha": { "allowedTools": ["Bash"], "mcpServers": { "fs": { "command": "uvx", "args": ["mcp-fs"] }, "db": { "command": "npx", "args": ["db"] } } },
                "/w/beta":  { "mcpServers": { "db": { "command": "npx", "args": ["db", "--other"] } } },
                "/w/empty": { "mcpServers": {} }
              },
              "numStartups": 7
            }
            """);
        var client = ClientConfigScanner.Parse(ClientConfigScanner.ClaudeCode, path)!;
        Assert.Equal(4, client.Servers.Count);
        Assert.Equal(2, client.ProjectBlocksWithServers);
        Assert.Equal(["", "/w/alpha", "/w/alpha", "/w/beta"], client.Servers.Select(s => s.Scope));

        var cfg = new HubrisConfig();
        var result = ClientConfigHijacker.Import(client, cfg);
        Assert.Equal(["fs", "db", "db-beta"], result.Added);       // same launch merged, clashing launch scoped by project folder
        Assert.Equal(["fs"], result.Skipped);
        Assert.Equal("claude-code:/w/beta", cfg.Bridges[2].Source);

        ClientConfigHijacker.Hijack(client, "/opt/Hubris", ["--stdio"]);
        var root = (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;
        Assert.Equal(["hubris"], ((JsonObject)root["mcpServers"]!).Select(kv => kv.Key));
        Assert.Empty((JsonObject)root["projects"]!["/w/alpha"]!["mcpServers"]!);
        Assert.Empty((JsonObject)root["projects"]!["/w/beta"]!["mcpServers"]!);
        Assert.Equal("Bash", root["projects"]!["/w/alpha"]!["allowedTools"]![0]!.GetValue<string>());
        Assert.Equal(7, root["numStartups"]!.GetValue<int>());
        Assert.True(File.Exists(Path.Combine(_home, "backups", "claude_mcp_snapshot.json")));
        Assert.True(ClientConfigScanner.Parse(ClientConfigScanner.ClaudeCode, path)!.IsGateway);

        // Claude Code keeps working and writes new state after the takeover; restore must keep it.
        root["projects"]!["/w/alpha"]!["history"] = new JsonArray("later");
        root["numStartups"] = 8;
        File.WriteAllText(path, root.ToJsonString());

        Assert.EndsWith("claude_mcp_snapshot.json", ClientConfigHijacker.Restore(client));
        var restored = (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;
        Assert.Equal(["fs"], ((JsonObject)restored["mcpServers"]!).Select(kv => kv.Key));
        Assert.Equal(["fs", "db"], ((JsonObject)restored["projects"]!["/w/alpha"]!["mcpServers"]!).Select(kv => kv.Key));
        Assert.Equal("--other", restored["projects"]!["/w/beta"]!["mcpServers"]!["db"]!["args"]![1]!.GetValue<string>());
        Assert.Equal("later", restored["projects"]!["/w/alpha"]!["history"]![0]!.GetValue<string>());
        Assert.Equal(8, restored["numStartups"]!.GetValue<int>());
        Assert.False(File.Exists(Path.Combine(_home, "backups", "claude_mcp_snapshot.json")));
    }

    [Fact]
    public void Import_keeps_servers_that_differ_only_by_env()
    {
        string path = Write("cfg.json", """{ "mcpServers": { "gh": { "command": "npx", "args": ["gh"], "env": { "GITHUB_TOKEN": "a" } } } }""");
        var client = ClientConfigScanner.Parse(ClientConfigScanner.Cursor, path)!;
        var cfg = new HubrisConfig();
        cfg.Bridges.Add(new BridgeConfig { Name = "gh", Command = "npx", Args = ["gh"], Env = new() { ["GITHUB_TOKEN"] = "b" } });
        var result = ClientConfigHijacker.Import(client, cfg);
        Assert.Equal(["gh-2"], result.Added);
        Assert.Equal("a", cfg.Bridges[1].Env!["GITHUB_TOKEN"]);
    }

    [Fact]
    public void Hijack_keeps_the_file_mode()
    {
        if (OperatingSystem.IsWindows()) return;
        string path = Write("desktop.json", """{ "mcpServers": { "a": { "command": "x" } } }""");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var client = ClientConfigScanner.Parse(ClientConfigScanner.ClaudeDesktop, path)!;
        ClientConfigHijacker.Hijack(client, "/opt/Hubris", ["--stdio"]);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
    }

    [Fact]
    public void Project_scan_finds_workspace_configs_and_can_empty_them()
    {
        Write(Path.Combine("dev", "alpha", ".mcp.json"), """{ "mcpServers": { "a": { "command": "npx", "args": ["a"] } } }""");
        Write(Path.Combine("dev", "beta", ".cursor", "mcp.json"), """{ "mcpServers": { "b": { "command": "node", "args": ["b.js"] } } }""");
        Write(Path.Combine("dev", "gamma", ".vscode", "mcp.json"), """{ "servers": { "c": { "type": "stdio", "command": "c" } } }""");
        Write(Path.Combine("dev", "node_modules", "pkg", ".mcp.json"), """{ "mcpServers": { "ignored": { "command": "x" } } }""");

        var found = ClientConfigScanner.ScanProjects(Path.Combine(_home, "dev"));
        Assert.Equal(["Claude Code project", "Cursor project", "VS Code workspace"], found.Select(c => c.Kind.Name).OrderBy(n => n));
        Assert.All(found, c => Assert.Single(c.Servers));

        var mcp = found.Single(c => c.Kind == ClientConfigScanner.ProjectMcp);
        ClientConfigHijacker.Hijack(mcp, "/opt/Hubris", ["--stdio"], empty: true);
        Assert.Equal("{}", JsonNode.Parse(File.ReadAllText(mcp.Path))!["mcpServers"]!.ToJsonString());
        Assert.True(ClientConfigScanner.Parse(ClientConfigScanner.ProjectMcp, mcp.Path)!.IsGateway);
        Assert.True(ClientConfigHijacker.HasRestorePoint(mcp.Path));
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("HUBRIS_HOME", null);
        try { Directory.Delete(_home, true); } catch (IOException) { }
    }
}

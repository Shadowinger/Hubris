using System.Text.Json.Nodes;
using Hubris.Config;
using Hubris.Transport;

namespace Hubris.Cli;

/// <summary>--install-vscode / --install-claude: register this binary in a client config (one writer: ClientConfigHijacker).</summary>
public static class AutoInstaller
{
    public const string ServerKey = ClientConfigHijacker.ServerKey;

    public static int InstallVsCode(string workspaceDir, string? exe, IReadOnlyList<string> serverArgs)
    {
        if (string.IsNullOrEmpty(exe)) { Log.Error("server executable path is unknown"); return 1; }
        string path = Path.Combine(workspaceDir, ".vscode", "mcp.json");
        var entry = new JsonObject { ["type"] = "stdio", ["command"] = exe, ["args"] = ToArray(serverArgs) };
        return ClientConfigHijacker.MergeServerEntry(path, "servers", ServerKey, entry) ? 0 : 1;
    }

    public static int InstallClaude(string? exe, IReadOnlyList<string> serverArgs)
    {
        if (string.IsNullOrEmpty(exe)) { Log.Error("server executable path is unknown"); return 1; }
        string? path = ClaudeConfigPath();
        if (path is null) { Log.Error("unsupported OS for Claude Desktop auto-config"); return 1; }
        var entry = new JsonObject { ["command"] = exe, ["args"] = ToArray(serverArgs) };
        return ClientConfigHijacker.MergeServerEntry(path, "mcpServers", ServerKey, entry) ? 0 : 1;
    }

    public static string? ClaudeConfigPath()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home)) home = Environment.GetEnvironmentVariable("HOME") ?? string.Empty;
        if (string.IsNullOrEmpty(home) && !OperatingSystem.IsWindows()) return null;
        return ClientConfigScanner.ClaudeDesktopPath(home);
    }

    private static JsonArray ToArray(IReadOnlyList<string> values)
    {
        var arr = new JsonArray();
        foreach (var v in values) arr.Add((JsonNode?)JsonValue.Create(v));
        return arr;
    }
}

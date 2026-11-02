using Hubris.Engine;
using Hubris.Security;

namespace Hubris.Cli;

/// <summary>
/// How to reach one external MCP server: a command to spawn (stdio), or a <paramref name="Url"/> to talk to over HTTP.
/// <paramref name="Transport"/> is "http" (Streamable HTTP, default for a url) or "sse" (the older HTTP+SSE pair).
/// </summary>
public sealed record BridgeSpec(
    string Name, string Command, IReadOnlyList<string> Args, IReadOnlyDictionary<string, string>? Env = null,
    string? Url = null, IReadOnlyDictionary<string, string>? Headers = null, string? Transport = null)
{
    public bool IsRemote => !string.IsNullOrEmpty(Url);
    public string TransportName => IsRemote ? (string.Equals(Transport, "sse", StringComparison.OrdinalIgnoreCase) ? "sse" : "http") : "stdio";

    /// <summary>What identifies the launch for the tool cache: command+args+env names, or url+transport+header names (values may rotate).</summary>
    public string ConfigHash() => IsRemote
        ? Hubris.Caching.ToolCacheStore.ComputeHash(Url!, [TransportName], Headers?.Keys ?? [])
        : Hubris.Caching.ToolCacheStore.ComputeHash(Command, Args, Env?.Keys ?? []);
}

public sealed class CliOptions
{
    public bool Stdio { get; private set; } = true;
    public ExecutionMode Mode { get; private set; } = ExecutionMode.Safe;
    public bool Compact { get; private set; }
    public bool Verbose { get; private set; }
    public bool InstallVsCode { get; private set; }
    public bool InstallClaude { get; private set; }
    public bool ShowHelp { get; private set; }
    public bool ShowVersion { get; private set; }
    public bool NoControl { get; private set; }
    public bool NoCache { get; private set; }
    public double CacheTtlHours { get; private set; } = 24;
    public double ApprovalTimeoutSec { get; private set; } = 120;
    public List<BridgeSpec> Bridges { get; } = new();

    /// <summary>Arguments to persist in client configs so the installed server matches the current flags.</summary>
    public IReadOnlyList<string> ServerArgs()
    {
        var list = new List<string> { "--stdio" };
        if (Mode == ExecutionMode.Bypass) list.Add("--mode=bypass");
        if (Compact) list.Add("--compact");
        if (Verbose) list.Add("--verbose");
        if (NoControl) list.Add("--no-control");
        if (NoCache) list.Add("--no-cache");
        if (CacheTtlHours != 24) list.Add($"--cache-ttl={CacheTtlHours.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
        if (ApprovalTimeoutSec != 120) list.Add($"--approval-timeout={ApprovalTimeoutSec.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
        foreach (var b in Bridges)
        {
            if (b.IsRemote)
            {
                list.Add($"--bridge={b.Name}:{(b.TransportName == "sse" ? "sse:" : string.Empty)}{b.Url}");
                if (b.Headers is not null) foreach (var h in b.Headers) list.Add($"{h.Key}: {h.Value}");
            }
            else
            {
                list.Add($"--bridge={b.Name}:{b.Command}");
                list.AddRange(b.Args);
            }
        }
        return list;
    }

    public static bool TryParse(string[] args, out CliOptions options, out string? error)
    {
        options = new CliOptions();
        error = null;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "--stdio": options.Stdio = true; continue;
                case "--compact": options.Compact = true; continue;
                case "--verbose" or "-v": options.Verbose = true; continue;
                case "--install-vscode": options.InstallVsCode = true; continue;
                case "--install-claude": options.InstallClaude = true; continue;
                case "--no-control": options.NoControl = true; continue;
                case "--no-cache": options.NoCache = true; continue;
                case "--help" or "-h": options.ShowHelp = true; continue;
                case "--version": options.ShowVersion = true; continue;
            }

            if (a.StartsWith("--mode=", StringComparison.Ordinal))
            {
                if (!ModeNames.TryParseMode(a[7..], out var mode)) { error = $"invalid --mode value '{a[7..]}' (expected safe|bypass)"; return false; }
                options.Mode = mode;
                continue;
            }
            if (a == "--mode")
            {
                if (i + 1 >= args.Length || !ModeNames.TryParseMode(args[i + 1], out var mode)) { error = "--mode requires safe|bypass"; return false; }
                options.Mode = mode; i++;
                continue;
            }

            if (a.StartsWith("--cache-ttl=", StringComparison.Ordinal))
            {
                if (!double.TryParse(a[12..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var hours) || hours <= 0 || hours > 24 * 365)
                { error = "--cache-ttl must be hours in (0, 8760]"; return false; }
                options.CacheTtlHours = hours;
                continue;
            }

            if (a.StartsWith("--approval-timeout=", StringComparison.Ordinal))
            {
                if (!double.TryParse(a[19..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var secs) || secs < 1 || secs > 3600)
                { error = "--approval-timeout must be 1..3600 seconds"; return false; }
                options.ApprovalTimeoutSec = secs;
                continue;
            }

            if (a.StartsWith("--bridge=", StringComparison.Ordinal) || a == "--bridge")
            {
                string spec;
                if (a == "--bridge")
                {
                    if (i + 1 >= args.Length) { error = "--bridge requires <name>:<command>"; return false; }
                    spec = args[++i];
                }
                else spec = a[9..];

                int colon = spec.IndexOf(':');
                if (colon <= 0 || colon == spec.Length - 1) { error = $"invalid --bridge spec '{spec}' (expected <name>:<command>)"; return false; }
                string name = spec[..colon];
                string command = spec[(colon + 1)..];
                foreach (char c in name)
                    if (!char.IsLetterOrDigit(c) && c != '-' && c != '_') { error = $"bridge name '{name}' may contain only letters, digits, '-' and '_'"; return false; }

                // Child servers take their own --flags; only Hubris's options end the bridge's argument list.
                var bridgeArgs = new List<string>();
                while (i + 1 < args.Length && !IsOwnOption(args[i + 1]))
                    bridgeArgs.Add(args[++i]);

                // --bridge=api:https://host/mcp  or  --bridge=api:sse:https://host/sse, followed by "Header: value" pairs
                string? transport = null;
                string target = command;
                if (target.StartsWith("sse:", StringComparison.OrdinalIgnoreCase)) { transport = "sse"; target = target[4..]; }
                if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    if (!Uri.TryCreate(target, UriKind.Absolute, out _)) { error = $"invalid bridge url '{target}'"; return false; }
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var h in bridgeArgs)
                    {
                        int sep = h.IndexOf(':');
                        if (sep <= 0) { error = $"remote bridge '{name}': expected 'Header: value', got '{h}'"; return false; }
                        headers[h[..sep].Trim()] = h[(sep + 1)..].Trim();
                    }
                    options.Bridges.Add(new BridgeSpec(name, string.Empty, [], null, target, headers.Count == 0 ? null : headers, transport ?? "http"));
                    continue;
                }
                options.Bridges.Add(new BridgeSpec(name, command, bridgeArgs));
                continue;
            }

            error = $"unknown option '{a}'";
            return false;
        }
        return true;
    }

    private static readonly string[] OwnOptions =
    [
        "--stdio", "--compact", "--verbose", "-v", "--install-vscode", "--install-claude", "--help", "-h",
        "--version", "--no-control", "--no-cache", "--cache-ttl", "--mode", "--bridge", "--approval-timeout",
    ];

    public static bool IsOwnOption(string arg)
    {
        foreach (var o in OwnOptions)
            if (arg == o || arg.StartsWith(o + "=", StringComparison.Ordinal)) return true;
        return false;
    }

    public static void PrintUsage()
    {
        Console.Error.WriteLine(
            "Hubris " + HubRuntime.Version + " – Native AOT MCP multiplexer & security gateway\n" +
            "\n" +
            "usage: Hubris [--stdio] [--mode=safe|bypass] [--compact] [--verbose]\n" +
            "              [--bridge=<name>:<command> [arg ...]]...\n" +
            "       Hubris --install-vscode [server flags]\n" +
            "       Hubris --install-claude [server flags]\n" +
            "\n" +
            "  --stdio            serve MCP over stdin/stdout (default)\n" +
            "  --mode=safe        block destructive tools and dangerous arguments (default)\n" +
            "  --mode=bypass      execute every tool call without policy checks\n" +
            "  --compact          list only core tools; others are discoverable via mcp_search_tools\n" +
            "  --bridge=n:cmd     spawn an external stdio MCP server; its tools appear as n__<tool>\n" +
            "  --bridge=n:URL     remote MCP server over Streamable HTTP (sse:URL for HTTP+SSE); 'Header: value' args follow\n" +
            "  --verbose          debug logging on stderr\n" +
            "  --no-control       do not open the local control socket (no desktop UI, no approvals)\n" +
            "  --no-cache         always spawn bridges at startup instead of using the SQLite tool cache\n" +
            "  --cache-ttl=H      hours a cached bridge tool list stays valid (default 24)\n" +
            "  --approval-timeout=S  seconds a blocked call waits for Approve/Deny in the UI (default 120)\n" +
            "  --install-vscode   write .vscode/mcp.json in the current directory\n" +
            "  --install-claude   register in Claude Desktop's claude_desktop_config.json\n" +
            "  --version, --help\n");
    }
}

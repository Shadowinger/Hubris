using Hubris.Engine;
using Hubris.Security;

namespace Hubris.Cli;

public sealed record BridgeSpec(string Name, string Command, IReadOnlyList<string> Args);

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
        if (ApprovalTimeoutSec != 120) list.Add($"--approval-timeout={ApprovalTimeoutSec.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
        foreach (var b in Bridges)
        {
            list.Add($"--bridge={b.Name}:{b.Command}");
            list.AddRange(b.Args);
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
        "--version", "--no-control", "--mode", "--bridge", "--approval-timeout",
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
            "  --verbose          debug logging on stderr\n" +
            "  --no-control       do not open the local control socket (no desktop UI, no approvals)\n" +
            "  --approval-timeout=S  seconds a blocked call waits for Approve/Deny in the UI (default 120)\n" +
            "  --install-vscode   write .vscode/mcp.json in the current directory\n" +
            "  --install-claude   register in Claude Desktop's claude_desktop_config.json\n" +
            "  --version, --help\n");
    }
}

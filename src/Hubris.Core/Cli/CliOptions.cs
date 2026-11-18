using Hubris.Engine;
using Hubris.Security;

namespace Hubris.Cli;

/// <summary>
/// How to reach one external MCP server: a command to spawn (stdio), or a <paramref name="Url"/> to talk to over HTTP.
/// <paramref name="Transport"/> is "http" (Streamable HTTP, default for a url) or "sse" (the older HTTP+SSE pair).
/// </summary>
/// <summary>OAuth login for a bridge. <paramref name="Env"/> names the variable a stdio child receives the token in.</summary>
public sealed record OAuthSpec(string? Provider = null, string? Issuer = null, string? ClientId = null, string? ClientSecret = null, string? Scope = null, string? Env = null);

public sealed record BridgeSpec(
    string Name, string Command, IReadOnlyList<string> Args, IReadOnlyDictionary<string, string>? Env = null,
    string? Url = null, IReadOnlyDictionary<string, string>? Headers = null, string? Transport = null, OAuthSpec? Auth = null)
{
    public const string NameRule = "letters, digits, '-' and '_' only, and no double underscore (it separates the bridge from the tool)";

    /// <summary>The name becomes the prefix of every tool and prompt ("name__tool"), so it must be a clean identifier.</summary>
    public static bool IsValidName(string name)
        => name.Length > 0 && !name.Contains("__", StringComparison.Ordinal) && name.All(c => char.IsLetterOrDigit(c) || c is '-' or '_');

    public bool IsRemote => !string.IsNullOrEmpty(Url);
    public string TransportName => IsRemote ? (string.Equals(Transport, "sse", StringComparison.OrdinalIgnoreCase) ? "sse" : "http") : "stdio";

    /// <summary>What identifies the launch for the tool cache: command+args+env names, or url+transport+header names (values may rotate).</summary>
    public string ConfigHash() => IsRemote
        ? Hubris.Caching.ToolCacheStore.ComputeHash(Url!, [TransportName], Headers?.Keys ?? [])
        : Hubris.Caching.ToolCacheStore.ComputeHash(Command, Args, Env?.Keys ?? []);
}

/// <summary>One line of text for a list of arguments, as the desktop app shows and edits them.</summary>
public static class ArgLine
{
    /// <summary>Plain when it can be; otherwise in double quotes with \ and " escaped, so <see cref="Split"/> gives back exactly this argument.</summary>
    public static string Quote(string s)
    {
        if (s.Length > 0 && !s.Any(c => char.IsWhiteSpace(c) || c is '"' or '\'')) return s;
        return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    /// <summary>Shell-ish split: whitespace separates, double or single quotes group, and inside quotes \ escapes a backslash or the quote.</summary>
    public static List<string> Split(string text)
    {
        var result = new List<string>();
        var cur = new System.Text.StringBuilder();
        char quote = '\0';
        bool any = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (quote != '\0')
            {
                if (c == '\\' && i + 1 < text.Length && (text[i + 1] == quote || text[i + 1] == '\\')) { cur.Append(text[++i]); continue; }
                if (c == quote) quote = '\0'; else cur.Append(c);
                continue;
            }
            if (c is '"' or '\'') { quote = c; any = true; continue; }
            if (char.IsWhiteSpace(c)) { if (any || cur.Length > 0) { result.Add(cur.ToString()); cur.Clear(); any = false; } continue; }
            cur.Append(c);
        }
        if (any || cur.Length > 0) result.Add(cur.ToString());
        return result;
    }
}

public sealed class CliOptions
{
    public ExecutionMode Mode { get; private set; } = ExecutionMode.Safe;
    public bool Compact { get; private set; }
    public bool Verbose { get; private set; }
    public bool InstallVsCode { get; private set; }
    public bool InstallClaude { get; private set; }
    public bool ShowHelp { get; private set; }
    public bool ShowVersion { get; private set; }
    public bool NoControl { get; private set; }
    /// <summary>Accept privileged control commands from any local process, not only the desktop app (tests, scripts).</summary>
    public bool ControlTrustAll { get; private set; }
    public bool NoCache { get; private set; }
    public double CacheTtlHours { get; private set; } = 24;
    public double ApprovalTimeoutSec { get; private set; } = 120;
    /// <summary>Seconds an unlocked tool may sit unused before it is hidden again; 0 keeps everything unlocked.</summary>
    public double AutoLockSec { get; private set; } = 600;
    public List<BridgeSpec> Bridges { get; } = new();

    /// <summary>Arguments to persist in client configs so the installed server matches the current flags.</summary>
    public IReadOnlyList<string> ServerArgs()
    {
        var list = new List<string> { "--stdio" };
        if (Mode != ExecutionMode.Safe) list.Add("--mode=" + ModeNames.ToText(Mode).ToLowerInvariant());
        if (Compact) list.Add("--compact");
        if (Verbose) list.Add("--verbose");
        if (NoControl) list.Add("--no-control");
        if (ControlTrustAll) list.Add("--control-trust-all");
        if (NoCache) list.Add("--no-cache");
        if (CacheTtlHours != 24) list.Add($"--cache-ttl={CacheTtlHours.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
        if (ApprovalTimeoutSec != 120) list.Add($"--approval-timeout={ApprovalTimeoutSec.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
        if (AutoLockSec != 600) list.Add($"--auto-lock={AutoLockSec.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
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
                case "--stdio": continue; // the only transport; accepted because client configs carry it
                case "--compact": options.Compact = true; continue;
                case "--verbose" or "-v": options.Verbose = true; continue;
                case "--install-vscode": options.InstallVsCode = true; continue;
                case "--install-claude": options.InstallClaude = true; continue;
                case "--no-control": options.NoControl = true; continue;
                case "--control-trust-all": options.ControlTrustAll = true; continue;
                case "--no-cache": options.NoCache = true; continue;
                case "--help" or "-h": options.ShowHelp = true; continue;
                case "--version": options.ShowVersion = true; continue;
            }

            if (a.StartsWith("--mode=", StringComparison.Ordinal))
            {
                if (!ModeNames.TryParseMode(a[7..], out var mode)) { error = $"invalid --mode value '{a[7..]}' (expected safe|auto|bypass)"; return false; }
                options.Mode = mode;
                continue;
            }
            if (a == "--mode")
            {
                if (i + 1 >= args.Length || !ModeNames.TryParseMode(args[i + 1], out var mode)) { error = "--mode requires safe|auto|bypass"; return false; }
                options.Mode = mode; i++;
                continue;
            }

            if (a.StartsWith("--cache-ttl=", StringComparison.Ordinal))
            {
                if (!double.TryParse(a[12..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var hours) || !double.IsFinite(hours) || hours <= 0 || hours > 24 * 365)
                { error = "--cache-ttl must be hours in (0, 8760]"; return false; }
                options.CacheTtlHours = hours;
                continue;
            }

            if (a.StartsWith("--auto-lock=", StringComparison.Ordinal))
            {
                if (!double.TryParse(a[12..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var secs) || !double.IsFinite(secs) || secs < 0 || secs > 86400)
                { error = "--auto-lock must be 0 (off) or 1..86400 seconds"; return false; }
                options.AutoLockSec = secs;
                continue;
            }

            if (a.StartsWith("--approval-timeout=", StringComparison.Ordinal))
            {
                if (!double.TryParse(a[19..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var secs) || !double.IsFinite(secs) || secs < 1 || secs > 3600)
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

                // Child servers take their own --flags; only Hubris's options end the bridge's argument list.
                var bridgeArgs = new List<string>();
                while (i + 1 < args.Length && !IsOwnOption(args[i + 1]))
                    bridgeArgs.Add(args[++i]);

                if (!TryParseBridge(spec, bridgeArgs, out var bridge, out error)) return false;
                options.Bridges.Add(bridge!);
                continue;
            }

            error = $"unknown option '{a}'";
            return false;
        }
        return true;
    }

    /// <summary>
    /// "name:command" with the child's arguments, or "name:https://host/mcp" ("name:sse:https://…" for HTTP+SSE) with
    /// "Header: value" pairs. Shared by --bridge and the bridge add command.
    /// </summary>
    public static bool TryParseBridge(string spec, IReadOnlyList<string> bridgeArgs, out BridgeSpec? bridge, out string? error)
    {
        bridge = null;
        error = null;
        int colon = spec.IndexOf(':');
        if (colon <= 0 || colon == spec.Length - 1) { error = $"invalid --bridge spec '{spec}' (expected <name>:<command>)"; return false; }
        string name = spec[..colon];
        string command = spec[(colon + 1)..];
        if (!BridgeSpec.IsValidName(name)) { error = $"bridge name '{name}': {BridgeSpec.NameRule}"; return false; }

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
            bridge = new BridgeSpec(name, string.Empty, [], null, target, headers.Count == 0 ? null : headers, transport ?? "http");
            return true;
        }
        bridge = new BridgeSpec(name, command, bridgeArgs);
        return true;
    }

    private static readonly string[] OwnOptions =
    [
        "--stdio", "--compact", "--verbose", "-v", "--install-vscode", "--install-claude", "--help", "-h",
        "--version", "--no-control", "--control-trust-all", "--no-cache", "--cache-ttl", "--mode", "--bridge", "--approval-timeout", "--auto-lock",
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
            "usage: Hubris [--stdio] [--mode=safe|auto|bypass] [--compact] [--verbose]\n" +
            "              [--bridge=<name>:<command> [arg ...]]...\n" +
            "       Hubris --install-vscode [server flags]\n" +
            "       Hubris --install-claude [server flags]\n" +
            "       Hubris status | tools [text] | watch | mode <safe|auto|bypass> | approve <id> | deny <id>   [--pid=N]\n" +
            "       Hubris bridge list | add <name> <command|url> [arg ...] | remove <name>\n" +
            "\n" +
            "  --stdio            serve MCP over stdin/stdout (default)\n" +
            "  --mode=safe        block destructive tools and dangerous arguments (default)\n" +
            "  --mode=auto        run without asking; block only dangerous calls and tell the model why\n" +
            "  --mode=bypass      execute every tool call without policy checks\n" +
            "  --compact          list only core tools; others are discoverable via mcp_search_tools\n" +
            "  --bridge=n:cmd     spawn an external stdio MCP server; its tools appear as n__<tool>\n" +
            "  --bridge=n:URL     remote MCP server over Streamable HTTP (sse:URL for HTTP+SSE); 'Header: value' args follow\n" +
            "  --verbose          debug logging on stderr\n" +
            "  --no-control       do not open the local control socket (no desktop UI, no approvals)\n" +
            "  --control-trust-all  accept mode/approval commands from any local process, not only the desktop app\n" +
            "  --no-cache         always spawn bridges at startup instead of using the SQLite tool cache\n" +
            "  --cache-ttl=H      hours a cached bridge tool list stays valid (default 24)\n" +
            "  --approval-timeout=S  seconds a blocked call waits for Approve/Deny in the UI (default 120)\n" +
            "  --auto-lock=S      hide an unlocked tool again after S seconds without a call (default 600, 0 = never)\n" +
            "  --install-vscode   write .vscode/mcp.json in the current directory\n" +
            "  --install-claude   register in Claude Desktop's claude_desktop_config.json\n" +
            "  --version, --help\n" +
            "\n" +
            "commands (they talk to the hubs that are running, or edit ~/.hubris/config.json):\n" +
            "  status             every running hub: client, mode, context cost, blocked calls, bridges, sign-ins, waiting approvals\n" +
            "  tools [text]       the tools of a hub and what each costs in tokens; text filters by name\n" +
            "  watch              calls, approval requests and mode changes as they happen, until Ctrl+C\n" +
            "  mode <m>           switch the mode of the running hubs\n" +
            "  approve|deny <id>  decide a waiting call; the id is in status and watch\n" +
            "  bridge list|add|remove   the servers in config.json; a hub reads them when it starts\n" +
            "  --pid=N            one hub instead of all of them\n" +
            "  mode, approve and deny are refused unless the hub runs with --control-trust-all: a shell tool the model drives\n" +
            "  can run this binary too, so by default only the desktop app may change what a hub does.\n");
    }
}

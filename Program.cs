using System.Diagnostics;
using System.Runtime.InteropServices;
using Hubris.Caching;
using Hubris.Cli;
using Hubris.Engine;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Tools;
using Hubris.Transport;

var uptime = Stopwatch.StartNew();

AppDomain.CurrentDomain.UnhandledException += static (_, e) => Log.Error($"unhandled: {e.ExceptionObject}");
TaskScheduler.UnobservedTaskException += static (_, e) => { Log.Error($"unobserved: {e.Exception.Message}"); e.SetObserved(); };

if (!CliOptions.TryParse(args, out var opts, out string? parseError))
{
    Log.Error(parseError ?? "invalid arguments");
    CliOptions.PrintUsage();
    return 2;
}

if (opts.ShowHelp) { CliOptions.PrintUsage(); return 0; }
if (opts.ShowVersion) { Console.Error.WriteLine($"Hubris {HubRuntime.Version}"); return 0; }
Log.Verbose = opts.Verbose;

if (opts.InstallVsCode) return AutoInstaller.InstallVsCode(Environment.CurrentDirectory, opts.ServerArgs());
if (opts.InstallClaude) return AutoInstaller.InstallClaude(opts.ServerArgs());

// ---------------------------------------------------------------- server mode

using var shutdown = new CancellationTokenSource();
void RequestShutdown(string why)
{
    if (!shutdown.IsCancellationRequested)
    {
        Log.Info($"shutdown requested ({why})");
        shutdown.Cancel();
    }
}

using var sigTerm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; RequestShutdown("SIGTERM"); });
using var sigInt = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; RequestShutdown("SIGINT"); });
using var sigHup = OperatingSystem.IsWindows() ? null : PosixSignalRegistration.Create(PosixSignal.SIGHUP, ctx => { ctx.Cancel = true; RequestShutdown("SIGHUP"); });
// Ctrl+C arrives as SIGINT and is covered above; Console.CancelKeyPress is deliberately not used because
// subscribing to it initialises the terminal layer (terminfo) which costs startup time and is meaningless on a pipe.

var cache = new FastLruCache(capacity: 256, ttl: TimeSpan.FromSeconds(60));
var security = new SecurityInterceptor(opts.Mode);
var registry = new ToolRegistry(opts.Compact);
var runtime = new HubRuntime
{
    Uptime = uptime,
    Mode = opts.Mode,
    CompactContext = opts.Compact,
    Cache = cache,
    Security = security,
    Registry = registry,
};

registry.Register(new HubStatusTool(runtime));
registry.Register(new SearchToolsMetaTool(registry));
registry.Register(new GitSmartStatusTool(pinned: !opts.Compact));
registry.Register(new FsReadHeadTool(pinned: !opts.Compact));

var bridges = new List<ExternalMcpBridge>(opts.Bridges.Count);
foreach (var spec in opts.Bridges)
{
    var bridge = new ExternalMcpBridge(spec.Name, spec.Command, spec.Args);
    try
    {
        var tools = await bridge.StartAsync(shutdown.Token);
        foreach (var def in tools) registry.Register(new BridgedTool(bridge, def));
        bridges.Add(bridge);
        Log.Info($"bridge '{spec.Name}' exposes {tools.Count} tool(s)" + (bridge.ServerInfo is { } si ? $" ({si.Name} {si.Version})" : string.Empty));
    }
    catch (Exception ex)
    {
        Log.Warn($"bridge '{spec.Name}' failed to start: {ex.Message}");
        await bridge.DisposeAsync();
    }
}
runtime.BridgeCount = bridges.Count;

await using var transport = new StdioTransport();
var router = new McpRouter(transport, registry, security, cache, runtime, bridges);

Log.Info($"ready mode={ModeNames.ToText(opts.Mode)} compact={(opts.Compact ? "on" : "off")} tools={registry.Count} bridges={bridges.Count} startup={uptime.Elapsed.TotalMilliseconds:0.0}ms");

try
{
    await transport.RunReadLoopAsync(router.HandleAsync, shutdown.Token);
}
catch (Exception ex)
{
    Log.Error($"transport loop failed: {ex.Message}");
}

if (!shutdown.IsCancellationRequested)
{
    // Client closed stdin: finish what is already running, stdout is still open for the answers.
    Log.Debug("stdin closed; draining in-flight requests");
    await router.DrainAsync(TimeSpan.FromSeconds(30));
}
RequestShutdown("stdin closed");
await router.ShutdownAsync();
foreach (var b in bridges) await b.DisposeAsync();
Log.Info("bye");
return 0;

// ==================================================================== CLI

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
    public List<BridgeSpec> Bridges { get; } = new();

    /// <summary>Arguments to persist in client configs so the installed server matches the current flags.</summary>
    public IReadOnlyList<string> ServerArgs()
    {
        var list = new List<string> { "--stdio" };
        if (Mode == ExecutionMode.Bypass) list.Add("--mode=bypass");
        if (Compact) list.Add("--compact");
        if (Verbose) list.Add("--verbose");
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

                var bridgeArgs = new List<string>();
                while (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    bridgeArgs.Add(args[++i]);
                options.Bridges.Add(new BridgeSpec(name, command, bridgeArgs));
                continue;
            }

            error = $"unknown option '{a}'";
            return false;
        }
        return true;
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
            "  --install-vscode   write .vscode/mcp.json in the current directory\n" +
            "  --install-claude   register in Claude Desktop's claude_desktop_config.json\n" +
            "  --version, --help\n");
    }
}

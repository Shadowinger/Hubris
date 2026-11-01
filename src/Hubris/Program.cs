using System.Diagnostics;
using System.Runtime.InteropServices;
using Hubris.Caching;
using Hubris.Cli;
using Hubris.Config;
using Hubris.Control;
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

if (opts.InstallVsCode) return AutoInstaller.InstallVsCode(Environment.CurrentDirectory, Environment.ProcessPath, opts.ServerArgs());
if (opts.InstallClaude) return AutoInstaller.InstallClaude(Environment.ProcessPath, opts.ServerArgs());

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

ToolCacheStore? toolCache = null;
if (!opts.NoCache)
{
    try
    {
        toolCache = new ToolCacheStore(HubrisPaths.CacheDbPath, TimeSpan.FromHours(opts.CacheTtlHours));
        toolCache.Open();
        toolCache.MaintainIfDue(TimeSpan.FromDays(7));
    }
    catch (Exception ex)
    {
        Log.Warn($"tool cache disabled: {ex.Message}");
        toolCache?.Dispose();
        toolCache = null;
    }
}
var security = new SecurityInterceptor(opts.Mode);
var registry = new ToolRegistry(opts.Compact);
var runtime = new HubRuntime
{
    Uptime = uptime,
    CompactContext = opts.Compact,
    ToolCache = toolCache,
    Security = security,
    Registry = registry,
};

registry.Register(new HubStatusTool(runtime));
registry.Register(new SearchToolsMetaTool(registry));
registry.Register(new ExecuteToolMetaTool(registry));
registry.Register(new GitSmartStatusTool(pinned: !opts.Compact));
registry.Register(new FsReadHeadTool(pinned: !opts.Compact));

// Bridges come from ~/.hubris/config.json; a --bridge on the command line adds to or overrides them by name.
var bridgeSpecs = new List<BridgeSpec>();
try { bridgeSpecs.AddRange(HubrisConfigFile.ToSpecs(HubrisConfigFile.Load())); }
catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException) { Log.Warn($"config {HubrisPaths.ConfigPath} ignored: {ex.Message}"); }
foreach (var cli in opts.Bridges)
{
    bridgeSpecs.RemoveAll(b => b.Name == cli.Name);
    bridgeSpecs.Add(cli);
}

var bridges = runtime.Bridges;
foreach (var spec in bridgeSpecs)
{
    var bridge = new ExternalMcpBridge(spec.Name, spec.Command, spec.Args, env: spec.Env);
    string hash = ToolCacheStore.ComputeHash(spec.Command, spec.Args, spec.Env?.Keys ?? []);

    // Cache hit: tools are listed from SQLite and the child is spawned only when one of them is called.
    var cachedTools = toolCache?.TryGet(spec.Name, hash);
    if (cachedTools is not null)
    {
        foreach (var def in cachedTools) registry.Register(new BridgedTool(bridge, def));
        bridges.Add(bridge);
        Log.Info($"bridge '{spec.Name}' exposes {cachedTools.Count} tool(s) from cache; process not started");
        continue;
    }

    try
    {
        var tools = await bridge.StartAsync(shutdown.Token);
        foreach (var def in tools) registry.Register(new BridgedTool(bridge, def));
        bridges.Add(bridge);
        Log.Info($"bridge '{spec.Name}' exposes {tools.Count} tool(s)" + (bridge.ServerInfo is { } si ? $" ({si.Name} {si.Version})" : string.Empty));
        if (toolCache is not null)
        {
            int tokens = 0;
            foreach (var def in tools) tokens += ToolRegistry.EstimateTokens(new BridgedTool(bridge, def));
            toolCache.Put(spec.Name, hash, tools, tokens);
        }
    }
    catch (Exception ex)
    {
        Log.Warn($"bridge '{spec.Name}' failed to start: {ex.Message}");
        await bridge.DisposeAsync();
    }
}

ControlHub? control = null;
if (!opts.NoControl)
{
    control = new ControlHub(runtime, registry, security, TimeSpan.FromSeconds(opts.ApprovalTimeoutSec));
    control.RequestShutdown = () => RequestShutdown("control channel");
    try
    {
        control.Start();
        runtime.Control = control;
    }
    catch (Exception ex)
    {
        Log.Warn($"control channel disabled: {ex.Message}");
        await control.DisposeAsync();
        control = null;
    }
}

var transport = new StdioTransport();
var router = new McpRouter(transport, registry, security, runtime, bridges, control);

Log.Info($"ready mode={ModeNames.ToText(opts.Mode)} compact={(opts.Compact ? "on" : "off")} tools={registry.Count} bridges={bridges.Count} startup={uptime.Elapsed.TotalMilliseconds:0.0}ms");

// A blocking console read cannot be cancelled on Unix, so a signal or a control-channel shutdown
// must not wait for the read loop: race it against the shutdown token instead.
var readLoop = Task.Run(async () =>
{
    try { await transport.RunReadLoopAsync(router.HandleAsync, shutdown.Token); }
    catch (Exception ex) { Log.Error($"transport loop failed: {ex.Message}"); }
});
var shutdownSignalled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
using var shutdownReg = shutdown.Token.Register(() => shutdownSignalled.TrySetResult());
await Task.WhenAny(readLoop, shutdownSignalled.Task);

bool stdinClosed = readLoop.IsCompleted;
if (stdinClosed && !shutdown.IsCancellationRequested)
{
    // Client closed stdin: finish what is already running, stdout is still open for the answers.
    Log.Debug("stdin closed; draining in-flight requests");
    await router.DrainAsync(TimeSpan.FromSeconds(30));
}
RequestShutdown(stdinClosed ? "stdin closed" : "signal");
await router.ShutdownAsync();
if (control is not null) await control.DisposeAsync();
foreach (var b in bridges) await b.DisposeAsync();
toolCache?.Dispose();
if (stdinClosed) await transport.DisposeAsync();
else Log.Debug("stdin read still pending; exiting without draining it");
Log.Info("bye");
return 0;

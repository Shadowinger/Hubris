using System.Diagnostics;
using System.Runtime.InteropServices;
using Hubris.Caching;
using System.Text.Json.Nodes;
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

if (opts.InstallVsCode || opts.InstallClaude)
{
    if (Environment.ProcessPath is not { } exe) { Log.Error("server executable path is unknown"); return 1; }
    var argNodes = new JsonArray();
    foreach (var a in opts.ServerArgs()) argNodes.Add((JsonNode?)JsonValue.Create(a));
    bool ok = opts.InstallVsCode
        ? ClientConfigHijacker.MergeServerEntry(Path.Combine(Environment.CurrentDirectory, ".vscode", "mcp.json"), "servers", ClientConfigHijacker.ServerKey, new JsonObject { ["type"] = "stdio", ["command"] = exe, ["args"] = argNodes })
        : ClientConfigHijacker.MergeServerEntry(ClientConfigScanner.ClaudeDesktopPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)), "mcpServers", ClientConfigHijacker.ServerKey, new JsonObject { ["command"] = exe, ["args"] = argNodes });
    return ok ? 0 : 1;
}

// ---------------------------------------------------------------- server mode

if (Environment.GetEnvironmentVariable("HUBRIS_PARENT") is { Length: > 0 } parent)
{
    // A bridge entry points back at the gateway (a wrapper script around Hubris, say): every level would spawn the next.
    Log.Error($"refusing to start: launched by another Hubris (pid {parent}); a bridge in config.json points at the gateway itself");
    return 3;
}

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
    Auth = new Hubris.Auth.OAuthManager(Hubris.Auth.SecureTokenStores.ForThisOs()),
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
var bridgeHost = new BridgeHost(runtime, registry);
// All at once: a client gives the hub ~30 s to answer initialize, and one cold npx bridge can eat that alone.
await Task.WhenAll(bridgeSpecs.Select(spec => bridgeHost.AddAsync(spec, shutdown.Token)));
toolCache?.MaintainIfDue(TimeSpan.FromDays(7)); // after the bridges: never on the startup path, never fatal

ControlHub? control = null;
if (!opts.NoControl)
{
    control = new ControlHub(runtime, registry, security, TimeSpan.FromSeconds(opts.ApprovalTimeoutSec));
    control.RequestShutdown = () => RequestShutdown("control channel");
    control.TrustAllClients = opts.ControlTrustAll;
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

runtime.Auth.StartKeepWarm(shutdown.Token); // idle hubs still refresh before expiry, so sliding refresh-token windows keep sliding

var transport = new StdioTransport();
var router = new McpRouter(transport, registry, security, runtime, bridges, control);
router.StartAutoLock(TimeSpan.FromSeconds(opts.AutoLockSec));

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
await Task.WhenAll(bridges.Select(b => b.DisposeAsync().AsTask()));
toolCache?.Dispose();
if (stdinClosed) await transport.DisposeAsync();
else Log.Debug("stdin read still pending; exiting without draining it");
Log.Info("bye");
return 0;

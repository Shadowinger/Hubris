using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Cli;
using Hubris.Protocol;
using Hubris.Transport;

namespace Hubris.Engine;

/// <summary>
/// Hosts an external MCP server as a child process over stdio, correlates requests/responses by id,
/// and guarantees the child is reaped on dispose.
/// </summary>
public sealed class ExternalMcpBridge : McpBridge
{
    private readonly string _command;
    private readonly IReadOnlyList<string> _args;
    private readonly string? _cwd;
    private readonly ConcurrentDictionary<RpcId, TaskCompletionSource<JsonNode?>> _pending = new();
    private readonly CancellationTokenSource _lifetime = new();

    private Process? _process;
    private JsonLineWriter? _stdin;
    private PipeReader? _stdout;
    private Task? _readLoop;
    private Task? _errLoop;
    private long _nextId;
    private int _disposed;

    private readonly SemaphoreSlim _startLock = new(1, 1);

    public ExternalMcpBridge(BridgeSpec spec, string? cwd = null) : base(spec)
    {
        _command = spec.Command;
        _args = spec.Args;
        _cwd = cwd;
        Env = spec.Env ?? new Dictionary<string, string>();
    }

    public ExternalMcpBridge(string name, string command, IReadOnlyList<string> args, string? cwd = null, IReadOnlyDictionary<string, string>? env = null)
        : this(new BridgeSpec(name, command, args, env), cwd)
    {
    }

    /// <summary>OAuth: fetched right before the spawn and handed to the child in the configured variable.</summary>
    public Func<CancellationToken, bool, Task<string?>>? TokenSource { get; set; }

    public string Command => _command;
    public IReadOnlyList<string> Args => _args;
    public IReadOnlyDictionary<string, string> Env { get; }
    public override string Launch => _command;
    public override bool IsStarted => _process is not null;
    public override bool IsAlive => _process is { HasExited: false };
    public int? ExitCode => _process is { HasExited: true } p ? p.ExitCode : null;

    // ------------------------------------------------------------------ lifecycle

    public override async Task EnsureStartedAsync(CancellationToken ct)
    {
        if (_process is not null) return;
        await _startLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_process is not null) return;
            if (Volatile.Read(ref _disposed) == 1) throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}' disposed");
            await StartProcessAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _startLock.Release();
        }
    }

    private async Task StartProcessAsync(CancellationToken ct)
    {
        var psi = new ProcessStartInfo(_command)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            StandardInputEncoding = new UTF8Encoding(false),
        };
        foreach (var a in _args) psi.ArgumentList.Add(a);
        foreach (var kv in Env) psi.Environment[kv.Key] = kv.Value;
        if (TokenSource is { } tokens && Spec.Auth?.Env is { } envName)
        {
            string token = await tokens(ct, false).ConfigureAwait(false)
                           ?? throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}' is not signed in: press Connect in the Hubris desktop app");
            psi.Environment[envName] = token; // shortcut: a token that expires while the child runs is not re-injected; restart the hub or Clear cache
        }
        if (!string.IsNullOrEmpty(_cwd)) psi.WorkingDirectory = _cwd;

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        process.Exited += OnExited;
        try { process.Start(); }
        catch
        {
            process.Exited -= OnExited;
            process.Dispose();
            throw;
        }
        _process = process;

        _stdin = new JsonLineWriter(PipeWriter.Create(process.StandardInput.BaseStream, new StreamPipeWriterOptions(leaveOpen: false)));
        _stdout = PipeReader.Create(process.StandardOutput.BaseStream, new StreamPipeReaderOptions(bufferSize: 64 * 1024, leaveOpen: false));
        _readLoop = Task.Run(() => ReadLoopAsync(_lifetime.Token), CancellationToken.None);
        _errLoop = Task.Run(() => PumpStderrAsync(process.StandardError, _lifetime.Token), CancellationToken.None);

        Log.Info($"bridge '{Name}' started pid={process.Id} ({_command})");

        JsonNode? initResult = await SendRequestAsync("initialize", InitializeParams(), ct, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        ReadInitializeResult(initResult);
        await SendNotificationAsync("notifications/initialized", null, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ outbound

    protected override async Task<JsonNode?> SendRequestAsync(string method, JsonNode? parameters, CancellationToken ct, TimeSpan timeout)
    {
        if (!IsAlive) throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}' is not running");

        var id = RpcId.FromNumber(Interlocked.Increment(ref _nextId));
        var tcs = new TaskCompletionSource<JsonNode?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct, _lifetime.Token);
        timeoutCts.CancelAfter(timeout);
        using var reg = timeoutCts.Token.Register(static state =>
        {
            var (t, bridge, rid, outer) = ((TaskCompletionSource<JsonNode?>, ExternalMcpBridge, RpcId, CancellationToken))state!;
            if (outer.IsCancellationRequested)
            {
                t.TrySetCanceled(outer);
                _ = bridge.SendCancelAsync(rid);
            }
            else
            {
                t.TrySetException(new TimeoutException($"bridge '{bridge.Name}' request {rid} timed out"));
            }
        }, (tcs, this, id, ct));

        try
        {
            await WriteFrameAsync(w =>
            {
                w.WriteStartObject();
                w.WriteString("jsonrpc"u8, "2.0"u8);
                w.WritePropertyName("id"u8);
                id.WriteTo(w);
                w.WriteString("method"u8, method);
                if (parameters is not null)
                {
                    w.WritePropertyName("params"u8);
                    parameters.WriteTo(w);
                }
                w.WriteEndObject();
            }, ct).ConfigureAwait(false);

            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    private async Task SendCancelAsync(RpcId id)
    {
        try
        {
            var p = new JsonObject { ["requestId"] = IdToNode(id), ["reason"] = "client cancelled" };
            await SendNotificationAsync("notifications/cancelled", p, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Debug($"bridge '{Name}' cancel forward failed: {ex.Message}");
        }
    }

    private ValueTask SendNotificationAsync(string method, JsonNode? parameters, CancellationToken ct)
        => WriteFrameAsync(w =>
        {
            w.WriteStartObject();
            w.WriteString("jsonrpc"u8, "2.0"u8);
            w.WriteString("method"u8, method);
            if (parameters is not null)
            {
                w.WritePropertyName("params"u8);
                parameters.WriteTo(w);
            }
            w.WriteEndObject();
        }, ct);

    private ValueTask SendErrorAsync(RpcId id, int code, string message)
        => WriteFrameAsync(w =>
        {
            w.WriteStartObject();
            w.WriteString("jsonrpc"u8, "2.0"u8);
            w.WritePropertyName("id"u8);
            id.WriteTo(w);
            w.WritePropertyName("error"u8);
            w.WriteStartObject();
            w.WriteNumber("code"u8, code);
            w.WriteString("message"u8, message);
            w.WriteEndObject();
            w.WriteEndObject();
        }, CancellationToken.None);

    private async ValueTask WriteFrameAsync(Action<Utf8JsonWriter> write, CancellationToken ct)
    {
        var stdin = _stdin ?? throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}' not started");
        if (Volatile.Read(ref _disposed) == 1) throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}' disposed");
        await stdin.WriteAsync(write, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ inbound

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        try
        {
            await JsonLines.ReadLoopAsync(_stdout!, HandleInboundAsync, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Warn($"bridge '{Name}' read loop ended: {ex.Message}");
        }
        finally
        {
            FailAllPending($"bridge '{Name}' stdout closed");
        }
    }

    private async ValueTask HandleInboundAsync(ReadOnlySequence<byte> line)
    {
        JsonRpcMessage? msg;
        try
        {
            var r = new Utf8JsonReader(line, isFinalBlock: true, state: default);
            msg = JsonSerializer.Deserialize(ref r, McpJsonContext.Default.JsonRpcMessage);
        }
        catch (JsonException ex)
        {
            Log.Warn($"bridge '{Name}' sent invalid JSON: {ex.Message}");
            return;
        }
        if (msg is null) return;

        if (msg.Method is null)
        {
            // Response to one of our requests.
            if (_pending.TryRemove(msg.Id, out var tcs))
            {
                if (msg.Error is { } err) tcs.TrySetException(new McpBridgeException(err.Code, err.Message));
                else tcs.TrySetResult(msg.Result);
            }
            else
            {
                Log.Debug($"bridge '{Name}' response for unknown id {msg.Id}");
            }
            return;
        }

        if (msg.Id.IsNone)
        {
            // Notification from child.
            if (string.Equals(msg.Method, "notifications/tools/list_changed", StringComparison.Ordinal))
                RaiseToolsChanged();
            else
                Log.Debug($"bridge '{Name}' notification {msg.Method}");
            return;
        }

        // Request from child (sampling/roots/elicitation) – not supported by the hub.
        if (string.Equals(msg.Method, "ping", StringComparison.Ordinal))
        {
            await WriteFrameAsync(w =>
            {
                w.WriteStartObject();
                w.WriteString("jsonrpc"u8, "2.0"u8);
                w.WritePropertyName("id"u8);
                msg.Id.WriteTo(w);
                w.WritePropertyName("result"u8);
                w.WriteStartObject();
                w.WriteEndObject();
                w.WriteEndObject();
            }, CancellationToken.None).ConfigureAwait(false);
            return;
        }
        await SendErrorAsync(msg.Id, JsonRpcErrorCodes.MethodNotFound, $"Hubris does not support client method '{msg.Method}'").ConfigureAwait(false);
    }

    private async Task PumpStderrAsync(StreamReader stderr, CancellationToken ct)
    {
        try
        {
            string? line;
            while ((line = await stderr.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
                Log.Info($"[bridge:{Name}] {line}");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log.Debug($"bridge '{Name}' stderr pump: {ex.Message}"); }
    }

    private void OnExited(object? sender, EventArgs e)
    {
        int code = -1;
        try { code = _process?.ExitCode ?? -1; } catch (InvalidOperationException) { }
        FailAllPending($"bridge '{Name}' exited with code {code}");
        if (Volatile.Read(ref _disposed) == 0)
        {
            Log.Warn($"bridge '{Name}' exited with code {code}");
            RaiseExited();
        }
    }

    private void FailAllPending(string reason)
    {
        foreach (var kv in _pending)
        {
            if (_pending.TryRemove(kv.Key, out var tcs))
                tcs.TrySetException(new McpBridgeException(JsonRpcErrorCodes.InternalError, reason));
        }
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        _lifetime.Cancel();

        var process = _process;
        if (process is not null)
        {
            // Polite EOF first so well-behaved servers exit on their own.
            if (_stdin is not null) await _stdin.DisposeAsync().ConfigureAwait(false);

            try
            {
                if (!process.HasExited)
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1500));
                    try { await process.WaitForExitAsync(cts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { }
                }
                if (!process.HasExited)
                {
                    Log.Warn($"bridge '{Name}' did not exit; killing process tree");
                    process.Kill(entireProcessTree: true);
                    using var cts2 = new CancellationTokenSource(TimeSpan.FromMilliseconds(1000));
                    try { await process.WaitForExitAsync(cts2.Token).ConfigureAwait(false); } catch (OperationCanceledException) { }
                }
            }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception ex) { Log.Debug($"bridge '{Name}' kill: {ex.Message}"); }

            process.Exited -= OnExited;
        }

        FailAllPending($"bridge '{Name}' disposed");

        if (_readLoop is not null) { try { await _readLoop.ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"bridge '{Name}' read loop: {ex.Message}"); } }
        if (_errLoop is not null) { try { await _errLoop.ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"bridge '{Name}' err loop: {ex.Message}"); } }

        process?.Dispose();
        _startLock.Dispose();
        _lifetime.Dispose();
        Log.Info($"bridge '{Name}' stopped");
    }
}

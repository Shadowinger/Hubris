using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text.Json;
using Hubris.Transport;

namespace Hubris.Control;

/// <summary>One connected UI client: framed JSON lines over a socket stream with a private write lock.</summary>
public sealed class ControlClient : IAsyncDisposable
{
    private static readonly JsonWriterOptions WriterOptions = new() { Indented = false, SkipValidation = true };

    private readonly Socket _socket;
    private readonly NetworkStream _stream;
    private readonly PipeReader _reader;
    private readonly PipeWriter _writer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private int _closed;

    internal ControlClient(Socket socket, int id)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: true);
        _reader = PipeReader.Create(_stream, new StreamPipeReaderOptions(leaveOpen: true));
        _writer = PipeWriter.Create(_stream, new StreamPipeWriterOptions(leaveOpen: true));
        Id = id;
    }

    public int Id { get; }
    public bool IsClosed => Volatile.Read(ref _closed) == 1;

    public async ValueTask SendAsync(ControlMessage message, CancellationToken ct = default)
    {
        if (IsClosed) return;
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (IsClosed) return;
            using (var json = new Utf8JsonWriter(_writer, WriterOptions))
            {
                JsonSerializer.Serialize(json, message, ControlJsonContext.Default.ControlMessage);
            }
            _writer.GetSpan(1)[0] = (byte)'\n';
            _writer.Advance(1);
            await _writer.FlushAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            Volatile.Write(ref _closed, 1);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    internal async Task ReadLoopAsync(Func<ControlClient, ControlMessage, ValueTask> onMessage, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                ReadResult result = await _reader.ReadAsync(ct).ConfigureAwait(false);
                ReadOnlySequence<byte> buffer = result.Buffer;
                while (LineFramer.TryReadLine(ref buffer, out var line))
                {
                    ControlMessage? msg = null;
                    try
                    {
                        var r = new Utf8JsonReader(line, isFinalBlock: true, state: default);
                        msg = JsonSerializer.Deserialize(ref r, ControlJsonContext.Default.ControlMessage);
                    }
                    catch (JsonException ex)
                    {
                        Log.Warn($"control client {Id}: bad frame: {ex.Message}");
                    }
                    if (msg is not null) await onMessage(this, msg).ConfigureAwait(false);
                }
                if (result.IsCompleted) { _reader.AdvanceTo(buffer.End); break; }
                _reader.AdvanceTo(buffer.Start, buffer.End);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            Log.Debug($"control client {Id} dropped: {ex.Message}");
        }
        finally
        {
            Volatile.Write(ref _closed, 1);
        }
    }

    public async ValueTask DisposeAsync()
    {
        Volatile.Write(ref _closed, 1);
        try { await _writer.CompleteAsync().ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"control client {Id} writer: {ex.Message}"); }
        try { await _reader.CompleteAsync().ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"control client {Id} reader: {ex.Message}"); }
        try { _socket.Shutdown(SocketShutdown.Both); } catch (Exception ex) { Log.Debug($"control client {Id} shutdown: {ex.Message}"); }
        await _stream.DisposeAsync().ConfigureAwait(false);
        _writeLock.Dispose();
    }
}

/// <summary>Unix-domain-socket listener; fans events out to every connected UI and routes their commands back.</summary>
public sealed class ControlServer : IAsyncDisposable
{
    private readonly string _socketPath;
    private readonly Func<ControlClient, ControlMessage, ValueTask> _onCommand;
    private readonly Func<ControlClient, ValueTask>? _onConnected;
    private readonly List<ControlClient> _clients = new();
    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetime = new();
    private Socket? _listener;
    private Task? _acceptLoop;
    private int _nextId;

    public ControlServer(string socketPath, Func<ControlClient, ControlMessage, ValueTask> onCommand, Func<ControlClient, ValueTask>? onConnected = null)
    {
        _socketPath = socketPath;
        _onCommand = onCommand;
        _onConnected = onConnected;
    }

    public string SocketPath => _socketPath;

    public int ClientCount { get { lock (_gate) return _clients.Count; } }
    public bool HasClients => ClientCount > 0;

    public event Action<int>? ClientCountChanged;

    public void Start()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_socketPath)!);
        if (File.Exists(_socketPath)) File.Delete(_socketPath);

        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(_socketPath));
        listener.Listen(8);
        if (!OperatingSystem.IsWindows())
        {
            try { File.SetUnixFileMode(_socketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch (Exception ex) { Log.Debug($"chmod socket: {ex.Message}"); }
        }
        _listener = listener;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(listener, _lifetime.Token), CancellationToken.None);
        Log.Info($"control socket {_socketPath}");
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket accepted;
            try { accepted = await listener.AcceptAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException ex) { Log.Warn($"control accept: {ex.Message}"); continue; }

            var client = new ControlClient(accepted, Interlocked.Increment(ref _nextId));
            int count;
            lock (_gate) { _clients.Add(client); count = _clients.Count; }
            Log.Info($"control client {client.Id} connected ({count} total)");
            ClientCountChanged?.Invoke(count);
            _ = Task.Run(() => ServeAsync(client, ct), CancellationToken.None);
        }
    }

    private async Task ServeAsync(ControlClient client, CancellationToken ct)
    {
        try
        {
            if (_onConnected is not null) await _onConnected(client).ConfigureAwait(false);
            await client.ReadLoopAsync(_onCommand, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Warn($"control client {client.Id} failed: {ex.Message}");
        }
        finally
        {
            int count;
            lock (_gate) { _clients.Remove(client); count = _clients.Count; }
            await client.DisposeAsync().ConfigureAwait(false);
            Log.Info($"control client {client.Id} disconnected ({count} total)");
            ClientCountChanged?.Invoke(count);
        }
    }

    public async ValueTask BroadcastAsync(ControlMessage message)
    {
        ControlClient[] snapshot;
        lock (_gate) { if (_clients.Count == 0) return; snapshot = _clients.ToArray(); }
        foreach (var c in snapshot)
            await c.SendAsync(message, _lifetime.Token).ConfigureAwait(false);
    }

    /// <summary>Fire-and-forget broadcast for hot paths; never throws into the caller.</summary>
    public void Broadcast(ControlMessage message)
    {
        if (!HasClients) return;
        _ = Task.Run(async () =>
        {
            try { await BroadcastAsync(message).ConfigureAwait(false); }
            catch (Exception ex) { Log.Debug($"broadcast {message.Type}: {ex.Message}"); }
        }, CancellationToken.None);
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel();
        try { _listener?.Dispose(); } catch (Exception ex) { Log.Debug($"listener dispose: {ex.Message}"); }
        if (_acceptLoop is not null) { try { await _acceptLoop.ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"accept loop: {ex.Message}"); } }
        ControlClient[] snapshot;
        lock (_gate) { snapshot = _clients.ToArray(); _clients.Clear(); }
        foreach (var c in snapshot) await c.DisposeAsync().ConfigureAwait(false);
        try { if (File.Exists(_socketPath)) File.Delete(_socketPath); } catch (Exception ex) { Log.Debug($"unlink socket: {ex.Message}"); }
        _lifetime.Dispose();
    }
}

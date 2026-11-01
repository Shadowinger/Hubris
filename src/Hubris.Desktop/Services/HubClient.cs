using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text.Json;
using Hubris.Control;
using Hubris.Transport;

namespace Hubris.Desktop.Services;

/// <summary>Connection to one running hub over its control socket. Events are delivered on a background thread.</summary>
public sealed class HubClient : IAsyncDisposable
{
    private static readonly JsonWriterOptions WriterOptions = new() { Indented = false, SkipValidation = true };

    private readonly string _socketPath;
    private readonly Socket _socket;
    private NetworkStream? _stream;
    private PipeReader? _reader;
    private PipeWriter? _writer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private Task? _readLoop;
    private long _reqSeq;

    public HubClient(HubDescriptor descriptor)
    {
        Descriptor = descriptor;
        _socketPath = descriptor.Socket;
        _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    }

    public HubDescriptor Descriptor { get; }
    public int Pid => Descriptor.Pid;
    public bool IsConnected => _stream is not null && !_lifetime.IsCancellationRequested && _socket.Connected;

    public event Action<HubClient, ControlMessage>? MessageReceived;
    public event Action<HubClient>? Disconnected;

    public async Task ConnectAsync(CancellationToken ct)
    {
        await _socket.ConnectAsync(new UnixDomainSocketEndPoint(_socketPath), ct).ConfigureAwait(false);
        _stream = new NetworkStream(_socket, ownsSocket: true);
        _reader = PipeReader.Create(_stream, new StreamPipeReaderOptions(leaveOpen: true));
        _writer = PipeWriter.Create(_stream, new StreamPipeWriterOptions(leaveOpen: true));
        _readLoop = Task.Run(() => ReadLoopAsync(_lifetime.Token), CancellationToken.None);
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        var reader = _reader!;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                ReadResult result = await reader.ReadAsync(ct).ConfigureAwait(false);
                ReadOnlySequence<byte> buffer = result.Buffer;
                while (LineFramer.TryReadLine(ref buffer, out var line))
                {
                    ControlMessage? msg = null;
                    try
                    {
                        var r = new Utf8JsonReader(line, isFinalBlock: true, state: default);
                        msg = JsonSerializer.Deserialize(ref r, ControlJsonContext.Default.ControlMessage);
                    }
                    catch (JsonException) { }
                    if (msg is not null) MessageReceived?.Invoke(this, msg);
                }
                if (result.IsCompleted) { reader.AdvanceTo(buffer.End); break; }
                reader.AdvanceTo(buffer.Start, buffer.End);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException) { }
        finally
        {
            Disconnected?.Invoke(this);
        }
    }

    public Task SetModeAsync(string mode) => SendAsync(new ControlMessage { Type = ControlTypes.SetMode, Mode = mode });
    public Task ApproveAsync(string approvalId) => SendAsync(new ControlMessage { Type = ControlTypes.Approve, ApprovalId = approvalId });
    public Task DenyAsync(string approvalId) => SendAsync(new ControlMessage { Type = ControlTypes.Deny, ApprovalId = approvalId });
    public Task RevealAsync(string tool) => SendAsync(new ControlMessage { Type = ControlTypes.Reveal, Tool = tool });
    public Task LockAsync(string tool) => SendAsync(new ControlMessage { Type = ControlTypes.Lock, Tool = tool });
    public Task ClearCacheAsync() => SendAsync(new ControlMessage { Type = ControlTypes.ClearCache });
    public Task RequestStatusAsync() => SendAsync(new ControlMessage { Type = ControlTypes.GetStatus });
    public Task ShutdownHubAsync() => SendAsync(new ControlMessage { Type = ControlTypes.Shutdown });

    private async Task SendAsync(ControlMessage msg)
    {
        var writer = _writer;
        if (writer is null || _lifetime.IsCancellationRequested) return;
        msg.ReqId = Interlocked.Increment(ref _reqSeq);
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            using (var json = new Utf8JsonWriter(writer, WriterOptions))
                JsonSerializer.Serialize(json, msg, ControlJsonContext.Default.ControlMessage);
            writer.GetSpan(1)[0] = (byte)'\n';
            writer.Advance(1);
            await writer.FlushAsync(_lifetime.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or OperationCanceledException) { }
        finally
        {
            _writeLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_lifetime.IsCancellationRequested) return;
        _lifetime.Cancel();
        try { _socket.Shutdown(SocketShutdown.Both); } catch (Exception) { }
        if (_writer is not null) { try { await _writer.CompleteAsync().ConfigureAwait(false); } catch (Exception) { } }
        if (_reader is not null) { try { await _reader.CompleteAsync().ConfigureAwait(false); } catch (Exception) { } }
        if (_readLoop is not null) { try { await _readLoop.ConfigureAwait(false); } catch (Exception) { } }
        _stream?.Dispose();
        _socket.Dispose();
        _writeLock.Dispose();
        _lifetime.Dispose();
    }
}

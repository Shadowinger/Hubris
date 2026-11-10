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
    private readonly string _socketPath;
    private readonly Socket _socket;
    private NetworkStream? _stream;
    private PipeReader? _reader;
    private JsonLineWriter? _writer;
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

    public event Action<HubClient, ControlMessage>? MessageReceived;
    public event Action<HubClient>? Disconnected;

    public async Task ConnectAsync(CancellationToken ct)
    {
        await _socket.ConnectAsync(new UnixDomainSocketEndPoint(_socketPath), ct).ConfigureAwait(false);
        _stream = new NetworkStream(_socket, ownsSocket: true);
        _reader = PipeReader.Create(_stream, new StreamPipeReaderOptions(leaveOpen: true));
        _writer = new JsonLineWriter(PipeWriter.Create(_stream, new StreamPipeWriterOptions(leaveOpen: true)));
    }

    /// <summary>Starts reading. Called after the subscribers are attached, so the hub's hello and replayed approvals reach them.</summary>
    public void Start() => _readLoop ??= Task.Run(() => ReadLoopAsync(_lifetime.Token), CancellationToken.None);

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        try
        {
            await JsonLines.ReadLoopAsync(_reader!, line =>
            {
                ControlMessage? msg = null;
                try
                {
                    var r = new Utf8JsonReader(line, isFinalBlock: true, state: default);
                    msg = JsonSerializer.Deserialize(ref r, ControlJsonContext.Default.ControlMessage);
                }
                catch (JsonException) { }
                if (msg is not null) MessageReceived?.Invoke(this, msg);
                return ValueTask.CompletedTask;
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException) { }
        finally
        {
            Disconnected?.Invoke(this);
        }
    }

    public Task SetModeAsync(string mode) => SendAsync(new ControlMessage { Type = ControlTypes.SetMode, Mode = mode });
    public Task ApproveAsync(string approvalId, bool remember = false) => SendAsync(new ControlMessage { Type = ControlTypes.Approve, ApprovalId = approvalId, Remember = remember ? true : null });
    public Task DenyAsync(string approvalId, bool remember = false) => SendAsync(new ControlMessage { Type = ControlTypes.Deny, ApprovalId = approvalId, Remember = remember ? true : null });
    public Task RevealAsync(string tool) => SendAsync(new ControlMessage { Type = ControlTypes.Reveal, Tool = tool });
    public Task LockAsync(string tool) => SendAsync(new ControlMessage { Type = ControlTypes.Lock, Tool = tool });
    public Task ReloadConfigAsync() => SendAsync(new ControlMessage { Type = ControlTypes.ReloadConfig });
    public Task ForgetAsync(string tool) => SendAsync(new ControlMessage { Type = ControlTypes.Forget, Tool = tool });
    public Task ClearCacheAsync() => SendAsync(new ControlMessage { Type = ControlTypes.ClearCache });
    public Task RefreshBridgeAsync(string bridge) => SendAsync(new ControlMessage { Type = ControlTypes.ClearCache, Bridge = bridge });
    public Task RequestStatusAsync() => SendAsync(new ControlMessage { Type = ControlTypes.GetStatus });
    public Task RequestToolsAsync() => SendAsync(new ControlMessage { Type = ControlTypes.ListTools });
    public Task ShutdownHubAsync() => SendAsync(new ControlMessage { Type = ControlTypes.Shutdown });
    public Task OAuthStartAsync(string bridge) => SendAsync(new ControlMessage { Type = ControlTypes.OAuthStart, Bridge = bridge });
    public Task OAuthRevokeAsync(string bridge) => SendAsync(new ControlMessage { Type = ControlTypes.OAuthRevoke, Bridge = bridge });

    private async Task SendAsync(ControlMessage msg)
    {
        var writer = _writer;
        if (writer is null || _lifetime.IsCancellationRequested) return;
        msg.ReqId = Interlocked.Increment(ref _reqSeq);
        try
        {
            await writer.WriteAsync(w => JsonSerializer.Serialize(w, msg, ControlJsonContext.Default.ControlMessage), _lifetime.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or OperationCanceledException) { }
    }

    public async ValueTask DisposeAsync()
    {
        if (_lifetime.IsCancellationRequested) return;
        _lifetime.Cancel();
        try { _socket.Shutdown(SocketShutdown.Both); } catch (Exception) { }
        if (_writer is not null) await _writer.DisposeAsync().ConfigureAwait(false);
        if (_reader is not null) { try { await _reader.CompleteAsync().ConfigureAwait(false); } catch (Exception) { } }
        if (_readLoop is not null) { try { await _readLoop.ConfigureAwait(false); } catch (Exception) { } }
        _stream?.Dispose();
        _socket.Dispose();
        _lifetime.Dispose();
    }
}

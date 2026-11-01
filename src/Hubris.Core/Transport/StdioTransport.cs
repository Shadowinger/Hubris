using System.Buffers;
using System.IO.Pipelines;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Hubris.Protocol;

namespace Hubris.Transport;

/// <summary>JSON-RPC over stdin/stdout. Nothing but frames ever reaches stdout; diagnostics go through <see cref="Log"/>.</summary>
public sealed class StdioTransport : IAsyncDisposable
{
    private readonly PipeReader _reader;
    private readonly JsonLineWriter _writer;
    private volatile bool _closed;

    public StdioTransport()
        : this(Console.OpenStandardInput(), Console.OpenStandardOutput())
    {
    }

    public StdioTransport(Stream input, Stream output)
    {
        _reader = PipeReader.Create(input, new StreamPipeReaderOptions(bufferSize: 64 * 1024, minimumReadSize: 4096, leaveOpen: false));
        _writer = new JsonLineWriter(PipeWriter.Create(output, new StreamPipeWriterOptions(minimumBufferSize: 16 * 1024, leaveOpen: false)));
    }

    // ---------------------------------------------------------------- read side

    public Task RunReadLoopAsync(Func<JsonRpcMessage, ValueTask> onMessage, CancellationToken ct)
        => JsonLines.ReadLoopAsync(_reader, line => DispatchLineAsync(line, onMessage), ct);

    private async ValueTask DispatchLineAsync(ReadOnlySequence<byte> line, Func<JsonRpcMessage, ValueTask> onMessage)
    {
        JsonRpcMessage? msg;
        try
        {
            var reader = new Utf8JsonReader(line, isFinalBlock: true, state: default);
            msg = JsonSerializer.Deserialize(ref reader, McpJsonContext.Default.JsonRpcMessage);
        }
        catch (JsonException ex)
        {
            Log.Warn($"parse error: {ex.Message}");
            await SendErrorAsync(RpcId.Null, JsonRpcErrorCodes.ParseError, "Parse error").ConfigureAwait(false);
            return;
        }

        if (msg is null)
        {
            await SendErrorAsync(RpcId.Null, JsonRpcErrorCodes.InvalidRequest, "Invalid Request").ConfigureAwait(false);
            return;
        }

        // A handler bug must never take the read loop (and the whole hub) down with it.
        try
        {
            await onMessage(msg).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Error($"{msg.Method ?? "response"} id={msg.Id} handler failed: {ex.Message}");
            if (!msg.Id.IsNone && msg.Method is not null)
                await SendErrorAsync(msg.Id, JsonRpcErrorCodes.InternalError, $"{ex.GetType().Name}: {ex.Message}").ConfigureAwait(false);
        }
    }

    // ---------------------------------------------------------------- write side

    public ValueTask SendResultAsync<T>(RpcId id, T value, JsonTypeInfo<T> typeInfo, CancellationToken ct = default)
        => WriteFrameAsync(w =>
        {
            w.WriteStartObject();
            w.WriteString("jsonrpc"u8, "2.0"u8);
            w.WritePropertyName("id"u8);
            id.WriteTo(w);
            w.WritePropertyName("result"u8);
            JsonSerializer.Serialize(w, value, typeInfo);
            w.WriteEndObject();
        }, ct);

    public ValueTask SendErrorAsync(RpcId id, int code, string message, JsonNode? data = null, CancellationToken ct = default)
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
            if (data is not null)
            {
                w.WritePropertyName("data"u8);
                data.WriteTo(w);
            }
            w.WriteEndObject();
            w.WriteEndObject();
        }, ct);

    public ValueTask SendNotificationAsync(string method, JsonNode? parameters = null, CancellationToken ct = default)
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

    private async ValueTask WriteFrameAsync(Action<Utf8JsonWriter> write, CancellationToken ct)
    {
        if (_closed) return;
        try
        {
            if (!await _writer.WriteAsync(write, ct).ConfigureAwait(false)) _closed = true; // client closed stdout
        }
        catch (IOException ex)
        {
            Log.Warn($"stdout write failed: {ex.Message}");
            _closed = true;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _closed = true;
        await _writer.DisposeAsync().ConfigureAwait(false);
        try { await _reader.CompleteAsync().ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"reader complete: {ex.Message}"); }
    }
}

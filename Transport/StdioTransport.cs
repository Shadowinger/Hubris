using System.Buffers;
using System.IO.Pipelines;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using McpHub.Protocol;

namespace McpHub.Transport;

/// <summary>
/// Pipelines-based stdio transport. Reads newline-delimited JSON-RPC frames from stdin and writes
/// frames to stdout under a semaphore so concurrent handlers never interleave bytes.
/// </summary>
public sealed class StdioTransport : IAsyncDisposable
{
    private readonly PipeReader _reader;
    private readonly PipeWriter _writer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private Utf8JsonWriter? _json;
    private bool _disposed;

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        SkipValidation = true,
    };

    public StdioTransport()
        : this(Console.OpenStandardInput(), Console.OpenStandardOutput())
    {
    }

    public StdioTransport(Stream input, Stream output)
    {
        _reader = PipeReader.Create(input, new StreamPipeReaderOptions(bufferSize: 64 * 1024, minimumReadSize: 4096, leaveOpen: false));
        _writer = PipeWriter.Create(output, new StreamPipeWriterOptions(minimumBufferSize: 16 * 1024, leaveOpen: false));
    }

    // ---------------------------------------------------------------- read side

    public async Task RunReadLoopAsync(Func<JsonRpcMessage, ValueTask> onMessage, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                ReadResult result = await _reader.ReadAsync(ct).ConfigureAwait(false);
                ReadOnlySequence<byte> buffer = result.Buffer;

                while (LineFramer.TryReadLine(ref buffer, out ReadOnlySequence<byte> line))
                {
                    await DispatchLineAsync(line, onMessage).ConfigureAwait(false);
                }

                if (result.IsCompleted)
                {
                    // Trailing frame without newline (client closed pipe mid-line).
                    var tail = LineFramer.TrimCr(buffer);
                    if (tail.Length > 0)
                        await DispatchLineAsync(tail, onMessage).ConfigureAwait(false);
                    _reader.AdvanceTo(result.Buffer.End);
                    break;
                }

                _reader.AdvanceTo(buffer.Start, buffer.End);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // graceful shutdown
        }
        finally
        {
            await _reader.CompleteAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask DispatchLineAsync(ReadOnlySequence<byte> line, Func<JsonRpcMessage, ValueTask> onMessage)
    {
        JsonRpcMessage? msg;
        try
        {
            msg = Parse(in line);
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

        await onMessage(msg).ConfigureAwait(false);
    }

    private static JsonRpcMessage? Parse(in ReadOnlySequence<byte> line)
    {
        // Utf8JsonReader consumes the sequence directly; no string / array materialisation.
        var reader = new Utf8JsonReader(line, isFinalBlock: true, state: default);
        return JsonSerializer.Deserialize(ref reader, McpJsonContext.Default.JsonRpcMessage);
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

    public ValueTask SendResultNodeAsync(RpcId id, JsonNode? result, CancellationToken ct = default)
        => WriteFrameAsync(w =>
        {
            w.WriteStartObject();
            w.WriteString("jsonrpc"u8, "2.0"u8);
            w.WritePropertyName("id"u8);
            id.WriteTo(w);
            w.WritePropertyName("result"u8);
            if (result is null) w.WriteStartObject(); else result.WriteTo(w);
            if (result is null) w.WriteEndObject();
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

    public ValueTask SendRawAsync(JsonNode node, CancellationToken ct = default)
        => WriteFrameAsync(w => node.WriteTo(w), ct);

    private async ValueTask WriteFrameAsync(Action<Utf8JsonWriter> write, CancellationToken ct)
    {
        if (_disposed) return;
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_disposed) return;
            var json = _json;
            if (json is null)
            {
                json = new Utf8JsonWriter(_writer, WriterOptions);
                _json = json;
            }
            else
            {
                json.Reset(_writer);
            }

            write(json);
            json.Flush();

            Span<byte> nl = _writer.GetSpan(1);
            nl[0] = (byte)'\n';
            _writer.Advance(1);

            FlushResult fr = await _writer.FlushAsync(ct).ConfigureAwait(false);
            if (fr.IsCompleted) _disposed = true; // stdout gone (client exited)
        }
        catch (IOException ex)
        {
            Log.Warn($"stdout write failed: {ex.Message}");
            _disposed = true;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { _json?.Dispose(); return; }
        _disposed = true;
        try { await _writer.CompleteAsync().ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"writer complete: {ex.Message}"); }
        try { await _reader.CompleteAsync().ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"reader complete: {ex.Message}"); }
        _json?.Dispose();
        _writeLock.Dispose();
    }
}

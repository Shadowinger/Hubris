using System.Buffers;
using System.IO.Pipelines;
using System.Text.Json;

namespace Hubris.Transport;

/// <summary>Newline-delimited JSON framing shared by stdio, bridges and the control channel.</summary>
public static class JsonLines
{
    /// <summary>
    /// Delivers every complete line (and a trailing unterminated one at EOF) to <paramref name="onLine"/>,
    /// then completes the reader. Cancellation ends the loop quietly; I/O errors propagate.
    /// </summary>
    /// <summary>Default cap for one line; a peer that never sends '\n' must not grow the heap without end.</summary>
    public const long DefaultMaxLine = 64L * 1024 * 1024;

    public static async Task ReadLoopAsync(PipeReader reader, Func<ReadOnlySequence<byte>, ValueTask> onLine, CancellationToken ct, long maxLine = DefaultMaxLine)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                ReadResult result = await reader.ReadAsync(ct).ConfigureAwait(false);
                ReadOnlySequence<byte> buffer = result.Buffer;

                while (LineFramer.TryReadLine(ref buffer, out ReadOnlySequence<byte> line))
                    await onLine(line).ConfigureAwait(false);

                if (result.IsCompleted)
                {
                    var tail = LineFramer.TrimCr(buffer);
                    if (tail.Length > 0) await onLine(tail).ConfigureAwait(false);
                    reader.AdvanceTo(result.Buffer.End);
                    break;
                }
                if (buffer.Length > maxLine) throw new InvalidDataException($"line longer than {maxLine} bytes");
                reader.AdvanceTo(buffer.Start, buffer.End);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        finally
        {
            await reader.CompleteAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>Writes one frame per call: serialised under a lock, '\n'-terminated, flushed at once.</summary>
public sealed class JsonLineWriter : IAsyncDisposable
{
    private static readonly JsonWriterOptions Options = new() { Indented = false, SkipValidation = true };

    private readonly PipeWriter _pipe;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private Utf8JsonWriter? _json;

    public JsonLineWriter(PipeWriter pipe) => _pipe = pipe;

    /// <summary>Returns false once the reader on the other side is gone. I/O errors propagate.</summary>
    public async ValueTask<bool> WriteAsync(Action<Utf8JsonWriter> write, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var json = _json;
            if (json is null) { json = new Utf8JsonWriter(_pipe, Options); _json = json; }
            else json.Reset(_pipe);

            write(json);
            json.Flush();
            _pipe.GetSpan(1)[0] = (byte)'\n';
            _pipe.Advance(1);
            FlushResult fr = await _pipe.FlushAsync(ct).ConfigureAwait(false);
            return !fr.IsCompleted;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        try { await _pipe.CompleteAsync().ConfigureAwait(false); } catch (Exception ex) { Log.Debug($"writer complete: {ex.Message}"); }
        _json?.Dispose();
        _lock.Dispose();
    }
}

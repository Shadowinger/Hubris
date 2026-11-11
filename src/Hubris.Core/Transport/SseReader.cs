using System.Runtime.CompilerServices;
using System.Text;

namespace Hubris.Transport;

/// <summary>Minimal text/event-stream parser: yields (event, data) per message; id/retry fields and comments are skipped.</summary>
public sealed class SseReader
{
    private readonly StreamReader _reader;

    public SseReader(Stream stream) => _reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 16 * 1024);

    public static IAsyncEnumerable<(string Event, string Data)> ReadAsync(Stream stream, CancellationToken ct) => new SseReader(stream).ReadAsync(ct);

    private readonly char[] _buf = new char[16 * 1024];
    private int _pos, _len;

    /// <summary>StreamReader.ReadLineAsync without its blind spot: a line that never ends is cut off at the cap instead of filling memory.</summary>
    private async ValueTask<string?> ReadLineAsync(CancellationToken ct)
    {
        StringBuilder? sb = null;
        while (true)
        {
            if (_pos == _len)
            {
                _len = await _reader.ReadAsync(_buf.AsMemory(), ct).ConfigureAwait(false);
                _pos = 0;
                if (_len == 0) return sb?.ToString(); // end of stream: what is left of the last line, or null
            }
            int nl = Array.IndexOf(_buf, '\n', _pos, _len - _pos);
            int end = nl < 0 ? _len : nl;
            (sb ??= new StringBuilder()).Append(_buf, _pos, end - _pos);
            if (sb.Length > JsonLines.DefaultMaxLine) throw new InvalidDataException($"line longer than {JsonLines.DefaultMaxLine} bytes");
            _pos = nl < 0 ? _len : nl + 1;
            if (nl < 0) continue;
            if (sb.Length > 0 && sb[^1] == '\r') sb.Length--;
            return sb.ToString();
        }
    }

    public async IAsyncEnumerable<(string Event, string Data)> ReadAsync([EnumeratorCancellation] CancellationToken ct)
    {
        string eventName = "message";
        var data = new StringBuilder();
        bool pending = false;
        while (true)
        {
            string? line = await ReadLineAsync(ct).ConfigureAwait(false);
            if (data.Length > JsonLines.DefaultMaxLine) throw new InvalidDataException($"event larger than {JsonLines.DefaultMaxLine} bytes");
            if (line is null)
            {
                if (pending) yield return (eventName, data.ToString());
                yield break;
            }
            if (line.Length == 0)
            {
                if (pending) yield return (eventName, data.ToString());
                eventName = "message";
                data.Clear();
                pending = false;
                continue;
            }
            if (line[0] == ':') continue;
            int colon = line.IndexOf(':');
            string field = colon < 0 ? line : line[..colon];
            string value = colon < 0 ? string.Empty : line[(colon + 1)..];
            if (value.StartsWith(' ')) value = value[1..];
            switch (field)
            {
                case "event": eventName = value; pending = true; break;
                case "data":
                    if (data.Length > 0) data.Append('\n');
                    data.Append(value);
                    pending = true;
                    break;
            }
        }
    }
}

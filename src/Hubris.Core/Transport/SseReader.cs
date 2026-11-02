using System.Runtime.CompilerServices;
using System.Text;

namespace Hubris.Transport;

/// <summary>Minimal text/event-stream parser: yields (event, data) per message; id/retry fields and comments are skipped.</summary>
public sealed class SseReader
{
    private readonly StreamReader _reader;

    public SseReader(Stream stream) => _reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 16 * 1024);

    public static IAsyncEnumerable<(string Event, string Data)> ReadAsync(Stream stream, CancellationToken ct) => new SseReader(stream).ReadAsync(ct);

    public async IAsyncEnumerable<(string Event, string Data)> ReadAsync([EnumeratorCancellation] CancellationToken ct)
    {
        string eventName = "message";
        var data = new StringBuilder();
        bool pending = false;
        while (true)
        {
            string? line = await _reader.ReadLineAsync(ct).ConfigureAwait(false);
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

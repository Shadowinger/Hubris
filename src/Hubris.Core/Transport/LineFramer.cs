using System.Buffers;

namespace Hubris.Transport;

/// <summary>Newline-delimited framing over a <see cref="ReadOnlySequence{T}"/> without copying.</summary>
public static class LineFramer
{
    /// <summary>
    /// Extracts the next complete line (without the trailing '\n' or "\r\n") from <paramref name="buffer"/>.
    /// On success the buffer is advanced past the delimiter. Empty lines are skipped.
    /// </summary>
    public static bool TryReadLine(ref ReadOnlySequence<byte> buffer, out ReadOnlySequence<byte> line)
    {
        while (true)
        {
            SequencePosition? nl = buffer.PositionOf((byte)'\n');
            if (nl is null)
            {
                line = default;
                return false;
            }

            line = buffer.Slice(0, nl.Value);
            buffer = buffer.Slice(buffer.GetPosition(1, nl.Value));

            line = TrimCr(line);
            if (line.Length == 0) continue; // keep-alive blank line; nothing to parse
            return true;
        }
    }

    public static ReadOnlySequence<byte> TrimCr(ReadOnlySequence<byte> line)
    {
        if (line.Length == 0) return line;
        if (line.IsSingleSegment)
        {
            ReadOnlySpan<byte> span = line.FirstSpan.TrimEnd((byte)'\r');
            return span.Length == line.Length ? line : line.Slice(0, span.Length);
        }

        // Multi-segment: inspect last byte without materialising the sequence.
        long len = line.Length;
        while (len > 0)
        {
            var last = line.Slice(len - 1, 1);
            if (last.FirstSpan[0] != (byte)'\r') break;
            len--;
        }
        return len == line.Length ? line : line.Slice(0, len);
    }
}

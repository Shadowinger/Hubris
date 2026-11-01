using System.Buffers;
using System.Text;
using System.Text.Json;
using Hubris.Protocol;
using Hubris.Transport;

namespace Hubris.Tests;

public class LineFramerTests
{
    private static ReadOnlySequence<byte> TwoSegments(string a, string b)
    {
        var first = new Segment(Encoding.UTF8.GetBytes(a));
        var last = first.Append(Encoding.UTF8.GetBytes(b));
        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory) => Memory = memory;
        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory) { RunningIndex = RunningIndex + Memory.Length };
            Next = next;
            return next;
        }
    }

    [Fact]
    public void Splits_lines_and_strips_cr()
    {
        var buffer = new ReadOnlySequence<byte>("{\"a\":1}\r\n\n{\"b\":2}\npartial"u8.ToArray());
        Assert.True(LineFramer.TryReadLine(ref buffer, out var l1));
        Assert.Equal("{\"a\":1}", Encoding.UTF8.GetString(l1));
        Assert.True(LineFramer.TryReadLine(ref buffer, out var l2)); // empty line skipped
        Assert.Equal("{\"b\":2}", Encoding.UTF8.GetString(l2));
        Assert.False(LineFramer.TryReadLine(ref buffer, out _));
        Assert.Equal("partial", Encoding.UTF8.GetString(buffer));
    }

    [Fact]
    public void Line_spanning_two_segments_is_read_without_copy()
    {
        var buffer = TwoSegments("{\"id\":", "1}\r\n");
        Assert.True(LineFramer.TryReadLine(ref buffer, out var line));
        Assert.False(line.IsSingleSegment);
        var reader = new Utf8JsonReader(line, isFinalBlock: true, state: default);
        var msg = JsonSerializer.Deserialize(ref reader, McpJsonContext.Default.JsonRpcMessage);
        Assert.Equal(RpcId.FromNumber(1), msg!.Id);
    }
}

public class RpcIdTests
{
    [Theory]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}", "7")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"method\":\"ping\"}", "\"abc\"")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}", "null")]
    public void Id_type_survives_round_trip(string json, string expectedIdJson)
    {
        var msg = JsonSerializer.Deserialize(json, McpJsonContext.Default.JsonRpcMessage)!;
        string back = JsonSerializer.Serialize(msg, McpJsonContext.Default.JsonRpcMessage);
        Assert.Contains("\"id\":" + expectedIdJson, back);
    }

    [Fact]
    public void Notification_has_no_id_property()
    {
        var msg = new JsonRpcMessage { Method = "notifications/initialized" };
        Assert.True(msg.Id.IsNone);
        Assert.DoesNotContain("\"id\"", JsonSerializer.Serialize(msg, McpJsonContext.Default.JsonRpcMessage));
    }
}

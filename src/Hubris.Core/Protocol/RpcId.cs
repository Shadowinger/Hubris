using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hubris.Protocol;

public enum RpcIdKind : byte
{
    /// <summary>Property absent (notification).</summary>
    None = 0,
    /// <summary>Explicit JSON null.</summary>
    Null = 1,
    Number = 2,
    String = 3,
}

/// <summary>
/// JSON-RPC 2.0 request identifier. Preserves the exact wire type (number vs string vs null)
/// so responses echo the id byte-for-byte. Value equality makes it a dictionary key.
/// </summary>
[JsonConverter(typeof(RpcIdConverter))]
public readonly record struct RpcId(RpcIdKind Kind, long Number, string? Text)
{
    public static readonly RpcId None = default;
    public static readonly RpcId Null = new(RpcIdKind.Null, 0, null);

    public static RpcId FromNumber(long value) => new(RpcIdKind.Number, value, null);
    public static RpcId FromString(string value) => new(RpcIdKind.String, 0, value);

    public bool IsNone => Kind == RpcIdKind.None;

    public override string ToString() => Kind switch
    {
        RpcIdKind.Number => Number.ToString(System.Globalization.CultureInfo.InvariantCulture),
        RpcIdKind.String => Text ?? string.Empty,
        RpcIdKind.Null => "null",
        _ => "<none>",
    };

    public void WriteTo(Utf8JsonWriter writer)
    {
        switch (Kind)
        {
            case RpcIdKind.Number: writer.WriteNumberValue(Number); break;
            case RpcIdKind.String: writer.WriteStringValue(Text); break;
            default: writer.WriteNullValue(); break;
        }
    }
}

public sealed class RpcIdConverter : JsonConverter<RpcId>
{
    public override bool HandleNull => true;

    public override RpcId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Number:
                if (reader.TryGetInt64(out long l)) return RpcId.FromNumber(l);
                // Non-integral numeric ids are not valid per spec; keep the textual form.
                return RpcId.FromString(reader.GetDouble().ToString(System.Globalization.CultureInfo.InvariantCulture));
            case JsonTokenType.String:
                return RpcId.FromString(reader.GetString() ?? string.Empty);
            case JsonTokenType.Null:
                return RpcId.Null;
            default:
                throw new JsonException($"Invalid JSON-RPC id token: {reader.TokenType}");
        }
    }

    public override void Write(Utf8JsonWriter writer, RpcId value, JsonSerializerOptions options)
        => value.WriteTo(writer);
}

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Hubris.Protocol;

[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    GenerationMode = JsonSourceGenerationMode.Default)]
[JsonSerializable(typeof(JsonRpcMessage))]
[JsonSerializable(typeof(JsonRpcError))]
[JsonSerializable(typeof(RpcId))]
[JsonSerializable(typeof(Implementation))]
[JsonSerializable(typeof(InitializeParams))]
[JsonSerializable(typeof(InitializeResult))]
[JsonSerializable(typeof(ServerCapabilities))]
[JsonSerializable(typeof(ToolsCapability))]
[JsonSerializable(typeof(ToolAnnotations))]
[JsonSerializable(typeof(ToolDefinition))]
[JsonSerializable(typeof(List<ToolDefinition>))]
[JsonSerializable(typeof(ListToolsResult))]
[JsonSerializable(typeof(CallToolParams))]
[JsonSerializable(typeof(CallToolResult))]
[JsonSerializable(typeof(ContentBlock))]
[JsonSerializable(typeof(List<ContentBlock>))]
[JsonSerializable(typeof(CancelledParams))]
[JsonSerializable(typeof(EmptyResult))]
[JsonSerializable(typeof(EmptyListResult))]
[JsonSerializable(typeof(JsonNode))]
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(JsonArray))]
[JsonSerializable(typeof(JsonValue))]
[JsonSerializable(typeof(JsonElement))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(double))]
public sealed partial class McpJsonContext : JsonSerializerContext
{
}

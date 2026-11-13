using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Hubris.Protocol;

/// <summary>Single wire shape for JSON-RPC requests, responses and notifications.</summary>
public sealed class JsonRpcMessage
{
    [JsonPropertyName("jsonrpc")] public string JsonRpc { get; set; } = "2.0";

    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public RpcId Id { get; set; }

    [JsonPropertyName("method")] public string? Method { get; set; }
    [JsonPropertyName("params")] public JsonNode? Params { get; set; }
    [JsonPropertyName("result")] public JsonNode? Result { get; set; }
    [JsonPropertyName("error")] public JsonRpcError? Error { get; set; }
}

public sealed class JsonRpcError
{
    [JsonPropertyName("code")] public int Code { get; set; }
    [JsonPropertyName("message")] public string Message { get; set; } = string.Empty;
    [JsonPropertyName("data")] public JsonNode? Data { get; set; }
}

/// <summary>The JSON-RPC shapes written by hand, shared by the stdio transport and both bridge kinds.</summary>
public static class JsonRpcFrames
{
    /// <summary>A request, or a notification when <paramref name="id"/> is <see cref="RpcId.None"/>.</summary>
    public static void Call(Utf8JsonWriter w, RpcId id, string method, JsonNode? parameters)
    {
        w.WriteStartObject();
        w.WriteString("jsonrpc"u8, "2.0"u8);
        if (!id.IsNone) { w.WritePropertyName("id"u8); id.WriteTo(w); }
        w.WriteString("method"u8, method);
        if (parameters is not null) { w.WritePropertyName("params"u8); parameters.WriteTo(w); }
        w.WriteEndObject();
    }

    public static void Error(Utf8JsonWriter w, RpcId id, int code, string message, JsonNode? data = null)
    {
        w.WriteStartObject();
        w.WriteString("jsonrpc"u8, "2.0"u8);
        w.WritePropertyName("id"u8);
        id.WriteTo(w);
        w.WritePropertyName("error"u8);
        w.WriteStartObject();
        w.WriteNumber("code"u8, code);
        w.WriteString("message"u8, message);
        if (data is not null) { w.WritePropertyName("data"u8); data.WriteTo(w); }
        w.WriteEndObject();
        w.WriteEndObject();
    }

    /// <summary>The answer to a ping.</summary>
    public static void EmptyResult(Utf8JsonWriter w, RpcId id)
    {
        w.WriteStartObject();
        w.WriteString("jsonrpc"u8, "2.0"u8);
        w.WritePropertyName("id"u8);
        id.WriteTo(w);
        w.WritePropertyName("result"u8);
        w.WriteStartObject();
        w.WriteEndObject();
        w.WriteEndObject();
    }
}

public static class JsonRpcErrorCodes
{
    public const int ParseError = -32700;
    public const int InvalidRequest = -32600;
    public const int MethodNotFound = -32601;
    public const int InvalidParams = -32602;
    public const int InternalError = -32603;
    public const int RequestCancelled = -32800;
}

public static class McpProtocol
{
    public const string Latest = "2025-06-18";
    public static readonly string[] Supported = ["2025-06-18", "2025-03-26", "2024-11-05"];

    public static string Negotiate(string? requested)
    {
        if (requested is null) return Latest;
        foreach (var v in Supported)
            if (string.Equals(v, requested, StringComparison.Ordinal)) return v;
        return Latest;
    }
}

public sealed class Implementation
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("version")] public string Version { get; set; } = string.Empty;
}

public sealed class InitializeParams
{
    [JsonPropertyName("protocolVersion")] public string? ProtocolVersion { get; set; }
    [JsonPropertyName("capabilities")] public JsonObject? Capabilities { get; set; }
    [JsonPropertyName("clientInfo")] public Implementation? ClientInfo { get; set; }
}

public sealed class ToolsCapability
{
    [JsonPropertyName("listChanged")] public bool ListChanged { get; set; } = true;
}

public sealed class ServerCapabilities
{
    [JsonPropertyName("tools")] public ToolsCapability Tools { get; set; } = new();
    [JsonPropertyName("resources")] public ToolsCapability Resources { get; set; } = new();
    [JsonPropertyName("prompts")] public ToolsCapability Prompts { get; set; } = new();
}

/// <summary>What a bridge offers besides tools: passed through as the server sent them, names of prompts get the bridge prefix.</summary>
public sealed class BridgeExtras
{
    [JsonPropertyName("resources")] public List<JsonObject> Resources { get; set; } = new();
    [JsonPropertyName("resourceTemplates")] public List<JsonObject> ResourceTemplates { get; set; } = new();
    [JsonPropertyName("prompts")] public List<JsonObject> Prompts { get; set; } = new();

    public bool IsEmpty => Resources.Count == 0 && ResourceTemplates.Count == 0 && Prompts.Count == 0;
}

public sealed class ListResourcesResult
{
    [JsonPropertyName("resources")] public List<JsonObject> Resources { get; set; } = new();
    [JsonPropertyName("nextCursor")] public string? NextCursor { get; set; }
}

public sealed class ListResourceTemplatesResult
{
    [JsonPropertyName("resourceTemplates")] public List<JsonObject> ResourceTemplates { get; set; } = new();
    [JsonPropertyName("nextCursor")] public string? NextCursor { get; set; }
}

public sealed class ListPromptsResult
{
    [JsonPropertyName("prompts")] public List<JsonObject> Prompts { get; set; } = new();
    [JsonPropertyName("nextCursor")] public string? NextCursor { get; set; }
}

public sealed class InitializeResult
{
    [JsonPropertyName("protocolVersion")] public string ProtocolVersion { get; set; } = McpProtocol.Latest;
    [JsonPropertyName("capabilities")] public ServerCapabilities Capabilities { get; set; } = new();
    [JsonPropertyName("serverInfo")] public Implementation ServerInfo { get; set; } = new();
    [JsonPropertyName("instructions")] public string? Instructions { get; set; }
}

public sealed class ToolAnnotations
{
    [JsonPropertyName("title")] public string? Title { get; set; }
    [JsonPropertyName("readOnlyHint")] public bool? ReadOnlyHint { get; set; }
    [JsonPropertyName("destructiveHint")] public bool? DestructiveHint { get; set; }
    [JsonPropertyName("idempotentHint")] public bool? IdempotentHint { get; set; }
    [JsonPropertyName("openWorldHint")] public bool? OpenWorldHint { get; set; }
}

public sealed class ToolDefinition
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("description")] public string? Description { get; set; }
    [JsonPropertyName("inputSchema")] public JsonObject? InputSchema { get; set; }
    [JsonPropertyName("annotations")] public ToolAnnotations? Annotations { get; set; }
}

public sealed class ListToolsResult
{
    [JsonPropertyName("tools")] public List<ToolDefinition> Tools { get; set; } = new();
    [JsonPropertyName("nextCursor")] public string? NextCursor { get; set; }
}

public sealed class CallToolParams
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("arguments")] public JsonObject? Arguments { get; set; }
}

public sealed class ContentBlock
{
    [JsonPropertyName("type")] public string Type { get; set; } = "text";
    [JsonPropertyName("text")] public string? Text { get; set; }
    [JsonPropertyName("data")] public string? Data { get; set; }
    [JsonPropertyName("mimeType")] public string? MimeType { get; set; }
    /// <summary>Everything else a server put in the block (an embedded resource, a link's uri and name, annotations): passed on as it came.</summary>
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }

    public static ContentBlock FromText(string text) => new() { Type = "text", Text = text };
}

public sealed class CallToolResult
{
    [JsonPropertyName("content")] public List<ContentBlock> Content { get; set; } = new();
    [JsonPropertyName("isError")] public bool? IsError { get; set; }
    /// <summary>structuredContent, _meta and whatever a later protocol version adds.</summary>
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }

    [JsonIgnore] public bool Failed => IsError == true;

    public static CallToolResult Text(string text) => new() { Content = { ContentBlock.FromText(text) } };
    public static CallToolResult Error(string text) => new() { Content = { ContentBlock.FromText(text) }, IsError = true };
}

public sealed class CancelledParams
{
    [JsonPropertyName("requestId")] public RpcId RequestId { get; set; }
    [JsonPropertyName("reason")] public string? Reason { get; set; }
}

/// <summary>Empty result object for ping.</summary>
public sealed class EmptyResult
{
}

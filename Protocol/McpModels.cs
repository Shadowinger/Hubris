using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace McpHub.Protocol;

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

    [JsonIgnore] public bool IsNotification => Method is not null && Id.IsNone;
    [JsonIgnore] public bool IsRequest => Method is not null && !Id.IsNone;
    [JsonIgnore] public bool IsResponse => Method is null && (Result is not null || Error is not null);
}

public sealed class JsonRpcError
{
    [JsonPropertyName("code")] public int Code { get; set; }
    [JsonPropertyName("message")] public string Message { get; set; } = string.Empty;
    [JsonPropertyName("data")] public JsonNode? Data { get; set; }
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

public sealed class ListToolsParams
{
    [JsonPropertyName("cursor")] public string? Cursor { get; set; }
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

    public static ContentBlock FromText(string text) => new() { Type = "text", Text = text };
}

public sealed class CallToolResult
{
    [JsonPropertyName("content")] public List<ContentBlock> Content { get; set; } = new();
    [JsonPropertyName("isError")] public bool? IsError { get; set; }

    [JsonIgnore] public bool Failed => IsError == true;

    public static CallToolResult Text(string text) => new() { Content = { ContentBlock.FromText(text) } };
    public static CallToolResult Error(string text) => new() { Content = { ContentBlock.FromText(text) }, IsError = true };
}

public sealed class CancelledParams
{
    [JsonPropertyName("requestId")] public RpcId RequestId { get; set; }
    [JsonPropertyName("reason")] public string? Reason { get; set; }
}

/// <summary>Empty result object for ping / resources/list / prompts/list.</summary>
public sealed class EmptyResult
{
}

public sealed class EmptyListResult
{
    [JsonPropertyName("resources")] public List<JsonObject>? Resources { get; set; }
    [JsonPropertyName("prompts")] public List<JsonObject>? Prompts { get; set; }
}

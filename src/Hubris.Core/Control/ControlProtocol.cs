using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Hubris.Control;

/// <summary>
/// One flat message shape for the control channel (newline-delimited JSON over a Unix domain socket).
/// Direction is implied by <see cref="Type"/>: events flow hub → UI, commands flow UI → hub.
/// </summary>
public sealed class ControlMessage
{
    // ---- envelope
    [JsonPropertyName("type")] public string Type { get; set; } = string.Empty;
    [JsonPropertyName("reqId")] public long? ReqId { get; set; }
    [JsonPropertyName("ts")] public string? Timestamp { get; set; }

    // ---- hello / status
    [JsonPropertyName("pid")] public int? Pid { get; set; }
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("mode")] public string? Mode { get; set; }
    [JsonPropertyName("compact")] public bool? Compact { get; set; }
    [JsonPropertyName("cwd")] public string? Cwd { get; set; }
    [JsonPropertyName("client")] public string? Client { get; set; }
    [JsonPropertyName("startedAt")] public string? StartedAt { get; set; }
    [JsonPropertyName("uptimeSec")] public double? UptimeSec { get; set; }
    [JsonPropertyName("rssBytes")] public long? RssBytes { get; set; }
    [JsonPropertyName("heapBytes")] public long? HeapBytes { get; set; }
    [JsonPropertyName("cacheHits")] public long? CacheHits { get; set; }
    [JsonPropertyName("cacheMisses")] public long? CacheMisses { get; set; }
    [JsonPropertyName("cacheSize")] public int? CacheSize { get; set; }
    [JsonPropertyName("cacheCapacity")] public int? CacheCapacity { get; set; }
    [JsonPropertyName("blocked")] public long? Blocked { get; set; }
    [JsonPropertyName("dlpRedactions")] public long? DlpRedactions { get; set; }
    [JsonPropertyName("toolCount")] public int? ToolCount { get; set; }
    [JsonPropertyName("bridgeCount")] public int? BridgeCount { get; set; }
    [JsonPropertyName("bridgesRunning")] public int? BridgesRunning { get; set; }
    [JsonPropertyName("pendingApprovals")] public int? PendingApprovals { get; set; }
    [JsonPropertyName("activeTools")] public int? ActiveTools { get; set; }
    [JsonPropertyName("activeTokens")] public int? ActiveTokens { get; set; }
    [JsonPropertyName("totalTokens")] public int? TotalTokens { get; set; }
    [JsonPropertyName("clients")] public int? Clients { get; set; }
    [JsonPropertyName("tools")] public List<ToolInfo>? Tools { get; set; }
    [JsonPropertyName("bridges")] public List<string>? Bridges { get; set; }
    [JsonPropertyName("bridgesStale")] public List<string>? BridgesStale { get; set; }
    [JsonPropertyName("decisions")] public List<ToolDecision>? Decisions { get; set; }
    /// <summary>OAuth state per bridge that has an auth block.</summary>
    [JsonPropertyName("auth")] public List<AuthInfo>? Auth { get; set; }
    /// <summary>oauth_start / oauth_revoke target.</summary>
    [JsonPropertyName("bridge")] public string? Bridge { get; set; }

    // ---- tool_call
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("tool")] public string? Tool { get; set; }
    [JsonPropertyName("risk")] public string? Risk { get; set; }
    [JsonPropertyName("outcome")] public string? Outcome { get; set; }
    [JsonPropertyName("durationMs")] public double? DurationMs { get; set; }
    [JsonPropertyName("args")] public JsonNode? Args { get; set; }
    [JsonPropertyName("preview")] public string? Preview { get; set; }

    // ---- approval_request / approval_resolved / approve / deny
    [JsonPropertyName("approvalId")] public string? ApprovalId { get; set; }
    [JsonPropertyName("reason")] public string? Reason { get; set; }
    [JsonPropertyName("decision")] public string? Decision { get; set; }
    [JsonPropertyName("timeoutSec")] public double? TimeoutSec { get; set; }
    [JsonPropertyName("remember")] public bool? Remember { get; set; }

    // ---- log
    [JsonPropertyName("level")] public string? Level { get; set; }
    [JsonPropertyName("text")] public string? Text { get; set; }

    // ---- ack
    [JsonPropertyName("ok")] public bool? Ok { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }

    public static ControlMessage Of(string type) => new() { Type = type, Timestamp = DateTime.UtcNow.ToString("O") };
}

public sealed class ToolInfo
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("description")] public string Description { get; set; } = string.Empty;
    [JsonPropertyName("risk")] public string Risk { get; set; } = string.Empty;
    [JsonPropertyName("pinned")] public bool Pinned { get; set; }
    [JsonPropertyName("visible")] public bool Visible { get; set; }
    [JsonPropertyName("unlocked")] public bool Unlocked { get; set; }
    [JsonPropertyName("tokens")] public int Tokens { get; set; }
    [JsonPropertyName("bridge")] public string? Bridge { get; set; }
    /// <summary>Remembered session decision for this tool: "always", "never", or null.</summary>
    [JsonPropertyName("decision")] public string? Decision { get; set; }
}

/// <summary>Sign-in state of one bridge's OAuth provider.</summary>
public sealed class AuthInfo
{
    [JsonPropertyName("bridge")] public string Bridge { get; set; } = string.Empty;
    [JsonPropertyName("provider")] public string Provider { get; set; } = string.Empty;
    /// <summary>connected, expired, none, pending, error.</summary>
    [JsonPropertyName("state")] public string State { get; set; } = string.Empty;
    [JsonPropertyName("expiresAt")] public string? ExpiresAt { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("env")] public string? Env { get; set; }
}

/// <summary>A remembered per-tool Safe-mode decision carried in status/hello.</summary>
public sealed class ToolDecision
{
    [JsonPropertyName("tool")] public string Tool { get; set; } = string.Empty;
    [JsonPropertyName("allow")] public bool Allow { get; set; }
}

/// <summary>Discovery record written to the runtime directory so UIs can find running hubs.</summary>
public sealed class HubDescriptor
{
    [JsonPropertyName("pid")] public int Pid { get; set; }
    [JsonPropertyName("socket")] public string Socket { get; set; } = string.Empty;
    [JsonPropertyName("cwd")] public string Cwd { get; set; } = string.Empty;
    [JsonPropertyName("startedAt")] public string StartedAt { get; set; } = string.Empty;
    [JsonPropertyName("version")] public string Version { get; set; } = string.Empty;
    [JsonPropertyName("mode")] public string Mode { get; set; } = string.Empty;
    [JsonPropertyName("compact")] public bool Compact { get; set; }
    [JsonPropertyName("client")] public string? Client { get; set; }
}

public static class ControlTypes
{
    // events (hub → ui)
    public const string Hello = "hello";
    public const string Status = "status";
    public const string ToolCall = "tool_call";
    public const string ApprovalRequest = "approval_request";
    public const string ApprovalResolved = "approval_resolved";
    public const string ToolsChanged = "tools_changed";
    public const string ModeChanged = "mode_changed";
    public const string Log = "log";
    public const string Ack = "ack";
    public const string OAuthChanged = "oauth_changed";

    // commands (ui → hub)
    public const string GetStatus = "get_status";
    public const string ListTools = "list_tools";
    public const string SetMode = "set_mode";
    public const string Approve = "approve";
    public const string Deny = "deny";
    public const string Reveal = "reveal";
    public const string Lock = "lock";
    public const string Forget = "forget";
    public const string ListDecisions = "list_decisions";
    public const string ClearCache = "clear_cache";
    public const string ReloadConfig = "reload_config";
    public const string CacheMaintain = "cache_maintain";
    public const string Shutdown = "shutdown";
    public const string OAuthStart = "oauth_start";
    public const string OAuthStatus = "oauth_status";
    public const string OAuthRevoke = "oauth_revoke";
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, WriteIndented = false)]
[JsonSerializable(typeof(ControlMessage))]
[JsonSerializable(typeof(ToolInfo))]
[JsonSerializable(typeof(List<ToolInfo>))]
[JsonSerializable(typeof(ToolDecision))]
[JsonSerializable(typeof(List<ToolDecision>))]
[JsonSerializable(typeof(AuthInfo))]
[JsonSerializable(typeof(List<AuthInfo>))]
[JsonSerializable(typeof(HubDescriptor))]
public sealed partial class ControlJsonContext : JsonSerializerContext
{
}

/// <summary>Well-known locations shared by the hub and the desktop UI.</summary>
public static class HubrisPaths
{
    /// <summary>~/.hubris, or HUBRIS_HOME (tests point it at a temp dir).</summary>
    public static string HomeDir
    {
        get
        {
            string? env = Environment.GetEnvironmentVariable("HUBRIS_HOME");
            if (!string.IsNullOrEmpty(env)) return env;
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrEmpty(home)) home = Path.GetTempPath();
            return Path.Combine(home, ".hubris");
        }
    }

    public static string RuntimeDir
    {
        get
        {
            string? env = Environment.GetEnvironmentVariable("HUBRIS_RUNTIME_DIR");
            return !string.IsNullOrEmpty(env) ? env : Path.Combine(HomeDir, "run");
        }
    }

    public static string ConfigPath => Path.Combine(HomeDir, "config.json");
    public static string BackupsDir => Path.Combine(HomeDir, "backups");
    public static string CacheDbPath => Path.Combine(HomeDir, "cache", "tools_cache.db");

    public static string SocketPath(int pid) => Path.Combine(RuntimeDir, pid.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".sock");
    public static string DescriptorPath(int pid) => Path.Combine(RuntimeDir, pid.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".json");
}

using System.Text.Json.Serialization;

namespace Hubris.Auth;

/// <summary>RFC 9728: where the MCP server says its authorization server lives.</summary>
public sealed class ProtectedResourceMetadata
{
    [JsonPropertyName("resource")] public string? Resource { get; set; }
    [JsonPropertyName("authorization_servers")] public List<string>? AuthorizationServers { get; set; }
    [JsonPropertyName("scopes_supported")] public List<string>? ScopesSupported { get; set; }
}

/// <summary>RFC 8414 (and the OpenID discovery document, same fields).</summary>
public sealed class AuthServerMetadata
{
    [JsonPropertyName("issuer")] public string? Issuer { get; set; }
    [JsonPropertyName("authorization_endpoint")] public string? AuthorizationEndpoint { get; set; }
    [JsonPropertyName("token_endpoint")] public string? TokenEndpoint { get; set; }
    [JsonPropertyName("registration_endpoint")] public string? RegistrationEndpoint { get; set; }
    [JsonPropertyName("revocation_endpoint")] public string? RevocationEndpoint { get; set; }
    [JsonPropertyName("code_challenge_methods_supported")] public List<string>? CodeChallengeMethodsSupported { get; set; }
    [JsonPropertyName("scopes_supported")] public List<string>? ScopesSupported { get; set; }
}

/// <summary>RFC 7591 request and response for dynamic client registration.</summary>
public sealed class ClientRegistration
{
    [JsonPropertyName("client_name")] public string? ClientName { get; set; }
    [JsonPropertyName("redirect_uris")] public List<string>? RedirectUris { get; set; }
    [JsonPropertyName("grant_types")] public List<string>? GrantTypes { get; set; }
    [JsonPropertyName("response_types")] public List<string>? ResponseTypes { get; set; }
    [JsonPropertyName("token_endpoint_auth_method")] public string? TokenEndpointAuthMethod { get; set; }
    [JsonPropertyName("scope")] public string? Scope { get; set; }
    [JsonPropertyName("client_id")] public string? ClientId { get; set; }
    [JsonPropertyName("client_secret")] public string? ClientSecret { get; set; }
}

public sealed class TokenResponse
{
    [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
    [JsonPropertyName("token_type")] public string? TokenType { get; set; }
    [JsonPropertyName("expires_in")] public long? ExpiresIn { get; set; }
    [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
    [JsonPropertyName("scope")] public string? Scope { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("error_description")] public string? ErrorDescription { get; set; }
}

/// <summary>What the secure store keeps per provider: enough to refresh without touching discovery again.</summary>
public sealed class StoredToken
{
    [JsonPropertyName("access_token")] public string AccessToken { get; set; } = string.Empty;
    [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
    /// <summary>Unix seconds; 0 when the server gave no expiry.</summary>
    [JsonPropertyName("expires_at")] public long ExpiresAt { get; set; }
    [JsonPropertyName("token_endpoint")] public string TokenEndpoint { get; set; } = string.Empty;
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = string.Empty;
    [JsonPropertyName("client_secret")] public string? ClientSecret { get; set; }
    [JsonPropertyName("resource")] public string? Resource { get; set; }
    [JsonPropertyName("scope")] public string? Scope { get; set; }
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, WriteIndented = false)]
[JsonSerializable(typeof(ProtectedResourceMetadata))]
[JsonSerializable(typeof(AuthServerMetadata))]
[JsonSerializable(typeof(ClientRegistration))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(StoredToken))]
[JsonSerializable(typeof(Dictionary<string, StoredToken>))]
public sealed partial class AuthJsonContext : JsonSerializerContext
{
}

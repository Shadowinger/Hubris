using System.Buffers.Text;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hubris.Transport;

namespace Hubris.Auth;

public sealed class OAuthException : Exception
{
    public OAuthException(string message, string? error = null) : base(message) => Error = error;
    /// <summary>The token endpoint's "error" code (invalid_grant, ...), when the failure came from there.</summary>
    public string? Error { get; }
}

/// <summary>Resolved endpoints for one MCP server, found through RFC 9728 → RFC 8414 (with the usual fallbacks).</summary>
/// <param name="DefaultScope">scopes_supported from the protected-resource metadata (the spec's default when the config names none), plus offline_access when the authorization server offers it, so a refresh token comes back.</param>
public sealed record OAuthEndpoints(string AuthorizationEndpoint, string TokenEndpoint, string? RegistrationEndpoint, string Resource, string? DefaultScope = null);

/// <summary>
/// The authorization-code + PKCE dance, in plain HttpClient and one TcpListener: discover, (register,) open the
/// browser, catch the redirect on 127.0.0.1, exchange the code. Everything static and stateless so it is easy to test.
/// </summary>
public static class OAuthPkceFlow
{
    public const string ClientName = "Hubris";

    // ------------------------------------------------------------------ PKCE

    public static (string Verifier, string Challenge) CreatePkce()
    {
        Span<byte> raw = stackalloc byte[32];
        RandomNumberGenerator.Fill(raw);
        string verifier = Base64Url.EncodeToString(raw); // 43 chars from the RFC 7636 unreserved set
        return (verifier, Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    // ------------------------------------------------------------------ discovery

    /// <summary>
    /// <paramref name="resource"/> is the MCP server URL. Its origin (or <paramref name="issuerHint"/>) is asked for
    /// protected-resource metadata; the authorization server named there is asked for its metadata. A server that
    /// publishes nothing gets the conventional /authorize and /token at the issuer.
    /// </summary>
    public static async Task<OAuthEndpoints> DiscoverAsync(HttpClient http, string resource, string? issuerHint, CancellationToken ct)
    {
        var resourceUri = new Uri(resource, UriKind.Absolute);
        string origin = resourceUri.GetLeftPart(UriPartial.Authority);
        string issuer = issuerHint ?? origin;

        var prm = await GetJsonAsync(http, origin + "/.well-known/oauth-protected-resource", AuthJsonContext.Default.ProtectedResourceMetadata, ct).ConfigureAwait(false)
                  ?? await GetJsonAsync(http, origin + "/.well-known/oauth-protected-resource" + resourceUri.AbsolutePath, AuthJsonContext.Default.ProtectedResourceMetadata, ct).ConfigureAwait(false);
        if (issuerHint is null && prm?.AuthorizationServers is { Count: > 0 } servers) issuer = servers[0];
        issuer = issuer.TrimEnd('/');

        var issuerUri = new Uri(issuer, UriKind.Absolute);
        string asOrigin = issuerUri.GetLeftPart(UriPartial.Authority);
        string path = issuerUri.AbsolutePath.TrimEnd('/');
        AuthServerMetadata? meta =
            (path.Length > 0 ? await GetJsonAsync(http, asOrigin + "/.well-known/oauth-authorization-server" + path, AuthJsonContext.Default.AuthServerMetadata, ct).ConfigureAwait(false) : null)
            ?? await GetJsonAsync(http, asOrigin + "/.well-known/oauth-authorization-server", AuthJsonContext.Default.AuthServerMetadata, ct).ConfigureAwait(false)
            ?? (path.Length > 0 ? await GetJsonAsync(http, asOrigin + "/.well-known/openid-configuration" + path, AuthJsonContext.Default.AuthServerMetadata, ct).ConfigureAwait(false) : null)
            ?? await GetJsonAsync(http, issuer + "/.well-known/openid-configuration", AuthJsonContext.Default.AuthServerMetadata, ct).ConfigureAwait(false);

        string authz = meta?.AuthorizationEndpoint ?? issuer + "/authorize";
        string token = meta?.TokenEndpoint ?? issuer + "/token";
        // The server chooses these, and the first one is handed to the system's "open": nothing but a web address may pass.
        foreach (var (what, url) in new[] { ("authorization", authz), ("token", token), ("registration", meta?.RegistrationEndpoint) })
            if (url is not null && !IsWebUrl(url)) throw new OAuthException($"the server's {what} endpoint is not an https address: {Trim(url)}");
        var scopes = new List<string>(prm?.ScopesSupported ?? []);
        if (meta?.ScopesSupported?.Contains("offline_access") == true && !scopes.Contains("offline_access")) scopes.Add("offline_access");
        string? scope = scopes.Count > 0 ? string.Join(' ', scopes) : null;
        return new OAuthEndpoints(authz, token, meta?.RegistrationEndpoint, prm?.Resource ?? resource, scope);
    }

    /// <summary>https anywhere; plain http only to this machine.</summary>
    public static bool IsWebUrl(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || (u.Scheme == Uri.UriSchemeHttp && u.IsLoopback));

    private static async Task<T?> GetJsonAsync<T>(HttpClient http, string url, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, CancellationToken ct) where T : class
    {
        try
        {
            using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;
            await using var s = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync(s, type, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or IOException)
        {
            Log.Debug($"oauth discovery {url}: {ex.Message}");
            return null;
        }
    }

    // ------------------------------------------------------------------ registration

    public static async Task<ClientRegistration> RegisterAsync(HttpClient http, string registrationEndpoint, string redirectUri, string? scope, CancellationToken ct)
    {
        var req = new ClientRegistration
        {
            ClientName = ClientName,
            RedirectUris = [redirectUri],
            GrantTypes = ["authorization_code", "refresh_token"],
            ResponseTypes = ["code"],
            TokenEndpointAuthMethod = "none",
            Scope = scope,
        };
        using var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(req, AuthJsonContext.Default.ClientRegistration));
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        using var resp = await http.PostAsync(registrationEndpoint, content, ct).ConfigureAwait(false);
        string body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) throw new OAuthException($"client registration failed: HTTP {(int)resp.StatusCode} {Trim(body)}");
        var reg = JsonSerializer.Deserialize(body, AuthJsonContext.Default.ClientRegistration);
        if (reg?.ClientId is null or "") throw new OAuthException("client registration returned no client_id");
        return reg;
    }

    // ------------------------------------------------------------------ loopback

    /// <summary>One-shot HTTP server on 127.0.0.1:0. <see cref="RedirectUri"/> is ready right after construction.</summary>
    public sealed class LoopbackListener : IDisposable
    {
        private readonly TcpListener _listener;

        public LoopbackListener()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start(1);
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        }

        public int Port { get; }
        public string RedirectUri => $"http://127.0.0.1:{Port}/callback";

        /// <summary>
        /// Waits for the GET /callback that carries <paramref name="state"/> and answers it with a page that closes itself.
        /// Anything else that reaches the port (a favicon probe, another page guessing the address) is turned away and the wait goes on.
        /// </summary>
        public async Task<Dictionary<string, string>> WaitForCallbackAsync(string state, CancellationToken ct)
        {
            while (true)
            {
                using var client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                // One connection at a time: a browser's spare socket that never sends anything, or one that is reset,
                // must not hold up or end the wait for the real redirect.
                using var one = CancellationTokenSource.CreateLinkedTokenSource(ct);
                one.CancelAfter(TimeSpan.FromSeconds(5));
                try
                {
                    using var stream = client.GetStream();
                    string head = await ReadHeadAsync(stream, one.Token).ConfigureAwait(false);
                    int sp1 = head.IndexOf(' '), sp2 = sp1 < 0 ? -1 : head.IndexOf(' ', sp1 + 1);
                    string target = sp1 < 0 || sp2 < 0 ? "/" : head[(sp1 + 1)..sp2];
                    if (!target.StartsWith("/callback", StringComparison.Ordinal))
                    {
                        await WriteAsync(stream, "404 Not Found", Page(false, "Nothing here", "This address only receives the sign-in redirect."), one.Token).ConfigureAwait(false);
                        continue; // a browser's favicon probe must not consume the callback
                    }
                    var query = ParseQuery(target);
                    if (query.GetValueOrDefault("state") != state)
                    {
                        await WriteAsync(stream, "400 Bad Request", Page(false, "Not this sign-in", "This is not the sign-in Hubris is waiting for."), one.Token).ConfigureAwait(false);
                        continue;
                    }
                    string html = query.ContainsKey("error")
                        ? Page(false, "Sign-in failed", WebUtility.HtmlEncode(query.GetValueOrDefault("error_description") is { Length: > 0 } why ? why : query["error"]))
                        : Page(true, "Hubris is connected", "You can close this tab and go back to your client.");
                    try { await WriteAsync(stream, "200 OK", html, one.Token).ConfigureAwait(false); }
                    catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !ct.IsCancellationRequested)) { } // the code is in hand; the page is a courtesy
                    return query;
                }
                catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
                {
                    Log.Debug($"oauth callback: dropped a connection ({ex.Message})");
                }
            }
        }

        private static async Task<string> ReadHeadAsync(NetworkStream s, CancellationToken ct)
        {
            var buf = new byte[8192];
            int n = 0;
            while (n < buf.Length)
            {
                int r = await s.ReadAsync(buf.AsMemory(n), ct).ConfigureAwait(false);
                if (r == 0) break;
                n += r;
                if (buf.AsSpan(0, n).IndexOf("\r\n\r\n"u8) >= 0) break;
            }
            return Encoding.ASCII.GetString(buf, 0, n);
        }

        /// <summary>
        /// The page the browser lands on, in the desktop app's look (its colours, its square status tag, the mark).
        /// Self-contained: no font, image or script comes from the network. <paramref name="detail"/> is HTML and must arrive encoded.
        /// </summary>
        public static string Page(bool ok, string title, string detail) => $$"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark">
            <title>Hubris</title>
            <style>
            *{box-sizing:border-box}
            body{margin:0;min-height:100vh;padding:0 16px 12vh;display:grid;place-items:center;background:#08090A;color:#F7F8F8;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;-webkit-font-smoothing:antialiased}
            main{width:min(400px,100%);padding:18px 24px 26px;background:#0F1011;border:1px solid #1C1D1F;border-radius:10px}
            .top{display:flex;align-items:center;justify-content:space-between}
            .brand{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:500;color:#7B8089}
            .brand svg{width:14px;height:16px;fill:#F7F8F8}
            .tag{display:inline-flex;align-items:center;gap:6px;height:20px;padding:0 7px;border:1px solid;border-radius:3px;font-size:12px}
            .tag i{width:6px;height:6px;border-radius:50%;background:currentColor}
            .ok{color:#4CC38A;border-color:#4CC38A59}
            .stop{color:#EF6B6B;border-color:#EF6B6B59}
            h1{margin:30px 0 6px;font-size:20px;line-height:1.3;font-weight:600;letter-spacing:-.01em}
            p{margin:0;color:#8A8F98;overflow-wrap:anywhere}
            </style></head>
            <body><main>
            <div class="top"><span class="brand"><svg viewBox="236 200 552 624" aria-hidden="true"><path d="M498 300A262 262 0 0 0 498 824Z"/><path d="M526 200A262 262 0 0 1 526 724Z"/></svg>Hubris</span><span class="tag {{(ok ? "ok" : "stop")}}"><i></i>{{(ok ? "connected" : "not connected")}}</span></div>
            <h1>{{title}}</h1>
            <p>{{detail}}</p>
            </main>{{(ok ? "<script>window.close()</script>" : "")}}</body></html>
            """;

        private static async Task WriteAsync(NetworkStream s, string status, string html, CancellationToken ct)
        {
            byte[] body = Encoding.UTF8.GetBytes(html);
            byte[] head = Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
            await s.WriteAsync(head, ct).ConfigureAwait(false);
            await s.WriteAsync(body, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);
        }

        public void Dispose() => _listener.Stop();
    }

    public static Dictionary<string, string> ParseQuery(string target)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        int q = target.IndexOf('?');
        if (q < 0) return dict;
        foreach (var pair in target[(q + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            string k = WebUtility.UrlDecode(eq < 0 ? pair : pair[..eq]);
            string v = eq < 0 ? string.Empty : WebUtility.UrlDecode(pair[(eq + 1)..]);
            dict[k] = v;
        }
        return dict;
    }

    // ------------------------------------------------------------------ browser

    public static void OpenBrowser(string url)
    {
        ProcessStartInfo psi;
        if (OperatingSystem.IsWindows()) psi = new ProcessStartInfo(url) { UseShellExecute = true };
        else if (OperatingSystem.IsMacOS()) psi = new ProcessStartInfo("open") { ArgumentList = { url } };
        else psi = new ProcessStartInfo("xdg-open") { ArgumentList = { url } };
        psi.RedirectStandardOutput = psi.RedirectStandardError = !OperatingSystem.IsWindows();
        using var p = Process.Start(psi) ?? throw new OAuthException("could not start a browser");
    }

    public static string BuildAuthorizeUrl(string authorizationEndpoint, string clientId, string redirectUri, string challenge, string state, string? scope, string resource)
    {
        var sb = new StringBuilder(authorizationEndpoint);
        sb.Append(authorizationEndpoint.Contains('?') ? '&' : '?');
        sb.Append("response_type=code&client_id=").Append(Uri.EscapeDataString(clientId));
        sb.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
        sb.Append("&code_challenge=").Append(challenge).Append("&code_challenge_method=S256");
        sb.Append("&state=").Append(state);
        sb.Append("&resource=").Append(Uri.EscapeDataString(resource));
        if (!string.IsNullOrEmpty(scope)) sb.Append("&scope=").Append(Uri.EscapeDataString(scope));
        return sb.ToString();
    }

    // ------------------------------------------------------------------ token endpoint

    public static Task<TokenResponse> ExchangeCodeAsync(HttpClient http, string tokenEndpoint, string code, string verifier, string redirectUri, string clientId, string? clientSecret, string resource, CancellationToken ct)
        => TokenRequestAsync(http, tokenEndpoint, new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = clientId,
            ["code_verifier"] = verifier,
            ["resource"] = resource,
        }, clientSecret, ct);

    public static Task<TokenResponse> RefreshAsync(HttpClient http, string tokenEndpoint, string refreshToken, string clientId, string? clientSecret, string? resource, CancellationToken ct)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = clientId,
        };
        if (resource is not null) form["resource"] = resource;
        return TokenRequestAsync(http, tokenEndpoint, form, clientSecret, ct);
    }

    private static async Task<TokenResponse> TokenRequestAsync(HttpClient http, string tokenEndpoint, Dictionary<string, string> form, string? clientSecret, CancellationToken ct)
    {
        if (clientSecret is not null) form["client_secret"] = clientSecret;
        using var content = new FormUrlEncodedContent(form);
        using var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) { Content = content };
        req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        using var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
        string body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        TokenResponse? tr = null;
        try { tr = JsonSerializer.Deserialize(body, AuthJsonContext.Default.TokenResponse); } catch (JsonException) { }
        if (!resp.IsSuccessStatusCode || tr?.AccessToken is null or "")
            throw new OAuthException($"token request failed: HTTP {(int)resp.StatusCode} {tr?.Error ?? ""} {tr?.ErrorDescription ?? Trim(body)}".TrimEnd(), tr?.Error);
        return tr;
    }

    private static string Trim(string s) => (s.Length > 200 ? s[..200] : s).ReplaceLineEndings(" ");
}

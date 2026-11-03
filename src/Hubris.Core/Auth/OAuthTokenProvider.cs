using System.Buffers.Text;
using System.Net.Sockets;
using System.Security.Cryptography;
using Hubris.Cli;
using Hubris.Control;
using Hubris.Transport;

namespace Hubris.Auth;

/// <summary>
/// One bridge's OAuth state: hands out a valid access token (refreshing inside a 60 s window of expiry under a
/// lock so concurrent calls share one refresh), runs the browser login, forgets the token on revoke.
/// </summary>
public sealed class OAuthTokenProvider
{
    public const int RefreshWindowSec = 60;

    private readonly OAuthSpec _spec;
    private readonly string? _resourceUrl;
    private readonly ISecureTokenStore _store;
    private readonly HttpClient _http;
    private readonly Action<string> _openBrowser;
    private readonly Func<DateTimeOffset> _clock;
    private readonly ProviderGate _gate;

    public OAuthTokenProvider(string bridge, OAuthSpec spec, string? resourceUrl, ISecureTokenStore store, HttpClient http,
                              Action<string>? openBrowser = null, Func<DateTimeOffset>? clock = null, ProviderGate? gate = null)
    {
        _gate = gate ?? new ProviderGate();
        Bridge = bridge;
        _spec = spec;
        _resourceUrl = resourceUrl;
        _store = store;
        _http = http;
        _openBrowser = openBrowser ?? OAuthPkceFlow.OpenBrowser;
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);
    }

    public string Bridge { get; }
    /// <summary>Account name in the secure store; bridges that share a provider share the token.</summary>
    public string Provider => _spec.Provider ?? Bridge;
    public string? EnvName => _spec.Env;
    /// <summary>"connected", "expired", "none", "pending" or "error".</summary>
    public string State { get; private set; } = "none";
    public string? LastError { get; private set; }
    public event Action? Changed;

    public AuthInfo Info()
    {
        var tok = _store.Get(Provider);
        if (State is not ("pending" or "error")) State = tok is null ? "none" : tok.ExpiresAt == 0 || tok.RefreshToken is not null || Fresh(tok) ? "connected" : "expired";
        return new AuthInfo
        {
            Bridge = Bridge, Provider = Provider, State = State, Error = LastError, Env = EnvName,
            ExpiresAt = tok is { ExpiresAt: > 0 } ? DateTimeOffset.FromUnixTimeSeconds(tok.ExpiresAt).ToString("O") : null,
        };
    }

    private bool Fresh(StoredToken t) => t.ExpiresAt == 0 || t.ExpiresAt - _clock().ToUnixTimeSeconds() > RefreshWindowSec;

    /// <summary>A usable access token, or null when the user has to sign in (again).</summary>
    public async Task<string?> GetAccessTokenAsync(CancellationToken ct, bool forceRefresh = false)
    {
        await _gate.Lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var tok = _store.Get(Provider);
            if (tok is null) { SetState("none"); return null; }
            bool fresh = Fresh(tok);
            if (fresh && !forceRefresh) { SetState("connected"); return tok.AccessToken; }
            // Another hub may have refreshed this provider already: read past the memory copy before spending the refresh token.
            if (_store.Reload(Provider) is { } latest)
            {
                tok = latest;
                fresh = Fresh(tok);
                if (fresh && !forceRefresh) { SetState("connected"); return tok.AccessToken; }
            }
            if (tok.RefreshToken is null)
            {
                SetState(fresh ? "connected" : "expired");
                return fresh ? tok.AccessToken : null;
            }
            try
            {
                var tr = await OAuthPkceFlow.RefreshAsync(_http, tok.TokenEndpoint, tok.RefreshToken, tok.ClientId, tok.ClientSecret, tok.Resource, ct).ConfigureAwait(false);
                tok.AccessToken = tr.AccessToken!;
                tok.RefreshToken = tr.RefreshToken ?? tok.RefreshToken; // servers may rotate it or keep it
                tok.ExpiresAt = tr.ExpiresIn is > 0 ? _clock().ToUnixTimeSeconds() + tr.ExpiresIn.Value : 0;
                _store.Set(Provider, tok);
                LastError = null;
                SetState("connected");
                Log.Info($"oauth '{Bridge}': token refreshed");
                return tok.AccessToken;
            }
            catch (Exception ex) when (ex is OAuthException or HttpRequestException)
            {
                LastError = ex.Message;
                Log.Warn($"oauth '{Bridge}': refresh failed: {ex.Message}");
                SetState(fresh ? "connected" : "expired");
                return fresh ? tok.AccessToken : null;
            }
        }
        finally
        {
            _gate.Lock.Release();
        }
    }

    /// <summary>Discovery → (registration →) browser → loopback redirect → code exchange → store.</summary>
    public async Task LoginAsync(CancellationToken ct)
    {
        if (Interlocked.CompareExchange(ref _gate.LoginRunning, 1, 0) == 1) throw new OAuthException($"bridge '{Bridge}': a login is already in progress");
        SetState("pending");
        try
        {
            string resource = _resourceUrl ?? _spec.Issuer ?? throw new OAuthException($"bridge '{Bridge}': set auth.issuer (the MCP server URL) for a stdio bridge");
            var ep = await OAuthPkceFlow.DiscoverAsync(_http, resource, _resourceUrl is null ? null : _spec.Issuer, ct).ConfigureAwait(false);

            using var listener = new OAuthPkceFlow.LoopbackListener();
            string? scope = _spec.Scope ?? ep.DefaultScope;
            string? clientId = _spec.ClientId, clientSecret = _spec.ClientSecret;
            if (string.IsNullOrEmpty(clientId))
            {
                if (ep.RegistrationEndpoint is null) throw new OAuthException($"bridge '{Bridge}': the server offers no dynamic client registration; set auth.clientId");
                var reg = await OAuthPkceFlow.RegisterAsync(_http, ep.RegistrationEndpoint, listener.RedirectUri, scope, ct).ConfigureAwait(false);
                clientId = reg.ClientId!;
                clientSecret = reg.ClientSecret;
            }

            var (verifier, challenge) = OAuthPkceFlow.CreatePkce();
            Span<byte> rnd = stackalloc byte[16];
            RandomNumberGenerator.Fill(rnd);
            string state = Base64Url.EncodeToString(rnd);
            string url = OAuthPkceFlow.BuildAuthorizeUrl(ep.AuthorizationEndpoint, clientId, listener.RedirectUri, challenge, state, scope, ep.Resource);
            Log.Info($"oauth '{Bridge}': opening the browser at {ep.AuthorizationEndpoint}");
            _openBrowser(url);

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromMinutes(5));
            var query = await listener.WaitForCallbackAsync(deadline.Token).ConfigureAwait(false);
            if (query.TryGetValue("error", out var error)) throw new OAuthException($"authorization refused: {error} {query.GetValueOrDefault("error_description")}".TrimEnd());
            if (query.GetValueOrDefault("state") != state) throw new OAuthException("redirect state does not match (wrong or replayed callback)");
            if (!query.TryGetValue("code", out var code) || code.Length == 0) throw new OAuthException("redirect carried no authorization code");

            var tr = await OAuthPkceFlow.ExchangeCodeAsync(_http, ep.TokenEndpoint, code, verifier, listener.RedirectUri, clientId, clientSecret, ep.Resource, ct).ConfigureAwait(false);
            _store.Set(Provider, new StoredToken
            {
                AccessToken = tr.AccessToken!,
                RefreshToken = tr.RefreshToken,
                ExpiresAt = tr.ExpiresIn is > 0 ? _clock().ToUnixTimeSeconds() + tr.ExpiresIn.Value : 0,
                TokenEndpoint = ep.TokenEndpoint,
                ClientId = clientId,
                ClientSecret = clientSecret,
                Resource = ep.Resource,
                Scope = tr.Scope ?? scope,
            });
            LastError = null;
            SetState("connected");
            Log.Info($"oauth '{Bridge}': signed in" + (tr.ExpiresIn is > 0 ? $", token valid {tr.ExpiresIn}s" : string.Empty));
        }
        catch (Exception ex) when (ex is OAuthException or HttpRequestException or OperationCanceledException or IOException or SocketException or UriFormatException or System.Text.Json.JsonException or System.ComponentModel.Win32Exception)
        {
            LastError = ex is OperationCanceledException && !ct.IsCancellationRequested ? "no redirect or server answer in time" : ex.Message;
            SetState("error");
            Log.Warn($"oauth '{Bridge}': login failed: {LastError}");
            throw new OAuthException(LastError);
        }
        finally
        {
            Volatile.Write(ref _gate.LoginRunning, 0);
            if (State == "pending") { LastError ??= "login failed unexpectedly"; SetState("error"); } // an exception outside the filter must not leave a stuck "pending"
        }
    }

    public void Revoke()
    {
        _store.Delete(Provider);
        LastError = null;
        SetState("none");
        Log.Info($"oauth '{Bridge}': token removed");
    }

    private void SetState(string state)
    {
        if (State == state) return;
        State = state;
        Changed?.Invoke();
    }
}

/// <summary>Shared by every bridge that names the same provider: one refresh at a time, one login at a time.</summary>
public sealed class ProviderGate
{
    public SemaphoreSlim Lock { get; } = new(1, 1);
    public int LoginRunning;
}

/// <summary>Attaches the bearer token; on 401 refreshes once and repeats the request.</summary>
public sealed class OAuthDelegatingHandler : DelegatingHandler
{
    private readonly OAuthTokenProvider _provider;

    public OAuthDelegatingHandler(OAuthTokenProvider provider, HttpMessageHandler inner) : base(inner) => _provider = provider;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        string token = await _provider.GetAccessTokenAsync(ct).ConfigureAwait(false) ?? throw new Engine.NotSignedInException(_provider.Bridge);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var response = await base.SendAsync(request, ct).ConfigureAwait(false);
        if (response.StatusCode != System.Net.HttpStatusCode.Unauthorized) return response;

        string? fresh = await _provider.GetAccessTokenAsync(ct, forceRefresh: true).ConfigureAwait(false);
        if (fresh is null || fresh == token) return response;
        response.Dispose();
        var retry = new HttpRequestMessage(request.Method, request.RequestUri) { Version = request.Version };
        foreach (var h in request.Headers) if (h.Key != "Authorization") retry.Headers.TryAddWithoutValidation(h.Key, h.Value);
        if (request.Content is not null)
        {
            retry.Content = new ByteArrayContent(await request.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false));
            foreach (var h in request.Content.Headers) retry.Content.Headers.TryAddWithoutValidation(h.Key, h.Value);
        }
        retry.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", fresh);
        return await base.SendAsync(retry, ct).ConfigureAwait(false);
    }
}

/// <summary>All providers of one hub, keyed by bridge name; the control hub reads states here.</summary>
public sealed class OAuthManager
{
    private readonly ISecureTokenStore _store;
    private readonly HttpClient _http;
    private readonly Dictionary<string, OAuthTokenProvider> _providers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ProviderGate> _gates = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public OAuthManager(ISecureTokenStore store, HttpClient? http = null)
    {
        _store = store;
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public event Action? Changed;
    public int Count { get { lock (_gate) return _providers.Count; } }

    public OAuthTokenProvider GetOrCreate(BridgeSpec spec)
    {
        var auth = spec.Auth ?? throw new ArgumentException("bridge has no auth block", nameof(spec));
        lock (_gate)
        {
            if (_providers.TryGetValue(spec.Name, out var p)) return p;
            string providerName = auth.Provider ?? spec.Name;
            if (!_gates.TryGetValue(providerName, out var gate)) _gates[providerName] = gate = new ProviderGate();
            p = new OAuthTokenProvider(spec.Name, auth, spec.Url, _store, _http, gate: gate);
            p.Changed += () => Changed?.Invoke();
            _providers[spec.Name] = p;
            return p;
        }
    }

    public bool TryGet(string bridge, out OAuthTokenProvider provider)
    {
        lock (_gate) return _providers.TryGetValue(bridge, out provider!);
    }

    public List<AuthInfo> Infos()
    {
        lock (_gate) return _providers.Values.OrderBy(p => p.Bridge, StringComparer.Ordinal).Select(p => p.Info()).ToList();
    }
}

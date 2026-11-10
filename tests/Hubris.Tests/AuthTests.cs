using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Hubris.Auth;
using Hubris.Cli;
using Hubris.Config;
using Hubris.Engine;

namespace Hubris.Tests;

/// <summary>Authorization server + MCP resource behind one fake handler: discovery, registration, PKCE exchange, refresh, bearer checks.</summary>
internal sealed class FakeAuthWorld : HttpMessageHandler
{
    public string? Challenge, RedirectUri, State;
    public int Registrations, Exchanges, Refreshes, ResourceCalls, TokenCalls, RefreshDelayMs;
    public string ValidToken = "A1";
    public bool RejectEverything;
    public bool BrokenRegistration;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        string host = req.RequestUri!.Host, path = req.RequestUri.AbsolutePath;
        if (host == "mcp.test" && path == "/.well-known/oauth-protected-resource")
            return Json("""{"resource":"https://mcp.test/mcp","authorization_servers":["https://as.test"],"scopes_supported":["openid"]}""");
        if (host == "as.test" && path == "/.well-known/oauth-authorization-server")
            return Json("""{"issuer":"https://as.test","authorization_endpoint":"https://as.test/authorize","token_endpoint":"https://as.test/token","registration_endpoint":"https://as.test/register","code_challenge_methods_supported":["S256"],"scopes_supported":["openid","email","offline_access"]}""");
        if (host == "as.test" && path == "/register")
        {
            Registrations++;
            var reg = JsonNode.Parse(await req.Content!.ReadAsStringAsync(ct))!.AsObject();
            Assert.Equal("none", reg["token_endpoint_auth_method"]!.GetValue<string>());
            RedirectUri = reg["redirect_uris"]![0]!.GetValue<string>();
            if (BrokenRegistration) return new HttpResponseMessage(HttpStatusCode.Created) { Content = new StringContent("<html>oops</html>", Encoding.UTF8, "text/html") };
            return Json("""{"client_id":"cid-1"}""", HttpStatusCode.Created);
        }
        if (host == "as.test" && path == "/token")
        {
            TokenCalls++;
            if (RejectEverything) return Json("""{"error":"invalid_grant","error_description":"revoked"}""", HttpStatusCode.BadRequest);
            var form = OAuthPkceFlow.ParseQuery("?" + await req.Content!.ReadAsStringAsync(ct));
            Assert.Equal("https://mcp.test/mcp", form["resource"]);
            if (form["grant_type"] == "authorization_code")
            {
                Exchanges++;
                Assert.Equal("C0DE", form["code"]);
                Assert.Equal("cid-1", form["client_id"]);
                Assert.Equal(RedirectUri, form["redirect_uri"]);
                string expected = System.Buffers.Text.Base64Url.EncodeToString(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"])));
                Assert.Equal(Challenge, expected); // PKCE: the verifier must hash to the challenge the browser saw
                return Json("""{"access_token":"A1","token_type":"Bearer","expires_in":3600,"refresh_token":"R1","scope":"read"}""");
            }
            Refreshes++;
            Assert.Equal("R1", form["refresh_token"]);
            if (RefreshDelayMs > 0) await Task.Delay(RefreshDelayMs, ct);
            ValidToken = "A2";
            return Json("""{"access_token":"A2","token_type":"Bearer","expires_in":3600}""");
        }
        if (host == "mcp.test" && path == "/mcp")
        {
            ResourceCalls++;
            return req.Headers.Authorization?.Parameter == ValidToken ? Json("""{"ok":true}""") : new HttpResponseMessage(HttpStatusCode.Unauthorized);
        }
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    /// <summary>Stands in for the browser: reads the authorize URL and performs the redirect to the loopback listener.</summary>
    public void Browser(string url)
    {
        var q = OAuthPkceFlow.ParseQuery(url);
        Assert.StartsWith("https://as.test/authorize?", url);
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.Equal("cid-1", q["client_id"]);
        Assert.Equal("https://mcp.test/mcp", q["resource"]);
        Assert.Equal("openid offline_access", q["scope"]); // resource scopes_supported + offline_access the AS offers, nothing configured
        Challenge = q["code_challenge"];
        State = q["state"];
        string redirect = q["redirect_uri"];
        _ = Task.Run(async () =>
        {
            await Task.Delay(50);
            using var http = new HttpClient();
            await http.GetAsync("http://127.0.0.1:" + new Uri(redirect).Port + "/favicon.ico"); // a browser probe must not eat the callback
            var resp = await http.GetAsync($"{redirect}?code=C0DE&state={State}");
            Assert.Contains("close this tab", await resp.Content.ReadAsStringAsync());
        });
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode code = HttpStatusCode.OK)
        => new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}

/// <summary>A keychain that would need a dialog: every access fails the way the macOS store does with interaction off.</summary>
internal sealed class RefusingStore : ISecureTokenStore
{
    private static IOException No() => new("keychain read failed (OSStatus -25293)");
    public StoredToken? Get(string account) => throw No();
    public StoredToken? Reload(string account) => throw No();
    public void Set(string account, StoredToken token) => throw No();
    public void Delete(string account) => throw No();
}

internal sealed class CountingStore : ISecureTokenStore
{
    public int Gets, Sets;
    private readonly Dictionary<string, StoredToken> _d = new();
    public StoredToken? Get(string account) { Gets++; return _d.GetValueOrDefault(account); }
    public StoredToken? Reload(string account) => Get(account);
    public void Set(string account, StoredToken token) { Sets++; _d[account] = token; }
    public void Delete(string account) => _d.Remove(account);
}

public class AuthTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("hubris-auth-").FullName;
    private static readonly BridgeSpec Remote = new("notion", "", [], null, "https://mcp.test/mcp", null, "http", new OAuthSpec());

    public void Dispose() => Directory.Delete(_dir, true);

    private (OAuthTokenProvider Provider, FakeAuthWorld World, ISecureTokenStore Store) Build(Func<DateTimeOffset>? clock = null, ISecureTokenStore? store = null)
    {
        var world = new FakeAuthWorld();
        store ??= new CachingTokenStore(new FileTokenStore(Path.Combine(_dir, "tokens")));
        var provider = new OAuthTokenProvider(Remote.Name, Remote.Auth!, Remote.Url, store, new HttpClient(world), world.Browser, clock);
        return (provider, world, store);
    }

    [Fact]
    public void Pkce_pair_is_base64url_and_s256()
    {
        var (verifier, challenge) = OAuthPkceFlow.CreatePkce();
        Assert.InRange(verifier.Length, 43, 128);
        Assert.DoesNotContain('=', verifier + challenge);
        Assert.DoesNotContain('+', verifier + challenge);
        Assert.Equal(System.Buffers.Text.Base64Url.EncodeToString(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(verifier))), challenge);
        Assert.NotEqual(verifier, OAuthPkceFlow.CreatePkce().Verifier);
    }

    [Fact]
    public async Task Login_discovers_registers_exchanges_and_stores_a_0600_token()
    {
        var (provider, world, store) = Build();
        Assert.Equal("none", provider.Info().State);

        await provider.LoginAsync(CancellationToken.None);

        Assert.Equal(1, world.Registrations);
        Assert.Equal(1, world.Exchanges);
        Assert.Equal("connected", provider.State);
        Assert.Equal("A1", await provider.GetAccessTokenAsync(CancellationToken.None));
        var stored = store.Get("notion")!;
        Assert.Equal("R1", stored.RefreshToken);
        Assert.Equal("cid-1", stored.ClientId);
        Assert.Equal("https://as.test/token", stored.TokenEndpoint);
        string file = Path.Combine(_dir, "tokens", "notion.json");
        Assert.True(File.Exists(file));
        if (!OperatingSystem.IsWindows()) Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
        Assert.NotNull(provider.Info().ExpiresAt);
    }

    [Fact]
    public async Task Token_near_expiry_is_refreshed_once_under_the_lock()
    {
        var now = DateTimeOffset.UtcNow;
        var (provider, world, store) = Build(() => now);
        store.Set("notion", new StoredToken { AccessToken = "A1", RefreshToken = "R1", ExpiresAt = now.ToUnixTimeSeconds() + 30, TokenEndpoint = "https://as.test/token", ClientId = "cid-1", Resource = "https://mcp.test/mcp" });

        var tokens = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => provider.GetAccessTokenAsync(CancellationToken.None)));
        Assert.All(tokens, t => Assert.Equal("A2", t));
        Assert.Equal(1, world.Refreshes); // five concurrent callers, one refresh
        Assert.Equal("R1", store.Get("notion")!.RefreshToken); // the server kept the refresh token
        Assert.True(store.Get("notion")!.ExpiresAt > now.ToUnixTimeSeconds() + 3000);
    }

    [Fact]
    public async Task Broken_registration_reply_ends_in_error_not_pending()
    {
        var (provider, world, _) = Build();
        world.BrokenRegistration = true;
        await Assert.ThrowsAsync<OAuthException>(() => provider.LoginAsync(CancellationToken.None));
        Assert.Equal("error", provider.State);
        Assert.NotNull(provider.LastError);
        world.BrokenRegistration = false;
        await provider.LoginAsync(CancellationToken.None); // the gate is free again
        Assert.Equal("connected", provider.State);
    }

    [Fact]
    public async Task Bridges_sharing_a_provider_share_one_refresh()
    {
        var now = DateTimeOffset.UtcNow;
        var world = new FakeAuthWorld();
        var store = new CachingTokenStore(new FileTokenStore(Path.Combine(_dir, "shared")));
        store.Set("notion", new StoredToken { AccessToken = "A1", RefreshToken = "R1", ExpiresAt = now.ToUnixTimeSeconds() + 30, TokenEndpoint = "https://as.test/token", ClientId = "cid-1", Resource = "https://mcp.test/mcp" });
        var manager = new OAuthManager(store, new HttpClient(world));
        var a = manager.GetOrCreate(new BridgeSpec("notion-a", "", [], null, "https://mcp.test/mcp", null, "http", new OAuthSpec(Provider: "notion")));
        var b = manager.GetOrCreate(new BridgeSpec("notion-b", "", [], null, "https://mcp.test/mcp", null, "http", new OAuthSpec(Provider: "notion")));
        var tokens = await Task.WhenAll(a.GetAccessTokenAsync(CancellationToken.None), b.GetAccessTokenAsync(CancellationToken.None), a.GetAccessTokenAsync(CancellationToken.None));
        Assert.All(tokens, t => Assert.Equal("A2", t));
        Assert.Equal(1, world.Refreshes);
    }

    [Fact]
    public void Store_chain_without_an_os_store_keeps_tokens_across_instances()
    {
        var dir = Path.Combine(_dir, "linux");
        var first = SecureTokenStores.Build(null, new FileTokenStore(dir));
        first.Set("x", new StoredToken { AccessToken = "t", TokenEndpoint = "e", ClientId = "c" });
        var second = SecureTokenStores.Build(null, new FileTokenStore(dir)); // a new hub process
        Assert.Equal("t", second.Get("x")!.AccessToken);
    }

    [Fact]
    public async Task Keep_warm_refreshes_only_tokens_close_to_expiry()
    {
        var now = DateTimeOffset.UtcNow;
        var (provider, world, store) = Build(() => now);
        store.Set("notion", new StoredToken { AccessToken = "A1", RefreshToken = "R1", ExpiresAt = now.ToUnixTimeSeconds() + 7200, TokenEndpoint = "https://as.test/token", ClientId = "cid-1", Resource = "https://mcp.test/mcp" });
        Assert.False(await provider.KeepWarmAsync(CancellationToken.None)); // two hours left: nothing to do
        Assert.Equal(0, world.Refreshes);

        store.Set("notion", new StoredToken { AccessToken = "A1", RefreshToken = "R1", ExpiresAt = now.ToUnixTimeSeconds() + 300, TokenEndpoint = "https://as.test/token", ClientId = "cid-1", Resource = "https://mcp.test/mcp" });
        Assert.True(await provider.KeepWarmAsync(CancellationToken.None));  // five minutes left, nobody calling: refreshed anyway
        Assert.Equal(1, world.Refreshes);
        Assert.Equal("A2", store.Get("notion")!.AccessToken);

        store.Set("notion", new StoredToken { AccessToken = "A2", ExpiresAt = now.ToUnixTimeSeconds() + 60, TokenEndpoint = "https://as.test/token", ClientId = "cid-1" });
        Assert.False(await provider.KeepWarmAsync(CancellationToken.None)); // no refresh token: nothing it can do
    }

    [Fact]
    public async Task Refresh_failure_without_a_valid_token_reports_expired()
    {
        var now = DateTimeOffset.UtcNow;
        var (provider, world, store) = Build(() => now);
        store.Set("notion", new StoredToken { AccessToken = "A1", RefreshToken = "R1", ExpiresAt = now.ToUnixTimeSeconds() - 1, TokenEndpoint = "https://as.test/token", ClientId = "cid-1" });
        world.RejectEverything = true;
        Assert.Null(await provider.GetAccessTokenAsync(CancellationToken.None));
        Assert.Equal("expired", provider.State);
        Assert.Contains("revoked", provider.LastError);
        provider.Revoke();
        Assert.Equal("none", provider.Info().State);
        Assert.Null(store.Get("notion"));
    }

    [Fact]
    public async Task Handler_sends_bearer_and_retries_once_after_401()
    {
        var (provider, world, store) = Build();
        store.Set("notion", new StoredToken { AccessToken = "stale", RefreshToken = "R1", ExpiresAt = 0, TokenEndpoint = "https://as.test/token", ClientId = "cid-1", Resource = "https://mcp.test/mcp" });
        world.ValidToken = "A2"; // the server already rotated; "stale" gets a 401
        using var http = new HttpClient(new OAuthDelegatingHandler(provider, world));

        using var resp = await http.PostAsync("https://mcp.test/mcp", new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(2, world.ResourceCalls);
        Assert.Equal(1, world.Refreshes);
        Assert.Equal("A2", store.Get("notion")!.AccessToken);

        using var again = await http.PostAsync("https://mcp.test/mcp", new StringContent("{}"));
        Assert.Equal(3, world.ResourceCalls); // fresh token: no retry needed
        Assert.Equal(1, world.Refreshes);
    }

    [Fact]
    public async Task Handler_without_a_token_asks_for_connect_instead_of_sending()
    {
        var (provider, world, _) = Build();
        using var http = new HttpClient(new OAuthDelegatingHandler(provider, world));
        var ex = await Assert.ThrowsAsync<NotSignedInException>(() => http.GetAsync("https://mcp.test/mcp"));
        Assert.Contains("Connect", ex.Message);
        Assert.Equal(0, world.ResourceCalls);
    }

    [Fact]
    public async Task Remote_bridge_with_auth_block_gets_the_bearer_handler()
    {
        var (provider, world, store) = Build();
        store.Set("notion", new StoredToken { AccessToken = "A1", ExpiresAt = 0, TokenEndpoint = "https://as.test/token", ClientId = "cid-1" });
        await using var bridge = new HttpMcpBridge(Remote, new OAuthDelegatingHandler(provider, world));
        var res = await bridge.CallToolAsync("x", null, CancellationToken.None); // the fake resource is not an MCP server: the point is the header reached it
        Assert.Equal(1, world.ResourceCalls);
        Assert.Contains("without an answer", res.Content[0].Text);
    }

    [Fact]
    public async Task Stdio_bridge_without_a_token_refuses_to_spawn()
    {
        var spec = new BridgeSpec("py", "/nonexistent/server", [], Auth: new OAuthSpec(Issuer: "https://mcp.test", Env: "NOTION_TOKEN"));
        await using var bridge = new ExternalMcpBridge(spec) { TokenSource = (_, _) => Task.FromResult<string?>(null) };
        var res = await bridge.CallToolAsync("x", null, CancellationToken.None);
        Assert.Equal(true, res.IsError);
        Assert.Contains("not signed in", res.Content[0].Text);
        Assert.False(bridge.IsStarted);
    }

    [Fact]
    public async Task Two_hubs_refreshing_at_once_spend_the_refresh_token_once()
    {
        var now = DateTimeOffset.UtcNow;
        var world = new FakeAuthWorld { RefreshDelayMs = 300 };
        string dir = Path.Combine(_dir, "two-hubs");
        new FileTokenStore(dir).Set("notion", new StoredToken { AccessToken = "A1", RefreshToken = "R1", ExpiresAt = now.ToUnixTimeSeconds() + 300, TokenEndpoint = "https://as.test/token", ClientId = "cid-1", Resource = "https://mcp.test/mcp" });
        // Two hub processes: each has its own memory cache and in-process gate, only the store and the lock file are shared.
        OAuthTokenProvider Hub() => new(Remote.Name, Remote.Auth!, Remote.Url, new CachingTokenStore(new FileTokenStore(dir)), new HttpClient(world), world.Browser, () => now, lockDir: dir);
        var (a, b) = (Hub(), Hub());
        Assert.Equal("A1", (await a.GetAccessTokenAsync(CancellationToken.None))!); // both have A1 in memory
        Assert.Equal("A1", (await b.GetAccessTokenAsync(CancellationToken.None))!);

        await Task.WhenAll(a.KeepWarmAsync(CancellationToken.None), b.KeepWarmAsync(CancellationToken.None)); // same 5-minute tick
        Assert.Equal(1, world.Refreshes); // the one that waited took the rotated token; a second use of R1 would get the grant revoked
        Assert.Equal("A2", await a.GetAccessTokenAsync(CancellationToken.None));
        Assert.Equal("A2", await b.GetAccessTokenAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Refresh_token_the_server_rejects_is_forgotten_so_nothing_retries()
    {
        var now = DateTimeOffset.UtcNow;
        var (provider, world, store) = Build(() => now);
        store.Set("notion", new StoredToken { AccessToken = "A1", RefreshToken = "R1", ExpiresAt = now.ToUnixTimeSeconds() + 300, TokenEndpoint = "https://as.test/token", ClientId = "cid-1", Resource = "https://mcp.test/mcp" });
        world.RejectEverything = true; // invalid_grant
        Assert.True(await provider.KeepWarmAsync(CancellationToken.None));
        Assert.Null(store.Get("notion")!.RefreshToken);
        Assert.Contains("press Connect", provider.LastError);
        Assert.Equal("A1", await provider.GetAccessTokenAsync(CancellationToken.None)); // the access token still has its five minutes
        Assert.False(await provider.KeepWarmAsync(CancellationToken.None));             // the dead refresh token is not sent again
        Assert.Equal(1, world.TokenCalls);
    }

    [Fact]
    public async Task Hub_that_saw_no_token_picks_up_a_sign_in_made_by_another_hub()
    {
        string dir = Path.Combine(_dir, "late");
        var world = new FakeAuthWorld();
        var mine = new OAuthTokenProvider(Remote.Name, Remote.Auth!, Remote.Url, new CachingTokenStore(new FileTokenStore(dir)), new HttpClient(world), world.Browser);
        Assert.Null(await mine.GetAccessTokenAsync(CancellationToken.None)); // "none" is now in the memory cache
        new FileTokenStore(dir).Set("notion", new StoredToken { AccessToken = "A1", TokenEndpoint = "https://as.test/token", ClientId = "cid-1" }); // the other hub's login
        Assert.Equal("A1", await mine.GetAccessTokenAsync(CancellationToken.None));
    }

    [Fact]
    public void File_copy_wins_over_the_os_store_and_writes_stay_with_it()
    {
        static StoredToken T(string a) => new() { AccessToken = a, TokenEndpoint = "e", ClientId = "c" };
        var os = new CountingStore();
        var file = new FileTokenStore(Path.Combine(_dir, "fb"));
        var store = new FallbackTokenStore(os, file);
        store.Set("x", T("os-1"));
        Assert.Null(file.Get("x")); // the OS store took it: no file
        Assert.Equal("os-1", store.Get("x")!.AccessToken);

        file.Set("x", T("file-2")); // a hub the OS store refused wrote the newer token here
        Assert.Equal("file-2", store.Reload("x")!.AccessToken);
        store.Set("x", T("file-3"));
        Assert.Equal("file-3", file.Get("x")!.AccessToken);
        Assert.Equal(1, os.Sets); // not split over two stores again

        var refused = new FallbackTokenStore(new RefusingStore(), new FileTokenStore(Path.Combine(_dir, "fb2")));
        Assert.Null(refused.Get("y"));
        refused.Set("y", T("f"));
        Assert.Equal("f", refused.Get("y")!.AccessToken);
        refused.Delete("y");
        Assert.Null(refused.Get("y"));
    }

    [Fact]
    public void Os_secret_store_round_trips_a_token()
    {
        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsWindows()) return; // Linux has the file store only
        ISecureTokenStore store = OperatingSystem.IsMacOS() ? new MacOsKeychainStore() : new WindowsCredentialStore();
        string account = "hubris-test-" + Environment.ProcessId;
        // The store never shows the keychain dialog. Where the vault item already exists and belongs to another binary
        // (a developer machine with a real hub), this process is refused and there is nothing to round-trip.
        try { store.Get(account); }
        catch (IOException ex) when (OperatingSystem.IsMacOS() && (ex.Message.Contains("-25293") || ex.Message.Contains("-25308"))) { return; } // errSecAuthFailed / errSecInteractionNotAllowed
        try
        {
            Assert.Null(store.Get(account));
            store.Set(account, new StoredToken { AccessToken = "first", RefreshToken = "r", ExpiresAt = 42, TokenEndpoint = "https://as.test/token", ClientId = "c" });
            Assert.Equal("first", store.Get(account)!.AccessToken);
            store.Set(account, new StoredToken { AccessToken = "second", TokenEndpoint = "https://as.test/token", ClientId = "c" }); // update = delete + add
            var back = store.Get(account)!;
            Assert.Equal("second", back.AccessToken);
            Assert.Null(back.RefreshToken);
        }
        finally
        {
            store.Delete(account);
        }
        Assert.Null(store.Get(account));
        store.Delete(account); // deleting twice is fine

        if (OperatingSystem.IsMacOS())
        {
            // The vault item is shared: a second process-like instance reads what the first wrote, without the first's cache.
            var a = new MacOsKeychainStore();
            var b = new MacOsKeychainStore();
            string acc2 = account + "-b";
            try
            {
                a.Set(account, new StoredToken { AccessToken = "va", TokenEndpoint = "x", ClientId = "c" });
                b.Get(acc2); // b has now loaded the vault once
                a.Set(acc2, new StoredToken { AccessToken = "vb", TokenEndpoint = "x", ClientId = "c" });
                Assert.Equal("va", b.Get(account)!.AccessToken);
                Assert.Equal("vb", b.Reload(acc2)!.AccessToken);          // reload sees a's later write
                b.Set(account + "-c", new StoredToken { AccessToken = "vc", TokenEndpoint = "x", ClientId = "c" });
                Assert.Equal("vb", new MacOsKeychainStore().Get(acc2)!.AccessToken); // b's write merged, did not drop a's
            }
            finally { a.Delete(account); a.Delete(acc2); a.Delete(account + "-c"); }
            Assert.Null(new MacOsKeychainStore().Get(acc2));
        }
    }

    [Fact]
    public async Task Unsigned_oauth_bridge_stays_registered_without_tools()
    {
        var registry = new ToolRegistry(compactContext: true);
        var rt = new HubRuntime
        {
            Uptime = System.Diagnostics.Stopwatch.StartNew(), CompactContext = true, Registry = registry,
            Security = new Hubris.Security.SecurityInterceptor(Hubris.Security.ExecutionMode.Safe),
            Auth = new OAuthManager(new CountingStore()),
        };
        var bridge = await new BridgeHost(rt, registry).AddAsync(Remote, CancellationToken.None);
        Assert.NotNull(bridge);
        Assert.Single(rt.Bridges);
        Assert.False(bridge.IsStarted);
        Assert.Equal(0, registry.BridgedCount);
        Assert.Equal("none", rt.Auth.Infos()[0].State);
    }

    [Fact]
    public void Caching_store_hits_the_inner_store_once_per_account()
    {
        var inner = new CountingStore();
        var cache = new CachingTokenStore(inner);
        Assert.Null(cache.Get("a")); Assert.Null(cache.Get("a"));
        Assert.Equal(1, inner.Gets);
        cache.Set("a", new StoredToken { AccessToken = "t" });
        Assert.Equal("t", cache.Get("a")!.AccessToken);
        Assert.Equal(1, inner.Gets);
        cache.Delete("a");
        Assert.Null(cache.Get("a"));
        Assert.Equal(1, inner.Gets);
    }

    [Fact]
    public void Config_auth_block_round_trips_and_expands_the_secret()
    {
        Environment.SetEnvironmentVariable("HUBRIS_TEST_SECRET", "s3");
        var cfg = new HubrisConfig();
        cfg.Bridges.Add(new BridgeConfig { Name = "notion", Command = "npx", Args = ["notion-mcp"], Auth = new BridgeAuthConfig { Issuer = "https://mcp.notion.com", Env = "NOTION_TOKEN", ClientSecret = "${HUBRIS_TEST_SECRET}" } });
        cfg.Bridges.Add(new BridgeConfig { Name = "plain", Url = "https://x.test/mcp", Auth = new BridgeAuthConfig { Type = "basic" } });
        string path = Path.Combine(_dir, "config.json");
        HubrisConfigFile.Save(cfg, path);
        var specs = HubrisConfigFile.ToSpecs(HubrisConfigFile.Load(path));
        Assert.Equal("NOTION_TOKEN", specs[0].Auth!.Env);
        Assert.Equal("https://mcp.notion.com", specs[0].Auth!.Issuer);
        Assert.Equal("s3", specs[0].Auth!.ClientSecret);
        Assert.Contains("${HUBRIS_TEST_SECRET}", File.ReadAllText(path)); // the file keeps the placeholder
        Assert.Null(specs[1].Auth); // unknown auth type: ignored, not an error
        Assert.Equal(specs[0].ConfigHash(), new BridgeSpec("notion", "npx", ["notion-mcp"]).ConfigHash()); // tokens do not change the cache identity
    }
}

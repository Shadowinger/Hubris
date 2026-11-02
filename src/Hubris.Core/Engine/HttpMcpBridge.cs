using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Cli;
using Hubris.Protocol;
using Hubris.Transport;

namespace Hubris.Engine;

/// <summary>The server no longer knows our Mcp-Session-Id (restart, idle expiry); one reconnect is worth a try.</summary>
internal sealed class SessionLostException : McpBridgeException
{
    public SessionLostException(string bridge) : base(JsonRpcErrorCodes.InternalError, $"bridge '{bridge}' session expired") { }
}

/// <summary>
/// A remote MCP server reached over HTTP. Streamable HTTP (2025-03-26: one POST per message, answered as JSON or
/// as an event stream, session in <c>Mcp-Session-Id</c>) is the default; transport "sse" speaks the older
/// HTTP+SSE pair (a GET stream announcing an endpoint, every message POSTed there, answers on the stream).
/// Nothing is sent until the first call: tool definitions come from the cache exactly like for a child process,
/// and a session that the server dropped is reopened on the next call instead of taking the tools away.
/// </summary>
public sealed class HttpMcpBridge : McpBridge
{
    public const string TransportHttp = "http";
    public const string TransportSse = "sse";

    private readonly Uri _url;
    private readonly IReadOnlyDictionary<string, string> _headers;
    private readonly bool _legacySse;
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _startLock = new(1, 1);
    private readonly ConcurrentDictionary<RpcId, TaskCompletionSource<JsonNode?>> _pending = new();
    private readonly CancellationTokenSource _lifetime = new();

    private string? _sessionId;
    private string _protocolVersion = McpProtocol.Latest;
    private volatile bool _negotiated; // initialize answered: every later message names the protocol version
    private volatile bool _started;
    private volatile bool _dead;
    private int _disposed;
    private long _nextId;

    // HTTP+SSE only
    private Uri? _postUrl;
    private HttpResponseMessage? _stream;
    private Task? _eventLoop;

    public HttpMcpBridge(BridgeSpec spec, HttpMessageHandler? handler = null) : base(spec)
    {
        _url = new Uri(spec.Url ?? throw new ArgumentException("a remote bridge needs a url", nameof(spec)), UriKind.Absolute);
        _headers = spec.Headers ?? new Dictionary<string, string>();
        _legacySse = string.Equals(spec.Transport, TransportSse, StringComparison.OrdinalIgnoreCase);
        _http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            AutomaticDecompression = DecompressionMethods.All,
        })
        { Timeout = Timeout.InfiniteTimeSpan }; // per-request timeouts are the bridge's own
    }

    public Uri Url => _url;
    public string Transport => _legacySse ? TransportSse : TransportHttp;
    public string? SessionId => _sessionId;
    public override string Launch => _url.ToString();
    public override bool IsStarted => _started;
    public override bool IsAlive => _started && !_dead;
    public override bool CanRestart => true;

    // ------------------------------------------------------------------ lifecycle

    public override async Task EnsureStartedAsync(CancellationToken ct)
    {
        if (IsAlive) return;
        await _startLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (IsAlive) return;
            if (Volatile.Read(ref _disposed) == 1) throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}' disposed");
            await ConnectAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _startLock.Release();
        }
    }

    private async Task ConnectAsync(CancellationToken ct)
    {
        _started = false;
        _dead = false;
        _sessionId = null;
        _protocolVersion = McpProtocol.Latest;
        _negotiated = false;
        if (_legacySse) await OpenEventStreamAsync(ct).ConfigureAwait(false);

        JsonNode? init = await SendRequestCoreAsync("initialize", InitializeParams(), ct, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        _protocolVersion = ReadInitializeResult(init);
        _negotiated = true;
        await SendNotificationAsync("notifications/initialized", null, ct).ConfigureAwait(false);
        _started = true;
        Log.Info($"bridge '{Name}' connected to {_url} via {Transport}"
                 + (_sessionId is null ? string.Empty : $" session={_sessionId}")
                 + (ServerInfo is { } si ? $" ({si.Name} {si.Version})" : string.Empty));
    }

    // ------------------------------------------------------------------ outbound

    protected override async Task<JsonNode?> SendRequestAsync(string method, JsonNode? parameters, CancellationToken ct, TimeSpan timeout)
    {
        if (!IsAlive) throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}' is not connected");
        try
        {
            return await SendRequestCoreAsync(method, parameters, ct, timeout).ConfigureAwait(false);
        }
        catch (SessionLostException)
        {
            Log.Warn($"bridge '{Name}' session expired; reconnecting");
            await EnsureStartedAsync(ct).ConfigureAwait(false);
            return await SendRequestCoreAsync(method, parameters, ct, timeout).ConfigureAwait(false);
        }
    }

    private async Task<JsonNode?> SendRequestCoreAsync(string method, JsonNode? parameters, CancellationToken ct, TimeSpan timeout)
    {
        var id = RpcId.FromNumber(Interlocked.Increment(ref _nextId));
        byte[] body = Frame(w =>
        {
            w.WriteStartObject();
            w.WriteString("jsonrpc"u8, "2.0"u8);
            w.WritePropertyName("id"u8);
            id.WriteTo(w);
            w.WriteString("method"u8, method);
            if (parameters is not null) { w.WritePropertyName("params"u8); parameters.WriteTo(w); }
            w.WriteEndObject();
        });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct, _lifetime.Token);
        cts.CancelAfter(timeout);
        try
        {
            return _legacySse
                ? await PostAndWaitOnStreamAsync(id, body, cts.Token).ConfigureAwait(false)
                : await PostStreamableAsync(id, body, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && !_lifetime.IsCancellationRequested)
        {
            throw new TimeoutException($"bridge '{Name}' request {id} timed out");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _ = SendCancelAsync(id);
            throw;
        }
    }

    /// <summary>Streamable HTTP: the answer is the response body, as plain JSON or as an event stream carrying it.</summary>
    private async Task<JsonNode?> PostStreamableAsync(RpcId id, byte[] body, CancellationToken ct)
    {
        using var req = NewPost(_url, body);
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        await ThrowOnFailureAsync(resp, ct).ConfigureAwait(false);
        if (resp.Headers.TryGetValues("Mcp-Session-Id", out var sids) && sids.FirstOrDefault() is { Length: > 0 } sid) _sessionId = sid;

        if (IsEventStream(resp))
        {
            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            await foreach (var (_, data) in SseReader.ReadAsync(stream, ct).ConfigureAwait(false))
            {
                foreach (var msg in ParseMessages(data))
                {
                    if (msg.Method is null && msg.Id == id) return ResultOf(msg);
                    await DispatchAsync(msg).ConfigureAwait(false);
                }
            }
            throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}': event stream ended before the answer to {id}");
        }

        byte[] bytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        foreach (var msg in ParseMessages(bytes))
        {
            if (msg.Method is null && msg.Id == id) return ResultOf(msg);
            await DispatchAsync(msg).ConfigureAwait(false);
        }
        throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}': HTTP {(int)resp.StatusCode} without an answer to {id}");
    }

    /// <summary>HTTP+SSE: POST to the announced endpoint, the answer arrives on the GET stream (or, for some servers, inline).</summary>
    private async Task<JsonNode?> PostAndWaitOnStreamAsync(RpcId id, byte[] body, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<JsonNode?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;
        try
        {
            using var reg = ct.Register(static s => ((TaskCompletionSource<JsonNode?>)s!).TrySetCanceled(), tcs);
            using (var req = NewPost(_postUrl ?? _url, body))
            using (var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
            {
                await ThrowOnFailureAsync(resp, ct).ConfigureAwait(false);
                if (resp.StatusCode != HttpStatusCode.Accepted && resp.StatusCode != HttpStatusCode.NoContent)
                {
                    byte[] bytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                    foreach (var msg in ParseMessages(bytes)) await DispatchAsync(msg).ConfigureAwait(false);
                }
            }
            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    private async Task SendNotificationAsync(string method, JsonNode? parameters, CancellationToken ct)
    {
        byte[] body = Frame(w =>
        {
            w.WriteStartObject();
            w.WriteString("jsonrpc"u8, "2.0"u8);
            w.WriteString("method"u8, method);
            if (parameters is not null) { w.WritePropertyName("params"u8); parameters.WriteTo(w); }
            w.WriteEndObject();
        });
        await PostFireAndForgetAsync(body, ct).ConfigureAwait(false);
    }

    private async Task PostFireAndForgetAsync(byte[] body, CancellationToken ct)
    {
        using var req = NewPost(_legacySse ? _postUrl ?? _url : _url, body);
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        await ThrowOnFailureAsync(resp, ct).ConfigureAwait(false);
    }

    private async Task SendCancelAsync(RpcId id)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var p = new JsonObject { ["requestId"] = IdToNode(id), ["reason"] = "client cancelled" };
            await SendNotificationAsync("notifications/cancelled", p, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or McpBridgeException)
        {
            Log.Debug($"bridge '{Name}' cancel forward failed: {ex.Message}");
        }
    }

    private HttpRequestMessage NewPost(Uri url, byte[] body)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new ByteArrayContent(body) };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        ApplyHeaders(req);
        return req;
    }

    private void ApplyHeaders(HttpRequestMessage req)
    {
        if (_sessionId is not null) req.Headers.TryAddWithoutValidation("Mcp-Session-Id", _sessionId);
        if (_negotiated) req.Headers.TryAddWithoutValidation("MCP-Protocol-Version", _protocolVersion);
        foreach (var kv in _headers)
        {
            if (!req.Headers.TryAddWithoutValidation(kv.Key, kv.Value) && req.Content is not null)
                req.Content.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        }
    }

    private async Task ThrowOnFailureAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode) return;
        if (resp.StatusCode == HttpStatusCode.NotFound && _sessionId is not null)
        {
            _dead = true;
            throw new SessionLostException(Name);
        }
        string detail = string.Empty;
        try
        {
            string text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (text.Length > 0) detail = ": " + (text.Length > 200 ? text[..200] : text).ReplaceLineEndings(" ");
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException) { }

        if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new McpBridgeException(JsonRpcErrorCodes.InternalError,
                $"HTTP {(int)resp.StatusCode} from {_url.Host}: the server wants credentials; put them in the bridge's headers (Authorization: Bearer …){detail}");
        throw new McpBridgeException(JsonRpcErrorCodes.InternalError, $"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase} from {_url.Host}{detail}");
    }

    private static bool IsEventStream(HttpResponseMessage resp)
        => string.Equals(resp.Content.Headers.ContentType?.MediaType, "text/event-stream", StringComparison.OrdinalIgnoreCase);

    // ------------------------------------------------------------------ HTTP+SSE stream

    private async Task OpenEventStreamAsync(CancellationToken ct)
    {
        await CloseEventStreamAsync().ConfigureAwait(false);
        var req = new HttpRequestMessage(HttpMethod.Get, _url);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        ApplyHeaders(req);
        var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        try { await ThrowOnFailureAsync(resp, ct).ConfigureAwait(false); }
        catch { resp.Dispose(); throw; }

        var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var endpoint = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
        _stream = resp;
        _eventLoop = Task.Run(() => EventLoopAsync(new SseReader(stream), endpoint, _lifetime.Token), CancellationToken.None);

        using var reg = ct.Register(static s => ((TaskCompletionSource<Uri>)s!).TrySetCanceled(), endpoint);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var reg2 = deadline.Token.Register(static s =>
            ((TaskCompletionSource<Uri>)s!).TrySetException(new TimeoutException("no endpoint event within 30 s")), endpoint);
        _postUrl = await endpoint.Task.ConfigureAwait(false);
    }

    private async Task EventLoopAsync(SseReader reader, TaskCompletionSource<Uri> endpoint, CancellationToken ct)
    {
        try
        {
            await foreach (var (name, data) in reader.ReadAsync(ct).ConfigureAwait(false))
            {
                if (string.Equals(name, "endpoint", StringComparison.Ordinal))
                {
                    endpoint.TrySetResult(new Uri(_url, data.Trim()));
                    continue;
                }
                foreach (var msg in ParseMessages(data)) await DispatchAsync(msg).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is HttpRequestException or IOException or ObjectDisposedException)
        {
            if (Volatile.Read(ref _disposed) == 0) Log.Warn($"bridge '{Name}' event stream ended: {ex.Message}");
        }
        finally
        {
            endpoint.TrySetException(new McpBridgeException(JsonRpcErrorCodes.InternalError, $"bridge '{Name}': event stream closed before the endpoint event"));
            FailAllPending($"bridge '{Name}' event stream closed");
            if (_started && Volatile.Read(ref _disposed) == 0)
            {
                _dead = true; // the next call reconnects; the tools stay listed
                Log.Warn($"bridge '{Name}' event stream closed; will reconnect on the next call");
            }
        }
    }

    private async Task CloseEventStreamAsync()
    {
        var s = _stream;
        _stream = null;
        s?.Dispose(); // ends the read loop
        if (_eventLoop is { } loop)
        {
            try { await loop.ConfigureAwait(false); }
            catch (Exception ex) { Log.Debug($"bridge '{Name}' event loop: {ex.Message}"); }
            _eventLoop = null;
        }
    }

    // ------------------------------------------------------------------ inbound

    private async Task DispatchAsync(JsonRpcMessage msg)
    {
        if (msg.Method is null)
        {
            if (_pending.TryRemove(msg.Id, out var tcs))
            {
                if (msg.Error is { } err) tcs.TrySetException(new McpBridgeException(err.Code, err.Message));
                else tcs.TrySetResult(msg.Result);
            }
            else Log.Debug($"bridge '{Name}' response for unknown id {msg.Id}");
            return;
        }
        if (msg.Id.IsNone)
        {
            if (string.Equals(msg.Method, "notifications/tools/list_changed", StringComparison.Ordinal)) RaiseToolsChanged();
            else Log.Debug($"bridge '{Name}' notification {msg.Method}");
            return;
        }
        // A request from the server (ping, sampling, elicitation): answered with a POST of its own.
        bool ping = string.Equals(msg.Method, "ping", StringComparison.Ordinal);
        byte[] body = Frame(w =>
        {
            w.WriteStartObject();
            w.WriteString("jsonrpc"u8, "2.0"u8);
            w.WritePropertyName("id"u8);
            msg.Id.WriteTo(w);
            if (ping) { w.WritePropertyName("result"u8); w.WriteStartObject(); w.WriteEndObject(); }
            else
            {
                w.WritePropertyName("error"u8);
                w.WriteStartObject();
                w.WriteNumber("code"u8, JsonRpcErrorCodes.MethodNotFound);
                w.WriteString("message"u8, $"Hubris does not support client method '{msg.Method}'");
                w.WriteEndObject();
            }
            w.WriteEndObject();
        });
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await PostFireAndForgetAsync(body, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or McpBridgeException)
        {
            Log.Debug($"bridge '{Name}' could not answer server request {msg.Id}: {ex.Message}");
        }
    }

    private List<JsonRpcMessage> ParseMessages(string text) => ParseMessages(System.Text.Encoding.UTF8.GetBytes(text));

    private List<JsonRpcMessage> ParseMessages(ReadOnlySpan<byte> json)
    {
        var list = new List<JsonRpcMessage>(1);
        int i = 0;
        while (i < json.Length && (json[i] is (byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t')) i++;
        if (i >= json.Length) return list;
        try
        {
            var r = new Utf8JsonReader(json, isFinalBlock: true, state: default);
            if (json[i] == (byte)'[')
            {
                var batch = JsonSerializer.Deserialize(ref r, McpJsonContext.Default.ListJsonRpcMessage);
                if (batch is not null) foreach (var m in batch) if (m is not null) list.Add(m);
            }
            else
            {
                var one = JsonSerializer.Deserialize(ref r, McpJsonContext.Default.JsonRpcMessage);
                if (one is not null) list.Add(one);
            }
        }
        catch (JsonException ex)
        {
            Log.Warn($"bridge '{Name}' sent invalid JSON: {ex.Message}");
        }
        return list;
    }

    private static JsonNode? ResultOf(JsonRpcMessage msg)
    {
        if (msg.Error is { } err) throw new McpBridgeException(err.Code, err.Message);
        return msg.Result;
    }

    private static byte[] Frame(Action<Utf8JsonWriter> write)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using (var w = new Utf8JsonWriter(buf)) write(w);
        return buf.WrittenSpan.ToArray();
    }

    private void FailAllPending(string reason)
    {
        foreach (var kv in _pending)
            if (_pending.TryRemove(kv.Key, out var tcs))
                tcs.TrySetException(new McpBridgeException(JsonRpcErrorCodes.InternalError, reason));
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        if (!_legacySse && _started && _sessionId is not null)
        {
            // Streamable HTTP lets the client end its session explicitly; servers may answer 405, which is fine.
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                using var req = new HttpRequestMessage(HttpMethod.Delete, _url);
                ApplyHeaders(req);
                using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException)
            {
                Log.Debug($"bridge '{Name}' session delete: {ex.Message}");
            }
        }
        _lifetime.Cancel();
        await CloseEventStreamAsync().ConfigureAwait(false);
        FailAllPending($"bridge '{Name}' disposed");
        _http.Dispose();
        _startLock.Dispose();
        _lifetime.Dispose();
        if (_started) Log.Info($"bridge '{Name}' disconnected");
    }
}

using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using Hubris.Control;

namespace Hubris.Desktop.Services;

/// <summary>Polls the runtime directory for hub descriptors, connects to new hubs and prunes dead ones.</summary>
public sealed class HubDiscovery : IAsyncDisposable
{
    private readonly Dictionary<int, HubClient> _clients = new();
    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetime = new();
    private Task? _loop;

    public event Action<HubClient>? HubConnected;
    public event Action<HubClient>? HubDisconnected;

    public string RuntimeDir => HubrisPaths.RuntimeDir;

    public void Start()
    {
        _loop ??= Task.Run(() => LoopAsync(_lifetime.Token), CancellationToken.None);
    }

    public Task RescanAsync() => ScanAsync(_lifetime.Token);

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await ScanAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (Exception) { }
            try { await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanAsync(CancellationToken ct)
    {
        string dir = RuntimeDir;
        if (!Directory.Exists(dir)) return;

        foreach (string path in Directory.EnumerateFiles(dir, "*.json"))
        {
            HubDescriptor? d;
            try
            {
                await using var fs = File.OpenRead(path);
                d = await JsonSerializer.DeserializeAsync(fs, ControlJsonContext.Default.HubDescriptor, ct).ConfigureAwait(false);
            }
            catch (Exception) { continue; }
            if (d is null || d.Pid <= 0) continue;

            lock (_gate) { if (_clients.ContainsKey(d.Pid)) continue; }

            if (!IsProcessAlive(d.Pid) || !File.Exists(d.Socket))
            {
                TryDelete(path);
                TryDelete(d.Socket);
                continue;
            }

            var client = new HubClient(d);
            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromSeconds(2));
                await client.ConnectAsync(connectCts.Token).ConfigureAwait(false);
            }
            catch (SocketException)
            {
                // Nobody listens there: the PID was reused by another process. Forget the hub for good.
                await client.DisposeAsync().ConfigureAwait(false);
                TryDelete(path);
                TryDelete(d.Socket);
                continue;
            }
            catch (Exception)
            {
                await client.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            lock (_gate) { _clients[d.Pid] = client; }
            client.Disconnected += OnClientDisconnected;
            HubConnected?.Invoke(client);
        }
    }

    private void OnClientDisconnected(HubClient client)
    {
        lock (_gate) { _clients.Remove(client.Pid); }
        client.Disconnected -= OnClientDisconnected;
        HubDisconnected?.Invoke(client);
        _ = client.DisposeAsync();
    }

    private static bool IsProcessAlive(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch (Exception) { }
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel();
        if (_loop is not null) { try { await _loop.ConfigureAwait(false); } catch (Exception) { } }
        HubClient[] all;
        lock (_gate) { all = _clients.Values.ToArray(); _clients.Clear(); }
        foreach (var c in all) await c.DisposeAsync().ConfigureAwait(false);
        _lifetime.Dispose();
    }
}

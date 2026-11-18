using System.Globalization;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Hubris.Config;
using Hubris.Control;
using Hubris.Security;

namespace Hubris.Cli;

/// <summary>
/// The commands a person types into a terminal: what the running hubs are doing, and the bridges in config.json.
/// It reaches a hub over its control socket like any other local process, so the hub refuses mode and approval
/// commands from here unless it runs with --control-trust-all: a shell tool the model drives can run this binary too.
/// </summary>
public static class HubCli
{
    private static readonly string[] Commands = ["status", "tools", "watch", "mode", "approve", "deny", "bridge"];

    public static bool IsCommand(string[] args) => args.Length > 0 && Array.IndexOf(Commands, args[0]) >= 0;

    public static async Task<int> RunAsync(string[] args, TextWriter o)
    {
        string command = args[0];
        if (command == "bridge") return Bridge(args, o); // what follows the name belongs to the child server, --pid included

        int? pid = null;
        var rest = new List<string>();
        foreach (string a in args.Skip(1))
        {
            if (!a.StartsWith("--pid=", StringComparison.Ordinal)) { rest.Add(a); continue; }
            if (!int.TryParse(a[6..], NumberStyles.None, CultureInfo.InvariantCulture, out int p)) return Fail($"--pid wants a number, got '{a[6..]}'", 2);
            pid = p;
        }

        switch (command)
        {
            case "status" when rest.Count == 0:
            case "tools" when rest.Count <= 1:
            {
                int shown = 0;
                foreach (var hub in Descriptors(pid))
                {
                    if (await SnapshotAsync(hub) is not var (hello, waiting)) continue; // a descriptor left behind by a hub that is gone
                    if (shown++ > 0) o.WriteLine();
                    o.Write(command == "status" ? Describe(hello, waiting) : DescribeTools(hello, rest.FirstOrDefault()));
                }
                if (shown == 0) o.WriteLine(pid is null ? "no hub is running; an MCP client starts one when it needs it" : $"hub {pid} is not running");
                return 0;
            }

            case "watch" when rest.Count == 0:
                return await WatchAsync(pid, o);

            case "mode" when rest.Count == 1 && ModeNames.TryParseMode(rest[0], out var mode):
                return await SendAsync(Descriptors(pid), () => new ControlMessage { Type = ControlTypes.SetMode, Mode = ModeNames.ToText(mode) }, $"{ModeNames.ToText(mode)} mode", o);

            case "approve" or "deny" when rest.Count == 1:
            {
                // An approval id is "<hub pid>-<number>", so it says which hub to ask.
                int dash = rest[0].IndexOf('-');
                if (dash <= 0 || !int.TryParse(rest[0][..dash], NumberStyles.None, CultureInfo.InvariantCulture, out int owner))
                    return Fail($"'{rest[0]}' is not an approval id; they look like 4242-3 and are shown by status and watch", 2);
                bool approve = command == "approve";
                return await SendAsync(Descriptors(owner), () => new ControlMessage { Type = approve ? ControlTypes.Approve : ControlTypes.Deny, ApprovalId = rest[0] }, $"{rest[0]} {(approve ? "approved" : "denied")}", o);
            }
        }
        return Fail("usage: Hubris status | tools [text] | watch | mode <safe|auto|bypass> | approve <id> | deny <id>   [--pid=N]", 2);
    }

    // ------------------------------------------------------------------ what a hub says about itself

    public static string Describe(ControlMessage h, IReadOnlyList<ControlMessage> waiting)
    {
        var sb = new StringBuilder();
        sb.Append(Inv($"hub {h.Pid} · {Client(h)} · {h.Mode} mode · up {Span(h.UptimeSec ?? 0)} · Hubris {h.Version}\n"));
        sb.Append(Inv($"  folder    {h.Cwd}\n"));
        sb.Append(Inv($"  context   {h.ActiveTools ?? 0} of {h.ToolCount ?? 0} tools listed, {h.ActiveTokens ?? 0:N0} of {h.TotalTokens ?? 0:N0} tokens\n"));
        sb.Append(Inv($"  policy    {h.Blocked ?? 0} blocked, {h.DlpRedactions ?? 0} masked\n"));
        sb.Append(Inv($"  bridges   {h.BridgeCount ?? 0} configured, {h.BridgesRunning ?? 0} running\n"));
        if (h.BridgesFailed is { } failed)
            foreach (var f in failed) sb.Append(Inv($"  failed    {f.Key}: {OneLine(f.Value)}\n"));
        if (h.Auth is { } auth)
            foreach (var a in auth) sb.Append(Inv($"  sign-in   {a.Bridge}: {a.State}{(a.Error is { Length: > 0 } e ? " (" + OneLine(e) + ")" : string.Empty)}\n"));
        foreach (var w in waiting) sb.Append(Inv($"  waiting   {w.ApprovalId}  {w.Tool}  {Why(w.Reason)}\n"));
        return sb.ToString();
    }

    public static string DescribeTools(ControlMessage h, string? filter)
    {
        var tools = (h.Tools ?? []).Where(t => filter is null || t.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        int width = tools.Count == 0 ? 0 : tools.Max(t => t.Name.Length);
        var sb = new StringBuilder();
        sb.Append(Inv($"hub {h.Pid} · {Client(h)}\n"));
        foreach (var t in tools)
        {
            string state = t.Pinned ? "pinned" : t.Visible ? "listed" : "hidden";
            if (t.Decision is { Length: > 0 } d) state += ", " + d + " allowed";
            sb.Append(Inv($"  {t.Name.PadRight(width)}  {t.Tokens,7:N0}  {t.Risk,-11}  {state}\n"));
        }
        var listed = tools.Where(t => t.Visible).ToList();
        sb.Append(Inv($"  {tools.Count} tools ({tools.Sum(t => t.Tokens):N0} tokens), {listed.Count} listed ({listed.Sum(t => t.Tokens):N0} tokens)\n"));
        return sb.ToString();
    }

    private static string Client(ControlMessage m) => string.IsNullOrEmpty(m.Client) ? "no client yet" : ClientNames.Label(m.Client);

    private static string Inv(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);

    private static string Span(double seconds) => seconds switch
    {
        < 60 => Inv($"{seconds:0} s"),
        < 3600 => Inv($"{Math.Floor(seconds / 60):0} min"),
        _ => Inv($"{Math.Floor(seconds / 3600):0} h {Math.Floor(seconds % 3600 / 60):0} min"),
    };

    /// <summary>Reasons and errors come from servers and command lines: one line, and not a screenful of it.</summary>
    private static string OneLine(string? text)
    {
        string flat = string.Join(' ', (text ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return flat.Length > 200 ? string.Concat(flat.AsSpan(0, 200), "…") : flat;
    }

    /// <summary>A block reason opens with a sentence written for the model; a person needs the tag and what matched.</summary>
    private static string Why(string? reason)
    {
        string text = reason ?? string.Empty;
        foreach (string prefix in (string[])[SecurityInterceptor.BlockedPrefix, SecurityInterceptor.CriticalPrefix, SecurityInterceptor.AutoBlockedPrefix])
            if (text.StartsWith(prefix, StringComparison.Ordinal)) text = string.Concat(prefix.AsSpan(0, prefix.IndexOf(']') + 1), text.AsSpan(prefix.Length));
        return OneLine(text);
    }

    private static string Clock(string? timestamp)
        => (DateTime.TryParse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var t) ? t.ToLocalTime() : DateTime.Now).ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    // ------------------------------------------------------------------ talking to hubs

    private static List<HubDescriptor> Descriptors(int? pid)
    {
        var list = new List<HubDescriptor>();
        if (!Directory.Exists(HubrisPaths.RuntimeDir)) return list;
        foreach (string path in Directory.EnumerateFiles(HubrisPaths.RuntimeDir, "*.json"))
        {
            try
            {
                using var fs = File.OpenRead(path);
                if (JsonSerializer.Deserialize(fs, ControlJsonContext.Default.HubDescriptor) is { Pid: > 0 } d && (pid is null || d.Pid == pid)) list.Add(d);
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { } // being written, or not ours to read
        }
        list.Sort(static (a, b) => a.Pid.CompareTo(b.Pid));
        return list;
    }

    private sealed class Link : IDisposable
    {
        private readonly NetworkStream _stream;
        private readonly StreamReader _reader;

        private Link(Socket socket)
        {
            _stream = new NetworkStream(socket, ownsSocket: true);
            _reader = new StreamReader(_stream, Encoding.UTF8);
        }

        /// <summary>Null when nobody listens there: the descriptor of a hub that died without cleaning up.</summary>
        public static async Task<Link?> OpenAsync(HubDescriptor hub)
        {
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(hub.Socket), limit.Token).ConfigureAwait(false);
                return new Link(socket);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
            {
                socket.Dispose();
                return null;
            }
        }

        public Task SendAsync(ControlMessage message)
            => _stream.WriteAsync((byte[])[.. JsonSerializer.SerializeToUtf8Bytes(message, ControlJsonContext.Default.ControlMessage), (byte)'\n']).AsTask();

        /// <summary>The next message; null when the hub closed the connection or <paramref name="ct"/> ran out.</summary>
        public async Task<ControlMessage?> ReadAsync(CancellationToken ct)
        {
            try
            {
                while (await _reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
                {
                    try { if (JsonSerializer.Deserialize(line, ControlJsonContext.Default.ControlMessage) is { } m) return m; }
                    catch (JsonException) { } // a frame from a newer hub this build cannot read
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
            return null;
        }

        public void Dispose() => _reader.Dispose();
    }

    /// <summary>The hub's hello (status and tools) and the approvals waiting in it.</summary>
    private static async Task<(ControlMessage Hello, List<ControlMessage> Waiting)?> SnapshotAsync(HubDescriptor hub)
    {
        using var link = await Link.OpenAsync(hub).ConfigureAwait(false);
        if (link is null) return null;
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        ControlMessage? hello = null;
        var waiting = new List<ControlMessage>();
        try
        {
            // A hub greets with hello and the approvals that are waiting, then answers: the ack of this request ends both.
            await link.SendAsync(new ControlMessage { Type = ControlTypes.GetStatus, ReqId = 1 }).ConfigureAwait(false);
            while (await link.ReadAsync(limit.Token).ConfigureAwait(false) is { } m)
            {
                if (m.Type == ControlTypes.Hello) hello = m;
                else if (m.Type == ControlTypes.ApprovalRequest) waiting.Add(m);
                else if (m.Type == ControlTypes.ApprovalResolved) waiting.RemoveAll(w => w.ApprovalId == m.ApprovalId);
                else if (m.Type == ControlTypes.Ack && m.ReqId == 1) break;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException) { }
        return hello is null ? null : (hello, waiting);
    }

    /// <summary>One command to each hub; prints what each answered. 0 only when every hub that answered agreed.</summary>
    private static async Task<int> SendAsync(List<HubDescriptor> hubs, Func<ControlMessage> command, string done, TextWriter o)
    {
        int answered = 0, refused = 0;
        foreach (var hub in hubs)
        {
            using var link = await Link.OpenAsync(hub).ConfigureAwait(false);
            if (link is null) continue;
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            ControlMessage? ack = null;
            try
            {
                var cmd = command();
                cmd.ReqId = 1;
                await link.SendAsync(cmd).ConfigureAwait(false);
                while (await link.ReadAsync(limit.Token).ConfigureAwait(false) is { } m)
                    if (m.Type == ControlTypes.Ack && m.ReqId == 1) { ack = m; break; }
            }
            catch (Exception ex) when (ex is IOException or SocketException) { }
            if (ack is null) continue;
            answered++;
            if (ack.Ok == true) o.WriteLine($"hub {hub.Pid}: {done}");
            else { refused++; Console.Error.WriteLine($"hub {hub.Pid}: refused: {ack.Error}"); }
        }
        if (answered == 0) return Fail("no hub answered; Hubris status shows the ones that are running");
        return refused == 0 ? 0 : 1;
    }

    private static async Task<int> WatchAsync(int? pid, TextWriter o)
    {
        var following = new Dictionary<int, Task>();
        bool told = false;
        while (true)
        {
            foreach (var ended in following.Where(f => f.Value.IsCompleted).ToList())
            {
                if (ended.Value.IsFaulted) return 1; // the terminal or the pipe this writes to is gone
                following.Remove(ended.Key);
            }
            // Hubs come and go with the client sessions that start them, so the folder is read again on every round.
            foreach (var hub in Descriptors(pid))
                if (!following.ContainsKey(hub.Pid)) following[hub.Pid] = FollowAsync(hub, o);
            if (following.Count == 0)
            {
                if (pid is not null) return Fail($"hub {pid} is not running");
                if (!told) { o.WriteLine("no hub is running; waiting for one"); told = true; }
            }
            await Task.Delay(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
    }

    private static async Task FollowAsync(HubDescriptor hub, TextWriter o)
    {
        using var link = await Link.OpenAsync(hub).ConfigureAwait(false);
        if (link is null) return;
        while (await link.ReadAsync(CancellationToken.None).ConfigureAwait(false) is { } m)
        {
            string? line = m.Type switch
            {
                ControlTypes.Hello => Inv($"hub       {Client(m)} · {m.Mode} mode · {m.ActiveTools ?? 0} of {m.ToolCount ?? 0} tools listed"),
                ControlTypes.ToolCall => Inv($"call      {m.Tool}  {m.Risk}  {m.Outcome}  {m.DurationMs ?? 0:0.#} ms"),
                ControlTypes.ApprovalRequest => Inv($"approval  {m.ApprovalId}  {m.Tool}  {Why(m.Reason)}"),
                ControlTypes.ApprovalResolved => Inv($"resolved  {m.ApprovalId}  {m.Tool}  {m.Decision}"),
                ControlTypes.ModeChanged => Inv($"mode      {m.Mode}"),
                _ => null, // the status every two seconds, tool list and sign-in changes
            };
            if (line is not null) o.WriteLine($"{Clock(m.Timestamp)}  {hub.Pid}  {line}");
        }
        o.WriteLine($"{Clock(null)}  {hub.Pid}  closed");
    }

    // ------------------------------------------------------------------ config.json

    private static int Bridge(string[] args, TextWriter o)
    {
        HubrisConfig config;
        try { config = HubrisConfigFile.Load(); }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return Fail($"{HubrisPaths.ConfigPath}: {ex.Message}"); }

        string done;
        switch (args.Length > 1 ? args[1] : "list")
        {
            case "list" when args.Length <= 2:
            {
                if (config.Bridges.Count == 0) o.WriteLine($"no bridges in {HubrisPaths.ConfigPath}");
                int width = config.Bridges.Count == 0 ? 0 : config.Bridges.Max(b => b.Name.Length);
                foreach (var b in config.Bridges)
                {
                    // Arguments are shown, env and header values are not: that is where the keys are.
                    string target = b.IsRemote ? b.Url! : string.Join(' ', b.Args.Select(ArgLine.Quote).Prepend(b.Command));
                    o.WriteLine($"{b.Name.PadRight(width)}  {b.ToSpec().TransportName,-5}  {target}{(b.Auth is not null ? "  (sign-in)" : string.Empty)}");
                }
                return 0;
            }

            case "add" when args.Length >= 4:
            {
                // The name is checked on its own first: "a:b" glued to the command would read as bridge "a" running "b:…".
                if (!BridgeSpec.IsValidName(args[2])) return Fail($"bridge name '{args[2]}': {BridgeSpec.NameRule}");
                if (!CliOptions.TryParseBridge($"{args[2]}:{args[3]}", args[4..], out var spec, out string? error) || spec is null) return Fail(error ?? "invalid bridge");
                if (config.Bridges.Any(b => b.Name == spec.Name)) return Fail($"bridge '{spec.Name}' is already in the config; remove it first");
                config.Bridges.Add(new BridgeConfig
                {
                    Name = spec.Name, Command = spec.Command, Args = [.. spec.Args], Url = spec.Url,
                    Headers = spec.Headers is null ? null : new Dictionary<string, string>(spec.Headers),
                    Transport = spec.IsRemote ? spec.TransportName : null, Source = "cli",
                });
                done = $"added '{spec.Name}'";
                break;
            }

            case "remove" when args.Length == 3:
                if (config.Bridges.RemoveAll(b => b.Name == args[2]) == 0) return Fail($"no bridge '{args[2]}' in the config");
                done = $"removed '{args[2]}'";
                break;

            default:
                return Fail("usage: Hubris bridge list | add <name> <command|url> [arg ...] | remove <name>", 2);
        }

        try { HubrisConfigFile.Save(config); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return Fail($"{HubrisPaths.ConfigPath}: {ex.Message}"); }
        o.WriteLine($"{done}; a hub reads the config when it starts, so it applies from the next client session");
        return 0;
    }

    private static int Fail(string message, int code = 1)
    {
        Console.Error.WriteLine("hubris: " + message);
        return code;
    }
}

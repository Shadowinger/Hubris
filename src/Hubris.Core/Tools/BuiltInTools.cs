using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hubris.Engine;
using Hubris.Protocol;
using Hubris.Security;
using Hubris.Transport;

namespace Hubris.Tools;

// ============================================================================ ProcessRunner

public readonly record struct ProcessResult(int ExitCode, string StdOut, string StdErr, bool TimedOut);

public static class ProcessRunner
{
    public static async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> args, string? workingDirectory, TimeSpan timeout, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardInput = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (!string.IsNullOrEmpty(workingDirectory)) psi.WorkingDirectory = workingDirectory;

        using var process = new Process { StartInfo = psi };
        process.Start();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);

        Task<string> stdout = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
        Task<string> stderr = process.StandardError.ReadToEndAsync(timeoutCts.Token);

        bool timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            timedOut = !ct.IsCancellationRequested;
            try { process.Kill(entireProcessTree: true); } catch (Exception ex) { Log.Debug($"kill {fileName}: {ex.Message}"); }
            if (ct.IsCancellationRequested) throw;
        }

        string outText = string.Empty, errText = string.Empty;
        try { outText = await stdout.ConfigureAwait(false); } catch (OperationCanceledException) { }
        try { errText = await stderr.ConfigureAwait(false); } catch (OperationCanceledException) { }

        int code = process.HasExited ? process.ExitCode : -1;
        return new ProcessResult(code, outText, errText, timedOut);
    }
}

// ============================================================================ hub_status

public sealed class HubStatusTool : IMcpTool
{
    private readonly HubRuntime _rt;

    public HubStatusTool(HubRuntime runtime) => _rt = runtime;

    public string Name => "hub_status";
    public string Description => "Hubris runtime status: RAM footprint, uptime, execution mode (Safe/Auto/Bypass), cache hit ratio, registered tool counts.";
    public ToolRiskLevel RiskLevel => ToolRiskLevel.ReadOnly;
    public bool Pinned => true;
    public JsonObject InputSchema { get; } = SchemaBuilder.Object();

    public ValueTask<CallToolResult> ExecuteAsync(JsonObject? arguments, CancellationToken ct)
    {
        var reg = _rt.Registry;
        long ws = Environment.WorkingSet;
        long heap = GC.GetTotalMemory(false);
        double up = _rt.Uptime.Elapsed.TotalSeconds;
        int tools = reg.Count, pinned = reg.PinnedCount, bridged = reg.BridgedCount;

        var sb = new StringBuilder(256);
        sb.Append("mode=").Append(ModeNames.ToText(_rt.Mode));
        sb.Append(" compact=").Append(_rt.CompactContext ? "on" : "off");
        sb.Append(" uptime=").Append(up.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture)).Append('s');
        sb.Append(" rss=").Append((ws / 1048576.0).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture)).Append("MB");
        sb.Append(" heap=").Append((heap / 1024.0).ToString("0", System.Globalization.CultureInfo.InvariantCulture)).Append("KB");
        sb.Append(" gc=").Append(GC.CollectionCount(0)).Append('/').Append(GC.CollectionCount(1)).Append('/').Append(GC.CollectionCount(2));
        sb.Append(" tools=").Append(tools).Append(" (pinned ").Append(pinned).Append(", on-demand ").Append(tools - pinned).Append(", bridged ").Append(bridged).Append(')');
        sb.Append(" bridges=").Append(_rt.BridgeCount).Append(" (").Append(_rt.BridgesRunning).Append(" running)");
        int resources = 0, templates = 0, prompts = 0;
        foreach (var kv in _rt.Extras) { resources += kv.Value.Resources.Count; templates += kv.Value.ResourceTemplates.Count; prompts += kv.Value.Prompts.Count; }
        if (resources + templates + prompts > 0) sb.Append(" resources=").Append(resources).Append('+').Append(templates).Append(" prompts=").Append(prompts);
        sb.Append(" context=").Append(reg.GetContextStats().ToString());
        if (_rt.ToolCache is { } tc) sb.Append(" toolcache=hits ").Append(tc.Hits).Append("/miss ").Append(tc.Misses).Append(" entries ").Append(tc.Count);
        else sb.Append(" toolcache=off");
        sb.Append(" blocked=").Append(_rt.Security.BlockedCount);
        if (_rt.Control is { } ctl)
            sb.Append(" control=").Append(ctl.Server.ClientCount).Append(" client(s), ").Append(ctl.Approvals.Count).Append(" pending approval(s)");
        else
            sb.Append(" control=off");
        sb.Append(" dlp_redactions=").Append(DlpSanitizer.RedactionCount);
        sb.Append(" pid=").Append(Environment.ProcessId);
        sb.Append(" version=").Append(HubRuntime.Version);
        return ValueTask.FromResult(CallToolResult.Text(sb.ToString()));
    }
}

// ============================================================================ git_smart_status

public sealed class GitSmartStatusTool : IMcpTool
{
    public GitSmartStatusTool(bool pinned) => Pinned = pinned;

    public string Name => "git_smart_status";
    public string Description => "Token-efficient git summary: branch, ahead/behind, change counts by kind (staged/unstaged/untracked/conflicts), top changed paths and diff stat.";
    public ToolRiskLevel RiskLevel => ToolRiskLevel.ReadOnly;
    public bool Pinned { get; }

    public JsonObject InputSchema { get; } = SchemaBuilder.Object(
        ("cwd", SchemaBuilder.String("Working directory of the repository (default: current directory)"), false),
        ("maxFiles", SchemaBuilder.Integer("Maximum number of file paths to list", 0, 500, 20), false));

    public async ValueTask<CallToolResult> ExecuteAsync(JsonObject? arguments, CancellationToken ct)
    {
        string cwd = ArgReader.GetString(arguments, "cwd", Environment.CurrentDirectory)!;
        int maxFiles = Math.Clamp(ArgReader.GetInt(arguments, "maxFiles", 20), 0, 500);

        if (!Directory.Exists(cwd))
            return CallToolResult.Error($"Directory not found: {cwd}");

        var timeout = TimeSpan.FromSeconds(15);
        ProcessResult status;
        try
        {
            status = await ProcessRunner.RunAsync("git", ["status", "--porcelain=v1", "-b", "--untracked-files=normal"], cwd, timeout, ct).ConfigureAwait(false);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return CallToolResult.Error("git executable not found on PATH.");
        }

        if (status.TimedOut) return CallToolResult.Error("git status timed out.");
        if (status.ExitCode != 0)
        {
            string err = FirstLine(status.StdErr);
            return CallToolResult.Error(err.Length > 0 ? err : $"git status failed (exit {status.ExitCode}).");
        }

        var diff = await ProcessRunner.RunAsync("git", ["diff", "--stat", "--no-color"], cwd, timeout, ct).ConfigureAwait(false);
        var staged = await ProcessRunner.RunAsync("git", ["diff", "--stat", "--no-color", "--cached"], cwd, timeout, ct).ConfigureAwait(false);

        return CallToolResult.Text(Summarize(status.StdOut, diff.StdOut, staged.StdOut, maxFiles));
    }

    private static string Summarize(string porcelain, string diffStat, string stagedStat, int maxFiles)
    {
        string branch = "(detached)";
        string tracking = string.Empty;
        int stagedN = 0, unstagedN = 0, untracked = 0, conflicts = 0, renamed = 0, deleted = 0, added = 0, modified = 0;
        var files = new List<string>(Math.Min(maxFiles, 64));
        int totalFiles = 0;

        foreach (var rawLine in porcelain.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');
            if (line.Length == 0) continue;

            if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                string hdr = line[3..];
                int bracket = hdr.IndexOf(" [", StringComparison.Ordinal);
                if (bracket >= 0)
                {
                    tracking = hdr[(bracket + 2)..].TrimEnd(']');
                    hdr = hdr[..bracket];
                }
                int dots = hdr.IndexOf("...", StringComparison.Ordinal);
                branch = dots >= 0 ? hdr[..dots] : hdr;
                if (dots >= 0 && tracking.Length == 0) tracking = "up to date";
                continue;
            }

            if (line.Length < 3) continue;
            char x = line[0], y = line[1];
            string path = line[3..];
            totalFiles++;

            if (x == '?' && y == '?') untracked++;
            else if (x == 'U' || y == 'U' || (x == 'A' && y == 'A') || (x == 'D' && y == 'D')) conflicts++;
            else
            {
                if (x != ' ' && x != '?') stagedN++;
                if (y != ' ' && y != '?') unstagedN++;
                char k = x != ' ' ? x : y;
                switch (k)
                {
                    case 'M': modified++; break;
                    case 'A': added++; break;
                    case 'D': deleted++; break;
                    case 'R': renamed++; break;
                    case 'C': added++; break;
                    case 'T': modified++; break;
                }
            }

            if (files.Count < maxFiles) files.Add(string.Concat(x.ToString(), y.ToString(), " ", path));
        }

        var sb = new StringBuilder(512);
        sb.Append("branch=").Append(branch);
        if (tracking.Length > 0) sb.Append(" [").Append(tracking).Append(']');
        sb.Append('\n');

        if (totalFiles == 0)
        {
            sb.Append("clean working tree");
            return sb.ToString();
        }

        sb.Append("changes=").Append(totalFiles)
          .Append(" staged=").Append(stagedN)
          .Append(" unstaged=").Append(unstagedN)
          .Append(" untracked=").Append(untracked);
        if (conflicts > 0) sb.Append(" CONFLICTS=").Append(conflicts);
        sb.Append(" | M").Append(modified).Append(" A").Append(added).Append(" D").Append(deleted).Append(" R").Append(renamed).Append('\n');

        string unstagedSummary = LastNonEmptyLine(diffStat);
        string stagedSummary = LastNonEmptyLine(stagedStat);
        if (stagedSummary.Length > 0) sb.Append("staged: ").Append(stagedSummary.Trim()).Append('\n');
        if (unstagedSummary.Length > 0) sb.Append("unstaged: ").Append(unstagedSummary.Trim()).Append('\n');

        if (files.Count > 0)
        {
            sb.Append("files:");
            foreach (var f in files) sb.Append("\n  ").Append(f);
            if (totalFiles > files.Count) sb.Append("\n  … +").Append(totalFiles - files.Count).Append(" more");
        }
        return sb.ToString();
    }

    private static string FirstLine(string text)
    {
        int nl = text.IndexOf('\n');
        return (nl >= 0 ? text[..nl] : text).Trim();
    }

    private static string LastNonEmptyLine(string text)
    {
        var lines = text.Split('\n');
        for (int i = lines.Length - 1; i >= 0; i--)
        {
            string l = lines[i].Trim();
            if (l.Length > 0) return l;
        }
        return string.Empty;
    }
}

// ============================================================================ fs_read_head

public sealed partial class FsReadHeadTool : IMcpTool
{
    [System.Runtime.InteropServices.LibraryImport("libc", SetLastError = true, StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf8)]
    private static partial int open(string path, int flags);

    /// <summary>
    /// A plain open() of a named pipe waits for a writer that may never come. Opened non-blocking it returns at once,
    /// and the CanSeek check turns the pipe away; for a regular file the flag changes nothing.
    /// </summary>
    private static FileStream OpenForRead(string path)
    {
        if (OperatingSystem.IsWindows())
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 16 * 1024, FileOptions.SequentialScan | FileOptions.Asynchronous);
        int fd = open(path, OperatingSystem.IsMacOS() ? 0x4 | 0x1000000 : 0x800 | 0x80000); // O_RDONLY | O_NONBLOCK | O_CLOEXEC on macOS, else Linux
        if (fd >= 0) return new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(fd, ownsHandle: true), FileAccess.Read, 16 * 1024);
        int errno = System.Runtime.InteropServices.Marshal.GetLastPInvokeError();
        throw errno == 13 ? new UnauthorizedAccessException($"Access to the path '{path}' is denied.") : new IOException($"cannot open '{path}' (errno {errno})");
    }

    public FsReadHeadTool(bool pinned) => Pinned = pinned;

    public string Name => "fs_read_head";
    public string Description => "Read the first N lines of a text file without loading it entirely; secrets and personal identifiers are masked.";
    public ToolRiskLevel RiskLevel => ToolRiskLevel.ReadOnly;
    public bool Pinned { get; }

    public JsonObject InputSchema { get; } = SchemaBuilder.Object(
        ("path", SchemaBuilder.String("Absolute or relative path to the file"), true),
        ("lines", SchemaBuilder.Integer("Number of lines to return", 1, 2000, 50), false),
        ("maxLineLength", SchemaBuilder.Integer("Truncate lines longer than this many characters", 16, 10000, 400), false));

    /// <summary>
    /// Reads at most <paramref name="lines"/> lines, each cut at <paramref name="maxLen"/> chars, and never more than
    /// lines × (maxLen + 1) characters in total – so a single 50 MB line or an endless device cannot pull everything into memory.
    /// </summary>
    public static async Task<(string Text, int Lines, bool More)> ReadHeadAsync(TextReader reader, int lines, int maxLen, CancellationToken ct)
    {
        long budget = (long)lines * (maxLen + 1);
        var sb = new StringBuilder((int)Math.Min(budget, 64 * 1024));
        char[] buf = new char[8192];
        int count = 0, lineLen = 0;
        bool truncated = false, more = false, atLineStart = true;

        while (count < lines)
        {
            int n = await reader.ReadAsync(buf.AsMemory(), ct).ConfigureAwait(false);
            if (n == 0) break;
            for (int i = 0; i < n; i++)
            {
                char c = buf[i];
                if (c == '\r') continue;
                if (c == '\n')
                {
                    if (truncated) sb.Append('…');
                    sb.Append('\n');
                    count++; lineLen = 0; truncated = false; atLineStart = true;
                    if (count == lines) { more = i + 1 < n || reader.Peek() >= 0; return (sb.ToString(), count, more); }
                    continue;
                }
                atLineStart = false;
                if (lineLen < maxLen) sb.Append(c); else truncated = true;
                lineLen++;
                if (--budget <= 0) { sb.Append('…').Append('\n'); return (sb.ToString(), count + 1, true); }
            }
        }
        if (!atLineStart) { if (truncated) sb.Append('…'); sb.Append('\n'); count++; }
        return (sb.ToString(), count, more);
    }

    public async ValueTask<CallToolResult> ExecuteAsync(JsonObject? arguments, CancellationToken ct)
    {
        string? rawPath = ArgReader.GetString(arguments, "path");
        if (string.IsNullOrWhiteSpace(rawPath)) return CallToolResult.Error("Missing required argument 'path'.");

        int lines = Math.Clamp(ArgReader.GetInt(arguments, "lines", 50), 1, 2000);
        int maxLen = Math.Clamp(ArgReader.GetInt(arguments, "maxLineLength", 400), 16, 10000);

        string path;
        try { path = Path.GetFullPath(rawPath); }
        catch (Exception ex) { return CallToolResult.Error($"Invalid path: {ex.Message}"); }

        if (Directory.Exists(path)) return CallToolResult.Error($"Path is a directory: {path}");
        if (!File.Exists(path)) return CallToolResult.Error($"File not found: {path}");

        try
        {
            await using var fs = OpenForRead(path);
            if (!fs.CanSeek) return CallToolResult.Error($"Not a regular file: {path}");

            // Binary sniff on the first 8 KiB (fixed size: devices report Length 0 but still produce bytes).
            byte[] probe = new byte[8192];
            int read = 0;
            while (read < probe.Length)
            {
                int n = await fs.ReadAsync(probe.AsMemory(read), ct).ConfigureAwait(false);
                if (n == 0) break;
                read += n;
            }
            if (probe.AsSpan(0, read).IndexOf((byte)0) >= 0)
                return CallToolResult.Error($"Binary file (NUL byte within first {read} bytes): {path}");
            fs.Position = 0;

            using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 16 * 1024, leaveOpen: true);
            var (text, count, more) = await ReadHeadAsync(reader, lines, maxLen, ct).ConfigureAwait(false);

            string header = $"# {path} ({count}{(more ? "+" : "")} lines, {fs.Length} bytes)\n";
            return CallToolResult.Text(DlpSanitizer.Sanitize(header + text));
        }
        catch (UnauthorizedAccessException) { return CallToolResult.Error($"Access denied: {path}"); }
        catch (IOException ex) { return CallToolResult.Error($"I/O error: {ex.Message}"); }
    }
}

// ============================================================================ mcp_search_tools

/// <summary>Marker for meta tools that may unlock on-demand tools; the router compares the registry's unlocked count around the call.</summary>
public interface IUnlockingTool : IMcpTool
{
}

public sealed class SearchToolsMetaTool : IUnlockingTool
{
    public const string ToolName = "mcp_search_tools";
    private readonly ToolRegistry _registry;

    public SearchToolsMetaTool(ToolRegistry registry) => _registry = registry;

    public string Name => ToolName;
    public string Description => "Discover additional tools by keyword. Returns full schemas of matching tools and unlocks them (they appear in tools/list and can also be run via mcp_execute_tool). Use when the task needs a capability not in the current tool list.";
    public ToolRiskLevel RiskLevel => ToolRiskLevel.ReadOnly;
    public bool Pinned => true;

    public JsonObject InputSchema { get; } = SchemaBuilder.Object(
        ("query", SchemaBuilder.String("Keywords describing the capability you need, e.g. 'git status' or 'read file'"), true),
        ("limit", SchemaBuilder.Integer("Maximum number of tools to return", 1, 50, 10), false));

    public ValueTask<CallToolResult> ExecuteAsync(JsonObject? arguments, CancellationToken ct)
    {
        string query = ArgReader.GetString(arguments, "query", string.Empty)!;
        int limit = Math.Clamp(ArgReader.GetInt(arguments, "limit", 10), 1, 50);

        if (string.IsNullOrWhiteSpace(query))
            return ValueTask.FromResult(CallToolResult.Error("Argument 'query' must be a non-empty string."));

        var hits = _registry.Search(query, limit);
        if (hits.Count == 0)
            return ValueTask.FromResult(CallToolResult.Text($"No tools match '{query}'. {_registry.Count} tools registered in total."));

        var defs = new List<ToolDefinition>(hits.Count);
        foreach (var hit in hits)
        {
            defs.Add(ToolRegistry.ToDefinition(hit.Tool));
            if (hit.Tool.Name != ToolName) _registry.Unlock(hit.Tool.Name);
        }

        string json = JsonSerializer.Serialize(defs, McpJsonContext.Default.ListToolDefinition);
        string text = $"{hits.Count} tool(s) match '{query}'. They are unlocked: call them by name (tools/list now includes them) or via mcp_execute_tool {{\"toolName\", \"arguments\"}} if your client ignores notifications/tools/list_changed.\n{json}";
        return ValueTask.FromResult(CallToolResult.Text(text));
    }
}

// ============================================================================ mcp_execute_tool

/// <summary>
/// Universal proxy: runs any registered tool by name through the hub's normal pipeline
/// (security, approval, cache, DLP). Lets clients that never refresh tools/list use unlocked tools.
/// </summary>
public sealed class ExecuteToolMetaTool : IUnlockingTool
{
    public const string ToolName = "mcp_execute_tool";
    private readonly ToolRegistry _registry;

    public ExecuteToolMetaTool(ToolRegistry registry) => _registry = registry;

    /// <summary>Installed by the router; executes the target through the full tools/call pipeline.</summary>
    public Func<string, JsonObject?, CancellationToken, ValueTask<CallToolResult>>? Invoker { get; set; }

    public string Name => ToolName;
    public string Description => "Execute any registered tool by name, including on-demand tools found via mcp_search_tools, without waiting for tools/list to refresh. Same security policy applies.";
    public ToolRiskLevel RiskLevel => ToolRiskLevel.ReadOnly; // the target's own risk is enforced inside the pipeline
    public bool Pinned => true;

    public JsonObject InputSchema { get; } = SchemaBuilder.Object(
        ("toolName", SchemaBuilder.String("Exact name of the tool to run (e.g. git_smart_status or gh__create_issue)"), true),
        ("arguments", new JsonObject { ["type"] = "object", ["description"] = "Arguments object for the target tool", ["additionalProperties"] = true }, false));

    public async ValueTask<CallToolResult> ExecuteAsync(JsonObject? arguments, CancellationToken ct)
    {
        string? target = ArgReader.GetString(arguments, "toolName");
        if (string.IsNullOrWhiteSpace(target))
            return CallToolResult.Error("Argument 'toolName' is required.");
        if (string.Equals(target, ToolName, StringComparison.Ordinal))
            return CallToolResult.Error($"{ToolName} cannot invoke itself.");
        if (!_registry.TryGet(target, out _))
            return CallToolResult.Error($"Unknown tool '{target}'. Use {SearchToolsMetaTool.ToolName} to discover available tools.");

        JsonObject? targetArgs = null;
        if (arguments is not null && arguments.TryGetPropertyValue("arguments", out var node))
        {
            if (node is JsonObject jo) targetArgs = (JsonObject)jo.DeepClone();
            else if (node is not null) return CallToolResult.Error("'arguments' must be a JSON object.");
        }

        var invoker = Invoker ?? throw new InvalidOperationException("ExecuteToolMetaTool has no invoker installed.");
        var result = await invoker(target, targetArgs, ct).ConfigureAwait(false);
        if (!result.Failed) _registry.Unlock(target);
        return result;
    }
}

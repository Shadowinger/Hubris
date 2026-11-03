using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Hubris.Transport;

namespace Hubris.Security;

public enum ExecutionMode : byte
{
    Safe = 0,
    Bypass = 1,
}

public enum ToolRiskLevel : byte
{
    ReadOnly = 0,
    Mutating = 1,
    Destructive = 2,
}

public static class ModeNames
{
    public static string ToText(ExecutionMode mode) => mode == ExecutionMode.Bypass ? "Bypass" : "Safe";

    public static string ToText(ToolRiskLevel level) => level switch
    {
        ToolRiskLevel.ReadOnly => "ReadOnly",
        ToolRiskLevel.Mutating => "Mutating",
        _ => "Destructive",
    };

    public static bool TryParseMode(string? text, out ExecutionMode mode)
    {
        if (string.Equals(text, "safe", StringComparison.OrdinalIgnoreCase)) { mode = ExecutionMode.Safe; return true; }
        if (string.Equals(text, "bypass", StringComparison.OrdinalIgnoreCase)) { mode = ExecutionMode.Bypass; return true; }
        mode = ExecutionMode.Safe;
        return false;
    }
}

/// <summary>Compiled-at-build-time danger signatures, scanned against the argument *values* (see <see cref="SecurityInterceptor.ScanText"/>).</summary>
public static partial class DangerPatterns
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private const int Timeout = 250; // ms; a timeout counts as a hit, so a crafted argument cannot stall the hub

    [GeneratedRegex(@"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|ROLE)\b", Opts, Timeout)]
    public static partial Regex DropStatement();

    [GeneratedRegex(@"\bTRUNCATE\s+(TABLE\s+)?[\w.""\[\]`]+", Opts, Timeout)]
    public static partial Regex TruncateStatement();

    // DELETE/UPDATE are judged per ';'-separated statement: a WHERE on the next line still counts.
    [GeneratedRegex(@"\bDELETE\s+FROM\s+[\w.""\[\]`]+", Opts, Timeout)]
    public static partial Regex DeleteFrom();

    [GeneratedRegex(@"\bUPDATE\s+[\w.""\[\]`]+\s+SET\b", Opts, Timeout)]
    public static partial Regex UpdateSet();

    [GeneratedRegex(@"\bWHERE\b", Opts, Timeout)]
    public static partial Regex WhereClause();

    // rm -rf / rm -fr / rm -r -f / rm --recursive --force; the binary may be quoted ('rm' -rf)
    [GeneratedRegex(@"\brm['""]?\s+(-\w*r\w*f|-\w*f\w*r|-\w*r\w*\s+-\w*f|-\w*f\w*\s+-\w*r|--recursive\s+--force|--force\s+--recursive)\b", Opts, Timeout)]
    public static partial Regex RmRecursiveForce();

    [GeneratedRegex(@"(^|[\s""'=])--force\b|(^|[\s""'])-f\b(?=[^\n]*\bpush\b)", Opts, Timeout)]
    public static partial Regex ForceFlag();

    // git [-C dir] push … --force|-f|+ref, reset --hard, clean -f (any flag order), branch -D, checkout -- .
    [GeneratedRegex(@"\bgit['""]?\s+(-C\s+\S+\s+)?(push\s+[^\n""]*?(--force\b|-f\b|\+\S)|reset\s+--hard|clean\s+(-\w+\s+)*-\w*f\b|branch\s+-D\b|checkout\s+--\s+\.)", Opts, Timeout)]
    public static partial Regex GitDestructive();

    [GeneratedRegex(@"\b(mkfs(\.\w+)?|dd\s+if=|shred\s|wipefs|diskutil\s+erase|format\s+[a-z]:)", Opts, Timeout)]
    public static partial Regex DiskWipe();

    [GeneratedRegex(@"\|\s*(sudo\s+)?(sh|bash|zsh|python\d?|perl|node)\b", Opts, Timeout)]
    public static partial Regex PipeToShell();

    [GeneratedRegex(@"\b(chmod\s+-R\s+0?777|chown\s+-R\s+root|:\(\)\s*\{\s*:\|:&\s*\};:)", Opts, Timeout)]
    public static partial Regex PrivilegeAbuse();

    public readonly record struct Rule(string Name, Regex Pattern);

    public static readonly Rule[] All =
    [
        new("DROP statement", DropStatement()),
        new("TRUNCATE statement", TruncateStatement()),
        new("rm -rf", RmRecursiveForce()),
        new("--force flag", ForceFlag()),
        new("destructive git", GitDestructive()),
        new("disk wipe", DiskWipe()),
        new("pipe to shell", PipeToShell()),
        new("privilege abuse", PrivilegeAbuse()),
    ];
}

/// <param name="PatternHit">The block came from a matched argument pattern, not from the tool's declared risk.</param>
public readonly record struct SecurityVerdict(bool Allowed, string? Reason, bool PatternHit = false)
{
    public static readonly SecurityVerdict Ok = new(true, null);
    public static SecurityVerdict Blocked(string reason, bool patternHit = false) => new(false, reason, patternHit);
}

public sealed class SecurityInterceptor
{
    public const string BlockedPrefix = "[SAFE MODE BLOCKED] Action requires explicit user confirmation or switching Hubris to Bypass mode.";

    private long _blocked;
    private int _mode;

    /// <summary>Session-scoped "remember this decision" per tool: true = always allow, false = always deny.</summary>
    private readonly ConcurrentDictionary<string, bool> _decisions = new(StringComparer.Ordinal);

    /// <summary>
    /// Every string value in the arguments, in document order, joined by spaces. A shell sees "rm -rf /" whether
    /// it came as one string, as {command:"rm", args:["-rf","/"]}, with a tab, or with a quoted binary; the JSON
    /// encoding (\t, \u0027, "," between array items) would hide all of those from the patterns.
    /// </summary>
    public static string ScanText(JsonObject? arguments)
    {
        if (arguments is null) return string.Empty;
        var sb = new System.Text.StringBuilder();
        Collect(arguments, sb);
        return sb.ToString();

        static void Collect(JsonNode? node, System.Text.StringBuilder sb)
        {
            switch (node)
            {
                case JsonObject o: foreach (var kv in o) Collect(kv.Value, sb); break;
                case JsonArray a: foreach (var item in a) Collect(item, sb); break;
                case JsonValue v when v.TryGetValue<string>(out var text):
                    if (sb.Length > 0) sb.Append(' ');
                    sb.Append(text);
                    break;
            }
        }
    }

    public SecurityInterceptor(ExecutionMode mode)
    {
        _mode = (int)mode;
    }

    /// <summary>null = never decided; true = allow-listed; false = deny-listed for this hub's lifetime.</summary>
    public bool? DecisionFor(string toolName) => _decisions.TryGetValue(toolName, out var allow) ? allow : null;
    public void Remember(string toolName, bool allow) => _decisions[toolName] = allow;
    public bool Forget(string toolName) => _decisions.TryRemove(toolName, out _);
    public IReadOnlyCollection<KeyValuePair<string, bool>> Decisions => _decisions;

    /// <summary>Switchable at runtime from the control channel; reads are lock-free.</summary>
    public ExecutionMode Mode
    {
        get => (ExecutionMode)Volatile.Read(ref _mode);
        set => Volatile.Write(ref _mode, (int)value);
    }
    public long BlockedCount => Interlocked.Read(ref _blocked);

    /// <param name="bridged">A bridge's own readOnlyHint is not trusted: its arguments are still scanned.</param>
    public SecurityVerdict Evaluate(string toolName, ToolRiskLevel risk, JsonObject? arguments, bool bridged = false)
    {
        if (Mode == ExecutionMode.Bypass) return SecurityVerdict.Ok;
        if (risk == ToolRiskLevel.ReadOnly && !bridged) return SecurityVerdict.Ok;

        if (risk == ToolRiskLevel.Destructive)
        {
            Interlocked.Increment(ref _blocked);
            Log.Warn($"blocked destructive tool '{toolName}' in Safe mode");
            return SecurityVerdict.Blocked($"{BlockedPrefix} Tool='{toolName}' Risk=Destructive (declared destructive; never auto-executed in Safe mode).");
        }

        // Mutating: scan the argument values the way the tool will see them, not their JSON encoding.
        string text = ScanText(arguments);
        if (text.Length == 0) return SecurityVerdict.Ok;

        List<string>? hits = null;
        try
        {
            foreach (ref readonly var rule in DangerPatterns.All.AsSpan())
            {
                if (rule.Pattern.IsMatch(text))
                    (hits ??= new List<string>(2)).Add(rule.Name);
            }
            foreach (var statement in text.Split(';'))
            {
                bool where = DangerPatterns.WhereClause().IsMatch(statement);
                if (!where && DangerPatterns.DeleteFrom().IsMatch(statement) && (hits ??= new()).Contains("DELETE without WHERE") == false) hits.Add("DELETE without WHERE");
                if (!where && DangerPatterns.UpdateSet().IsMatch(statement) && (hits ??= new()).Contains("UPDATE without WHERE") == false) hits.Add("UPDATE without WHERE");
            }
        }
        catch (RegexMatchTimeoutException)
        {
            (hits ??= new List<string>(1)).Add("scan timeout (argument too large to judge)");
        }

        if (hits is null || hits.Count == 0) return SecurityVerdict.Ok;

        Interlocked.Increment(ref _blocked);
        string matched = string.Join(", ", hits);
        Log.Warn($"blocked '{toolName}' in Safe mode: {matched}");
        return SecurityVerdict.Blocked($"{BlockedPrefix} Tool='{toolName}' Risk={ModeNames.ToText(risk)} Matched: {matched}.", patternHit: true);
    }
}

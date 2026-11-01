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

/// <summary>Compiled-at-build-time danger signatures scanned against raw tool arguments.</summary>
public static partial class DangerPatterns
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    [GeneratedRegex(@"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|ROLE)\b", Opts)]
    public static partial Regex DropStatement();

    [GeneratedRegex(@"\bTRUNCATE\s+(TABLE\s+)?[\w.""\[\]`]+", Opts)]
    public static partial Regex TruncateStatement();

    // DELETE FROM <table> followed directly by end / ';' / another statement, i.e. no WHERE clause.
    [GeneratedRegex(@"\bDELETE\s+FROM\s+[\w.""\[\]`]+\s*(;|$|\n|\\n|"")", Opts)]
    public static partial Regex DeleteWithoutWhere();

    [GeneratedRegex(@"\bUPDATE\s+[\w.""\[\]`]+\s+SET\s+[^;]*?(?<!\bWHERE\b[^;]*)(;|$|\n|\\n|"")", Opts)]
    public static partial Regex UpdateWithoutWhere();

    // rm -rf / rm -fr / rm -r -f / rm --recursive --force
    [GeneratedRegex(@"\brm\s+(-\w*r\w*f|-\w*f\w*r|-\w*r\w*\s+-\w*f|-\w*f\w*\s+-\w*r|--recursive\s+--force|--force\s+--recursive)\b", Opts)]
    public static partial Regex RmRecursiveForce();

    [GeneratedRegex(@"(^|[\s""'=])--force\b|(^|[\s""'])-f\b(?=[^\n]*\bpush\b)", Opts)]
    public static partial Regex ForceFlag();

    [GeneratedRegex(@"\bgit\s+(push\s+[^\n""]*?(--force|-f)\b|reset\s+--hard|clean\s+-\w*f|branch\s+-D\b|checkout\s+--\s+\.)", Opts)]
    public static partial Regex GitDestructive();

    [GeneratedRegex(@"\b(mkfs(\.\w+)?|dd\s+if=|shred\s|wipefs|diskutil\s+erase|format\s+[a-z]:)", Opts)]
    public static partial Regex DiskWipe();

    [GeneratedRegex(@"\|\s*(sudo\s+)?(sh|bash|zsh|python\d?|perl|node)\b", Opts)]
    public static partial Regex PipeToShell();

    [GeneratedRegex(@"\b(chmod\s+-R\s+0?777|chown\s+-R\s+root|:\(\)\s*\{\s*:\|:&\s*\};:)", Opts)]
    public static partial Regex PrivilegeAbuse();

    public readonly record struct Rule(string Name, Regex Pattern);

    public static readonly Rule[] All =
    [
        new("DROP statement", DropStatement()),
        new("TRUNCATE statement", TruncateStatement()),
        new("DELETE without WHERE", DeleteWithoutWhere()),
        new("UPDATE without WHERE", UpdateWithoutWhere()),
        new("rm -rf", RmRecursiveForce()),
        new("--force flag", ForceFlag()),
        new("destructive git", GitDestructive()),
        new("disk wipe", DiskWipe()),
        new("pipe to shell", PipeToShell()),
        new("privilege abuse", PrivilegeAbuse()),
    ];
}

public readonly record struct SecurityVerdict(bool Allowed, string? Reason)
{
    public static readonly SecurityVerdict Ok = new(true, null);
    public static SecurityVerdict Blocked(string reason) => new(false, reason);
}

public sealed class SecurityInterceptor
{
    public const string BlockedPrefix = "[SAFE MODE BLOCKED] Action requires explicit user confirmation or switching Hubris to Bypass mode.";

    private long _blocked;
    private int _mode;

    public SecurityInterceptor(ExecutionMode mode)
    {
        _mode = (int)mode;
    }

    /// <summary>Switchable at runtime from the control channel; reads are lock-free.</summary>
    public ExecutionMode Mode
    {
        get => (ExecutionMode)Volatile.Read(ref _mode);
        set => Volatile.Write(ref _mode, (int)value);
    }
    public long BlockedCount => Interlocked.Read(ref _blocked);

    public SecurityVerdict Evaluate(string toolName, ToolRiskLevel risk, JsonObject? arguments)
    {
        if (Mode == ExecutionMode.Bypass) return SecurityVerdict.Ok;
        if (risk == ToolRiskLevel.ReadOnly) return SecurityVerdict.Ok;

        if (risk == ToolRiskLevel.Destructive)
        {
            Interlocked.Increment(ref _blocked);
            Log.Warn($"blocked destructive tool '{toolName}' in Safe mode");
            return SecurityVerdict.Blocked($"{BlockedPrefix} Tool='{toolName}' Risk=Destructive (declared destructive; never auto-executed in Safe mode).");
        }

        // Mutating: scan the raw argument JSON once against every rule.
        string text = arguments?.ToJsonString() ?? string.Empty;
        if (text.Length == 0) return SecurityVerdict.Ok;

        List<string>? hits = null;
        foreach (ref readonly var rule in DangerPatterns.All.AsSpan())
        {
            if (rule.Pattern.IsMatch(text))
                (hits ??= new List<string>(2)).Add(rule.Name);
        }

        if (hits is null) return SecurityVerdict.Ok;

        Interlocked.Increment(ref _blocked);
        string matched = string.Join(", ", hits);
        Log.Warn($"blocked '{toolName}' in Safe mode: {matched}");
        return SecurityVerdict.Blocked($"{BlockedPrefix} Tool='{toolName}' Risk=Mutating Matched: {matched}.");
    }
}

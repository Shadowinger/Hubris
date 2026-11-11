using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Hubris.Transport;

namespace Hubris.Security;

public enum ExecutionMode : byte
{
    /// <summary>Ask: anything declared destructive or matching a danger pattern waits for the user.</summary>
    Safe = 0,
    /// <summary>No checks at all.</summary>
    Bypass = 1,
    /// <summary>Run without asking; block only what the rules call dangerous and tell the model why.</summary>
    Auto = 2,
}

public enum ToolRiskLevel : byte
{
    ReadOnly = 0,
    Mutating = 1,
    Destructive = 2,
}

public static class ModeNames
{
    public static string ToText(ExecutionMode mode) => mode switch
    {
        ExecutionMode.Bypass => "Bypass",
        ExecutionMode.Auto => "Auto",
        _ => "Safe",
    };

    public static string ToText(ToolRiskLevel level) => level switch
    {
        ToolRiskLevel.ReadOnly => "ReadOnly",
        ToolRiskLevel.Mutating => "Mutating",
        _ => "Destructive",
    };

    public static bool TryParseMode(string? text, out ExecutionMode mode)
    {
        if (string.Equals(text, "safe", StringComparison.OrdinalIgnoreCase)) { mode = ExecutionMode.Safe; return true; }
        if (string.Equals(text, "auto", StringComparison.OrdinalIgnoreCase)) { mode = ExecutionMode.Auto; return true; }
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

    // git [-C dir] push … --force|-f|+ref, reset --hard, clean -f (any flag order), branch -D, checkout -- ., restore ., stash drop|clear
    [GeneratedRegex(@"\bgit['""]?\s+(-C\s+\S+\s+)?(push\b[^\n""]*?(--force\b|\s-f\b|\s\+\S)|reset\s+--hard|clean\s+(-\w+\s+)*-\w*f\b|branch\s+-D\b|checkout\s+--\s+\.|restore\s+(-\S+\s+)*\.(\s|$)|stash\s+(drop|clear)\b)", Opts, Timeout)]
    public static partial Regex GitDestructive();

    [GeneratedRegex(@"\b(mkfs(\.\w+)?|dd\s+if=|shred\s|wipefs|diskutil\s+erase|format\s+[a-z]:)", Opts, Timeout)]
    public static partial Regex DiskWipe();

    // something fetched from the network and run: curl … | sh, bash -c "$(curl …)", bash <(curl …)
    [GeneratedRegex(@"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python\d?|perl|node|ruby)\b|\b(sh|bash|zsh)\s+(-c\s+)?['""]?(\$\(|<\()\s*(curl|wget)\b", Opts, Timeout)]
    public static partial Regex PipeToShell();

    [GeneratedRegex(@"\b(chmod\s+-R\s+0?777|chown\s+-R\s+root|:\(\)\s*\{\s*:\|:&\s*\};:)", Opts, Timeout)]
    public static partial Regex PrivilegeAbuse();

    [GeneratedRegex(@"\b(deploy|publish|release|promote|vercel|netlify)\b[^\n]*\s--prod(uction)?\b|\b(terraform|terragrunt)\s+(apply|destroy)\b|\b(pulumi|cdk)\s+destroy\b|\bkubectl\s+(delete|apply|replace|drain)\b|\bhelm\s+(install|upgrade|uninstall|delete|rollback)\b|\b(migrate\s+deploy|db:migrate|alembic\s+upgrade|flyway\s+migrate)\b", Opts, Timeout)]
    public static partial Regex ProductionChange();

    [GeneratedRegex(@"\baws\s+s3\s+(rb\b|rm\b[^\n]*--recursive)|\bgsutil\s+(-m\s+)?rm\s+-\w*r|\bgcloud\s+storage\s+rm\b[^\n]*(\s-r\b|--recursive)|\baz\s+storage\s+\S+\s+delete-batch\b", Opts, Timeout)]
    public static partial Regex CloudMassDelete();

    [GeneratedRegex(@"\baws\s+iam\s+(attach|put|create|add)[\w-]*|\badd-iam-policy-binding\b|\bgh\s+api\b[^\n]*/collaborators\b|\bgh\s+repo\s+edit\b[^\n]*--visibility\b", Opts, Timeout)]
    public static partial Regex PermissionGrant();

    // a flag that switches a safety guard off
    [GeneratedRegex(@"(^|\s)(--insecure|--no-sandbox|--dangerously-skip-permissions|--yes-always)\b", Opts, Timeout)]
    public static partial Regex GuardOff();

    // rm with any flag on /, ~, $HOME or a system directory, with or without a trailing slash or glob: asked about in every mode, Bypass included
    [GeneratedRegex(@"\brm['""]?\s+(-[\w-]+\s+)+['""]?(/|~|\$HOME|\$\{HOME\}|/(usr|etc|var|bin|sbin|opt|home|Users|System|Library|Applications))/?\*?['""]?(\s|$)", Opts, Timeout)]
    public static partial Regex CriticalRemoval();

    public readonly record struct Rule(string Name, Regex Pattern);

    public static readonly Rule[] All =
    [
        new("DROP statement", DropStatement()),
        new("TRUNCATE statement", TruncateStatement()),
        new("rm -rf", RmRecursiveForce()),
        new("destructive git", GitDestructive()),
        new("disk wipe", DiskWipe()),
        new("pipe to shell", PipeToShell()),
        new("privilege abuse", PrivilegeAbuse()),
        new("production deploy or migration", ProductionChange()),
        new("cloud mass deletion", CloudMassDelete()),
        new("permission grant", PermissionGrant()),
        new("safety guard switched off", GuardOff()),
        new("rm on a critical path", CriticalRemoval()),
    ];

    /// <summary>
    /// Auto mode judges a tool that is not read-only by the verbs in its name too, because a server's
    /// destructiveHint is true for half of what it offers and says nothing about how bad a call is.
    /// </summary>
    private static readonly (string Category, string[] Verbs)[] NameRules =
    [
        ("irreversible deletion", ["delete", "destroy", "purge", "wipe", "erase", "truncate", "terminate", "reset", "uninstall"]),
        ("production deploy or migration", ["deploy", "redeploy", "promote", "rollback", "migrate", "migration", "merge"]),
        ("permission grant", ["grant", "invite", "authorize", "permission", "permissions", "collaborator", "iam"]),
        ("secrets, DNS, certificates or firewall", ["secret", "secrets", "dns", "cert", "certificate", "firewall"]),
        ("payment", ["buy", "purchase", "pay", "refund", "charge", "transfer"]), // not on Claude's list; money does not come back
    ];

    /// <summary>The category a tool name falls into ("vercel__delete_project" → irreversible deletion), or null.</summary>
    public static string? NameCategory(string toolName)
    {
        int sep = toolName.IndexOf("__", StringComparison.Ordinal);
        var name = (sep < 0 ? toolName : toolName[(sep + 2)..]).AsSpan(); // the bridge prefix is the user's label, not the server's verb
        Span<char> word = stackalloc char[32];
        int len = 0;
        for (int i = 0; i <= name.Length; i++)
        {
            char c = i < name.Length ? name[i] : '_';
            bool boundary = !char.IsLetter(c) || (char.IsUpper(c) && i > 0 && char.IsLower(name[i - 1])); // snake, kebab, dotted and camelCase
            if (boundary && len > 0)
            {
                var w = word[..len];
                foreach (var (category, verbs) in NameRules)
                    foreach (string v in verbs)
                        if (w.SequenceEqual(v)) return category;
                len = 0;
            }
            if (char.IsLetter(c) && len < word.Length) word[len++] = char.ToLowerInvariant(c);
        }
        return null;
    }
}

/// <param name="PatternHit">The block came from a matched argument pattern, not from the tool's declared risk.</param>
/// <param name="Ask">A blocked call may wait for the user's decision; false = the caller gets the reason at once (Auto mode).</param>
public readonly record struct SecurityVerdict(bool Allowed, string? Reason, bool PatternHit = false, bool Ask = true)
{
    public static readonly SecurityVerdict Ok = new(true, null);
    public static SecurityVerdict Blocked(string reason, bool patternHit = false, bool ask = true) => new(false, reason, patternHit, ask);
}

public sealed class SecurityInterceptor
{
    public const string BlockedPrefix = "[SAFE MODE BLOCKED] Action requires explicit user confirmation or switching Hubris to Bypass mode.";

    public const string CriticalPrefix = "[BLOCKED IN EVERY MODE] Removing a critical path needs the user's approval in the Hubris desktop app.";
    public const string AutoBlockedPrefix = "[AUTO MODE BLOCKED] Hubris did not run this call.";
    /// <summary>Auto mode stops deciding alone after this many blocked calls in a row, or in total, and asks the user instead.</summary>
    public const int AutoMaxConsecutiveBlocks = 3, AutoMaxTotalBlocks = 20;

    private long _blocked;
    private int _mode;
    private int _autoRun, _autoTotal; // blocked calls in a row / since auto mode last resumed

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
        set { Volatile.Write(ref _mode, (int)value); Volatile.Write(ref _autoRun, 0); Volatile.Write(ref _autoTotal, 0); }
    }

    /// <summary>Auto mode has blocked too much to keep deciding alone: blocked calls wait for the user until one is approved.</summary>
    public bool AutoPaused => Volatile.Read(ref _autoRun) >= AutoMaxConsecutiveBlocks || Volatile.Read(ref _autoTotal) >= AutoMaxTotalBlocks;

    /// <summary>The user approved a call auto mode had asked about: it decides alone again. The total starts over only when it was the limit that tripped.</summary>
    public void ResumeAuto()
    {
        Volatile.Write(ref _autoRun, 0);
        if (Volatile.Read(ref _autoTotal) >= AutoMaxTotalBlocks) Volatile.Write(ref _autoTotal, 0);
    }
    public long BlockedCount => Interlocked.Read(ref _blocked);

    /// <param name="bridged">A bridge's own readOnlyHint is not trusted: its arguments are still scanned.</param>
    public SecurityVerdict Evaluate(string toolName, ToolRiskLevel risk, JsonObject? arguments, bool bridged = false)
    {
        var mode = Mode;
        if (risk == ToolRiskLevel.ReadOnly && !bridged) return SecurityVerdict.Ok;
        if (mode != ExecutionMode.Safe && IsCriticalRemoval(arguments))
        {
            // The one check Bypass and Auto do not decide alone: deleting /, the home directory or a system directory
            // waits for the user (Safe asks about it through its ordinary pattern scan).
            Interlocked.Increment(ref _blocked);
            Log.Warn($"holding '{toolName}' in {ModeNames.ToText(mode)} mode: removal of a critical path");
            return SecurityVerdict.Blocked($"{CriticalPrefix} Tool='{toolName}' Matched: rm on a critical path.", patternHit: true);
        }
        if (mode == ExecutionMode.Bypass) return SecurityVerdict.Ok;
        if (mode == ExecutionMode.Auto) return EvaluateAuto(toolName, risk, arguments);

        if (risk == ToolRiskLevel.Destructive)
        {
            Interlocked.Increment(ref _blocked);
            Log.Warn($"blocked destructive tool '{toolName}' in Safe mode");
            return SecurityVerdict.Blocked($"{BlockedPrefix} Tool='{toolName}' Risk=Destructive (declared destructive; never auto-executed in Safe mode).");
        }

        // Mutating: scan the argument values the way the tool will see them, not their JSON encoding.
        var hits = PatternHits(arguments);
        if (hits is null) return SecurityVerdict.Ok;

        Interlocked.Increment(ref _blocked);
        string matched = string.Join(", ", hits);
        Log.Warn($"blocked '{toolName}' in Safe mode: {matched}");
        return SecurityVerdict.Blocked($"{BlockedPrefix} Tool='{toolName}' Risk={ModeNames.ToText(risk)} Matched: {matched}.", patternHit: true);
    }

    /// <summary>
    /// Auto mode: everything runs except a call whose arguments match a danger pattern or, for a tool that is not
    /// read-only, whose name says deletion, deploy, permission grant or payment. A blocked call goes back to the
    /// model with the reason so it can try something else; only after 3 blocks in a row or 20 in total does the
    /// next blocked call wait for the user, and an approval lets auto mode decide alone again.
    /// </summary>
    private SecurityVerdict EvaluateAuto(string toolName, ToolRiskLevel risk, JsonObject? arguments)
    {
        var hits = PatternHits(arguments);
        // A tool the user allowed for the session is allowed by name; its arguments are still judged.
        string? byName = hits is null && risk != ToolRiskLevel.ReadOnly && DecisionFor(toolName) != true ? DangerPatterns.NameCategory(toolName) : null;
        if (hits is null && byName is null)
        {
            Volatile.Write(ref _autoRun, 0); // a call that went through ends the streak
            return SecurityVerdict.Ok;
        }

        bool ask = AutoPaused; // decided before this block counts: the third block in a row is still answered, the fourth asks
        Interlocked.Increment(ref _blocked);
        Interlocked.Increment(ref _autoRun);
        Interlocked.Increment(ref _autoTotal);
        string matched = hits is null ? $"tool name ({byName})" : string.Join(", ", hits);
        Log.Warn($"blocked '{toolName}' in Auto mode: {matched}{(ask ? " (auto mode paused: asking)" : string.Empty)}");
        string next = ask
            ? "Auto mode has blocked several calls and is paused: this call needs the user's approval in the Hubris desktop app."
            : "Do not repeat it: take a different approach, or if exactly this action is what the user asked for, tell them Hubris blocked it and that Safe mode asks for approval and Bypass mode runs everything.";
        return SecurityVerdict.Blocked($"{AutoBlockedPrefix} Tool='{toolName}' Matched: {matched}. {next}", patternHit: hits is not null, ask: ask);
    }

    private static readonly string Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static bool IsCriticalRemoval(JsonObject? arguments)
    {
        string text = ScanText(arguments);
        if (text.Length == 0) return false;
        if (Home.Length > 1) text = text.Replace(Home, "~", StringComparison.OrdinalIgnoreCase); // the home folder spelled out is still the home folder
        try { return DangerPatterns.CriticalRemoval().IsMatch(text); }
        catch (RegexMatchTimeoutException) { return false; } // too large to judge here; the mode's own scan treats a timeout as a hit
    }

    /// <summary>Names of the danger patterns the argument values match, or null.</summary>
    private static List<string>? PatternHits(JsonObject? arguments)
    {
        string text = ScanText(arguments);
        if (text.Length == 0) return null;

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

        return hits is { Count: > 0 } ? hits : null;
    }
}

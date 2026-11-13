using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Hubris.Protocol;

namespace Hubris.Security;

/// <summary>Masks secrets and personal identifiers in tool output before it reaches the model.</summary>
public static partial class DlpSanitizer
{
    private const RegexOptions Opts = RegexOptions.CultureInvariant;

    // key=value / key: value style secrets (connection strings, env dumps, YAML, INI)
    // key=value / key: value / "key": "value" / PREFIX_KEY=value; a purely numeric value ("Token: 1814") is a count, not a secret
    [GeneratedRegex(@"(?i)(?<![A-Za-z0-9])(password|passwd|pwd|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|secret[_-]?access[_-]?key|access[_-]?key|accesskey|secret[_-]?key|private[_-]?key)([""']?\s*[=:]\s*[""']?)(?!\*\*\*)(?=[^;,\s""'&]*[^0-9;,\s""'&])([^;,\s""'&]+)", Opts)]
    private static partial Regex KeyValueSecret();

    // OpenAI / Anthropic style keys
    [GeneratedRegex(@"\bsk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_\-]{16,}\b", Opts)]
    private static partial Regex SkKey();

    // GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_, github_pat_
    [GeneratedRegex(@"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b", Opts)]
    private static partial Regex GitHubToken();

    [GeneratedRegex(@"\b(AKIA|ASIA)[0-9A-Z]{16}\b", Opts)]
    private static partial Regex AwsAccessKey();

    [GeneratedRegex(@"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{16,}=*", Opts)]
    private static partial Regex BearerToken();

    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", Opts)]
    private static partial Regex Jwt();

    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", Opts)]
    private static partial Regex PemPrivateKey();

    // Czech / Slovak rodné číslo written the usual way, YYMMDD/XXX(X); the slash is required so that plain
    // 10-digit ids and timestamps (1.3 % of which pass the mod-11 test) are left alone
    [GeneratedRegex(@"\b\d{2}(0[1-9]|1[0-2]|2[1-9]|3[0-2]|5[1-9]|6[0-2]|7[1-9]|8[0-2])(0[1-9]|[12]\d|3[01])\s?/\s?\d{3,4}\b", Opts)]
    private static partial Regex RodneCislo();

    // IBAN (validated with mod 97) and payment card numbers (validated with Luhn)
    [GeneratedRegex(@"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b", Opts)]
    private static partial Regex Iban();

    [GeneratedRegex(@"\b(?:\d[ -]?){12,18}\d\b", Opts)]
    private static partial Regex CardNumber();

    // Slack tokens
    [GeneratedRegex(@"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", Opts)]
    private static partial Regex SlackToken();

    private static long _redactions;
    public static long RedactionCount => Interlocked.Read(ref _redactions);

    private const string Mask = "***";

    public static string Sanitize(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        string s = input;

        s = Replace(PemPrivateKey(), s, static _ => "-----BEGIN PRIVATE KEY----- *** REDACTED *** -----END PRIVATE KEY-----");
        s = Replace(KeyValueSecret(), s, static m => m.Groups[1].Value + m.Groups[2].Value + Mask);
        s = Replace(SkKey(), s, static _ => "sk-" + Mask);
        s = Replace(GitHubToken(), s, static _ => "gh*_" + Mask);
        s = Replace(AwsAccessKey(), s, static m => m.Groups[1].Value + Mask);
        s = Replace(BearerToken(), s, static _ => "Bearer " + Mask);
        s = Replace(Jwt(), s, static _ => "eyJ" + Mask + "." + Mask + "." + Mask);
        s = Replace(SlackToken(), s, static _ => "xox*-" + Mask);
        s = Replace(RodneCislo(), s, static m => IsRodneCislo(m.Value) ? "******/" + Mask : m.Value);
        s = Replace(Iban(), s, static m => IsIban(m.Value) ? m.Value[..4] + " " + Mask : m.Value);
        s = Replace(CardNumber(), s, static m => IsCardNumber(m.Value) ? "**** **** **** " + Digits(m.Value)[^4..] : m.Value);

        return s;
    }

    /// <summary>10-digit numbers must pass the mod-11 rule; 9-digit (pre-1954) ones have no check digit.</summary>
    public static bool IsRodneCislo(string text)
    {
        string digits = Digits(text);
        if (digits.Length == 10) return long.Parse(digits, System.Globalization.CultureInfo.InvariantCulture) % 11 == 0;
        return digits.Length == 9;
    }

    /// <summary>ISO 13616: move the first four characters to the end, letters become 10..35, the number mod 97 is 1.</summary>
    public static bool IsIban(string text)
    {
        string compact = text.Replace(" ", "");
        if (compact.Length < 15 || compact.Length > 34) return false;
        string rearranged = compact[4..] + compact[..4];
        int rem = 0;
        foreach (char c in rearranged)
        {
            int v = char.IsAsciiDigit(c) ? c - '0' : char.IsAsciiLetterUpper(c) ? c - 'A' + 10 : -1;
            if (v < 0) return false;
            rem = v < 10 ? (rem * 10 + v) % 97 : (rem * 100 + v) % 97;
        }
        return rem == 1;
    }

    /// <summary>Luhn check over 13..19 digits.</summary>
    public static bool IsCardNumber(string text)
    {
        string digits = Digits(text);
        if (digits.Length < 13 || digits.Length > 19) return false;
        int sum = 0;
        bool dbl = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i] - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    private static string Digits(string text)
    {
        var sb = new System.Text.StringBuilder(text.Length);
        foreach (char c in text) if (char.IsAsciiDigit(c)) sb.Append(c);
        return sb.ToString();
    }

    private static string Replace(Regex regex, string input, MatchEvaluator evaluator)
        => regex.Replace(input, m =>
        {
            string r = evaluator(m);
            if (!string.Equals(r, m.Value, StringComparison.Ordinal)) Interlocked.Increment(ref _redactions);
            return r;
        });

    public static CallToolResult Sanitize(CallToolResult result)
    {
        var content = result.Content;
        for (int i = 0; i < content.Count; i++)
        {
            var block = content[i];
            if (block.Text is { Length: > 0 } text && string.Equals(block.Type, "text", StringComparison.Ordinal))
            {
                string clean = Sanitize(text);
                if (!ReferenceEquals(clean, text)) block.Text = clean;
            }
            SanitizeExtra(block.Extra);
        }
        SanitizeExtra(result.Extra);
        return result;
    }

    /// <summary>
    /// The fields the hub passes on without reading them (an embedded resource, structuredContent) reach the model
    /// just like a text block: every string in them is masked. "blob" and "data" hold base64 and are left alone.
    /// </summary>
    private static void SanitizeExtra(Dictionary<string, JsonElement>? extra)
    {
        if (extra is null) return;
        foreach (string key in extra.Keys.ToArray())
        {
            if (key is "blob" or "data" || extra[key].ValueKind is not (JsonValueKind.Object or JsonValueKind.Array or JsonValueKind.String)) continue;
            var holder = new JsonArray(JsonNode.Parse(extra[key].GetRawText()));
            if (SanitizeStrings(holder)) extra[key] = JsonSerializer.SerializeToElement(holder[0], McpJsonContext.Default.JsonNode);
        }
    }

    /// <summary>Masks every string under <paramref name="node"/> in place; true when something changed.</summary>
    private static bool SanitizeStrings(JsonNode? node)
    {
        bool changed = false;
        if (node is JsonArray arr)
        {
            for (int i = 0; i < arr.Count; i++)
            {
                if (arr[i] is JsonValue v && v.TryGetValue<string>(out var s)) { string clean = Sanitize(s); if (!ReferenceEquals(clean, s)) { arr[i] = clean; changed = true; } }
                else changed |= SanitizeStrings(arr[i]);
            }
        }
        else if (node is JsonObject obj)
        {
            foreach (var kv in obj.ToArray())
            {
                if (kv.Key is "blob" or "data") continue;
                if (kv.Value is JsonValue v && v.TryGetValue<string>(out var s)) { string clean = Sanitize(s); if (!ReferenceEquals(clean, s)) { obj[kv.Key] = clean; changed = true; } }
                else changed |= SanitizeStrings(kv.Value);
            }
        }
        return changed;
    }
}

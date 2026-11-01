using System.Text.RegularExpressions;
using McpHub.Protocol;

namespace McpHub.Security;

/// <summary>Masks secrets and personal identifiers in tool output before it reaches the model.</summary>
public static partial class DlpSanitizer
{
    private const RegexOptions Opts = RegexOptions.CultureInvariant;

    // key=value / key: value style secrets (connection strings, env dumps, YAML, INI)
    [GeneratedRegex(@"(?i)\b(password|passwd|pwd|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|accesskey|secret[_-]?key|private[_-]?key)(\s*[=:]\s*[""']?)(?!\*\*\*)([^;,\s""'&]+)", Opts)]
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

    // Czech / Slovak rodné číslo: YYMMDD/XXX(X), month 01-12 or 51-62 for women (+20/+70 variants)
    [GeneratedRegex(@"\b\d{2}(0[1-9]|1[0-2]|2[1-9]|3[0-2]|5[1-9]|6[0-2]|7[1-9]|8[0-2])(0[1-9]|[12]\d|3[01])\s?/?\s?\d{3,4}\b", Opts)]
    private static partial Regex RodneCislo();

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
        s = Replace(RodneCislo(), s, static _ => "******/" + Mask);

        return s;
    }

    private static string Replace(Regex regex, string input, MatchEvaluator evaluator)
    {
        if (!regex.IsMatch(input)) return input;
        int count = regex.Count(input);
        Interlocked.Add(ref _redactions, count);
        return regex.Replace(input, evaluator);
    }

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
        }
        return result;
    }
}

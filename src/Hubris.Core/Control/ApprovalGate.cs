using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Hubris.Security;

namespace Hubris.Control;

public enum ApprovalDecision : byte
{
    Approved = 0,
    Denied = 1,
    TimedOut = 2,
    Cancelled = 3,
}

public sealed class PendingApproval
{
    public required string Id { get; init; }
    public required string Tool { get; init; }
    public required ToolRiskLevel Risk { get; init; }
    public required string Reason { get; init; }
    public JsonObject? Arguments { get; init; }
    public DateTime RequestedAt { get; init; } = DateTime.UtcNow;
    public TimeSpan Timeout { get; init; }
    internal TaskCompletionSource<ApprovalDecision> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
}

/// <summary>Holds blocked calls until a human decides, with a hard timeout so the MCP client never hangs.</summary>
public sealed class ApprovalGate
{
    private readonly ConcurrentDictionary<string, PendingApproval> _pending = new(StringComparer.Ordinal);
    private long _seq;

    public int Count => _pending.Count;
    public IEnumerable<PendingApproval> Pending => _pending.Values;

    public event Action<PendingApproval>? Requested;
    public event Action<PendingApproval, ApprovalDecision>? Resolved;

    public async Task<ApprovalDecision> RequestAsync(string tool, ToolRiskLevel risk, string reason, JsonObject? arguments, TimeSpan timeout, CancellationToken ct)
    {
        string id = $"{Environment.ProcessId}-{Interlocked.Increment(ref _seq)}";
        var pending = new PendingApproval
        {
            Id = id,
            Tool = tool,
            Risk = risk,
            Reason = reason,
            Arguments = arguments,
            Timeout = timeout,
        };
        _pending[id] = pending;
        Requested?.Invoke(pending);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        using var reg = timeoutCts.Token.Register(static state =>
        {
            var (p, outer) = ((PendingApproval, CancellationToken))state!;
            p.Completion.TrySetResult(outer.IsCancellationRequested ? ApprovalDecision.Cancelled : ApprovalDecision.TimedOut);
        }, (pending, ct));

        ApprovalDecision decision = await pending.Completion.Task.ConfigureAwait(false);
        _pending.TryRemove(id, out _);
        Resolved?.Invoke(pending, decision);
        return decision;
    }

    public bool TryGet(string id, out PendingApproval pending) => _pending.TryGetValue(id, out pending!);

    public bool Resolve(string id, bool approved)
    {
        if (!_pending.TryGetValue(id, out var p)) return false;
        return p.Completion.TrySetResult(approved ? ApprovalDecision.Approved : ApprovalDecision.Denied);
    }

    public void CancelAll()
    {
        foreach (var p in _pending.Values) p.Completion.TrySetResult(ApprovalDecision.Cancelled);
    }

    public static string DecisionText(ApprovalDecision d) => d switch
    {
        ApprovalDecision.Approved => "approved",
        ApprovalDecision.Denied => "denied",
        ApprovalDecision.TimedOut => "timeout",
        _ => "cancelled",
    };
}

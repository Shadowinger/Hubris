using Hubris.Cli;
using Hubris.Control;

namespace Hubris.Tests;

public class CliTests
{
    private static ControlMessage Hello() => new()
    {
        Type = ControlTypes.Hello, Pid = 4242, Client = "claude-code 2.1.325", Mode = "Safe", UptimeSec = 4330, Version = "1.4.1", Cwd = "/work",
        ActiveTools = 11, ToolCount = 368, ActiveTokens = 5043, TotalTokens = 180691, Blocked = 1, DlpRedactions = 3, BridgeCount = 7, BridgesRunning = 5,
        BridgesFailed = new() { ["fs"] = "npx: not found\nsecond line" },
        Auth = [new AuthInfo { Bridge = "notion", State = "connected" }],
        Tools =
        [
            new ToolInfo { Name = "hub_status", Risk = "ReadOnly", Pinned = true, Visible = true, Tokens = 120 },
            new ToolInfo { Name = "py__shell", Risk = "Destructive", Tokens = 1400, Decision = "always" },
        ],
    };

    [Fact]
    public void Status_says_who_is_connected_what_the_context_costs_and_what_waits()
    {
        string text = HubCli.Describe(Hello(), [new ControlMessage { ApprovalId = "4242-3", Tool = "py__shell", Reason = Hubris.Security.SecurityInterceptor.BlockedPrefix + " Tool='py__shell'\nMatched: rm -rf." }]);
        Assert.Contains("hub 4242 · Claude Code 2.1.325 · Safe mode · up 1 h 12 min · Hubris 1.4.1", text);
        Assert.Contains("11 of 368 tools listed, 5,043 of 180,691 tokens", text);
        Assert.Contains("1 blocked, 3 masked", text);
        Assert.Contains("failed    fs: npx: not found second line\n", text); // a reason stays on its line
        Assert.Contains("sign-in   notion: connected", text);
        Assert.Contains("waiting   4242-3  py__shell  [SAFE MODE BLOCKED] Tool='py__shell' Matched: rm -rf.\n", text); // without the sentence meant for the model
    }

    [Fact]
    public void Tools_are_filtered_by_name_and_summed()
    {
        string all = HubCli.DescribeTools(Hello(), null);
        Assert.Contains("hub_status      120  ReadOnly     pinned", all);
        Assert.Contains("py__shell     1,400  Destructive  hidden, always allowed", all);
        Assert.Contains("2 tools (1,520 tokens), 1 listed (120 tokens)", all);

        string some = HubCli.DescribeTools(Hello(), "PY__");
        Assert.DoesNotContain("hub_status", some);
        Assert.Contains("1 tools (1,400 tokens), 0 listed (0 tokens)", some);
    }

    [Theory]
    [InlineData(true, "status")]
    [InlineData(true, "bridge", "list")]
    [InlineData(false, "--stdio")]
    [InlineData(false, "statuz")]
    [InlineData(false)]
    public void Only_a_known_first_word_is_a_command(bool expected, params string[] args) => Assert.Equal(expected, HubCli.IsCommand(args));
}

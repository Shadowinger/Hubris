# Hubris

[![ci](https://github.com/Shadowinger/Hubris/actions/workflows/ci.yml/badge.svg)](https://github.com/Shadowinger/Hubris/actions/workflows/ci.yml)

MCP gateway. One stdio server that sits between an MCP client (Claude Desktop, Claude Code, Cursor, VS Code)
and all the MCP servers you actually use, local child processes and remote (HTTP) servers alike. It caches
their tool definitions so nothing has to be spawned or connected at startup, keeps most of their tools out of
the model's context until they are needed, blocks destructive calls in Safe mode and asks you in a desktop app
before letting them through.

.NET 10, Native AOT, no reflection, no runtime to install. A desktop app (Avalonia) does configuration,
takeover of existing client configs, live call view and approvals.

![Hubris desktop app: a call waiting for approval, the context cost and the live call log with its inspector](docs/hubris-dashboard.png)

## Numbers

Measured on an M-series Mac with the 4 bridges from my own `~/.hubris/config.json`
(filesystem, playwright, figma, one node server), 52 tools in total.

| | without Hubris | with Hubris |
|---|---|---|
| `tools/list` sent to the model | 52 tools, 38 444 bytes (~9 600 tokens) | 3 tools, 1 558 bytes (~390 tokens) in `--compact` mode |
| context used after unlocking the tools a task needs | all 52 | 13 of 52, ~1 800 tokens (81 % less, from `hub_status` on a real session) |
| time until `tools/list` is answered | ~1.8 s (every bridge spawned via `npx`) | 72 ms (definitions served from the SQLite cache, bridges spawned on first call) |
| MCP server processes after start | 4 (one per server) | 0 (bridges start lazily; 1 of 4 running after a typical session) |
| server binary | | 9.3 MB, starts in ~50 ms, ~13 MB RSS in steady state |

The token numbers are bytes/4 estimates. The second row comes from a live session where the model
searched for and unlocked 10 bridged tools; the rest stayed off the list.

## How it works

```
client ──stdio──▶ Hubris ──stdio──▶ bridge 1 (npx …)
                    │    ──stdio──▶ bridge 2
                    │    ──https──▶ bridge 3 (remote MCP server, Streamable HTTP or SSE)
                    └──unix socket──▶ Hubris.Desktop (approvals, dashboard, config)
```

- **Compact context.** With `--compact` the model sees three tools: `hub_status`, `mcp_search_tools`
  and `mcp_execute_tool`. It searches by keyword, the matches get unlocked (`notifications/tools/list_changed`),
  and it calls them directly or through `mcp_execute_tool {toolName, arguments}`. `Lock` in the desktop app
  puts them away again, and so does the hub itself: an unlocked tool that has not been called for `--auto-lock`
  seconds (default 600) is hidden again with a `tools/list_changed`, so the context cost of a long session drifts
  back to the three core tools instead of growing with every search.
- **Resources and prompts.** A bridge's resources, resource templates and prompts are passed through: `resources/list`
  and `resources/templates/list` merge every bridge's lists, `resources/read` is routed to the bridge that listed the
  URI (or whose template prefix matches) and its text goes through DLP, prompts carry the bridge prefix
  (`notion__summarize`) and `prompts/get` strips it. They are cached next to the tools, so they are listed without
  starting anything, and refreshed on the server's list_changed notifications.
- **Tool cache.** Bridge tool definitions are stored in `~/.hubris/cache.db` keyed by command, args and env
  key names (url, transport and header names for a remote server), with a TTL (`--cache-ttl`, default 24 h).
  On the next start the definitions are served from the cache; the child process is only started, or the
  remote session only opened, on the first real call to one of its tools.
  A bridge that is not in the cache is started at once, and the hub waits at most 2 s for it: one that is slower
  joins later and its tools are announced with `tools/list_changed`, so a slow or broken server does not hold up the client.
  A bridge that could not start is named, with the reason, in `hub_status` (`failed=…`) and in the desktop app's call list.
  A child that exits is started again by the next call; after four exits in a row without an answer its tools
  are withdrawn until Clear cache or a restart.
- **Remote servers.** A bridge with a `url` instead of a `command` is reached over HTTP: Streamable HTTP
  (POST per message, JSON or event-stream answers, `Mcp-Session-Id`) by default, the older HTTP+SSE pair with
  `"transport": "sse"` (its announced endpoint must be on the server's own origin). Answers are capped at
  64 MB, like a child's lines. Headers from the config go on every request, so a bearer token or API key works; redirects are not followed
  (the headers would go to another host; the error names the target), and Brotli is not accepted as a response encoding;
  an expired session is reopened on the next call, and the server's tools stay listed in between.
  A server that answers 401 without an auth block fails the call with a hint to add a header or an auth block.
- **OAuth.** A bridge with `"auth": { "type": "oauth" }` signs in through the browser: Hubris discovers the
  authorization server (RFC 9728 → RFC 8414), registers itself dynamically when the server allows it (or uses
  `clientId`/`clientSecret` from the block), runs the authorization-code flow with PKCE against a loopback
  listener on 127.0.0.1, and keeps the token in the OS secret store: on macOS one login-keychain item (service `com.hubris.mcp.oauth`,
  account `vault`) holding every provider's token, read once per hub and updated in place;
  the Credential Manager on Windows; a 0600 file under `~/.hubris/tokens` elsewhere.
  The hub never shows a Keychain dialog. When the Keychain would need one (the item was created by a different
  build of the binary), the token is kept in the 0600 file instead and stays there, so every hub reads the same copy.
  Tokens are never written to `config.json` or the cache database. A token inside 60 s of expiry is refreshed
  before use, a 401 triggers one refresh and retry, concurrent calls share one refresh, and every 5 minutes an
  idle hub refreshes any token within 10 minutes of expiry so refresh tokens with an idle timeout keep living.
  Several hubs share the token: a lock file per provider lets one of them refresh while the others wait and take
  the rotated token, because a refresh token used twice gets the whole grant revoked. A refresh token the server
  rejects with `invalid_grant` is dropped and the bridge shows as expired until the next Connect. For a stdio bridge
  the token goes into the child's environment under `auth.env` right before the lazy spawn. The desktop app's
  Connections card shows the state per bridge with Connect / Disconnect (Disconnect is sent to every running hub,
  and a hub that finds the token gone from the store stops using its copy); the same goes over the control socket
  as `oauth_start`, `oauth_revoke` and the `oauth_changed` event.
- **Safe mode.** Tools are classified read-only / mutating / destructive from their annotations and names.
  Read-only calls pass, mutating calls have their argument values scanned (every string in the call, joined the way
  a shell would see them, so `{"command":"rm","args":["-rf","/"]}`, a tab or a quoted binary read the same as
  `rm -rf /`) for things like `rm` with a recursive and a force flag in any spelling (`-rf`, `-r --force`, `-r -v -f`), `DROP TABLE`, `DELETE`/`UPDATE` without `WHERE`, `git push --force`;
  destructive calls are blocked. Every pattern has a match timeout, and a timeout counts as a hit. A blocked call waits for Approve / Deny in the desktop app
  (`--approval-timeout`, default 120 s) and fails with `[SAFE MODE BLOCKED]` if nobody answers, or at once when no
  client that may approve is attached. "Remember for
  this session" covers a tool's declared risk, never an argument-pattern hit.
- **Auto mode** (`--mode=auto`, or the Auto button per hub). Modelled on Claude Code's auto mode, with fixed
  rules where Claude Code uses a classifier model. Everything runs without asking, including tools a server
  marks destructive, except a call whose arguments match a danger pattern (the Safe-mode list plus discarding
  git work, `terraform`/`pulumi`/`cdk destroy`, `--prod` deploys and migrations, cloud mass deletion, IAM and
  repository permission grants, flags like `--insecure`) or, for a tool that is not read-only, whose name says
  deletion, deploy or migration, permission grant, secrets/DNS/certificates/firewall, or payment. Pushing to
  the default branch is allowed; force push is not. A blocked call is not put in front of you: it returns
  `[AUTO MODE BLOCKED]` with the rule it matched, so the model takes another route. After 3 blocked calls in
  a row or 20 in total the next blocked call waits for Approve / Deny, and an approval lets auto mode decide
  alone again. A tool allowed with "Remember for this session" is no longer blocked by its name, and a tool
  denied that way stays denied in Safe and Auto mode alike.
- **Bypass mode** (`--mode=bypass`). No checks and no prompts. The one exception, as in Claude Code: `rm` on
  `/`, the home directory (as `~`, `$HOME` or spelled out) or a system directory still waits for approval,
  in Auto mode too.
- **DLP.** Tool output (text blocks, the text of embedded resources, `structuredContent`; other fields of a result
  are passed on as the server sent them) is scanned for API keys and `key=value` / `"key": "value"` secrets (password, token,
  secret, api key and the like, also as `DATABASE_PASSWORD=`), bearer tokens and JWTs, private keys, Slack
  tokens, card numbers (Luhn-checked), IBANs (mod-97-checked) and Czech birth numbers written with a slash;
  the values are masked before they reach the model. Each pattern has 2 s per text; a text that makes one run
  longer is withheld whole instead of passed on unscanned.
- **Takeover.** The desktop app scans the MCP configs of Claude Desktop, Claude Code (including per-project
  entries in `~/.claude.json`), Cursor, Windsurf, VS Code and project-level `.mcp.json` / `.cursor/mcp.json` /
  `.vscode/mcp.json`, imports the servers (commands and `url` entries, with their headers) into
  `~/.hubris/config.json` and rewrites the client config so that it points at Hubris only. A snapshot and a whole-file backup go to `~/.hubris/backups/` (0600, never next to a project file; the newest 5 backups per file are kept), a second takeover adds to the snapshot what the user added in between, Restore puts it all back (with the client closed; a Restore that has only a whole-file backup left first saves the file it replaces), and symlinked configs are written through the link.

## Install

Requirements: .NET SDK 10. On macOS the Xcode command line tools (for the linker).

```bash
dotnet publish src/Hubris -c Release
# -> src/Hubris/bin/Release/net10.0/<rid>/publish/Hubris
```

Register it with a client:

```bash
Hubris --install-claude --compact        # Claude Desktop (writes claude_desktop_config.json, keeps a .bak)
Hubris --install-vscode --compact        # .vscode/mcp.json in the current directory
claude mcp add hubris -- /path/to/Hubris --stdio --compact
```

Or let the desktop app do it: open the configurator, Scan, Import & hijack. Quit the client first, the app
refuses to rewrite the config of a running client.

Bridges live in `~/.hubris/config.json` (mode 0600):

```json
{
  "bridges": [
    { "name": "fs", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/dev"] },
    { "name": "gh", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" } },
    { "name": "linear", "url": "https://mcp.linear.app/mcp",
      "headers": { "Authorization": "Bearer ${LINEAR_TOKEN}" } },
    { "name": "legacy", "url": "https://old.example.com/sse", "transport": "sse" },
    { "name": "notion", "url": "https://mcp.notion.com/mcp", "auth": { "type": "oauth" } },
    { "name": "supabase", "command": "npx", "args": ["-y", "@supabase/mcp-server-supabase"],
      "auth": { "type": "oauth", "issuer": "https://mcp.supabase.com/mcp", "env": "SUPABASE_ACCESS_TOKEN" } }
  ]
}
```

The desktop configurator has a "Known remote servers" list: 54 servers from the Claude connector directory
(`catalog/remote-servers.json`, Notion, Linear, Atlassian, Stripe, Slack, Figma, Supabase and so on), each added
to `config.json` with one click as a URL bridge with an OAuth block; running hubs load it at once and one of
them opens the browser sign-in right away, unless the server already answers without one. The search box next to it queries the public
registry at registry.modelcontextprotocol.io and lists every entry that has a remote endpoint.

An `auth` block takes `provider` (secret-store account, default the bridge name; two bridges naming the same
provider share one login), `issuer` (the MCP server URL to discover from; required for a stdio bridge),
`clientId` / `clientSecret` (otherwise dynamic registration), `scope`, and `env` (stdio only: the variable the
child reads the token from). Servers added from the list sign in on their own; for a hand-written bridge press
Connect in the desktop app once. Refreshes happen in the background and never open a window.

`${NAME}` in env and header values is read from the hub's environment at start; the file keeps the
placeholder. They can also be given on the command line with `--bridge=name:command arg…` or
`--bridge=name:https://host/mcp "Authorization: Bearer …"` (`sse:https://…` for the older transport).
Bridged tools show up as `fs__read_file`, `gh__create_issue`, `linear__create_issue` and so on; a bridge name
is letters, digits, `-` and `_`, without a double underscore.

## Usage

```
Hubris --stdio [--compact] [--mode=safe|auto|bypass] [--approval-timeout=120] [--auto-lock=600] [--cache-ttl=24h]
       [--no-cache] [--no-control] [--control-trust-all] [--verbose]
       [--bridge=<name>:<command> [args…]]… [--bridge=<name>:<url> ["Header: value"…]]…
```

Built-in tools: `hub_status`, `git_smart_status`, `fs_read_head`, `mcp_search_tools`, `mcp_execute_tool`.

The control socket is `~/.hubris/run/<pid>.sock`; the desktop app finds running hubs through it, and the
following commands are available over it: `get_status`, `list_tools`, `set_mode`, `approve`, `deny`, `forget`,
`reveal`, `lock`, `clear_cache`, `reload_config`, `shutdown`, `oauth_start`,
`oauth_revoke`. The socket is 0600, and the commands that change what the hub does (mode, approvals, locks,
cache, config, OAuth, shutdown) are accepted only from the `Hubris.Desktop` binary in the hub's own folder
(the same bundle or install), compared by the full path the kernel reports for the peer; the bridges and
shell tools the hub itself runs are the same user, so a plain `nc -U` from a tool call, or a program that is
merely named like the app, is refused. `--control-trust-all` lifts that for tests, scripts and a desktop app
run from another folder. A same-user attacker who can replace that binary or inject code into it still wins;
that is the limit of a local gateway.
`HUBRIS_HOME` moves the whole state directory.

## Desktop app

```bash
dotnet publish src/Hubris.Desktop -c Release
build/bundle-macos.sh                 # macOS: publishes both and writes artifacts/Hubris.app
build/bundle-macos.sh --no-publish    # bundle the existing publish output
```

Sidebar lists running hubs (a hub built from an older version is marked). Per hub: Safe / Auto / Bypass switch,
pending approvals with a remember checkbox, telemetry (calls, blocked, DLP redactions, cache hits, bridges
running, context cost), live call log with request/response inspector, the tool list with Lock / Unlock /
Forget. The configurator tab does client config scan / hijack / restore, edits `config.json`, and can launch a
test instance.

The bundle is ad-hoc signed without the hardened runtime on purpose: library validation would reject the
Skia/HarfBuzz dylibs. Set `CODESIGN_IDENTITY` for a real signature.

## Tests

```bash
tests/run.sh                        # unit tests, warning-free AOT publish, e2e over stdio + control socket
dotnet test tests/Hubris.Tests      # unit tests only
```

233 xUnit tests and 93 end-to-end checks (`tests/e2e/control_test.py` drives a published binary with a Python
stdio echo server as bridge, `tests/e2e/http_test.py` with a Python Streamable HTTP server). Both projects publish with `TreatWarningsAsErrors` and zero IL/AOT warnings.

## Layout

```
src/Hubris.Core      protocol, transport, security, DLP, tool cache, engine, control channel, client config scan
src/Hubris           the server
src/Hubris.Desktop   Avalonia 12 app
tests/Hubris.Tests   xUnit
tests/e2e            python e2e
build/               macOS bundle script, icon renderer
brand/               icon, mark, wordmark
```

## Status

CI runs the unit tests, the warning-free Native AOT publish and the e2e suites on macOS, Ubuntu and Windows (the
control-socket suite skips Windows, where CPython has no AF_UNIX). The desktop app is used on macOS only:
on Windows the hub cannot tell which program is on the other end of the control socket, so without `--control-trust-all`
it accepts no approval and Safe mode can block but not ask.
Version 1.4.0. MIT license.

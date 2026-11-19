# Changelog

## 1.5.0

**Command line**

- The hub binary answers commands: `status` (every running hub with its client, mode, context cost, blocked calls,
  failed bridges, sign-ins and waiting approvals), `tools`, `watch` (calls and approval requests as they happen),
  `mode`, `approve`, `deny`, and `bridge list|add|remove` for `config.json`.
- `mode`, `approve` and `deny` are accepted only by a hub started with `--control-trust-all`; the default is unchanged,
  only the desktop app may change what a hub does.

**Install**

- `install.sh` installs the hub alone with one line (macOS on Apple Silicon, Linux x64): latest release, checked
  against `SHA256SUMS`, into `~/.hubris/bin` with a `hubris` launcher in `~/.local/bin`.
- Releases carry a new archive for it, `Hubris-<version>-macos-arm64-cli.tar.gz`; the desktop app archive is unchanged.

## 1.4.1

**Desktop app**

- A long client or tool name no longer runs under the mode switch or out of the approval card: it is cut with an
  ellipsis and its tags stay beside it.
- Known clients are shown by a readable name (Claude Desktop, Claude Code, Claude Desktop · agent for the app's
  agent-mode proxy); the name the client gave is in the tooltip.

The hub itself is unchanged.

## 1.4.0

The first tagged release.

**The gateway**

- One stdio MCP server in front of local servers (child processes) and remote ones (Streamable HTTP and HTTP+SSE).
- Tool definitions cached in SQLite: listed without starting anything, bridges start on the first call.
- Compact context: three tools in the list until the model searches; unlocked tools are hidden again after idle time.
- Resources and prompts of the bridged servers pass through.
- A bridge that is slow to start no longer holds up the client; one that fails is named in `hub_status` and the app.

**Policy**

- Safe, Auto and Bypass modes; danger patterns over the argument values; approvals in the desktop app.
- Secrets and personal identifiers masked in tool results, embedded resources and structured content.
- Removing `/`, the home directory or a system directory waits for approval in every mode.

**Sign-in**

- OAuth 2.1 with PKCE and dynamic client registration; tokens in the OS secret store; one refresh shared by all hubs.
- 54 known remote servers can be added from the desktop app with one click.

**Desktop app (macOS)**

- Live calls, approvals, context cost, tool list, sign-in state per server.
- Takes over the MCP configs of Claude Desktop, Claude Code, Cursor, Windsurf and VS Code, and restores them.

**Known limits**

- The macOS app is not signed with an Apple developer certificate; see the README for opening it.
- On Windows and Linux only the hub is released. On Windows the hub cannot accept approvals.

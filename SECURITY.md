# Security

Hubris sits between an AI agent and its tools, so a hole in it matters. Please report one privately.

## Reporting a vulnerability

Use GitHub's private reporting on this repository: **Security → Report a vulnerability**. Please do not open a
public issue for it. Say what you did, what happened and which version (`Hubris --version`); a short script or a
config that shows it helps most.

Reports are read by the maintainer, usually within a week. A fix goes into the next release, and the release notes
name the reporter unless they ask not to be named.

Only the latest release gets fixes.

## What Hubris protects against, and what it does not

- **It checks what the agent asks for.** Tool calls are judged by the tool's declared risk, by danger patterns in the
  arguments and, in Auto mode, by the tool's name. The patterns are a best effort: a command spelled in a way no
  pattern knows goes through. Safe mode with a human approving is the stronger setting.
- **It masks secrets in tool output** with patterns (keys, tokens, passwords, card and account numbers). A secret in a
  shape no pattern knows is not masked.
- **It does not protect against another program of the same user.** The control socket accepts commands only from the
  desktop app in the hub's own folder, by the path the kernel reports. A program that can replace that binary, inject
  code into it or pose as it still wins; that is the limit of a local gateway.
- **On Windows it cannot ask.** The hub cannot tell which program is on the other end of the control socket there, so
  without `--control-trust-all` it accepts no approval: Safe mode blocks but cannot let a call through.
- **The macOS app is not signed with an Apple developer certificate.** Check the download against `SHA256SUMS` from the
  release page.
- **No telemetry.** Hubris talks only to the MCP servers you configured, to their sign-in servers and, when you search
  in the desktop app, to the public MCP registry.

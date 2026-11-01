# Hubris

Native AOT MCP gateway for .NET 10: one stdio server in front of your MCP tools, with a security interceptor
(Safe / Bypass), DLP masking of tool output, compact tool discovery for small context windows, bridges to
other MCP servers, and an Avalonia desktop app to watch calls and approve blocked ones.

```
src/Hubris.Core      library: protocol, transport, security, cache, engine, control channel
src/Hubris           the server  (Hubris --stdio …)           ~4 MB, starts in ~5 ms
src/Hubris.Desktop   dashboard / configurator / launcher      Avalonia 12, Native AOT
tests/Hubris.Tests   xUnit unit tests
tests/e2e            end-to-end suite over stdio + control socket
```

## Build

Requirements: .NET SDK 10, on macOS the Xcode command line tools (linker).

```bash
dotnet publish src/Hubris -c Release            # server  -> src/Hubris/bin/Release/net10.0/<rid>/publish/Hubris
dotnet publish src/Hubris.Desktop -c Release    # desktop -> src/Hubris.Desktop/bin/Release/net10.0/<rid>/publish/
```

Both publish with `TreatWarningsAsErrors` and zero trim/AOT warnings; keep it that way.

### macOS app bundle

```bash
build/bundle-macos.sh                 # publishes both projects and writes artifacts/Hubris.app
build/bundle-macos.sh --no-publish    # bundle the existing publish output
CODESIGN_IDENTITY="Developer ID Application: …" build/bundle-macos.sh   # real signature (default: ad-hoc)
```

The bundle contains the desktop app, the `Hubris` server next to it (the configurator finds it there),
the native Skia/HarfBuzz/Avalonia libraries, an `Info.plist` with the version from `Directory.Build.props`
and a generated placeholder icon. `open artifacts/Hubris.app` starts it.

## Run

```bash
Hubris --stdio [--mode=safe|bypass] [--compact] [--approval-timeout=120] [--no-control]
       [--bridge=<name>:<command> [args…]]…
```

- `--compact` lists only core tools; the model unlocks others with `mcp_search_tools` or runs them through
  `mcp_execute_tool`.
- `--bridge=gh:npx -y @modelcontextprotocol/server-github` spawns another MCP server; its tools appear as `gh__<tool>`.
- Safe mode blocks destructive tools and dangerous arguments. With the desktop app connected, a blocked call waits
  for Approve / Deny instead of failing.

Register in clients:

```bash
Hubris --install-claude --compact                 # Claude Desktop config (keeps a .bak)
Hubris --install-vscode --compact                 # .vscode/mcp.json in the current folder
claude mcp add hubris -- /path/to/Hubris --stdio --compact
```

## Test

```bash
tests/run.sh                                     # unit tests, warning-free publish, e2e
dotnet test tests/Hubris.Tests                   # unit tests only
```

# End-to-end tests

`control_test.py` starts the published `Hubris` binary with a Python echo MCP server as a bridge,
drives it over stdio exactly like an MCP client and over the control socket exactly like the desktop app,
and checks approvals, runtime mode switching, unlock/lock, `mcp_execute_tool`, DLP, shutdown and cleanup.

    tests/run.sh            # unit tests + publish + e2e
    python3 -I tests/e2e/control_test.py [path/to/Hubris]

`driver.py` is a paced stdio client (one request, wait for its response) for manual poking:

    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
      | python3 -I tests/e2e/driver.py /dev/stdin src/Hubris/bin/Release/net10.0/osx-arm64/publish/Hubris --stdio

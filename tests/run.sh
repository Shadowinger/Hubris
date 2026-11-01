#!/usr/bin/env bash
# Unit tests, Native AOT publish of the server (must be warning-free), then the end-to-end suite.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== unit tests"
dotnet test tests/Hubris.Tests -c Release --nologo -v q

echo "== publish server (0 warnings required)"
log=$(mktemp)
dotnet publish src/Hubris -c Release --nologo > "$log" 2>&1 || { cat "$log"; exit 1; }
if grep -qE "warning|error" "$log"; then grep -E "warning|error" "$log" | sort -u; exit 1; fi
rid=$(dotnet --info 2>/dev/null | awk '/RID:/ {print $2; exit}')
bin="src/Hubris/bin/Release/net10.0/${rid}/publish/Hubris"
[ -x "$bin" ] || bin=$(ls src/Hubris/bin/Release/net10.0/*/publish/Hubris | head -1)

echo "== e2e ($bin)"
export HUBRIS_HOME="${HUBRIS_HOME:-$(mktemp -d)}"
python3 -I tests/e2e/control_test.py "$bin"

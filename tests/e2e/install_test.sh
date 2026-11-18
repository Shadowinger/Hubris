#!/bin/sh
# Packs a published hub the way the release workflow does and installs it with install.sh into a throwaway home.
#   tests/e2e/install_test.sh <path to the published Hubris binary>
set -eu
bin=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
unset HUBRIS_HOME # the installed hub must use the throwaway home, not the one the other suites share
case "$(uname -s)" in
  Darwin) asset="macos-arm64-cli.tar.gz"; libs="*.dylib" ;;
  *) asset="linux-x64.tar.gz"; libs="*.so" ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/pkg" "$work/dist" "$work/home"
cp "$bin" "$(dirname "$bin")"/$libs "$work/pkg/"
tar -czf "$work/dist/Hubris-0.0.0-$asset" -C "$work/pkg" .
(cd "$work/dist" && if command -v sha256sum > /dev/null 2>&1; then sha256sum Hubris-*; else shasum -a 256 Hubris-*; fi > SHA256SUMS)

install() { HOME="$work/home" HUBRIS_VERSION=0.0.0 HUBRIS_RELEASE_BASE="file://$work/dist" sh "$root/install.sh"; }
hubris() { HOME="$work/home" "$work/home/.local/bin/hubris" "$@"; }

install > /dev/null
hubris bridge add demo echo hi > /dev/null 2>&1
hubris bridge list | grep -q '^demo  stdio  echo hi' || { echo "FAIL the installed launcher does not run the hub"; exit 1; }
echo "PASS install.sh installs the archive and the launcher runs the hub"

install > /dev/null
hubris bridge list | grep -q '^demo' || { echo "FAIL installing again lost the config"; exit 1; }
echo "PASS installing again keeps the config"

echo tampered >> "$work/dist/Hubris-0.0.0-$asset"
if install > /dev/null 2>&1; then echo "FAIL a tampered archive was installed"; exit 1; fi
hubris --version > /dev/null 2>&1 || { echo "FAIL the old install is gone after a refused update"; exit 1; }
echo "PASS an archive that does not match SHA256SUMS is refused and the old install still runs"

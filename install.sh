#!/bin/sh
# Installs the Hubris hub (the command-line binary, no desktop app) for the current user:
# the release archive goes to ~/.hubris/bin and a `hubris` launcher to ~/.local/bin.
#
#   curl -fsSL https://raw.githubusercontent.com/Shadowinger/Hubris/main/install.sh | sh
#   curl -fsSL … | HUBRIS_VERSION=1.5.0 sh        # a given version instead of the latest
#
# Running it again updates. To remove: rm -rf ~/.hubris/bin ~/.local/bin/hubris
set -eu

repo="https://github.com/Shadowinger/Hubris"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) asset="macos-arm64-cli.tar.gz" ;;
  Linux-x86_64) asset="linux-x64.tar.gz" ;;
  *) echo "hubris: no prebuilt binary for $(uname -s) $(uname -m); build it from source, see $repo#build-from-source" >&2; exit 1 ;;
esac

version="${HUBRIS_VERSION:-}"
if [ -z "$version" ]; then
  # /releases/latest redirects to /releases/tag/vX.Y.Z: the version without an API call and its rate limit
  version=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$repo/releases/latest" | sed -n 's:.*/tag/v::p')
  [ -n "$version" ] || { echo "hubris: could not find the latest release at $repo/releases" >&2; exit 1; }
fi
base="${HUBRIS_RELEASE_BASE:-$repo/releases/download/v$version}" # the test points this at a local folder
file="Hubris-$version-$asset"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "hubris: downloading $file"
curl -fsSL -o "$tmp/$file" "$base/$file" || { echo "hubris: $base/$file could not be downloaded; release $version may not have this archive" >&2; exit 1; }
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

if command -v sha256sum > /dev/null 2>&1; then sum="sha256sum"; else sum="shasum -a 256"; fi
(cd "$tmp" && grep " $file\$" SHA256SUMS > sum.txt && $sum -c sum.txt > /dev/null 2>&1) \
  || { echo "hubris: $file does not match SHA256SUMS; nothing was installed" >&2; exit 1; }

# Unpacked beside the old folder and swapped in: a hub that is running keeps the binary it started from.
dir="$HOME/.hubris/bin"
mkdir -p "$HOME/.hubris" "$HOME/.local/bin"
rm -rf "$dir.new"
mkdir "$dir.new"
tar -xzf "$tmp/$file" -C "$dir.new"
[ -x "$dir.new/Hubris" ] || { echo "hubris: the archive has no Hubris binary in it" >&2; rm -rf "$dir.new"; exit 1; }
rm -rf "$dir"
mv "$dir.new" "$dir"

# A launcher, not a symlink: the hub looks for its SQLite library next to the path it was started from.
printf '#!/bin/sh\nexec "%s/Hubris" "$@"\n' "$dir" > "$HOME/.local/bin/hubris"
chmod +x "$HOME/.local/bin/hubris"

echo "hubris: $("$dir/Hubris" --version 2>&1) installed in $dir"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo "hubris: $HOME/.local/bin is not on your PATH; add it, or run $HOME/.local/bin/hubris" ;;
esac
echo "next:"
echo "  hubris --install-claude --compact    register the hub with Claude Desktop"
echo "  claude mcp add hubris -- $dir/Hubris --stdio --compact"
echo "  hubris status                        what the running hubs are doing"

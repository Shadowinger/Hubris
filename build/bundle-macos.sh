#!/usr/bin/env bash
# Builds artifacts/Hubris.app: the Native AOT desktop app plus the Hubris server binary side by side,
# Info.plist with the version from Directory.Build.props, a Hubris icon rendered by build/render-icon.py, ad-hoc signature.
#
#   build/bundle-macos.sh                 # publish both projects, then bundle
#   build/bundle-macos.sh --no-publish    # bundle what is already in bin/Release/.../publish
#   CODESIGN_IDENTITY="Developer ID Application: …" build/bundle-macos.sh   # real signature instead of ad-hoc
set -euo pipefail
cd "$(dirname "$0")/.."

rid=$(dotnet --info 2>/dev/null | awk '/RID:/ {print $2; exit}')
case "$rid" in osx-*) ;; *) echo "this script targets macOS (RID $rid)" >&2; exit 1 ;; esac

if [ "${1:-}" != "--no-publish" ]; then
  echo "== publish"
  dotnet publish src/Hubris -c Release --nologo
  dotnet publish src/Hubris.Desktop -c Release --nologo
fi

server="src/Hubris/bin/Release/net10.0/$rid/publish"
desktop="src/Hubris.Desktop/bin/Release/net10.0/$rid/publish"
[ -x "$server/Hubris" ] && [ -x "$desktop/Hubris.Desktop" ] || { echo "publish output missing under $server / $desktop" >&2; exit 1; }

version=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' Directory.Build.props | head -1)
app="artifacts/Hubris.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

echo "== assemble $app (version $version)"
cp "$desktop/Hubris.Desktop" "$desktop"/*.dylib "$server/Hubris" "$app/Contents/MacOS/"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Hubris</string>
  <key>CFBundleDisplayName</key><string>Hubris</string>
  <key>CFBundleIdentifier</key><string>dev.vystaveno.hubris</string>
  <key>CFBundleVersion</key><string>${version}</string>
  <key>CFBundleShortVersionString</key><string>${version}</string>
  <key>CFBundleExecutable</key><string>Hubris.Desktop</string>
  <key>CFBundleIconFile</key><string>Hubris</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST

echo "== icon"
iconset=$(mktemp -d)/Hubris.iconset
mkdir -p "$iconset"
python3 -I build/render-icon.py "$iconset/icon_512x512@2x.png" 1024
for s in 16 32 128 256 512; do
  sips -z $s $s "$iconset/icon_512x512@2x.png" --out "$iconset/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2)); [ $s -lt 512 ] && sips -z $d $d "$iconset/icon_512x512@2x.png" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/Hubris.icns"

echo "== sign"
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  codesign --force --deep --options runtime --sign "$CODESIGN_IDENTITY" "$app"
else
  # Ad-hoc signatures carry no Team ID, and hardened runtime's library validation would then refuse the
  # bundled Skia/HarfBuzz dylibs (SkiaPlatform.Initialize aborts). So: no hardened runtime without an identity.
  codesign --force --deep --sign - "$app"
fi
codesign --verify --deep --strict "$app"

echo "== done: $app"
ls -la "$app/Contents/MacOS"

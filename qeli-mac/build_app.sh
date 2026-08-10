#!/usr/bin/env bash
#
# Build a self-contained Qeli.app bundle for macOS AND a ready-to-ship archive.
# Runs on macOS or, for a CI/lab cross-build, on Linux (Windows via Git-Bash too).
#
#   ./build_app.sh             # Apple Silicon (arm64), the default
#   ./build_app.sh x86_64      # Intel
#
# Requirements:
#   • .NET 10 SDK (the build host runs `genicns` to render the .icns in-process —
#     no macOS sips/iconutil needed).
#   • A code signer. macOS: `codesign` (built in). Linux/Windows lab: `rcodesign`
#     (cargo install apple-codesign) — Apple Silicon refuses to launch an UNSIGNED
#     arm64 binary, so the archive must be ad-hoc signed at build time.
#
set -euo pipefail

ARCH="${1:-arm64}"
case "$ARCH" in
  arm64)  RID=osx-arm64 ;;
  x86_64) RID=osx-x64 ;;
  *) echo "unknown arch '$ARCH' (use arm64 or x86_64)"; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")" && pwd)"
PROJ="$ROOT/QeliMac/QeliMac.csproj"
OUT="$ROOT/dist/$RID"
APP="$ROOT/dist/Qeli.app"
ARCHIVE="$ROOT/dist/Qeli-macos-$ARCH.tar.gz"
PER_APP_OUT="$ROOT/dist/per-app-$ARCH"
SIGNED_PER_APP=0

# 1. Native whole-client core (ABI 1.10 + realtls FFI) — universal libqeli.dylib. Built once
#    into QeliMac/native/ by build_dylib.sh (cargo + lipo on Mac, cargo-zigbuild on Linux).
if [[ ! -f "$ROOT/QeliMac/native/libqeli.dylib" && -d "$ROOT/../qeli" ]]; then
  echo "==> Building native whole-client dylib…"
  "$ROOT/build_dylib.sh"
fi

# 2. Publish the self-contained .NET payload for the target RID.
echo "==> Publishing self-contained ($RID)…"
dotnet publish "$PROJ" -c Release -r "$RID" --self-contained true \
  -p:PublishSingleFile=false -o "$OUT"

# 3. Render the .icns in-process (works on any build host — no sips/iconutil).
echo "==> Rendering app icon (.icns)…"
dotnet run --project "$PROJ" -c Release -- genicns "$ROOT/dist/Qeli.icns"

# 4. Assemble Qeli.app.
echo "==> Assembling Qeli.app…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -R "$OUT/." "$APP/Contents/MacOS/"
cp "$ROOT/dist/Qeli.icns" "$APP/Contents/Resources/Qeli.icns"
sed "s/__ARCH__/$ARCH/g" "$ROOT/Info.plist.in" > "$APP/Contents/Info.plist"
chmod +x "$APP/Contents/MacOS/QeliMac"

# 5. A usable Network Extension cannot be ad-hoc signed. When Developer-ID inputs are
# supplied on a Mac, build/embed the transparent+DNS system extension and sign every nested
# item inside-out. Cross/lab builds deliberately omit the helper, so app-filter profiles fail
# closed instead of silently widening into a global tunnel.
if [[ "$(uname -s)" == "Darwin" && -n "${QELI_MAC_SIGN_IDENTITY:-}" \
      && -n "${QELI_MAC_HOST_PROFILE:-}" && -n "${QELI_MAC_EXTENSION_PROFILE:-}" ]]; then
  echo "==> Building and embedding signed per-app Network Extension…"
  "$ROOT/per-app/build.sh" "$PER_APP_OUT" "$ARCH"
  mkdir -p "$APP/Contents/Library/SystemExtensions"
  cp -R "$PER_APP_OUT/QeliPerAppExtension.systemextension" \
    "$APP/Contents/Library/SystemExtensions/ru.qeli.app.perapp.systemextension"
  cp "$PER_APP_OUT/QeliPerAppCtl" "$APP/Contents/MacOS/QeliPerAppCtl"
  chmod +x "$APP/Contents/MacOS/QeliPerAppCtl"
  cp "$QELI_MAC_HOST_PROFILE" "$APP/Contents/embedded.provisionprofile"
  cp "$QELI_MAC_EXTENSION_PROFILE" \
    "$APP/Contents/Library/SystemExtensions/ru.qeli.app.perapp.systemextension/Contents/embedded.provisionprofile"

  while IFS= read -r native; do
    if file -b "$native" | grep -q 'Mach-O'; then
      codesign --force --timestamp --options runtime --sign "$QELI_MAC_SIGN_IDENTITY" "$native"
    fi
  done < <(find "$APP/Contents/MacOS" -type f)
  codesign --force --timestamp --options runtime --identifier ru.qeli.app \
    --entitlements "$ROOT/per-app/Config/Host.entitlements" \
    --sign "$QELI_MAC_SIGN_IDENTITY" "$APP/Contents/MacOS/QeliPerAppCtl"
  codesign --force --timestamp --options runtime \
    --entitlements "$ROOT/per-app/Config/Extension.entitlements" \
    --sign "$QELI_MAC_SIGN_IDENTITY" \
    "$APP/Contents/Library/SystemExtensions/ru.qeli.app.perapp.systemextension"
  codesign --force --timestamp --options runtime \
    --entitlements "$ROOT/per-app/Config/Host.entitlements" \
    --sign "$QELI_MAC_SIGN_IDENTITY" "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP"
  SIGNED_PER_APP=1
  echo "   Developer-ID signed with per-app routing support"
else
  echo "==> Ad-hoc code-signing (per-app extension unavailable in this build)…"
  if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$APP"
    echo "   signed with codesign (ad-hoc)"
  elif command -v rcodesign >/dev/null 2>&1; then
    rcodesign sign "$APP"
    echo "   signed with rcodesign (ad-hoc)"
  else
    echo "   WARNING: no codesign/rcodesign — bundle is UNSIGNED (won't launch on Apple Silicon)."
    echo "            install one:  cargo install apple-codesign   # provides rcodesign"
  fi
fi

# 6. Notarize/staple a distribution build when a notarytool keychain profile is supplied.
# A local Developer-ID build can be tested without this, but a public system-extension build
# must be notarized so Gatekeeper can validate it offline after stapling.
if [[ "$SIGNED_PER_APP" == "1" && -n "${QELI_MAC_NOTARY_PROFILE:-}" ]]; then
  NOTARY_ZIP="$ROOT/dist/Qeli-macos-$ARCH-notary.zip"
  echo "==> Notarizing Developer-ID bundle…"
  rm -f "$NOTARY_ZIP"
  ditto -c -k --keepParent "$APP" "$NOTARY_ZIP"
  xcrun notarytool submit "$NOTARY_ZIP" \
    --keychain-profile "$QELI_MAC_NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP"
  rm -f "$NOTARY_ZIP"
elif [[ "$SIGNED_PER_APP" == "1" ]]; then
  echo "   WARNING: Developer-ID per-app bundle is not notarized."
  echo "            Set QELI_MAC_NOTARY_PROFILE for a public release."
fi

# 7. Package the ready-to-ship archive (tar preserves exec bit + symlinks; unlike zip
#    on Windows). Extract on the Mac with: tar -xzf Qeli-macos-<arch>.tar.gz
echo "==> Packaging archive…"
( cd "$ROOT/dist" && tar -czf "$ARCHIVE" Qeli.app )

echo
echo "Done."
echo "  Bundle:  $APP"
echo "  Archive: $ARCHIVE"
echo
echo "On the Mac:"
echo "  tar -xzf $(basename "$ARCHIVE")"
echo "  xattr -dr com.apple.quarantine Qeli.app    # clear the download/copy quarantine"
echo "  open Qeli.app                               # GUI"
echo "  sudo Qeli.app/Contents/MacOS/QeliMac        # connect a tunnel (utun needs root)"

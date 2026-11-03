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

ROOT="$(cd "$(dirname "$0")" && pwd -P)"
if [[ -L "$ROOT/dist" ]]; then
  echo "refusing symlinked dist directory" >&2; exit 1
fi
# SDK selection searches from the current directory, even for an absolute --project.
# Run within the checkout so global.json and the dependency policy apply.
cd "$ROOT"
PROJ="$ROOT/QeliMac/QeliMac.csproj"
OUT="$ROOT/dist/$RID"
APP="$ROOT/dist/Qeli.app"
ARCHIVE="$ROOT/dist/Qeli-macos-$ARCH.tar.gz"
PER_APP_OUT="$ROOT/dist/per-app-$ARCH"
SIGNED_PER_APP=0
for output in "$OUT" "$APP" "$ARCHIVE" "$PER_APP_OUT" "$ROOT/dist/Qeli.icns"; do
  if [[ -L "$output" ]]; then
    echo "refusing symlinked app output: $output" >&2; exit 1
  fi
done

# An unsigned bundle is not a successful package. Admit a signer before any
# compiler, publish or output replacement; keep one selected tool for this run.
if SIGN_TOOL="$(command -v codesign)"; then
  SIGN_KIND=codesign
elif SIGN_TOOL="$(command -v rcodesign)"; then
  SIGN_KIND=rcodesign
else
  echo "codesign or rcodesign is required before building an app archive" >&2
  exit 1
fi

# 1. Native whole-client core (current ABI 1.16, compatibility floor 1.11 + realtls FFI) —
#    universal libqeli.dylib. Built once
#    into QeliMac/native/ by build_dylib.sh (cargo + lipo on Mac, cargo-zigbuild on Linux).
NATIVE_CORE="${QeliNativeCorePath:-$ROOT/QeliMac/native/libqeli.dylib}"
if [[ ! -f "$NATIVE_CORE" && -z "${QeliNativeCorePath:-}" && -d "$ROOT/../qeli" ]]; then
  echo "==> Building native whole-client dylib…"
  "$ROOT/build_dylib.sh"
fi
if [[ ! -f "$NATIVE_CORE" ]]; then
  echo "native whole-client dylib is missing: $NATIVE_CORE" >&2; exit 1
fi

# 2. Publish the self-contained .NET payload for the target RID.
echo "==> Publishing self-contained ($RID)…"
dotnet publish "$PROJ" -c Release -r "$RID" --self-contained true \
  -p:PublishSingleFile=false -o "$OUT"
# A prior publish can contain a newer host-only CI core. MSBuild PreserveNewest
# compares timestamps, so explicitly install the selected packaging input and
# verify its bytes before signing (which legitimately changes Mach-O signatures).
cp "$NATIVE_CORE" "$OUT/libqeli.dylib"
cmp "$NATIVE_CORE" "$OUT/libqeli.dylib"

# Legal sidecars must survive publish before an app/archive is assembled.
PYTHON="${PYTHON:-python3}"
"$PYTHON" "$ROOT/../scripts/native_licenses.py" --repo "$ROOT/.." --bundle "$OUT/Legal/NativeRust"
"$PYTHON" "$ROOT/../scripts/managed_licenses.py" --repo "$ROOT/.." --bundle "$OUT/Legal/DotNet"
cmp "$ROOT/LICENSE" "$OUT/Legal/MPL-2.0.txt"

# 3. Render the .icns in-process (works on any build host — no sips/iconutil).
echo "==> Rendering app icon (.icns)…"
dotnet run --project "$PROJ" -c Release -- genicns "$ROOT/dist/Qeli.icns"

# 4. Assemble Qeli.app.
echo "==> Assembling Qeli.app…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -R "$OUT/." "$APP/Contents/MacOS/"
# Legal files are resources, not nested code. In MacOS/, codesign interprets
# dotted version directories (for example axum-core/0.5.6) as malformed bundles.
mv "$APP/Contents/MacOS/Legal" "$APP/Contents/Resources/Legal"
cp "$ROOT/dist/Qeli.icns" "$APP/Contents/Resources/Qeli.icns"
sed "s/__ARCH__/$ARCH/g" "$ROOT/Info.plist.in" > "$APP/Contents/Info.plist"
chmod +x "$APP/Contents/MacOS/QeliMac"
"$PYTHON" "$ROOT/../scripts/check_macos_deployment.py" "$APP"

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
  if [[ "$SIGN_KIND" == codesign ]]; then
    "$SIGN_TOOL" --force --deep --sign - "$APP"
    echo "   signed with codesign (ad-hoc)"
  else
    "$SIGN_TOOL" sign "$APP"
    echo "   signed with rcodesign (ad-hoc)"
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

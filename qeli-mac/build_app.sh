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

# 1. Native REALITY core (Rust realtls FFI) — universal libqeli.dylib. Built once
#    into QeliMac/native/ by build_dylib.sh (cargo + lipo on Mac, cargo-zigbuild on Linux).
if [[ ! -f "$ROOT/QeliMac/native/libqeli.dylib" && -d "$ROOT/../qeli" ]]; then
  echo "==> Building native REALITY dylib…"
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

# 5. Ad-hoc code-sign (mandatory for Apple Silicon to launch).
echo "==> Ad-hoc code-signing…"
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APP"
  echo "   signed with codesign (ad-hoc)"
elif command -v rcodesign >/dev/null 2>&1; then
  # rcodesign signs nested Mach-O (dylibs) then the bundle; no key = ad-hoc.
  rcodesign sign "$APP"
  echo "   signed with rcodesign (ad-hoc)"
else
  echo "   WARNING: no codesign/rcodesign — bundle is UNSIGNED (won't launch on Apple Silicon)."
  echo "            install one:  cargo install apple-codesign   # provides rcodesign"
fi

# 6. Package the ready-to-ship archive (tar preserves exec bit + symlinks; unlike zip
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

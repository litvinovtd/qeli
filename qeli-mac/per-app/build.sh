#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd -P)"
OUTPUT="${1:?output directory required}"
ARCH="${2:-arm64}"
case "$ARCH" in arm64|x86_64) ;; *) echo "unknown arch: $ARCH" >&2; exit 1 ;; esac

# Only the architecture-specific output leaf used by build_app.sh is deletable.
# Prefix matching alone accepts ../ and symlinked parents outside the workspace.
DIST_ROOT="$(cd "$ROOT/.." && pwd -P)/dist"
DERIVED="$ROOT/build/$ARCH"
if [ "$OUTPUT" != "$DIST_ROOT/per-app-$ARCH" ]; then
  echo "output must be exactly $DIST_ROOT/per-app-$ARCH" >&2; exit 1
fi
for directory in "$DIST_ROOT" "$ROOT/build" "$DERIVED" "$OUTPUT"; do
  if [ -L "$directory" ]; then
    echo "refusing symlinked build/output path: $directory" >&2; exit 1
  fi
done

test "$(uname -s)" = Darwin || { echo "per-app system extension requires a macOS/Xcode build host" >&2; exit 1; }
command -v xcodebuild >/dev/null 2>&1 || { echo "Xcode is required" >&2; exit 1; }
"$ROOT/generate_project.sh"

rm -rf "$DERIVED" "$OUTPUT"
xcodebuild -project "$ROOT/QeliMacPerApp.xcodeproj" -scheme QeliMacPerApp \
  -configuration Release -derivedDataPath "$DERIVED" ARCHS="$ARCH" ONLY_ACTIVE_ARCH=YES \
  CODE_SIGNING_ALLOWED=NO build

PRODUCTS="$DERIVED/Build/Products/Release"
"$PRODUCTS/QeliPerAppPolicyTests"
mkdir -p "$OUTPUT"
cp -R "$PRODUCTS/QeliPerAppExtension.systemextension" "$OUTPUT/"
cp "$PRODUCTS/QeliPerAppCtl" "$OUTPUT/"
chmod +x "$OUTPUT/QeliPerAppCtl"
echo "Built unsigned per-app components in $OUTPUT (the containing build signs them inside-out)."

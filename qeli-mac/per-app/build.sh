#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="${1:?output directory required}"
ARCH="${2:-arm64}"
case "$ARCH" in arm64|x86_64) ;; *) echo "unknown arch: $ARCH" >&2; exit 1 ;; esac

# build.sh removes/recreates OUTPUT. Keep that destructive operation inside qeli-mac/dist;
# callers must not be able to turn a typo such as `/` into an arbitrary recursive delete.
DIST_ROOT="$(cd "$ROOT/.." && pwd)/dist"
case "$OUTPUT" in
  "$DIST_ROOT"/*) ;;
  *) echo "output must be inside $DIST_ROOT" >&2; exit 1 ;;
esac

test "$(uname -s)" = Darwin || { echo "per-app system extension requires a macOS/Xcode build host" >&2; exit 1; }
command -v xcodebuild >/dev/null 2>&1 || { echo "Xcode is required" >&2; exit 1; }
"$ROOT/generate_project.sh"

DERIVED="$ROOT/build/$ARCH"
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

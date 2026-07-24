#!/usr/bin/env bash
#
# Verify the committed native libraries against native-libs/SHA256SUMS. (R-06)
#
# WHY THIS EXISTS. `.so` / `.dll` / `.dylib` are committed to the repo as opaque binaries:
# a reviewer cannot read a diff of them, so a swapped library is invisible in review. The
# manifest records what each file is SUPPOSED to hash to, turning "trust the blob" into a
# check anyone (and CI) can run.
#
# It also catches a mundane failure that has bitten this tree before: each library exists
# TWICE — the canonical copy under native-libs/ and the copy the build stack actually reads
# (jniLibs/, QeliWin/native/, QeliMac/native/). Nothing enforces that they match, so a
# library updated in one place and not the other ships a stale binary. The manifest lists
# both paths, so drift fails here instead of at runtime.
#
# Usage:
#   ./native-libs/verify.sh            # verify (exit 1 on mismatch)
#   ./native-libs/verify.sh --update   # re-record hashes after a DELIBERATE rebuild
#
# Run from the repository root.

set -euo pipefail

MANIFEST="native-libs/SHA256SUMS"

if [ "${1:-}" = "--update" ]; then
  # Deliberately re-record. Use ONLY after rebuilding the libraries on purpose (see
  # native-libs/README.md for the build recipes) and after copying them to BOTH
  # locations — otherwise this just blesses whatever drift is currently present.
  : > "$MANIFEST"
  while read -r path; do
    [ -n "$path" ] || continue
    [ -f "$path" ] || { echo "missing: $path" >&2; exit 1; }
    sha256sum "$path" >> "$MANIFEST"
  done <<'PATHS'
native-libs/android/arm64-v8a/libqeli.so
qeli-android/app/src/main/jniLibs/arm64-v8a/libqeli.so
native-libs/android/x86_64/libqeli.so
qeli-android/app/src/main/jniLibs/x86_64/libqeli.so
native-libs/windows-x64/qeli.dll
qeli-win/QeliWin/native/qeli.dll
native-libs/macos-universal/libqeli.dylib
qeli-mac/QeliMac/native/libqeli.dylib
native-libs/third-party/windows-x64/wintun.dll
qeli-win/QeliWin/wintun/wintun.dll
PATHS
  echo "updated $MANIFEST:"
  cat "$MANIFEST"
  exit 0
fi

[ -f "$MANIFEST" ] || { echo "ERROR: $MANIFEST not found — run from the repo root." >&2; exit 1; }

if sha256sum -c "$MANIFEST"; then
  echo
  echo "OK: every committed native library matches the manifest, and each canonical copy"
  echo "    matches the copy the build stack consumes."
else
  echo
  echo "MISMATCH. Either a library was rebuilt without updating the manifest, or the" >&2
  echo "canonical copy and the build-stack copy have drifted apart. Do NOT run --update" >&2
  echo "until you know which: --update would simply record the wrong state as correct." >&2
  exit 1
fi

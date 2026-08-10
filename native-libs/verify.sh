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

# Each line is a PAIR: the canonical copy under native-libs/, then the copy the build stack
# actually reads. Kept as pairs rather than a flat path list because the pairing is the
# thing being checked — see check_pairs below.
PAIRS='
native-libs/android/arm64-v8a/libqeli.so|qeli-android/app/src/main/jniLibs/arm64-v8a/libqeli.so
native-libs/android/x86_64/libqeli.so|qeli-android/app/src/main/jniLibs/x86_64/libqeli.so
native-libs/windows-x64/qeli.dll|qeli-win/QeliWin/native/qeli.dll
native-libs/macos-universal/libqeli.dylib|qeli-mac/QeliMac/native/libqeli.dylib
native-libs/third-party/windows-x64/wintun.dll|qeli-win/QeliWin/wintun/wintun.dll
native-libs/third-party/windows-x64/windivert/WinDivert.dll|qeli-win/QeliWin/windivert/WinDivert.dll
native-libs/third-party/windows-x64/windivert/WinDivert64.sys|qeli-win/QeliWin/windivert/WinDivert64.sys
'

# Cross-check every canonical copy against the copy the build stack consumes.
#
# This used to be left to `sha256sum -c`, which does NOT do it: the manifest records each
# path's own hash, so each file was only ever compared against itself and a pair that had
# drifted apart passed silently — the exact failure this script's header claims to catch.
# It bit us for real: `scripts/build_android_so_11.py` writes ONLY to jniLibs, so every
# Android rebuild left native-libs/android/ stale, `--update` recorded the two different
# hashes without complaint, and the manifest ended up certifying the drift as correct.
check_pairs() {
  local rc=0 canonical consumed
  while IFS='|' read -r canonical consumed; do
    [ -n "$canonical" ] || continue
    for p in "$canonical" "$consumed"; do
      [ -f "$p" ] || { echo "missing: $p" >&2; rc=1; }
    done
    [ -f "$canonical" ] && [ -f "$consumed" ] || continue
    if ! cmp -s "$canonical" "$consumed"; then
      echo "DRIFT: $canonical != $consumed" >&2
      rc=1
    fi
  done <<EOF
$PAIRS
EOF
  return $rc
}

if [ "${1:-}" = "--update" ]; then
  # Deliberately re-record. Use ONLY after rebuilding the libraries on purpose (see
  # native-libs/README.md for the build recipes). Refuses to run while a pair has drifted:
  # recording that state would bless a stale binary as canonical, which is precisely how
  # the Android copies went unnoticed.
  if ! check_pairs; then
    echo >&2
    echo "Refusing to --update: copy the rebuilt library to BOTH locations first." >&2
    echo "Recording this state would certify a stale binary as the canonical one." >&2
    exit 1
  fi
  : > "$MANIFEST"
  while IFS='|' read -r canonical consumed; do
    [ -n "$canonical" ] || continue
    sha256sum "$canonical" "$consumed" >> "$MANIFEST"
  done <<EOF
$PAIRS
EOF
  echo "updated $MANIFEST:"
  cat "$MANIFEST"
  exit 0
fi

[ -f "$MANIFEST" ] || { echo "ERROR: $MANIFEST not found — run from the repo root." >&2; exit 1; }

hashes_ok=0
sha256sum -c "$MANIFEST" || hashes_ok=1
pairs_ok=0
check_pairs || pairs_ok=1

if [ "$hashes_ok" = 0 ] && [ "$pairs_ok" = 0 ]; then
  echo
  echo "OK: every committed native library matches the manifest, and each canonical copy"
  echo "    matches the copy the build stack consumes."
else
  echo
  echo "MISMATCH. Either a library was rebuilt without updating the manifest, or the" >&2
  echo "canonical copy and the build-stack copy have drifted apart (DRIFT lines above)." >&2
  echo "Do NOT run --update until you know which: for drift, copy the intended binary to" >&2
  echo "both locations first — --update now refuses, but the point is to fix the cause." >&2
  exit 1
fi

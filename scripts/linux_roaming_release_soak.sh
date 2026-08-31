#!/usr/bin/env bash
# Bounded release soak: representative TCP and UDP QUIC share one session across repeated A/B flips.
set -eu
set -o pipefail
export LC_ALL=C

BIN=${1:-}
ITERATIONS=${2:-100}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ ! -x "$BIN" ]; then
  echo "usage: $0 <qeli-binary> [iterations>=100]" >&2
  exit 2
fi
case "$ITERATIONS" in
  *[!0-9]*|'') echo "iterations must be an integer >= 100" >&2; exit 2 ;;
esac
if [ "$ITERATIONS" -lt 100 ]; then
  echo "release certification requires at least 100 committed flips per transport" >&2
  exit 2
fi
BIN=$(readlink -f "$BIN")
SAMPLE_EVERY=$((ITERATIONS / 10))
if [ "$SAMPLE_EVERY" -lt 1 ]; then SAMPLE_EVERY=1; fi

echo "binary_version=$($BIN --version)"
echo "binary_sha256=$(sha256sum "$BIN" | cut -d' ' -f1)"
echo "iterations_per_transport=$ITERATIONS"

echo "=== bounded TCP same-session roaming soak ==="
QELI_ROAMING_SOAK_ITERATIONS="$ITERATIONS" QELI_ROAMING_SOAK_SAMPLE_EVERY="$SAMPLE_EVERY" \
  bash "$SCRIPT_DIR/roaming_netns_e2e.sh" "$BIN" soak

echo "=== bounded UDP QUIC same-session roaming soak ==="
QELI_ROAMING_SOAK_ITERATIONS="$ITERATIONS" QELI_ROAMING_SOAK_SAMPLE_EVERY="$SAMPLE_EVERY" \
  QELI_ROAMING_UDP_WIRE_MODE=quic \
  bash "$SCRIPT_DIR/roaming_udp_netns_e2e.sh" "$BIN" soak

echo "=== RESULT bounded Linux roaming soak: TCP and UDP passed $ITERATIONS flips each ==="

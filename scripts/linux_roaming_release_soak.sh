#!/usr/bin/env bash
# Bounded release soak: representative TCP and UDP QUIC share one session across repeated A/B flips.
set -eu
set -o pipefail
export LC_ALL=C

BIN=${1:-}
ITERATIONS=${2:-100}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$#" -gt 2 ] || [ ! -x "$BIN" ]; then
  echo "usage: $0 <qeli-binary> [iterations>=100]" >&2
  exit 2
fi
if [ ! -r "$SCRIPT_DIR/roaming_soak_parameters.sh" ]; then
  echo "required roaming soak parameter helper is missing" >&2
  exit 2
fi
source "$SCRIPT_DIR/roaming_soak_parameters.sh" || exit 2
roaming_soak_count iterations "$ITERATIONS" 100 || exit 2
BIN=$(readlink -f "$BIN")
SAMPLE_EVERY=$((ITERATIONS / 10))
if [ "$SAMPLE_EVERY" -lt 1 ]; then SAMPLE_EVERY=1; fi

echo "binary_version=$("$BIN" --version)"
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

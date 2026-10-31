#!/usr/bin/env bash
# Prove active PMTU/DATA_FRAG and explicit IPv6-minimum MTU/PTB as distinct runtime modes.
set -eu
set -o pipefail
export LC_ALL=C

BIN=${1:-}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CASE_SCRIPT="$SCRIPT_DIR/ipv6_netns_case.sh"

if [ ! -x "$BIN" ]; then
  echo "usage: $0 <qeli-binary>" >&2
  exit 2
fi
BIN=$(readlink -f "$BIN")

echo "=== auto PMTU and DATA_FRAG on outer MTU 1280 ==="
# Observe the actual carrier in both modes as well as checking reported budgets:
# both directions must fit 1280 IP bytes, without any outer IPv4 fragmentation.
QELI_PACKET_AUDIT=1 bash "$CASE_SCRIPT" "$BIN" 4 6 udp quic full pmtu

echo "=== explicit inner MTU 1280 and ICMPv6 PTB ==="
QELI_PACKET_AUDIT=1 bash "$CASE_SCRIPT" "$BIN" 4 6 udp quic full mtu

echo "=== RESULT MTU 1280/PMTU/PTB: both runtime modes passed ==="

#!/usr/bin/env bash
# Prove dual-stack DNS proxy/listener and Linux resolver application over both upstream families.
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

echo "=== dual DNS via IPv4 upstream ==="
bash "$CASE_SCRIPT" "$BIN" 4 dual tcp fake-tls full dns4

echo "=== dual DNS via IPv6 upstream ==="
bash "$CASE_SCRIPT" "$BIN" 4 dual tcp fake-tls full dns6

echo "=== RESULT dual-stack DNS: both upstream families passed ==="

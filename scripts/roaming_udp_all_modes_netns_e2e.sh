#!/usr/bin/env bash
# Prove that transport camouflage does not fork UDP roaming behavior. Each run creates and tears
# down its own namespaces; no host route or production process is changed.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNNER="$SCRIPT_DIR/roaming_udp_netns_e2e.sh"
PASS=0
FAIL=0

for mode in quic fake-tls obfs obfs-awg; do
  echo "=== UDP roaming wire mode: $mode ==="
  if QELI_ROAMING_UDP_WIRE_MODE="$mode" "$RUNNER" "$BIN" success; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done

echo
echo "UDP roaming transport-mode matrix: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi

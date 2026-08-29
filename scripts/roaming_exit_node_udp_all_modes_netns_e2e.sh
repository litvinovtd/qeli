#!/usr/bin/env bash
# Prove that the Linux exit-node COMMIT path is shared by every UDP wire mode.
# Runs are sequential because every case owns the same isolated namespace names.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/var/tmp/qeli-exit-node-target/release/qeli}}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNNER="$SCRIPT_DIR/roaming_exit_node_netns_e2e.sh"
PASS=0
FAIL=0

if [ "$#" -gt 1 ]; then
  echo "usage: $0 [qeli-binary]" >&2
  exit 2
fi

for mode in quic fake-tls obfs obfs-awg; do
  echo "=== UDP exit-node roaming wire mode: $mode ==="
  if "$RUNNER" "$BIN" udp "$mode"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done

echo
echo "UDP exit-node roaming transport-mode matrix: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi

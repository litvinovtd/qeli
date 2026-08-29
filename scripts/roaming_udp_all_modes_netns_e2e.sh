#!/usr/bin/env bash
# Prove that transport camouflage does not fork UDP roaming behavior. The optional second argument
# forwards any supported netns case (including soak) through every UDP wire mode. Each run creates and tears
# down its own namespaces; no host route or production process is changed.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
CASE=${2:-${CASE:-success}}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNNER="$SCRIPT_DIR/roaming_udp_netns_e2e.sh"
PASS=0
FAIL=0

usage() {
  echo "usage: $0 [qeli-binary] [success|rollback|supersede|commit-race|loss-replay|pmtu|pmtu-asym|drain-reorder|family-switch|frag-loss|nat-rebind|soak]" >&2
}

if [ "$#" -gt 2 ]; then
  usage
  exit 2
fi
case "$CASE" in
  success|rollback|supersede|commit-race|loss-replay|pmtu|pmtu-asym|drain-reorder|family-switch|frag-loss|nat-rebind|soak) ;;
  *)
    usage
    exit 2
    ;;
esac

for mode in quic fake-tls obfs obfs-awg; do
  echo "=== UDP roaming wire mode: $mode; case: $CASE ==="
  if QELI_ROAMING_UDP_WIRE_MODE="$mode" "$RUNNER" "$BIN" "$CASE"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done

echo
echo "UDP roaming transport-mode matrix ($CASE): $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi

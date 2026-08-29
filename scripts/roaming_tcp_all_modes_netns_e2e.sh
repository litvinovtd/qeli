#!/usr/bin/env bash
# Prove that the shared TCP roaming actor is independent of wire camouflage. REALITY-TLS gets a
# genuine local TLS target plus pinned identity; the other modes stay fully self-contained.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
CASE=${2:-${CASE:-success}}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RUNNER="$SCRIPT_DIR/roaming_netns_e2e.sh"
PASS=0
FAIL=0

if [ "$#" -gt 2 ] || { [ "$CASE" != success ] && [ "$CASE" != soak ]; }; then
  echo "usage: $0 [qeli-binary] [success|soak]" >&2
  exit 2
fi

for mode in fake-tls reality-tls plain obfs-ws obfs-none obfs-awg; do
  echo "=== TCP roaming wire mode: $mode; case: $CASE ==="
  if "$RUNNER" "$BIN" "$CASE" "$mode"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done

echo
echo "TCP roaming transport-mode matrix ($CASE): $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi

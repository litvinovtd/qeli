#!/usr/bin/env bash
# Fail-closed resource/performance acceptance for one immutable roaming build.
#
# The individual netns runners remain useful on their own. This wrapper is the release-order
# contract: wire-mode smoke -> TCP 10k -> UDP 4x10k -> performance -> cross-node fallback.
# A later phase is never started after an earlier failure, and the binary hash is checked before
# every phase so a rebuild cannot silently mix results from two revisions.
set -eu
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
EXPECTED_SHA256=${QELI_ROAMING_RELEASE_SHA256:-}

if [ "$#" -gt 1 ]; then
  echo "usage: $0 [qeli-binary]" >&2
  exit 2
fi
if [ ! -x "$BIN" ]; then
  echo "qeli binary is missing or not executable: $BIN" >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required for the roaming resource release gate" >&2
  exit 2
fi

actual_sha256=$(sha256sum "$BIN" | awk '{print $1}')
if [ -n "$EXPECTED_SHA256" ] && [ "$actual_sha256" != "$EXPECTED_SHA256" ]; then
  echo "qeli binary hash mismatch: expected $EXPECTED_SHA256, got $actual_sha256" >&2
  exit 1
fi
EXPECTED_SHA256=$actual_sha256

verify_binary() {
  local phase=$1 actual
  actual=$(sha256sum "$BIN" | awk '{print $1}')
  if [ "$actual" != "$EXPECTED_SHA256" ]; then
    echo "qeli binary changed before $phase: expected $EXPECTED_SHA256, got $actual" >&2
    exit 1
  fi
  echo "=== roaming release phase: $phase; sha256=$actual ==="
}

run_phase() {
  local phase=$1 marker=$2
  shift 2
  verify_binary "$phase"
  "$@"
  verify_binary "$phase completion"
  echo "$marker"
}

echo "ROAMING_RESOURCE_RELEASE_SHA256=$EXPECTED_SHA256"

run_phase tcp-wire-smoke ROAMING_RELEASE_TCP_WIRE_SMOKE_PASS \
  "$SCRIPT_DIR/roaming_tcp_all_modes_netns_e2e.sh" "$BIN" success
run_phase udp-wire-smoke ROAMING_RELEASE_UDP_WIRE_SMOKE_PASS \
  "$SCRIPT_DIR/roaming_udp_all_modes_netns_e2e.sh" "$BIN" success
run_phase tcp-resource-soak ROAMING_RELEASE_TCP_10K_PASS \
  env QELI_ROAMING_MULTIPATH_MODE=single \
  "$SCRIPT_DIR/roaming_netns_e2e.sh" "$BIN" soak fake-tls
run_phase udp-resource-soak ROAMING_RELEASE_UDP_ALL_10K_PASS \
  "$SCRIPT_DIR/roaming_udp_all_modes_netns_e2e.sh" "$BIN" soak
run_phase tcp-performance ROAMING_RELEASE_TCP_PERF_PASS \
  "$SCRIPT_DIR/roaming_tcp_perf_netns_gate.sh" "$BIN" fake-tls
run_phase tcp-cross-node-fallback ROAMING_RELEASE_TCP_MULTINODE_PASS \
  "$SCRIPT_DIR/roaming_netns_e2e.sh" "$BIN" multinode fake-tls

verify_binary complete
echo ROAMING_RESOURCE_RELEASE_GATE_PASS

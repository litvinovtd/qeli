#!/usr/bin/env bash
# Fail-closed resource/performance acceptance for one immutable roaming build.
#
# The individual netns runners remain useful on their own. This wrapper is the release-order
# contract: wire-mode smoke -> resume/grace -> TCP 10k -> UDP representative 10k plus adapter
# 3x1k -> performance -> cross-node
# fallback.
# A later phase is never started after an earlier failure, and the binary hash is checked before
# every phase so a rebuild cannot silently mix results from two revisions.
set -eu
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
EXPECTED_SHA256=${QELI_ROAMING_RELEASE_SHA256:-}
MIN_RELEASE_SOAK_NS=28800000000000

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
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for a monotonic release-soak duration" >&2
  exit 2
fi

if [ ! -r "$SCRIPT_DIR/roaming_soak_parameters.sh" ]; then
  echo "required roaming soak parameter helper is missing" >&2
  exit 2
fi
source "$SCRIPT_DIR/roaming_soak_parameters.sh" || exit 2
# This is the full endurance gate; bounded 100-flip certification has its own wrapper.
TCP_ITERATIONS=${QELI_ROAMING_SOAK_ITERATIONS:-10000}
UDP_REPRESENTATIVE_ITERATIONS=${QELI_ROAMING_UDP_REPRESENTATIVE_SOAK_ITERATIONS:-10000}
UDP_ADAPTER_ITERATIONS=${QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS:-1000}
roaming_soak_counts "$TCP_ITERATIONS" "${QELI_ROAMING_SOAK_SAMPLE_EVERY:-100}" 10000 || exit 2
roaming_soak_counts "$UDP_REPRESENTATIVE_ITERATIONS" "${QELI_ROAMING_SOAK_SAMPLE_EVERY:-100}" 10000 || exit 2
roaming_soak_counts "$UDP_ADAPTER_ITERATIONS" "${QELI_ROAMING_SOAK_SAMPLE_EVERY:-100}" 1000 || exit 2

actual_sha256=$(sha256sum "$BIN" | awk '{print $1}')
if [ -n "$EXPECTED_SHA256" ] && [ "$actual_sha256" != "$EXPECTED_SHA256" ]; then
  echo "qeli binary hash mismatch: expected $EXPECTED_SHA256, got $actual_sha256" >&2
  exit 1
fi
EXPECTED_SHA256=$actual_sha256
START_NS=$(python3 -c 'import time; print(time.monotonic_ns())') || exit 2
case "$START_NS" in ''|*[!0-9]*) echo "invalid monotonic release-soak start" >&2; exit 2;; esac
RUN_LOG=
cleanup_run_log() { if [ -n "$RUN_LOG" ]; then rm -f -- "$RUN_LOG"; fi; }
trap cleanup_run_log EXIT

verify_binary() {
  local phase=$1 actual
  actual=$(sha256sum "$BIN" | awk '{print $1}')
  if [ "$actual" != "$EXPECTED_SHA256" ]; then
    echo "qeli binary changed before $phase: expected $EXPECTED_SHA256, got $actual" >&2
    exit 1
  fi
  echo "=== roaming release phase: $phase; sha256=$actual ==="
}

require_result() {
  local phase=$1 pattern=$2
  if ! grep -Eq "$pattern" "$RUN_LOG"; then
    echo "release phase $phase returned success without its verified result" >&2
    return 1
  fi
}

verify_phase_output() {
  local phase=$1 count marker
  case "$phase" in
    tcp-wire-smoke) require_result "$phase" '^TCP roaming transport-mode matrix \(success\): 6 passed, 0 failed$' ;;
    udp-wire-smoke) require_result "$phase" '^UDP roaming transport-mode matrix \(success\): 4 passed, 0 failed$' ;;
    tcp-hard-resume) require_result "$phase" '^=== RESULT \(fake-tls/resume/[^)]*\): [1-9][0-9]* passed, 0 failed ===$' ;;
    tcp-grace-expiry) require_result "$phase" '^=== RESULT \(fake-tls/grace-expiry/[^)]*\): [1-9][0-9]* passed, 0 failed ===$' ;;
    tcp-resource-soak)
      require_result "$phase" '^=== RESULT \(fake-tls/soak/[^)]*\): [1-9][0-9]* passed, 0 failed ===$' || return 1
      if ! grep -Fq "  TCP soak progress $TCP_ITERATIONS/$TCP_ITERATIONS " "$RUN_LOG"; then
        echo "release phase $phase lacks its final $TCP_ITERATIONS-flip checkpoint" >&2
        return 1
      fi
      ;;
    udp-resource-soak)
      for marker in ROAMING_UDP_QUIC_REPRESENTATIVE_SOAK_PASS ROAMING_UDP_FAKE_TLS_ADAPTER_SOAK_PASS ROAMING_UDP_OBFS_ADAPTER_SOAK_PASS ROAMING_UDP_OBFS_AWG_ADAPTER_SOAK_PASS ROAMING_UDP_RESOURCE_SOAK_MATRIX_PASS; do
        if ! grep -Fxq "$marker" "$RUN_LOG"; then
          echo "release phase $phase lacks $marker" >&2
          return 1
        fi
      done
      if ! grep -Fq "  soak progress $UDP_REPRESENTATIVE_ITERATIONS/$UDP_REPRESENTATIVE_ITERATIONS " "$RUN_LOG"; then
        echo "release phase $phase lacks its representative final checkpoint" >&2
        return 1
      fi
      count=$(grep -Fc "  soak progress $UDP_ADAPTER_ITERATIONS/$UDP_ADAPTER_ITERATIONS " "$RUN_LOG" || true)
      if [ "$count" -lt 3 ]; then
        echo "release phase $phase lacks its three adapter final checkpoints" >&2
        return 1
      fi
      ;;
    tcp-performance) require_result "$phase" '^=== RESULT: [1-9][0-9]* passed, 0 failed ===$' ;;
    tcp-cross-node-fallback) require_result "$phase" '^=== RESULT \(fake-tls/multinode/[^)]*\): [1-9][0-9]* passed, 0 failed ===$' ;;
    *) echo "unknown release phase $phase" >&2; return 1 ;;
  esac
}

run_phase() {
  local phase=$1 marker=$2
  shift 2
  verify_binary "$phase"
  RUN_LOG=$(mktemp "${TMPDIR:-/tmp}/qeli-roaming-release.XXXXXXXX") || exit 2
  "$@" 2>&1 | tee "$RUN_LOG"
  verify_phase_output "$phase"
  verify_binary "$phase completion"
  rm -f -- "$RUN_LOG"
  RUN_LOG=
  echo "$marker"
}

echo "ROAMING_RESOURCE_RELEASE_SHA256=$EXPECTED_SHA256"

run_phase tcp-wire-smoke ROAMING_RELEASE_TCP_WIRE_SMOKE_PASS \
  "$SCRIPT_DIR/roaming_tcp_all_modes_netns_e2e.sh" "$BIN" success
run_phase udp-wire-smoke ROAMING_RELEASE_UDP_WIRE_SMOKE_PASS \
  "$SCRIPT_DIR/roaming_udp_all_modes_netns_e2e.sh" "$BIN" success
run_phase tcp-hard-resume ROAMING_RELEASE_TCP_RESUME_PASS \
  "$SCRIPT_DIR/roaming_netns_e2e.sh" "$BIN" resume fake-tls
run_phase tcp-grace-expiry ROAMING_RELEASE_TCP_GRACE_EXPIRY_PASS \
  "$SCRIPT_DIR/roaming_netns_e2e.sh" "$BIN" grace-expiry fake-tls
run_phase tcp-resource-soak ROAMING_RELEASE_TCP_10K_PASS \
  env QELI_ROAMING_MULTIPATH_MODE=single \
  "$SCRIPT_DIR/roaming_netns_e2e.sh" "$BIN" soak fake-tls
run_phase udp-resource-soak ROAMING_RELEASE_UDP_RESOURCE_MATRIX_PASS \
  "$SCRIPT_DIR/roaming_udp_resource_soak_netns_gate.sh" "$BIN"
run_phase tcp-performance ROAMING_RELEASE_TCP_PERF_PASS \
  "$SCRIPT_DIR/roaming_tcp_perf_netns_gate.sh" "$BIN" fake-tls
run_phase tcp-cross-node-fallback ROAMING_RELEASE_TCP_MULTINODE_PASS \
  "$SCRIPT_DIR/roaming_netns_e2e.sh" "$BIN" multinode fake-tls

verify_binary complete
END_NS=$(python3 -c 'import time; print(time.monotonic_ns())') || exit 2
case "$END_NS" in ''|*[!0-9]*) echo "invalid monotonic release-soak end" >&2; exit 2;; esac
ELAPSED_NS=$((END_NS - START_NS))
if [ "$ELAPSED_NS" -lt "$MIN_RELEASE_SOAK_NS" ]; then
  echo "release endurance requires at least 28800 seconds; observed $((ELAPSED_NS / 1000000000))" >&2
  exit 1
fi
echo "ROAMING_RESOURCE_RELEASE_ELAPSED_SECONDS=$((ELAPSED_NS / 1000000000))"
echo ROAMING_RESOURCE_RELEASE_GATE_PASS

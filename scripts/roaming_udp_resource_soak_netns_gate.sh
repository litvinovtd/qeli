#!/usr/bin/env bash
# Resource acceptance for the shared UDP roaming actor. QUIC carries the representative 10k
# same-session endurance gate; the other wire adapters each run a bounded 1k transport check.
set -eu
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RUNNER="$SCRIPT_DIR/roaming_udp_netns_e2e.sh"
REPRESENTATIVE_ITERATIONS=${QELI_ROAMING_UDP_REPRESENTATIVE_SOAK_ITERATIONS:-10000}
ADAPTER_ITERATIONS=${QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS:-1000}
SAMPLE_EVERY=${QELI_ROAMING_SOAK_SAMPLE_EVERY:-100}

if [ "$#" -gt 1 ]; then
  echo "usage: $0 [qeli-binary]" >&2
  exit 2
fi
if [ ! -x "$BIN" ]; then
  echo "qeli binary is missing or not executable: $BIN" >&2
  exit 2
fi
if [ ! -r "$SCRIPT_DIR/roaming_soak_parameters.sh" ]; then
  echo "required roaming soak parameter helper is missing" >&2
  exit 2
fi
source "$SCRIPT_DIR/roaming_soak_parameters.sh" || exit 2
roaming_soak_counts "$REPRESENTATIVE_ITERATIONS" "$SAMPLE_EVERY" || exit 2
roaming_soak_counts "$ADAPTER_ITERATIONS" "$SAMPLE_EVERY" || exit 2
QUALIFICATION=SMOKE
if [ "$REPRESENTATIVE_ITERATIONS" -ge 10000 ] && [ "$ADAPTER_ITERATIONS" -ge 1000 ]; then
  QUALIFICATION=PASS
fi
echo "qualification=$QUALIFICATION representative_iterations=$REPRESENTATIVE_ITERATIONS adapter_iterations=$ADAPTER_ITERATIONS sample_every=$SAMPLE_EVERY"

run_mode() {
  local mode=$1 iterations=$2 marker=$3
  echo "=== UDP roaming resource soak: mode=$mode iterations=$iterations ==="
  QELI_ROAMING_SOAK_ITERATIONS="$iterations" \
  QELI_ROAMING_SOAK_SAMPLE_EVERY="$SAMPLE_EVERY" \
  QELI_ROAMING_UDP_WIRE_MODE="$mode" \
    "$RUNNER" "$BIN" soak
  echo "$marker"
}

run_mode quic "$REPRESENTATIVE_ITERATIONS" "ROAMING_UDP_QUIC_REPRESENTATIVE_SOAK_$QUALIFICATION"
run_mode fake-tls "$ADAPTER_ITERATIONS" "ROAMING_UDP_FAKE_TLS_ADAPTER_SOAK_$QUALIFICATION"
run_mode obfs "$ADAPTER_ITERATIONS" "ROAMING_UDP_OBFS_ADAPTER_SOAK_$QUALIFICATION"
run_mode obfs-awg "$ADAPTER_ITERATIONS" "ROAMING_UDP_OBFS_AWG_ADAPTER_SOAK_$QUALIFICATION"
echo "ROAMING_UDP_RESOURCE_SOAK_MATRIX_$QUALIFICATION"

#!/usr/bin/env bash
# Release performance comparison for the exact same TCP carrier with negotiated roaming on/off.
# The gate uses medians and fails when either direction loses more than the configured budget or
# combined qeli client+server CPU grows beyond that same relative budget.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
WIRE_MODE=${2:-${QELI_ROAMING_TCP_WIRE_MODE:-fake-tls}}
MAX_REGRESSION_PERCENT=${QELI_ROAMING_PERF_MAX_REGRESSION_PERCENT:-5}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
WORK=/tmp/qeli-roaming-perf-gate-${WIRE_MODE}
BASE_RUNNER=$SCRIPT_DIR/roaming_netns_e2e.sh

case "$WIRE_MODE" in
  fake-tls|reality-tls|plain|obfs-ws|obfs-none|obfs-awg) ;;
  *)
    echo "unsupported TCP wire mode: $WIRE_MODE" >&2
    exit 2
    ;;
esac

case "$MAX_REGRESSION_PERCENT" in
  ''|*[!0-9.]*|.*|*.*.*)
    echo "QELI_ROAMING_PERF_MAX_REGRESSION_PERCENT must be a non-negative number" >&2
    exit 2
    ;;
esac
if ! awk -v value="$MAX_REGRESSION_PERCENT" 'BEGIN { exit !(value >= 0 && value <= 100) }'; then
  echo "QELI_ROAMING_PERF_MAX_REGRESSION_PERCENT must be between 0 and 100" >&2
  exit 2
fi
if [ ! -x "$BASE_RUNNER" ]; then
  echo "required roaming runner is missing or not executable: $BASE_RUNNER" >&2
  exit 2
fi
mkdir -p "$WORK"
rm -f "$WORK"/*.log

run_variant() {
  local policy=$1 server_enabled=$2 output_file=$3
  QELI_ROAMING_SERVER_ENABLED="$server_enabled" \
  QELI_ROAMING_CLIENT_POLICY="$policy" \
    "$BASE_RUNNER" "$BIN" perf "$WIRE_MODE" | tee "$output_file"
}

echo "=== roaming-off baseline ==="
if ! run_variant off false "$WORK/off.log"; then
  echo "FAIL: roaming-off performance baseline failed" >&2
  exit 1
fi
echo "=== negotiated roaming-required sample ==="
if ! run_variant required true "$WORK/required.log"; then
  echo "FAIL: roaming-required performance sample failed" >&2
  exit 1
fi

field() {
  local name=$1 file=$2
  awk -v name="$name" '
    /^QELI_ROAMING_PERF_RESULT / {
      for (i = 1; i <= NF; i++) {
        split($i, pair, "=")
        if (pair[1] == name) value = pair[2]
      }
    }
    END { print value }
  ' "$file"
}

off_up=$(field upload_mbps "$WORK/off.log")
off_down=$(field download_mbps "$WORK/off.log")
off_cpu=$(field cpu_percent "$WORK/off.log")
required_up=$(field upload_mbps "$WORK/required.log")
required_down=$(field download_mbps "$WORK/required.log")
required_cpu=$(field cpu_percent "$WORK/required.log")
for value in "$off_up" "$off_down" "$off_cpu" "$required_up" "$required_down" "$required_cpu"; do
  if ! awk -v value="$value" 'BEGIN { exit !(value + 0 > 0) }'; then
    echo "FAIL: performance runner did not emit a positive numeric result" >&2
    exit 1
  fi
done

PASS=0
FAIL=0
compare_floor() {
  local label=$1 baseline=$2 candidate=$3
  if awk -v baseline="$baseline" -v candidate="$candidate" -v budget="$MAX_REGRESSION_PERCENT" \
      'BEGIN { exit !(candidate >= baseline * (1 - budget / 100.0)) }'; then
    echo "  PASS  $label baseline=$baseline candidate=$candidate"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label baseline=$baseline candidate=$candidate"
    FAIL=$((FAIL + 1))
  fi
}
compare_ceiling() {
  local label=$1 baseline=$2 candidate=$3
  if awk -v baseline="$baseline" -v candidate="$candidate" -v budget="$MAX_REGRESSION_PERCENT" \
      'BEGIN { exit !(candidate <= baseline * (1 + budget / 100.0)) }'; then
    echo "  PASS  $label baseline=$baseline candidate=$candidate"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label baseline=$baseline candidate=$candidate"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== roaming performance comparison (budget ${MAX_REGRESSION_PERCENT}%) ==="
compare_floor "upload throughput regression is within budget" "$off_up" "$required_up"
compare_floor "download throughput regression is within budget" "$off_down" "$required_down"
compare_ceiling "combined qeli CPU regression is within budget" "$off_cpu" "$required_cpu"
echo "=== RESULT: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi

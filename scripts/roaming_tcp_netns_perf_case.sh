# shellcheck shell=bash
# Sourced by roaming_netns_e2e.sh. Measures the same live tunnel without changing paths so the
# wrapper can compare a negotiated roaming session with a byte-compatible roaming-off baseline.

qeli_cpu_ticks() {
  local ns=$1 pid comm ticks total=0
  for pid in $(ip netns pids "$ns" 2>/dev/null); do
    if ! comm=$(cat "/proc/$pid/comm" 2>/dev/null); then
      continue
    fi
    if [ "$comm" != qeli ]; then
      continue
    fi
    ticks=$(awk '{ print $14 + $15 }' "/proc/$pid/stat" 2>/dev/null || true)
    case "$ticks" in
      ''|*[!0-9]*) continue ;;
    esac
    total=$((total + ticks))
  done
  echo "$total"
}

median_sample() {
  local -n source_values=$1
  local -a sorted_values
  mapfile -t sorted_values < <(printf '%s\n' "${source_values[@]}" | sort -n)
  echo "${sorted_values[$((${#sorted_values[@]} / 2))]}"
}

run_tcp_perf_case() {
  local rounds=${QELI_ROAMING_PERF_ROUNDS:-3}
  local duration=${QELI_ROAMING_PERF_DURATION_SECS:-20}
  case "$rounds:$duration" in
    *[!0-9:]*|0:*|*:0)
      echo "QELI_ROAMING_PERF_ROUNDS and QELI_ROAMING_PERF_DURATION_SECS must be positive integers" >&2
      return 2
      ;;
  esac
  if [ $((rounds % 2)) -ne 1 ]; then
    echo "QELI_ROAMING_PERF_ROUNDS must be odd so the median is unambiguous" >&2
    return 2
  fi
  if [ "$duration" -lt 5 ]; then
    echo "QELI_ROAMING_PERF_DURATION_SECS must be at least 5" >&2
    return 2
  fi
  if ! command -v iperf3 >/dev/null 2>&1; then
    echo "iperf3 is required for the roaming performance gate" >&2
    return 2
  fi

  local clock_ticks
  clock_ticks=$(getconf CLK_TCK)
  case "$clock_ticks" in
    ''|*[!0-9]*|0)
      echo "could not determine CLK_TCK for roaming performance sampling" >&2
      return 2
      ;;
  esac

  local -a upload_samples=() download_samples=() cpu_samples=()
  local round direction reverse_flag output rate round_cpu_sum round_cpu_average
  local start_ticks end_ticks start_ns end_ns delta_ticks elapsed_ns cpu
  round=1
  while [ "$round" -le "$rounds" ]; do
    round_cpu_sum=0
    for direction in upload download; do
      reverse_flag=
      if [ "$direction" = download ]; then
        reverse_flag=-R
      fi
      ip netns exec "$SRV_NS" iperf3 -s -1 -B 10.88.0.1 -p 5201 \
        >"$WORK/iperf-${direction}-${round}-server.log" 2>&1 &
      LOAD_JOB_PID=$!
      if ! wait_for 50 "ip netns exec $SRV_NS ss -lnt | grep -q ':5201'"; then
        bad "performance $direction round $round server did not listen"
        return 1
      fi

      start_ticks=$(( $(qeli_cpu_ticks "$CLI_NS") + $(qeli_cpu_ticks "$SRV_NS") ))
      start_ns=$(date +%s%N)
      if ! output=$(ip netns exec "$CLI_NS" timeout $((duration + 15)) \
          iperf3 -c 10.88.0.1 -p 5201 -t "$duration" -O 2 -i 0 -f m $reverse_flag 2>&1); then
        printf '%s\n' "$output" >"$WORK/iperf-${direction}-${round}-client.log"
        bad "performance $direction round $round completed"
        return 1
      fi
      end_ns=$(date +%s%N)
      end_ticks=$(( $(qeli_cpu_ticks "$CLI_NS") + $(qeli_cpu_ticks "$SRV_NS") ))
      printf '%s\n' "$output" >"$WORK/iperf-${direction}-${round}-client.log"
      wait "$LOAD_JOB_PID" 2>/dev/null || true
      LOAD_JOB_PID=

      rate=$(printf '%s\n' "$output" | awk '$NF == "receiver" { value=$(NF-2) } END { print value }')
      if ! awk -v value="$rate" 'BEGIN { exit !(value + 0 > 0) }'; then
        bad "performance $direction round $round produced a receiver rate"
        return 1
      fi
      delta_ticks=$((end_ticks - start_ticks))
      elapsed_ns=$((end_ns - start_ns))
      cpu=$(awk -v ticks="$delta_ticks" -v hz="$clock_ticks" -v ns="$elapsed_ns" \
        'BEGIN { printf "%.3f", (ticks * 100000000000.0) / (hz * ns) }')
      if [ "$direction" = upload ]; then
        upload_samples+=("$rate")
      else
        download_samples+=("$rate")
      fi
      round_cpu_sum=$(awk -v total="$round_cpu_sum" -v sample="$cpu" \
        'BEGIN { printf "%.3f", total + sample }')
      echo "  PERF  policy=$CLIENT_ROAMING_POLICY direction=$direction round=$round/$rounds throughput_mbps=$rate cpu_percent=$cpu"
    done
    round_cpu_average=$(awk -v total="$round_cpu_sum" 'BEGIN { printf "%.3f", total / 2.0 }')
    cpu_samples+=("$round_cpu_average")
    round=$((round + 1))
  done

  local upload_median download_median cpu_median
  upload_median=$(median_sample upload_samples)
  download_median=$(median_sample download_samples)
  cpu_median=$(median_sample cpu_samples)
  check "performance sampling preserved the same process and tunnel" \
    "ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qrm0/ifindex)\" = '$TUN_IFINDEX'"
  check "performance sampling left the tunnel usable" \
    "ip netns exec $CLI_NS ping -c3 -W1 10.88.0.1"
  check "performance sampling did not reconnect" \
    "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"
  echo "QELI_ROAMING_PERF_RESULT policy=$CLIENT_ROAMING_POLICY server_enabled=$SERVER_ROAMING_ENABLED upload_mbps=$upload_median download_mbps=$download_median cpu_percent=$cpu_median rounds=$rounds duration_secs=$duration"
}

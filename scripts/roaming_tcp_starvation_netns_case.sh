# shellcheck shell=bash
# One blackholed outer carrier must not stop healthy inner UDP flows.
run_bonded_starvation_direction() {
  local direction=$1 port=$2 source_ns=$CLI_NS echo_ns=$SRV_NS reverse= input=qrm-ar output=qrm-sr sport=$2 dport=4443
  if [ "$direction" = download ]; then
    source_ns=$SRV_NS; echo_ns=$CLI_NS; reverse=--reverse
    input=qrm-sr; output=qrm-ar; sport=4443; dport=$port
  fi
  ip netns exec "$echo_ns" python3 "$SCRIPT_DIR/roaming_bonding_udp_probe.py" server --seconds 30 $reverse \
    >"$WORK/starvation-$direction-echo-server.log" 2>&1 &
  LOAD_JOB_PID=$!
  sleep 1
  ip netns exec "$source_ns" timeout 8 python3 "$SCRIPT_DIR/roaming_bonding_udp_probe.py" probe --seconds 3 $reverse \
    >"$WORK/starvation-$direction-baseline.log" || return 1
  check "sixteen $direction echo flows work before a carrier is stalled" \
    "python3 -c 'import json; v=json.load(open(\"$WORK/starvation-$direction-baseline.log\")); assert v[\"distinct_echo_flows\"]==16 and v[\"received\"]>=300'"
  ip netns exec "$RTR_NS" iptables -I FORWARD -i "$input" -o "$output" -p tcp --sport "$sport" --dport "$dport" -j DROP || return 1
  check "only one outer $direction carrier is blackholed" \
    "ip netns exec $RTR_NS iptables -C FORWARD -i $input -o $output -p tcp --sport $sport --dport $dport -j DROP"
  ip netns exec "$source_ns" timeout 15 python3 "$SCRIPT_DIR/roaming_bonding_udp_probe.py" flood-probe --seconds 10 $reverse \
    >"$WORK/starvation-$direction-impaired.log" || return 1
  check "healthy $direction flows progress after the blocked carrier fills its queue" \
    "python3 -c 'import json; v=json.load(open(\"$WORK/starvation-$direction-impaired.log\")); assert v[\"last_half_received\"]>=40'"
  ip netns exec "$RTR_NS" iptables -D FORWARD -i "$input" -o "$output" -p tcp --sport "$sport" --dport "$dport" -j DROP || return 1
  check "$direction tunnel recovers after the selected carrier is unblocked" \
    "ip netns exec $CLI_NS ping -c5 -W2 10.88.0.1 && ip netns exec $SRV_NS ping -c5 -W2 10.88.0.2"
  kill "$LOAD_JOB_PID" 2>/dev/null || true
  wait "$LOAD_JOB_PID" 2>/dev/null || true
  LOAD_JOB_PID=
}

run_tcp_starvation_case() {
  local port
  [ "$MULTIPATH_MODE" = fixed ] || return 2
  port=$(sed -n 's/.*Stream #1 JOINed session.*from 10\.40\.1\.2:\([0-9][0-9]*\).*/\1/p' "$WORK/server.log" | tail -n1)
  case "$port" in ''|*[!0-9]*) return 2;; esac
  run_bonded_starvation_direction upload "$port" || return 1
  run_bonded_starvation_direction download "$port" || return 1
  check "bounded flood did not replace the client process or TUN" \
    "ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qrm0/ifindex)\" = '$TUN_IFINDEX'"
}

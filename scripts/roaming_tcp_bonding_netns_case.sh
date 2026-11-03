# shellcheck shell=bash
# Private namespace qualification of shared caps and one-carrier failure.
# Loaded only by roaming_netns_e2e.sh; no host sockets, routes or services are touched.

bonding_rate_probe() {
  local direction=$1 phase=${2:-baseline} reverse= result
  result="$WORK/bonding-$direction-$phase.log"
  if [ "$direction" = download ]; then reverse=-R; fi
  ip netns exec "$SRV_NS" iperf3 -s -1 -B 10.88.0.1 -p 5201 >"$WORK/bonding-$direction-$phase-server.log" 2>&1 &
  LOAD_JOB_PID=$!
  sleep 1
  if ! ip netns exec "$CLI_NS" timeout 35 iperf3 -c 10.88.0.1 -p 5201 -P 8 -t 12 -O 2 -J $reverse >"$result" 2>&1; then
    bad "eight inner flows completed $direction under the shared cap"
    return 1
  fi
  wait "$LOAD_JOB_PID" 2>/dev/null || true
  LOAD_JOB_PID=
  # Receiver goodput permits 25% timing/burst overhead, but rejects a 3x cap.
  # A floor also rejects a stalled tunnel that would trivially pass the upper bound.
  if python3 - "$result" >"$WORK/bonding-$direction-$phase-rate.log" <<'PY'
import json, math, sys
from pathlib import Path
v = json.loads(Path(sys.argv[1]).read_text())
assert not v.get('error'), v.get('error')
assert len(v['end']['streams']) == 8, 'eight completed inner streams required'
rate = v['end']['sum_received']['bits_per_second']
assert isinstance(rate, (int, float)) and math.isfinite(rate)
print(f'receiver_goodput_mbps={rate / 1e6:.6f}; configured_mbps=8; inner_flows=8')
assert 1_000_000 <= rate <= 10_000_000, rate
PY
  then
    ok "eight $direction flows share one 8 Mbps cap without starvation"
  else
    bad "eight $direction flows escaped the aggregate cap or stalled"
  fi
}

run_tcp_bonding_case() {
  local port= before_joins expected_streams=1
  if [ "$MULTIPATH_MODE" = fixed ]; then
    expected_streams=$MULTIPATH_MAX_STREAMS
  elif [ "$MULTIPATH_MODE" = adaptive ]; then
    expected_streams=$(sed -n 's/.*Multipath adaptive: ramped to \([0-9][0-9]*\) stream.*/\1/p' "$WORK/client.log" | tail -n1)
    expected_streams=${expected_streams:-1}
  fi
  if [ "$expected_streams" -gt 1 ]; then
    port=$(sed -n 's/.*Stream #1 JOINed session.*from 10\.40\.1\.2:\([0-9][0-9]*\).*/\1/p' "$WORK/server.log" | tail -n1)
    case "$port" in ''|*[!0-9]*) bad "secondary socket tuple was identified"; return 1;; esac
    before_joins=$(grep -c 'Stream #1 JOINed session' "$WORK/server.log")
    check "secondary socket tuple exists in the private server namespace" \
      "ip netns exec $SRV_NS ss -Htn state established '( sport = :4443 and dport = :$port )' | grep -q '10.40.1.2:$port'"
    check "only the selected secondary socket was reset" \
      "ip netns exec $SRV_NS ss -K dst 10.40.1.2 dport = :$port sport = :4443"
    check "healthy carriers keep bidirectional traffic during secondary replacement" \
      "ip netns exec $CLI_NS ping -c5 -W1 10.88.0.1 && ip netns exec $SRV_NS ping -c5 -W1 10.88.0.2"
    if wait_for 100 "test \"\$(grep -c 'Stream #1 JOINed session' $WORK/server.log)\" -gt '$before_joins'"; then
      ok "failed secondary logical slot was authenticated again"
    else
      bad "failed secondary logical slot was not restored"
    fi
    if wait_for 100 "grep -Eq 'TCP stream slot 1 resumed; $expected_streams/$expected_streams stream' $WORK/client.log"; then
      ok "one-carrier failure restored the original width"
    else
      bad "one-carrier failure changed the desired width"
    fi
  fi
  check "the private control socket sets the shared session limit" \
    "'$BIN' set-bandwidth roam-user 8 --socket '$ROAMING_CONTROL_SOCKET' >'$WORK/bandwidth-control.log' && ! grep -q '^Error:' '$WORK/bandwidth-control.log'"
  bonding_rate_probe upload || return 1
  bonding_rate_probe download || return 1
  # Make one carrier lossy; delay the reverse link to model asymmetric RTT.
  # Other carriers retain their own independent TCP congestion/record state.
  if [ "$expected_streams" -gt 1 ]; then
    port=$(sed -n 's/.*Stream #1 JOINed session.*from 10\.40\.1\.2:\([0-9][0-9]*\).*/\1/p' "$WORK/server.log" | tail -n1)
    ip netns exec "$RTR_NS" iptables -I FORWARD -i qrm-ar -o qrm-sr -p tcp --sport "$port" --dport 4443 \
      -m statistic --mode random --probability 0.15 -j DROP || return 1
    check "loss affects only the selected secondary carrier" \
      "ip netns exec $RTR_NS iptables -C FORWARD -i qrm-ar -o qrm-sr -p tcp --sport $port --dport 4443 -m statistic --mode random --probability 0.15 -j DROP"
    if ip netns exec "$RTR_NS" tc qdisc add dev qrm-ar root netem delay 60ms 10ms; then
      ok "reverse-link delay creates asymmetric RTT"
    else
      bad "reverse-link asymmetric delay could not be installed"
      return 1
    fi
    # Bound the impairment itself: iperf control can be pinned to this lossy
    # carrier too, so restore it before expecting its final result exchange.
    (
      sleep 18
      ip netns exec "$RTR_NS" iptables -D FORWARD -i qrm-ar -o qrm-sr -p tcp --sport "$port" --dport 4443 \
        -m statistic --mode random --probability 0.15 -j DROP
    ) &
    FAULT_JOB_PID=$!
    bonding_rate_probe download impaired || return 1
    wait "$FAULT_JOB_PID" || return 1
    FAULT_JOB_PID=
    ip netns exec "$RTR_NS" tc qdisc del dev qrm-ar root || return 1

  fi
  check "all probes retained the original process and TUN" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qrm0/ifindex)\" = '$TUN_IFINDEX'"
  check "one logical AUTH owns every bonded carrier" \
    "test \"\$(grep -c 'bandwidth_limit: .*streams<=' $WORK/server.log)\" -eq 1 && ! grep -q 'Reconnecting in' $WORK/client.log"
  check "administrative revocation disables the private test user" \
    "'$BIN' disable-user roam-user --socket '$ROAMING_CONTROL_SOCKET' >'$WORK/revoke-control.log' && ! grep -q '^Error:' '$WORK/revoke-control.log'"
  if wait_for 100 "test \"\$(python3 '$SCRIPT_DIR/roaming_control_stats.py' '$ROAMING_CONTROL_SOCKET' roam tcp active_sessions)\" = 0"; then
    ok "revocation removed the entire session rather than one stream"
  else
    bad "revocation retained a bonded session"
  fi
  if wait_for 100 "! ip netns exec $SRV_NS ss -Htn state established '( sport = :4443 )' | grep -q '10.40.1.2:'"; then
    ok "revocation released every test carrier socket"
  else
    bad "revocation retained a test carrier socket"
  fi
}

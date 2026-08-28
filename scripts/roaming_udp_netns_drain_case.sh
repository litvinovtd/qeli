# Sourced by roaming_udp_netns_e2e.sh for the deterministic previous-path drain gate.
# The parent owns namespace setup, process cleanup, counters, and final result reporting.
run_drain_reorder_case() {
  if wait_for 100 "grep -q 'UDP path probe: inner MTU .* uplink UDP payload budget 1161' $WORK/client.log"; then
    ok "path A certified the 1280-byte uplink ceiling before drain"
  else
    bad "path A did not certify the expected uplink ceiling"
  fi
  if wait_for 100 "grep -q 'client at 10.41.1.2:.*reverse-probe certified UDP downlink budget 1161' $WORK/server.log"; then
    ok "path A certified the 1280-byte downlink ceiling before drain"
  else
    bad "path A did not certify the expected downlink ceiling"
  fi

  ip netns exec "$CLI_NS" iptables -I INPUT 1 -i qru-a -p udp --sport 4444 \
    -m length --length 1100:1280 -j ACCEPT
  ip netns exec "$CLI_NS" iptables -I INPUT 1 -i qru-a -p udp --sport 4444 \
    -m length --length 200:1099 -j ACCEPT
  ip netns exec "$SRV_NS" iptables -I INPUT 1 -i qru-s -p udp --dport 4444 \
    -m length --length 1100:1280 -j ACCEPT
  ip netns exec "$SRV_NS" iptables -I INPUT 1 -i qru-s -p udp --dport 4444 \
    -m length --length 200:1099 -j ACCEPT
  ip netns exec "$CLI_NS" tc qdisc replace dev qru-a root netem \
    delay 3000ms reorder 100% gap 2
  ip netns exec "$RTR_NS" tc qdisc replace dev qru-ar root netem \
    delay 3000ms reorder 100% gap 2
  check "old path applies deterministic bidirectional delay and gap reordering" \
    "ip netns exec $CLI_NS tc qdisc show dev qru-a | grep -Eq 'delay 3s.*reorder 100%.*gap 2' && ip netns exec $RTR_NS tc qdisc show dev qru-ar | grep -Eq 'delay 3s.*reorder 100%.*gap 2'"

  ip netns exec "$CLI_NS" ping -M do -s 1350 -c1 -W10 10.89.0.1 \
    >"$WORK/drain-uplink.log" 2>&1 &
  DRAIN_UP_PID=$!
  ip netns exec "$SRV_NS" ping -M do -s 1350 -c1 -W10 10.89.0.2 \
    >"$WORK/drain-downlink.log" 2>&1 &
  DRAIN_DOWN_PID=$!

  if wait_for 10 "test \"\$(rule_packets $CLI_NS '--sport 4444' '200:1099')\" -ge 1 && test \"\$(rule_packets $SRV_NS '--dport 4444' '200:1099')\" -ge 1"; then
    ok "later fragments overtook the delayed first fragments in both directions"
  else
    bad "deterministic gap reordering did not expose both later fragments"
  fi
  check "first large fragments are still delayed before PATH_COMMIT" \
    "test \"\$(rule_packets $CLI_NS '--sport 4444' '1100:1280')\" -eq 0 && test \"\$(rule_packets $SRV_NS '--dport 4444' '1100:1280')\" -eq 0"

  ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 50
  # The observer intentionally requires two stable one-second samples. Give it a bounded five
  # seconds; the independent pending-process and fragment-counter assertions below still prove
  # that COMMIT happened before either delayed first fragment was released.
  if wait_for 25 "grep -q 'UDP make-before-break committed candidate' $WORK/client.log"; then
    ok "path B committed while old DATA_FRAG records were incomplete"
  else
    bad "path B did not commit within the bounded observer window"
  fi
  check "both fragmented pings remain pending across commit" \
    "kill -0 '$DRAIN_UP_PID' && kill -0 '$DRAIN_DOWN_PID'"
  check "delayed first fragments had not reached either receiver at commit" \
    "test \"\$(rule_packets $CLI_NS '--sport 4444' '1100:1280')\" -eq 0 && test \"\$(rule_packets $SRV_NS '--dport 4444' '1100:1280')\" -eq 0"

  if wait "$DRAIN_UP_PID"; then
    ok "server receive drain completed the reordered old-path uplink record"
  else
    bad "server receive drain lost the old-path uplink record"
  fi
  DRAIN_UP_PID=
  if wait "$DRAIN_DOWN_PID"; then
    ok "client receive drain completed the reordered old-path downlink record"
  else
    bad "client receive drain lost the old-path downlink record"
  fi
  DRAIN_DOWN_PID=
  check "delayed first fragments crossed old path A after commit" \
    "test \"\$(rule_packets $CLI_NS '--sport 4444' '1100:1280')\" -ge 1 && test \"\$(rule_packets $SRV_NS '--dport 4444' '1100:1280')\" -ge 1"

  ip netns exec "$CLI_NS" tc qdisc del dev qru-a root 2>/dev/null || true
  ip netns exec "$RTR_NS" tc qdisc del dev qru-ar root 2>/dev/null || true
  if wait_for 100 "grep -q 'UDP live PMTU widened uplink payload budget to 1161' $WORK/client.log"; then
    ok "committed path B certified its uplink DATA_FRAG budget"
  else
    bad "path B uplink PMTU certification did not complete"
  fi
  if wait_for 100 "grep -q 'client at 10.41.2.2:.*reverse-probe certified UDP downlink budget 1161' $WORK/server.log"; then
    ok "committed path B certified its downlink DATA_FRAG budget"
  else
    bad "path B downlink PMTU certification did not complete"
  fi

  ip netns exec "$CLI_NS" iptables -I INPUT 1 -i qru-b -p udp --sport 4444 \
    -m length --length 1100:1280 -j ACCEPT
  ip netns exec "$SRV_NS" iptables -I INPUT 1 -i qru-s -p udp --dport 4444 \
    -m length --length 1100:1280 -j ACCEPT
  ip netns exec "$CLI_NS" tc qdisc replace dev qru-b root netem duplicate 100%
  ip netns exec "$RTR_NS" tc qdisc replace dev qru-br root netem duplicate 100%
  check "active path B duplicates every outer fragment in both directions" \
    "ip netns exec $CLI_NS tc qdisc show dev qru-b | grep -q 'duplicate 100%' && ip netns exec $RTR_NS tc qdisc show dev qru-br | grep -q 'duplicate 100%'"
  check "duplicate DATA_FRAG remains idempotent client to server" \
    "ip netns exec $CLI_NS ping -M do -s 1350 -c3 -W3 10.89.0.1"
  check "duplicate DATA_FRAG remains idempotent server to client" \
    "ip netns exec $SRV_NS ping -M do -s 1350 -c3 -W3 10.89.0.2"
  check "both receivers observed duplicated full-size fragments" \
    "test \"\$(rule_packets $CLI_NS '--sport 4444' '1100:1280')\" -ge 2 && test \"\$(rule_packets $SRV_NS '--dport 4444' '1100:1280')\" -ge 2"

  check "receive-drain handover preserves process and TUN" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "receive-drain handover leaves carrier bypass on path B" \
    "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.2.1 dev qru-b'"
  check "delay, reorder, and duplicate do not enter the reconnect loop" \
    "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"
}

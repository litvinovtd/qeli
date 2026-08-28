# Sourced by roaming_udp_netns_e2e.sh for deterministic DATA_FRAG loss across handover.
# The parent owns namespace setup, process cleanup, counters, and final result reporting.
run_frag_loss_case() {
  if wait_for 100 "grep -q 'UDP path probe: inner MTU .* uplink UDP payload budget 1161' $WORK/client.log"; then
    ok "path A certified the 1280-byte uplink ceiling before fragment loss"
  else
    bad "path A did not certify the expected uplink ceiling"
  fi
  if wait_for 100 "grep -q 'client at 10.41.1.2:.*reverse-probe certified UDP downlink budget 1161' $WORK/server.log"; then
    ok "path A certified the 1280-byte downlink ceiling before fragment loss"
  else
    bad "path A did not certify the expected downlink ceiling"
  fi

  # PMTU is already certified, so the first matching 1100..1280-byte datagram is a full-size
  # DATA_FRAG. The huge nth period makes each DROP deterministic and effectively one-shot.
  # The following ACCEPT rules count the smaller tail fragments that leave an incomplete record.
  ip netns exec "$CLI_NS" iptables -I INPUT 1 -i qru-a -p udp --sport 4444 \
    -m length --length 1100:1280 \
    -m statistic --mode nth --every 100000 --packet 0 -j DROP
  ip netns exec "$CLI_NS" iptables -I INPUT 2 -i qru-a -p udp --sport 4444 \
    -m length --length 200:1099 -j ACCEPT
  ip netns exec "$SRV_NS" iptables -I INPUT 1 -i qru-s -p udp --dport 4444 \
    -m length --length 1100:1280 \
    -m statistic --mode nth --every 100000 --packet 0 -j DROP
  ip netns exec "$SRV_NS" iptables -I INPUT 2 -i qru-s -p udp --dport 4444 \
    -m length --length 200:1099 -j ACCEPT
  check "one-shot downlink DATA_FRAG loss rule is active" \
    "ip netns exec $CLI_NS iptables -C INPUT -i qru-a -p udp --sport 4444 -m length --length 1100:1280 -m statistic --mode nth --every 100000 --packet 0 -j DROP"
  check "one-shot uplink DATA_FRAG loss rule is active" \
    "ip netns exec $SRV_NS iptables -C INPUT -i qru-s -p udp --dport 4444 -m length --length 1100:1280 -m statistic --mode nth --every 100000 --packet 0 -j DROP"

  ip netns exec "$CLI_NS" ping -M do -s 1350 -c1 -W3 10.89.0.1 \
    >"$WORK/frag-loss-uplink.log" 2>&1 &
  DRAIN_UP_PID=$!
  ip netns exec "$SRV_NS" ping -M do -s 1350 -c1 -W3 10.89.0.2 \
    >"$WORK/frag-loss-downlink.log" 2>&1 &
  DRAIN_DOWN_PID=$!

  if wait_for 25 "test \"\$(rule_packets $CLI_NS '--sport 4444' '1100:1280')\" -eq 1 && test \"\$(rule_packets $SRV_NS '--dport 4444' '1100:1280')\" -eq 1"; then
    ok "exactly one full-size fragment was dropped in each direction"
  else
    bad "one-shot rules did not drop the expected full-size fragments"
  fi
  check "both receivers retained a later tail fragment" \
    "test \"\$(rule_packets $CLI_NS '--sport 4444' '200:1099')\" -ge 1 && test \"\$(rule_packets $SRV_NS '--dport 4444' '200:1099')\" -ge 1"
  if wait "$DRAIN_UP_PID"; then
    bad "uplink record unexpectedly completed after a full-size fragment was lost"
  else
    ok "incomplete uplink DATA_FRAG record was not delivered"
  fi
  DRAIN_UP_PID=
  if wait "$DRAIN_DOWN_PID"; then
    bad "downlink record unexpectedly completed after a full-size fragment was lost"
  else
    ok "incomplete downlink DATA_FRAG record was not delivered"
  fi
  DRAIN_DOWN_PID=

  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 220 -W1 10.89.0.1 \
    >"$WORK/frag-loss-continuous.log" 2>&1 &
  PING_PID=$!
  ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 50
  if wait_for 150 "grep -q 'UDP make-before-break committed candidate' $WORK/client.log"; then
    ok "path B committed while both old DATA_FRAG records were incomplete"
  else
    bad "path B did not commit after deterministic fragment loss"
  fi
  check "carrier bypass moved to path B without a stale path-A route" \
    "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.2.1 dev qru-b' && ! ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q 'dev qru-a'"
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

  # Let the five-second reassembly and old-receive drain windows expire. A new fragmented record
  # invokes bounded cleanup before allocation and must complete independently on active path B.
  sleep 6
  ip netns exec "$CLI_NS" ip link set qru-a down
  check "active path survives removal of the old fragment-loss path" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "a later fragmented uplink record succeeds after incomplete-record expiry" \
    "ip netns exec $CLI_NS ping -M do -s 1350 -c3 -W3 10.89.0.1"
  check "a later fragmented downlink record succeeds after incomplete-record expiry" \
    "ip netns exec $SRV_NS ping -M do -s 1350 -c3 -W3 10.89.0.2"
  check "one-shot rules dropped no second full-size fragment" \
    "test \"\$(rule_packets $CLI_NS '--sport 4444' '1100:1280')\" -eq 1 && test \"\$(rule_packets $SRV_NS '--dport 4444' '1100:1280')\" -eq 1"
  check "fragment-loss handover preserves process and TUN" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "fragment loss and expiry do not enter the reconnect loop" \
    "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

  wait "$PING_PID" 2>/dev/null || true
  PING_PID=
  PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
    "$WORK/frag-loss-continuous.log" | tail -n1)
  check "continuous probe retained at least 205 of 220 packets across loss and handover" \
    "test -n '$PING_RX' && test '$PING_RX' -ge 205"
}

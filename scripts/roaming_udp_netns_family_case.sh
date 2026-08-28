# Sourced by roaming_udp_netns_e2e.sh for the dual-listener outer-family gate.
# The parent owns namespace setup, process cleanup, counters, and final result reporting.
run_family_switch_case() {
  check "client namespace resolves both generation-scoped server families" \
    "ip netns exec $CLI_NS getent ahostsv4 roam-family.qeli.test | grep -q '10.41.3.2' && ip netns exec $CLI_NS getent ahostsv6 roam-family.qeli.test | grep -q 'fd41:3::2'"
  check "epoch zero authenticated over IPv4 path A" \
    "grep -q 'client at 10.41.1.2:' $WORK/server.log"

  INITIAL_V4_UP=$(grep -c 'UDP live PMTU widened uplink payload budget to 1461 bytes' "$WORK/client.log" || true)
  INITIAL_V4_DOWN=$(grep -c 'client at 10.41.1.2:.*reverse-probe certified UDP downlink budget 1461 bytes' "$WORK/server.log" || true)
  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 260 -W1 10.89.0.1 >"$WORK/family-ping.log" 2>&1 &
  PING_PID=$!

  # Keep the authenticated IPv4 carrier alive through its exact /32 while removing only the
  # physical IPv4 default. The observer must therefore choose the retained AAAA on path B.
  ip netns exec "$CLI_NS" ip -6 route replace default via fd41:2::1 dev qru-b metric 50
  ip netns exec "$CLI_NS" ip route del default via 10.41.1.1 dev qru-a metric 100
  if wait_for 180 "grep -q 'UDP PATH_COMMIT.*to \[fd41:2::2\]:' $WORK/server.log"; then
    ok "IPv4 owner committed an authenticated IPv6 candidate on the other listener"
  else
    bad "IPv4 to IPv6 cross-listener commit did not complete"
  fi
  check "Linux observer prepared the IPv6 path B" \
    "grep -q 'Linux roaming prepared candidate .* on qru-b' $WORK/client.log"
  check "candidate socket connected to the IPv6 listener" \
    "grep -q 'UDP connected candidate .* through \[fd41:3::2\]:4444' $WORK/client.log"
  check "client published the IPv6 candidate exactly once" \
    "test \"\$(grep -c 'UDP make-before-break committed candidate' $WORK/client.log)\" -eq 1"
  check "IPv6 carrier bypass is exact and uses path B" \
    "ip netns exec $CLI_NS ip -6 route show fd41:3::2 | grep -Eq '^fd41:3::2 via fd41:2::1 dev qru-b'"
  check "committed IPv6 path removed the stale IPv4 carrier bypass" \
    "! ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q 'dev qru-a'"
  if wait_for 120 "grep -q 'UDP live PMTU widened uplink payload budget to 1341 bytes' $WORK/client.log"; then
    ok "IPv6 path re-certified the 1400-byte uplink budget"
  else
    bad "IPv6 uplink PMTU re-certification did not complete"
  fi
  if wait_for 120 "grep -q 'client at \[fd41:2::2\]:.*reverse-probe certified UDP downlink budget 1341 bytes' $WORK/server.log"; then
    ok "IPv6 path re-certified the 1400-byte downlink budget"
  else
    bad "IPv6 downlink PMTU re-certification did not complete"
  fi
  check "IPv6 carrier carries a DATA_FRAG-sized inner packet" \
    "ip netns exec $CLI_NS ping -M do -s 1350 -c3 -W3 10.89.0.1"

  ip netns exec "$CLI_NS" ip link set qru-a down
  check "tunnel survives removal of old IPv4 path A" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"

  # Restore A as a candidate while B remains the active exact /128. Deleting only the IPv6
  # default makes the observer select the retained A record without breaking current traffic.
  ip netns exec "$CLI_NS" ip link set qru-a up
  ip netns exec "$CLI_NS" ip route replace default via 10.41.1.1 dev qru-a metric 50
  ip netns exec "$CLI_NS" ip -6 route del default via fd41:2::1 dev qru-b metric 50
  if wait_for 180 "test \"\$(grep -c 'UDP PATH_COMMIT' $WORK/server.log)\" -ge 2 && grep -q 'UDP PATH_COMMIT.*to 10.41.1.2:' $WORK/server.log"; then
    ok "IPv6 owner committed the authenticated IPv4 return path"
  else
    bad "IPv6 to IPv4 cross-listener return commit did not complete"
  fi
  check "client published both family commits exactly once" \
    "test \"\$(grep -c 'UDP make-before-break committed candidate' $WORK/client.log)\" -eq 2"
  check "server published exactly two family commits" \
    "test \"\$(grep -c 'UDP PATH_COMMIT' $WORK/server.log)\" -eq 2"
  check "returned IPv4 carrier bypass is exact and uses path A" \
    "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -Eq '^10.41.3.2 via 10.41.1.1 dev qru-a'"
  check "returned IPv4 path removed the stale IPv6 carrier bypass" \
    "! ip netns exec $CLI_NS ip -6 route show fd41:3::2 | grep -q 'dev qru-b'"
  if wait_for 120 "test \"\$(grep -c 'UDP live PMTU widened uplink payload budget to 1461 bytes' $WORK/client.log)\" -gt '$INITIAL_V4_UP'"; then
    ok "returned IPv4 path independently re-certified uplink PMTU"
  else
    bad "returned IPv4 uplink PMTU re-certification did not complete"
  fi
  if wait_for 120 "test \"\$(grep -c 'client at 10.41.1.2:.*reverse-probe certified UDP downlink budget 1461 bytes' $WORK/server.log)\" -gt '$INITIAL_V4_DOWN'"; then
    ok "returned IPv4 path independently re-certified downlink PMTU"
  else
    bad "returned IPv4 downlink PMTU re-certification did not complete"
  fi

  ip netns exec "$CLI_NS" ip link set qru-b down
  check "tunnel survives removal of old IPv6 path B" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "family round-trip preserves client process and TUN" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "family round-trip does not enter the reconnect loop" \
    "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

  wait "$PING_PID" 2>/dev/null || true
  PING_PID=
  PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
    "$WORK/family-ping.log" | tail -n1)
  check "continuous probe retained at least 245 of 260 packets across both families" \
    "test -n '$PING_RX' && test '$PING_RX' -ge 245"
}

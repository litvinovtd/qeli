# Sourced by roaming_udp_netns_e2e.sh for same-network NAT dead-mapping recovery.
# The parent owns namespaces, process cleanup, counters, and final result reporting.
run_nat_rebind_case() {
  if wait_for 50 "grep -q \"UDP client 10.41.3.1:.* authenticated on profile 'roam'\" $WORK/server.log"; then
    ok "server authenticated the initial stateless NAT mapping"
  else
    bad "server did not observe the initial NAT mapping"
  fi
  check "initial NAT mapping leaves the physical and carrier routes on path A" \
    "ip netns exec $CLI_NS ip route show default | grep -q '^default via 10.41.1.1 dev qru-a metric 100' && ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.1.1 dev qru-a'"

  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 360 -W1 10.89.0.1 \
    >"$WORK/nat-rebind-continuous.log" 2>&1 &
  PING_PID=$!

  # Delete the old return rewrite first so server heartbeat/cover to 10.41.3.1 becomes dead.
  # Then publish 10.41.3.254 in both directions. The qeli socket, source address, interface,
  # default route and server endpoint do not change; only the server-observed mapping does.
  ip netns exec "$RTR_NS" tc filter del dev qru-sr ingress protocol ip pref 20
  ip netns exec "$RTR_NS" tc filter del dev qru-sr egress protocol ip pref 10
  ip netns exec "$RTR_NS" tc filter add dev qru-sr egress protocol ip pref 10 flower \
    src_ip 10.41.1.2 dst_ip 10.41.3.2 ip_proto udp dst_port 4444 \
    action pedit ex munge ip src set 10.41.3.254 pipe action csum ip and udp
  ip netns exec "$RTR_NS" tc filter add dev qru-sr ingress protocol ip pref 20 flower \
    src_ip 10.41.3.2 dst_ip 10.41.3.254 ip_proto udp src_port 4444 \
    action pedit ex munge ip dst set 10.41.1.2 pipe action csum ip and udp
  check "client address and physical default path stayed byte-for-byte stable" \
    "ip netns exec $CLI_NS ip route show default | grep -q '^default via 10.41.1.1 dev qru-a metric 100' && ip netns exec $CLI_NS ip -o addr show dev qru-a | grep -q '10.41.1.2/24'"

  if wait_for 210 "grep -q 'requesting same-network NAT rebind at epoch 0' $WORK/client.log"; then
    ok "authenticated RX silence requested one bounded same-network NAT rebind"
  else
    bad "RX liveness did not request same-network NAT recovery"
  fi
  if wait_for 50 "grep -q 'Linux roaming prepared candidate .* on qru-a (SameNetworkNatFailure)' $WORK/client.log"; then
    ok "Linux observer emitted a flagged fresh PathUpdate for the unchanged path"
  else
    bad "Linux observer did not prepare a same-network candidate"
  fi
  if wait_for 100 "grep -q 'UDP make-before-break committed candidate' $WORK/client.log"; then
    ok "same-network candidate committed through the replacement NAT mapping"
  else
    bad "same-network NAT candidate did not commit"
  fi

  check "server validated and committed the alternate external mapping" \
    "grep -q 'UDP PATH_CHALLENGE sent.*to 10.41.3.254:' $WORK/server.log && grep -q 'UDP PATH_COMMIT.*to 10.41.3.254:' $WORK/server.log"
  check "NAT recovery kept one authenticated session and one local commit" \
    "test \"\$(grep -c 'UDP client .* authenticated on profile' $WORK/server.log)\" -eq 1 && test \"\$(grep -c 'UDP make-before-break committed candidate' $WORK/client.log)\" -eq 1"
  check "NAT recovery did not manufacture a default-route change" \
    "test \"\$(grep -c 'DefaultRouteChanged' $WORK/client.log || true)\" -eq 0"
  check "carrier bypass remains exact on the unchanged path A" \
    "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.1.1 dev qru-a' && ! ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -Eq 'dev qru-(b|c)'"
  check "tunnel transfers traffic through the replacement mapping" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "same-network NAT recovery preserves process and TUN" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "same-network NAT recovery does not enter the reconnect loop" \
    "! grep -Eq 'Connection error|Reconnecting in|no authenticated data from server.*reconnecting' $WORK/client.log"

  wait "$PING_PID" 2>/dev/null || true
  PING_PID=
  PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
    "$WORK/nat-rebind-continuous.log" | tail -n1)
  check "continuous probe retained at least 170 of 360 packets across dead mapping and recovery" \
    "test -n '$PING_RX' && test '$PING_RX' -ge 170"
}

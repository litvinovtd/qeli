# shellcheck shell=bash
# Sourced by roaming_netns_e2e.sh. Path A reaches the original server process while path B is
# DNATed to a second process with the same profile identity/users but an independent registry.
# Authenticated JOIN must fail there; after path A disappears, `auto` must perform a full AUTH.

tcp_multinode_carrier_reset_rules() {
  ip netns exec "$RTR_NS" iptables "$@" FORWARD -i qrm-sr -o qrm-ar \
    -p tcp --sport 4443 -j REJECT --reject-with tcp-reset
  ip netns exec "$RTR_NS" iptables "$@" FORWARD -i qrm-ar -o qrm-sr \
    -p tcp --dport 4443 -j REJECT --reject-with tcp-reset
}

run_tcp_multinode_case() {
  local client_probe_pid server_probe_pid

  check "primary process owns exactly one initial authenticated session" \
    "test \"\$(grep -c 'bandwidth_limit: .*streams<=' $WORK/server.log || true)\" -eq 1"
  check "secondary process has no inherited authenticated session" \
    "test \"\$(grep -c 'bandwidth_limit: .*streams<=' $WORK/server-secondary.log || true)\" -eq 0"

  sleep 3
  ip netns exec "$CLI_NS" ip route replace default via 10.40.2.1 dev qrm-b metric 50
  if wait_for 150 "grep -q 'TCP make-before-break candidate .* failed: JOIN:' $WORK/client.log"; then
    ok "candidate JOIN was rejected by the independent process"
  else
    bad "candidate JOIN was not rejected by the independent process"
  fi
  check "secondary registry rejected the foreign resume locator" \
    "grep -q 'resume JOIN with unknown locator' $WORK/server-secondary.log"
  check "a foreign process never committed the original logical session" \
    "! grep -q 'TCP make-before-break committed candidate' $WORK/client.log && ! grep -q 'ROAMING transport=tcp event=commit' $WORK/server-secondary.log"

  # The original exact bypass remains deliberately usable after candidate rollback. Remove its
  # physical carrier after bidirectional RST rules have made carrier loss deterministic. A bare
  # link-down can leave either half of the established TCP socket silent until an idle reap,
  # which is longer than this gate's bounded wait and does not model an observable carrier reset.
  tcp_multinode_carrier_reset_rules -I
  check "bidirectional primary-carrier reset rules are active" \
    "tcp_multinode_carrier_reset_rules -C"
  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 100 -W1 10.88.0.1 \
    >"$WORK/multinode-client-ping.log" 2>&1 &
  client_probe_pid=$!
  ip netns exec "$SRV_NS" ping -n -i 0.2 -c 100 -W1 10.88.0.2 \
    >"$WORK/multinode-server-ping.log" 2>&1 &
  server_probe_pid=$!
  if wait_for 100 "grep -q 'lost its last TCP path.*retaining session for authenticated resume' $WORK/server.log"; then
    ok "primary process entered resume grace after carrier reset"
  else
    bad "primary process did not observe the carrier reset"
  fi
  if wait_for 100 "grep -q 'TCP stream slot 0 lost; preserving TUN during resume grace' $WORK/client.log"; then
    ok "client entered hard-resume after carrier reset"
  else
    bad "client did not observe the carrier reset"
  fi
  ip netns exec "$CLI_NS" ip link set qrm-a down
  tcp_multinode_carrier_reset_rules -D 2>/dev/null || true
  kill "$client_probe_pid" "$server_probe_pid" 2>/dev/null || true
  wait "$client_probe_pid" "$server_probe_pid" 2>/dev/null || true
  if wait_for 400 "grep -q 'bandwidth_limit: .*streams<=' $WORK/server-secondary.log && ip netns exec $CLI_NS ip -4 addr show dev qrm0 | grep -q '10.89.0.2/32'"; then
    ok "auto policy performed a full AUTH against the new process"
  else
    bad "auto policy did not complete full AUTH against the new process"
  fi

  check "fallback entered the top-level reconnect loop" \
    "grep -q 'Reconnecting in' $WORK/client.log"
  check "the client supervisor process survived the node transition" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID'"
  check "the new process assigned its own tunnel address" \
    "ip netns exec $CLI_NS ip -4 addr show dev qrm0 | grep -q '10.89.0.2/32'"
  check "the old process tunnel address was removed" \
    "! ip netns exec $CLI_NS ip -4 addr show dev qrm0 | grep -q '10.88.0.2/32'"
  check "full reconnect installed the path-B carrier bypass" \
    "ip netns exec $CLI_NS ip route show 10.40.3.2 | grep -q '^10.40.3.2 via 10.40.2.1 dev qrm-b'"
  check "the secondary tunnel carries traffic after full reconnect" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "the two processes performed one full AUTH each" \
    "test \"\$(grep -c 'bandwidth_limit: .*streams<=' $WORK/server.log || true)\" -eq 1 && test \"\$(grep -c 'bandwidth_limit: .*streams<=' $WORK/server-secondary.log || true)\" -eq 1"
  check "cross-process fallback never emitted a roaming commit" \
    "! grep -q 'TCP make-before-break committed candidate' $WORK/client.log && ! grep -q 'ROAMING transport=tcp event=commit' $WORK/server-secondary.log"
}

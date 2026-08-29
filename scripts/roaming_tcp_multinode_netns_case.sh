# shellcheck shell=bash
# Sourced by roaming_netns_e2e.sh. Path A reaches the original server process while path B is
# DNATed to a second process with the same profile identity/users but an independent registry.
# Authenticated JOIN must fail there; after path A disappears, `auto` must perform a full AUTH.

run_tcp_multinode_case() {
  check "primary process owns exactly one initial authenticated session" \
    "test \"\$(grep -c \"connected on profile 'roam'\" $WORK/server.log || true)\" -eq 1"
  check "secondary process has no inherited authenticated session" \
    "test \"\$(grep -c \"connected on profile 'roam'\" $WORK/server-secondary.log || true)\" -eq 0"

  sleep 3
  ip netns exec "$CLI_NS" ip route replace default via 10.40.2.1 dev qrm-b metric 50
  if wait_for 150 "grep -q 'TCP make-before-break candidate .* failed: JOIN rejected by server' $WORK/client.log"; then
    ok "candidate JOIN was rejected by the independent process"
  else
    bad "candidate JOIN was not rejected by the independent process"
  fi
  check "secondary registry rejected the foreign resume locator" \
    "grep -q 'resume JOIN with unknown locator' $WORK/server-secondary.log"
  check "a foreign process never committed the original logical session" \
    "! grep -q 'TCP make-before-break committed candidate' $WORK/client.log && ! grep -q 'ROAMING transport=tcp event=commit' $WORK/server-secondary.log"

  # The original exact bypass remains deliberately usable after candidate rollback. Remove its
  # physical carrier to force hard-resume expiry and the documented full reconnect fallback.
  ip netns exec "$CLI_NS" ip link set qrm-a down
  if wait_for 400 "grep -q \"connected on profile 'roam'\" $WORK/server-secondary.log && ip netns exec $CLI_NS ip -4 addr show dev qrm0 | grep -q '10.89.0.2/24'"; then
    ok "auto policy performed a full AUTH against the new process"
  else
    bad "auto policy did not complete full AUTH against the new process"
  fi

  check "fallback entered the top-level reconnect loop" \
    "grep -q 'Reconnecting in' $WORK/client.log"
  check "the client supervisor process survived the node transition" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID'"
  check "the new process assigned its own tunnel address" \
    "ip netns exec $CLI_NS ip -4 addr show dev qrm0 | grep -q '10.89.0.2/24'"
  check "the old process tunnel address was removed" \
    "! ip netns exec $CLI_NS ip -4 addr show dev qrm0 | grep -q '10.88.0.2/24'"
  check "full reconnect installed the path-B carrier bypass" \
    "ip netns exec $CLI_NS ip route show 10.40.3.2 | grep -q '^10.40.3.2 via 10.40.2.1 dev qrm-b'"
  check "the secondary tunnel carries traffic after full reconnect" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "the two processes performed one full AUTH each" \
    "test \"\$(grep -c \"connected on profile 'roam'\" $WORK/server.log || true)\" -eq 1 && test \"\$(grep -c \"connected on profile 'roam'\" $WORK/server-secondary.log || true)\" -eq 1"
  check "cross-process fallback never emitted a roaming commit" \
    "! grep -q 'TCP make-before-break committed candidate' $WORK/client.log && ! grep -q 'ROAMING transport=tcp event=commit' $WORK/server-secondary.log"
}

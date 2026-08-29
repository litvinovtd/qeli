# shellcheck shell=bash
# Sourced by roaming_netns_e2e.sh. A reverse-path TCP reset makes the server lose the live
# carrier without changing the physical route. The resume case restores the same authenticated
# session within grace; grace-expiry blocks replacement carriers until the server reaps the
# locator, then requires the ordinary full-AUTH fallback.

tcp_resume_reverse_reset_rule() {
  ip netns exec "$RTR_NS" iptables "$@" FORWARD -i qrm-sr -o qrm-ar \
    -p tcp --sport 4443 -j REJECT --reject-with tcp-reset
}

tcp_resume_block_rule() {
  ip netns exec "$RTR_NS" iptables "$@" FORWARD -i qrm-ar -o qrm-sr \
    -p tcp --dport 4443 -j DROP
}

run_tcp_resume_case() {
  local client_probe_pid server_probe_pid

  check "server can send tunnel traffic before carrier loss" \
    "ip netns exec $SRV_NS ping -c3 -W1 10.88.0.2"
  check "one full AUTH established the original logical session" \
    "test \"\$(grep -c 'bandwidth_limit: .*streams<=' $WORK/server.log || true)\" -eq 1"

  if [ "$CASE" = grace-expiry ]; then
    tcp_resume_block_rule -I
    check "replacement carriers are blackholed for the grace-expiry case" \
      "tcp_resume_block_rule -C"
  fi
  tcp_resume_reverse_reset_rule -I
  check "one-sided server-carrier reset rule is active" \
    "tcp_resume_reverse_reset_rule -C"

  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 300 -W1 10.88.0.1 \
    >"$WORK/resume-client-ping.log" 2>&1 &
  client_probe_pid=$!
  ip netns exec "$SRV_NS" ping -n -i 0.2 -c 300 -W1 10.88.0.2 \
    >"$WORK/resume-server-ping.log" 2>&1 &
  server_probe_pid=$!

  if wait_for 100 "grep -q 'lost its last TCP path.*retaining session for authenticated resume' $WORK/server.log"; then
    ok "server entered authenticated resume grace after carrier reset"
  else
    bad "server did not enter authenticated resume grace after carrier reset"
  fi
  tcp_resume_reverse_reset_rule -D 2>/dev/null || true

  if [ "$CASE" = grace-expiry ]; then
    if wait_for 100 "grep -q 'disconnected from profile.*roaming grace expired' $WORK/server.log"; then
      ok "server reaped the locator after the configured roaming grace"
    else
      bad "server did not reap the locator after the configured roaming grace"
    fi
    tcp_resume_block_rule -D 2>/dev/null || true

    if wait_for 400 "test \"\$(grep -c 'bandwidth_limit: .*streams<=' $WORK/server.log || true)\" -eq 2"; then
      ok "client used full AUTH after the resume locator expired"
    else
      bad "client did not complete full AUTH after the resume locator expired"
    fi
    check "expired locator was rejected instead of being resumed" \
      "grep -q 'resume JOIN with unknown locator' $WORK/server.log"
    check "grace expiry entered the top-level reconnect loop" \
      "grep -q 'Reconnecting in' $WORK/client.log"
    check "no authenticated resume JOIN committed after locator expiry" \
      "! grep -q 'Stream #0 JOINed session' $WORK/server.log"
    check "full reconnect restored tunnel traffic" \
      "ip netns exec $CLI_NS ping -c5 -W1 10.88.0.1"
  else
    if wait_for 150 "grep -q 'TCP stream slot 0 resumed; 1/1 stream(s) active' $WORK/client.log"; then
      ok "client resumed slot zero within server grace"
    else
      bad "client did not resume slot zero within server grace"
    fi
    check "server attached exactly one authenticated resume carrier" \
      "test \"\$(grep -c 'Stream #0 JOINed session' $WORK/server.log || true)\" -eq 1"
    check "hard resume did not repeat full AUTH" \
      "test \"\$(grep -c 'bandwidth_limit: .*streams<=' $WORK/server.log || true)\" -eq 1"
    check "hard resume preserved the client process and TUN instance" \
      "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qrm0/ifindex)\" = '$TUN_IFINDEX'"
    check "hard resume retained the exact path-A carrier bypass" \
      "ip netns exec $CLI_NS ip route show 10.40.3.2 | grep -q '^10.40.3.2 via 10.40.1.1 dev qrm-a'"
    check "hard resume never entered full reconnect or server expiry" \
      "! grep -q 'Reconnecting in' $WORK/client.log && ! grep -q 'roaming grace expired' $WORK/server.log"
    check "hard resume restored bidirectional tunnel traffic" \
      "ip netns exec $CLI_NS ping -c5 -W1 10.88.0.1 && ip netns exec $SRV_NS ping -c5 -W1 10.88.0.2"
  fi

  kill "$client_probe_pid" "$server_probe_pid" 2>/dev/null || true
  wait "$client_probe_pid" "$server_probe_pid" 2>/dev/null || true
}

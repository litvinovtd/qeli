# shellcheck shell=bash
# Sourced by roaming_udp_netns_e2e.sh for repeated same-session path migration.
# The release gate defaults to 10,000 committed A/B flips. Set
# QELI_ROAMING_SOAK_ITERATIONS to a smaller value only for harness smoke tests.
run_udp_soak_case() {
  local iterations=${QELI_ROAMING_SOAK_ITERATIONS:-10000}
  local sample_every=${QELI_ROAMING_SOAK_SAMPLE_EVERY:-100}
  case "$iterations:$sample_every" in
    *[!0-9:]*|0:*|*:0)
      echo "QELI_ROAMING_SOAK_ITERATIONS and QELI_ROAMING_SOAK_SAMPLE_EVERY must be positive integers" >&2
      return 2
      ;;
  esac

  local server_pid client_fd_before server_fd_before client_rss_before server_rss_before
  local client_fd_max server_fd_max client_rss_max server_rss_max
  server_pid=$(ip netns pids "$SRV_NS" 2>/dev/null | head -n1)
  if [ -z "$CLIENT_PID" ] || [ -z "$server_pid" ]; then
    bad "soak could not identify the live client/server processes"
    return
  fi
  client_fd_before=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  server_fd_before=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  client_rss_before=$(awk '/^VmRSS:/ { print $2 }' "/proc/$CLIENT_PID/status")
  server_rss_before=$(awk '/^VmRSS:/ { print $2 }' "/proc/$server_pid/status")
  client_fd_max=$client_fd_before
  server_fd_max=$server_fd_before
  client_rss_max=$client_rss_before
  server_rss_max=$server_rss_before

  local iteration target gateway route_pattern commit_count
  iteration=1
  while [ "$iteration" -le "$iterations" ]; do
    if [ $((iteration % 2)) -eq 1 ]; then
      target=qru-b
      gateway=10.41.2.1
      ip netns exec "$CLI_NS" ip route replace default via 10.41.1.1 dev qru-a metric 200
      ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 50
    else
      target=qru-a
      gateway=10.41.1.1
      ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 200
      ip netns exec "$CLI_NS" ip route replace default via 10.41.1.1 dev qru-a metric 50
    fi
    route_pattern="^10.41.3.2 via $gateway dev $target"

    if ! wait_for 150 "[ \"\$(grep -c 'UDP make-before-break committed candidate' $WORK/client.log || true)\" -ge $iteration ]"; then
      bad "soak iteration $iteration did not commit within the bounded wait"
      return
    fi
    if ! ip netns exec "$CLI_NS" ip route show 10.41.3.2 | grep -q "$route_pattern"; then
      bad "soak iteration $iteration left the carrier bypass off $target"
      return
    fi
    if [ "$(ip netns exec "$CLI_NS" ip route show 10.41.3.2 | wc -l)" -ne 1 ]; then
      bad "soak iteration $iteration left duplicate carrier bypass routes"
      return
    fi

    if [ $((iteration % sample_every)) -eq 0 ] || [ "$iteration" -eq "$iterations" ]; then
      if ! ip netns exec "$CLI_NS" ping -c2 -W1 10.89.0.1 >/dev/null 2>&1; then
        bad "soak traffic probe failed after iteration $iteration"
        return
      fi
      local value
      value=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
      if [ "$value" -gt "$client_fd_max" ]; then client_fd_max=$value; fi
      value=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
      if [ "$value" -gt "$server_fd_max" ]; then server_fd_max=$value; fi
      value=$(awk '/^VmRSS:/ { print $2 }' "/proc/$CLIENT_PID/status")
      if [ "$value" -gt "$client_rss_max" ]; then client_rss_max=$value; fi
      value=$(awk '/^VmRSS:/ { print $2 }' "/proc/$server_pid/status")
      if [ "$value" -gt "$server_rss_max" ]; then server_rss_max=$value; fi
      echo "  soak progress $iteration/$iterations target=$target client_fd=$client_fd_max server_fd=$server_fd_max client_rss_kib=$client_rss_max server_rss_kib=$server_rss_max"
    fi
    iteration=$((iteration + 1))
  done

  commit_count=$(grep -c 'UDP make-before-break committed candidate' "$WORK/client.log" || true)
  local server_commits auth_count client_fd_after server_fd_after client_rss_after server_rss_after
  server_commits=$(grep -c 'UDP PATH_COMMIT sent' "$WORK/server.log" || true)
  auth_count=$(grep -c 'UDP client .* authenticated on profile' "$WORK/server.log" || true)
  client_fd_after=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  server_fd_after=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  client_rss_after=$(awk '/^VmRSS:/ { print $2 }' "/proc/$CLIENT_PID/status")
  server_rss_after=$(awk '/^VmRSS:/ { print $2 }' "/proc/$server_pid/status")

  check "soak committed every requested client/server path transaction exactly once" \
    "test '$commit_count' -eq '$iterations' && test '$server_commits' -eq '$iterations'"
  check "soak retained one authenticated session without reconnect" \
    "test '$auth_count' -eq 1 && ! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"
  check "soak preserved the original process and TUN" \
    "ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "soak left one exact carrier bypass and a usable tunnel" \
    "test \"\$(ip netns exec $CLI_NS ip route show 10.41.3.2 | wc -l)\" -eq 1 && ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "soak closed superseded sockets instead of leaking file descriptors" "test '$client_fd_after' -le $((client_fd_before + 4)) && test '$server_fd_after' -le $((server_fd_before + 4)) && test '$client_fd_max' -le $((client_fd_before + 16)) && test '$server_fd_max' -le $((server_fd_before + 16))"
  check "soak kept sampled RSS growth within the 32 MiB acceptance budget" "test $((client_rss_max - client_rss_before)) -le 32768 && test $((server_rss_max - server_rss_before)) -le 32768 && test $((client_rss_after - client_rss_before)) -le 32768 && test $((server_rss_after - server_rss_before)) -le 32768"
}

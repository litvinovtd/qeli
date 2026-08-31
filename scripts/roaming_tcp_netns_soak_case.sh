# shellcheck shell=bash
# Sourced by roaming_netns_e2e.sh for repeated same-session TCP path migration.
# The standalone endurance harness defaults to 10,000 committed A/B flips. The bounded release
# certification wrapper deliberately runs 100 per representative transport; values below 100 are
# suitable only for harness smoke tests.
run_tcp_soak_case() {
  local iterations=${QELI_ROAMING_SOAK_ITERATIONS:-10000}
  local sample_every=${QELI_ROAMING_SOAK_SAMPLE_EVERY:-100}
  case "$iterations:$sample_every" in
    *[!0-9:]*|0:*|*:0)
      echo "QELI_ROAMING_SOAK_ITERATIONS and QELI_ROAMING_SOAK_SAMPLE_EVERY must be positive integers" >&2
      return 2
      ;;
  esac
  local stats_helper="$SCRIPT_DIR/roaming_control_stats.py"
  if ! command -v python3 >/dev/null 2>&1 || [ ! -r "$stats_helper" ]; then
    echo "TCP roaming soak requires python3 and $stats_helper" >&2
    return 2
  fi
  local process_probe="$SCRIPT_DIR/roaming_process_probe.sh"
  if [ ! -r "$process_probe" ]; then
    echo "TCP roaming soak requires $process_probe" >&2
    return 2
  fi
  # shellcheck source=roaming_process_probe.sh
  source "$process_probe"
  tcp_roaming_stats() {
    local line
    line=$(python3 "$stats_helper" "$WORK/control.sock" roam tcp \
      attempts_total commits_total failures_total grace_expired_total active_sessions \
      orphaned_sessions orphaned_bytes) || return
    IFS=$'\t' read -r TCP_ATTEMPTS TCP_COMMITS TCP_FAILURES TCP_GRACE TCP_SESSIONS \
      TCP_ORPHANS TCP_ORPHAN_BYTES <<<"$line"
  }

  local server_pid client_fd_before server_fd_before client_rss_before server_rss_before
  local client_start_ticks server_start_ticks
  local client_socket_before server_socket_before client_socket_max server_socket_max
  local client_fd_max server_fd_max client_rss_max server_rss_max
  local -a server_pids=()
  mapfile -t server_pids < <(ip netns pids "$SRV_NS" 2>/dev/null)
  if [ -z "$CLIENT_PID" ] \
      || ! server_pid=$(roaming_find_server_worker_pid \
        "$BIN" "$WORK/server.conf" /proc "${server_pids[@]}"); then
    bad "TCP soak could not identify the exact live client/data-plane worker processes"
    return
  fi
  client_start_ticks=$(awk '{ print $22 }' "/proc/$CLIENT_PID/stat" 2>/dev/null || true)
  server_start_ticks=$(awk '{ print $22 }' "/proc/$server_pid/stat" 2>/dev/null || true)
  if [ -z "$client_start_ticks" ] || [ -z "$server_start_ticks" ]; then
    bad "TCP soak could not record exact process start identities"
    return
  fi
  client_fd_before=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  server_fd_before=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  client_socket_before=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 -lname 'socket:*' 2>/dev/null | wc -l)
  server_socket_before=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 -lname 'socket:*' 2>/dev/null | wc -l)
  client_rss_before=$(awk '/^VmRSS:/ { print $2 }' "/proc/$CLIENT_PID/status")
  server_rss_before=$(awk '/^VmRSS:/ { print $2 }' "/proc/$server_pid/status")
  client_fd_max=$client_fd_before
  server_fd_max=$server_fd_before
  client_socket_max=$client_socket_before
  server_socket_max=$server_socket_before
  client_rss_max=$client_rss_before
  server_rss_max=$server_rss_before

  # Let the platform observer retain a stable path-A baseline before the first flip.
  sleep 3
  if ! tcp_roaming_stats \
      || [ "$TCP_ATTEMPTS:$TCP_COMMITS:$TCP_FAILURES:$TCP_GRACE:$TCP_SESSIONS:$TCP_ORPHANS:$TCP_ORPHAN_BYTES" != "0:0:0:0:1:0:0" ]; then
    bad "TCP soak did not start with one healthy session and empty transaction/orphan counters"
    return
  fi

  local iteration target gateway route_pattern commit_count
  iteration=1
  while [ "$iteration" -le "$iterations" ]; do
    if [ $((iteration % 2)) -eq 1 ]; then
      target=qrm-b
      gateway=10.40.2.1
      ip netns exec "$CLI_NS" ip route replace default via 10.40.1.1 dev qrm-a metric 200
      ip netns exec "$CLI_NS" ip route replace default via 10.40.2.1 dev qrm-b metric 50
    else
      target=qrm-a
      gateway=10.40.1.1
      ip netns exec "$CLI_NS" ip route replace default via 10.40.2.1 dev qrm-b metric 200
      ip netns exec "$CLI_NS" ip route replace default via 10.40.1.1 dev qrm-a metric 50
    fi
    route_pattern="^10.40.3.2 via $gateway dev $target"

    if ! wait_for 150 "[ \"\$(grep -c 'TCP make-before-break committed candidate' $WORK/client.log || true)\" -ge $iteration ]"; then
      bad "TCP soak iteration $iteration did not commit within the bounded wait"
      return
    fi
    if ! ip netns exec "$CLI_NS" ip route show 10.40.3.2 | grep -q "$route_pattern"; then
      bad "TCP soak iteration $iteration left the carrier bypass off $target"
      return
    fi
    if [ "$(ip netns exec "$CLI_NS" ip route show 10.40.3.2 | wc -l)" -ne 1 ]; then
      bad "TCP soak iteration $iteration left duplicate carrier bypass routes"
      return
    fi

    if [ $((iteration % sample_every)) -eq 0 ] || [ "$iteration" -eq "$iterations" ]; then
      if ! ip netns exec "$CLI_NS" ping -c2 -W1 10.88.0.1 >/dev/null 2>&1; then
        bad "TCP soak traffic probe failed after iteration $iteration"
        return
      fi
      if ! tcp_roaming_stats; then
        bad "TCP soak could not read control counters after iteration $iteration"
        return
      fi
      if [ "$TCP_ATTEMPTS:$TCP_COMMITS:$TCP_FAILURES:$TCP_GRACE:$TCP_SESSIONS:$TCP_ORPHANS:$TCP_ORPHAN_BYTES" != "$iteration:$iteration:0:0:1:0:0" ]; then
        bad "TCP soak counters diverged or retained orphan state after iteration $iteration"
        return
      fi
      local value
      value=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
      if [ "$value" -gt "$client_fd_max" ]; then client_fd_max=$value; fi
      value=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
      if [ "$value" -gt "$server_fd_max" ]; then server_fd_max=$value; fi
      value=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 -lname 'socket:*' 2>/dev/null | wc -l)
      if [ "$value" -gt "$client_socket_max" ]; then client_socket_max=$value; fi
      value=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 -lname 'socket:*' 2>/dev/null | wc -l)
      if [ "$value" -gt "$server_socket_max" ]; then server_socket_max=$value; fi
      value=$(awk '/^VmRSS:/ { print $2 }' "/proc/$CLIENT_PID/status")
      if [ "$value" -gt "$client_rss_max" ]; then client_rss_max=$value; fi
      value=$(awk '/^VmRSS:/ { print $2 }' "/proc/$server_pid/status")
      if [ "$value" -gt "$server_rss_max" ]; then server_rss_max=$value; fi
      echo "  TCP soak progress $iteration/$iterations target=$target server_worker_pid=$server_pid client_fd=$client_fd_max server_fd=$server_fd_max client_sockets_max=$client_socket_max server_sockets_max=$server_socket_max client_rss_kib=$client_rss_max server_rss_kib=$server_rss_max orphans=$TCP_ORPHANS orphan_bytes=$TCP_ORPHAN_BYTES"
    fi
    iteration=$((iteration + 1))
  done

  sleep 1
  commit_count=$(grep -c 'TCP make-before-break committed candidate' "$WORK/client.log" || true)
  local server_commits server_joins auth_count client_fd_after server_fd_after client_rss_after server_rss_after
  local client_socket_after server_socket_after client_start_after server_start_after
  server_commits=$(grep -c 'ROAMING transport=tcp event=commit' "$WORK/server.log" || true)
  server_joins=$(grep -c 'Stream #0 JOINed session' "$WORK/server.log" || true)
  auth_count=$(grep -c "connected on profile 'roam'" "$WORK/server.log" || true)
  client_start_after=$(awk '{ print $22 }' "/proc/$CLIENT_PID/stat" 2>/dev/null || true)
  server_start_after=$(awk '{ print $22 }' "/proc/$server_pid/stat" 2>/dev/null || true)
  client_fd_after=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  server_fd_after=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  client_socket_after=$(find "/proc/$CLIENT_PID/fd" -mindepth 1 -maxdepth 1 -lname 'socket:*' 2>/dev/null | wc -l)
  server_socket_after=$(find "/proc/$server_pid/fd" -mindepth 1 -maxdepth 1 -lname 'socket:*' 2>/dev/null | wc -l)
  client_rss_after=$(awk '/^VmRSS:/ { print $2 }' "/proc/$CLIENT_PID/status")
  server_rss_after=$(awk '/^VmRSS:/ { print $2 }' "/proc/$server_pid/status")

  check "TCP soak committed every requested client/server path transaction exactly once" "test '$commit_count' -eq '$iterations' && test '$server_commits' -eq '$iterations' && test '$server_joins' -eq '$iterations'"
  check "TCP soak retained one authenticated session without reconnect or grace" "test '$auth_count' -eq 1 && ! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log && ! grep -Eq 'retaining session|grace expired' $WORK/server.log"
  check "TCP soak control counters retained one session without failures or orphan state" "test '$TCP_ATTEMPTS' -eq '$iterations' && test '$TCP_COMMITS' -eq '$iterations' && test '$TCP_FAILURES' -eq 0 && test '$TCP_GRACE' -eq 0 && test '$TCP_SESSIONS' -eq 1 && test '$TCP_ORPHANS' -eq 0 && test '$TCP_ORPHAN_BYTES' -eq 0"
  check "TCP soak preserved the original client/server worker processes and TUN" "ip netns pids $CLI_NS | grep -qx '$CLIENT_PID' && ip netns pids $SRV_NS | grep -qx '$server_pid' && test '$client_start_after' = '$client_start_ticks' && test '$server_start_after' = '$server_start_ticks' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qrm0/ifindex)\" = '$TUN_IFINDEX'"
  check "TCP soak left one exact carrier bypass and a usable tunnel" "test \"\$(ip netns exec $CLI_NS ip route show 10.40.3.2 | wc -l)\" -eq 1 && ip netns exec $CLI_NS ping -c5 -W1 10.88.0.1"
  check "TCP soak closed superseded sockets instead of leaking file descriptors" "test '$client_fd_after' -le $((client_fd_before + 4)) && test '$server_fd_after' -le $((server_fd_before + 4)) && test '$client_fd_max' -le $((client_fd_before + 16)) && test '$server_fd_max' -le $((server_fd_before + 16))"
  check "TCP soak did not accumulate socket descriptors" "test '$client_socket_after' -le $((client_socket_before + 2)) && test '$server_socket_after' -le $((server_socket_before + 2)) && test '$client_socket_max' -le $((client_socket_before + 8)) && test '$server_socket_max' -le $((server_socket_before + 8))"
  check "TCP soak kept sampled RSS growth within the 32 MiB acceptance budget" "test $((client_rss_max - client_rss_before)) -le 32768 && test $((server_rss_max - server_rss_before)) -le 32768 && test $((client_rss_after - client_rss_before)) -le 32768 && test $((server_rss_after - server_rss_before)) -le 32768"
}

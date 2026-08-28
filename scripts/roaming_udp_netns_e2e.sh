#!/usr/bin/env bash
# Linux UDP+QUIC make-before-break integration tests. Everything runs in three isolated network
# namespaces; no host route or production process is changed. The success case commits path B;
# rollback blackholes B; supersede replaces that in-flight candidate with reachable path C.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
CASE=${2:-${CASE:-success}}
WORK=/tmp/qeli-roaming-udp-netns
CLI_NS=qru-cli
RTR_NS=qru-rtr
SRV_NS=qru-srv
PASS=0
FAIL=0
SERVER_JOB_PID=
CLIENT_JOB_PID=
PING_PID=

case "$CASE" in
  success|rollback|supersede) ;;
  *)
    echo "usage: $0 [qeli-binary] [success|rollback|supersede]" >&2
    exit 2
    ;;
esac

ok() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check() {
  if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi
}
wait_for() { # $1=attempts, $2=command
  local attempts=$1 command=$2 i=0
  while [ "$i" -lt "$attempts" ]; do
    if eval "$command" >/dev/null 2>&1; then return 0; fi
    i=$((i + 1))
    sleep 0.2
  done
  return 1
}

cleanup() {
  ip netns pids "$CLI_NS" 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids "$SRV_NS" 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 1
  ip netns pids "$CLI_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns pids "$SRV_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
  for job_pid in "$PING_PID" "$CLIENT_JOB_PID" "$SERVER_JOB_PID"; do
    if [ -n "$job_pid" ]; then wait "$job_pid" 2>/dev/null || true; fi
  done
  for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do ip netns del "$ns" 2>/dev/null; done
  sleep 0.2
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK"
rm -f "$WORK"/*.log "$WORK"/*.conf

for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do ip netns add "$ns"; done
ip link add qru-a type veth peer name qru-ar
ip link add qru-b type veth peer name qru-br
ip link add qru-c type veth peer name qru-cr
ip link add qru-s type veth peer name qru-sr
ip link set qru-a netns "$CLI_NS"
ip link set qru-b netns "$CLI_NS"
ip link set qru-c netns "$CLI_NS"
ip link set qru-ar netns "$RTR_NS"
ip link set qru-br netns "$RTR_NS"
ip link set qru-cr netns "$RTR_NS"
ip link set qru-s netns "$SRV_NS"
ip link set qru-sr netns "$RTR_NS"

ip netns exec "$CLI_NS" ip addr add 10.41.1.2/24 dev qru-a
ip netns exec "$CLI_NS" ip addr add 10.41.2.2/24 dev qru-b
ip netns exec "$CLI_NS" ip addr add 10.41.4.2/24 dev qru-c
ip netns exec "$RTR_NS" ip addr add 10.41.1.1/24 dev qru-ar
ip netns exec "$RTR_NS" ip addr add 10.41.2.1/24 dev qru-br
ip netns exec "$RTR_NS" ip addr add 10.41.4.1/24 dev qru-cr
ip netns exec "$RTR_NS" ip addr add 10.41.3.1/24 dev qru-sr
ip netns exec "$SRV_NS" ip addr add 10.41.3.2/24 dev qru-s
for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do ip netns exec "$ns" ip link set lo up; done
ip netns exec "$CLI_NS" ip link set qru-a up
ip netns exec "$CLI_NS" ip link set qru-b up
ip netns exec "$CLI_NS" ip link set qru-c up
ip netns exec "$RTR_NS" ip link set qru-ar up
ip netns exec "$RTR_NS" ip link set qru-br up
ip netns exec "$RTR_NS" ip link set qru-cr up
ip netns exec "$RTR_NS" ip link set qru-sr up
ip netns exec "$SRV_NS" ip link set qru-s up
ip netns exec "$RTR_NS" sysctl -qw net.ipv4.ip_forward=1

ip netns exec "$CLI_NS" ip route add default via 10.41.1.1 dev qru-a metric 100
ip netns exec "$CLI_NS" ip route add default via 10.41.2.1 dev qru-b metric 200
ip netns exec "$CLI_NS" ip route add default via 10.41.4.1 dev qru-c metric 300
ip netns exec "$SRV_NS" ip route add default via 10.41.3.1 dev qru-s

check "path A reaches the server" \
  "ip netns exec $CLI_NS ping -I 10.41.1.2 -c1 -W2 10.41.3.2"
check "path B reaches the server" \
  "ip netns exec $CLI_NS ping -I 10.41.2.2 -c1 -W2 10.41.3.2"

cat >"$WORK/server.conf" <<EOF
[auth]
users_file = $WORK/users.conf
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = info
[profile:roam]
enabled = true
bind.address = 0.0.0.0
bind.port = 4444
bind.transport = udp
tun.name = qrus0
tun.address = 10.89.0.1
tun.mtu = 1400
pool.cidr = 10.89.0.0/24
pool.exclude = 10.89.0.1
dns.enabled = false
obf.mode = fake-tls
obf.quic.enabled = true
obf.quic.cid_length = 4
obf.quic.version = 1
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 1000
obf.heartbeat.jitter_ms = 100
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
perf.connection.new_session_rate_max = 100
perf.connection.new_session_rate_window_secs = 60
EOF
: >"$WORK/users.conf"
"$BIN" add-client roam-user -p roam-pass-1234 -c "$WORK/server.conf" >/dev/null 2>&1
ip netns exec "$SRV_NS" "$BIN" server -c "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
SERVER_JOB_PID=$!
wait_for 50 "ip netns exec $SRV_NS ss -lnu | grep -q ':4444'" || bad "server did not listen"

cat >"$WORK/client.conf" <<EOF
[qeli]
server = 10.41.3.2:4444
proto = udp
user = roam-user
pass = roam-pass-1234
mode = fake-tls
quic = true
dev = qru0
bind_static = false
gateway = true
dns = off
allow_ipv6_leak = true
timeout = 5
[logging]
level = info
EOF
ip netns exec "$CLI_NS" "$BIN" client -c "$WORK/client.conf" >"$WORK/client.log" 2>&1 &
CLIENT_JOB_PID=$!
wait_for 100 "ip netns exec $CLI_NS ip link show qru0" || bad "client TUN did not come up"

CLIENT_PID=$(ip netns pids "$CLI_NS" 2>/dev/null | head -n1)
TUN_IFINDEX=$(ip netns exec "$CLI_NS" cat /sys/class/net/qru0/ifindex 2>/dev/null || true)
check "UDP roaming capability was negotiated" \
  "grep -q 'UDP make-before-break negotiated' $WORK/client.log"
check "initial carrier bypass uses path A" \
  "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.1.1 dev qru-a'"
check "tunnel works before route change" \
  "ip netns exec $CLI_NS ping -c3 -W1 10.89.0.1"

if [ "$CASE" = rollback ]; then
  sleep 3
  ip netns exec "$RTR_NS" iptables -I FORWARD 1 -i qru-br -o qru-sr \
    -p udp --dport 4444 -j DROP
  check "candidate path B blackhole is active" \
    "ip netns exec $RTR_NS iptables -C FORWARD -i qru-br -o qru-sr -p udp --dport 4444 -j DROP"

  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 150 -W1 10.89.0.1 >"$WORK/ping.log" 2>&1 &
  PING_PID=$!
  ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 50

  if wait_for 100 "grep -q 'UDP path candidate .* expired' $WORK/client.log"; then
    ok "candidate validation failed within the bounded retry budget"
  else
    bad "candidate validation did not expire"
  fi
  check "Linux observer prepared blackholed path B" \
    "grep -q 'Linux roaming prepared candidate .* on qru-b' $WORK/client.log"
  check "client sent PATH_INIT only on the candidate" \
    "grep -q 'UDP PATH_INIT sent for candidate' $WORK/client.log"
  check "platform acknowledged exact candidate rollback" \
    "grep -q 'UDP candidate .* rollback completed' $WORK/client.log"
  check "blackholed candidate received no PATH_CHALLENGE" \
    "! grep -q 'UDP PATH_CHALLENGE sent' $WORK/server.log"
  check "server published no PATH_COMMIT" \
    "! grep -q 'UDP PATH_COMMIT' $WORK/server.log"
  check "client published no candidate commit" \
    "! grep -q 'UDP make-before-break committed candidate' $WORK/client.log"
  check "active carrier bypass remains on path A" \
    "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.1.1 dev qru-a'"
  check "rollback leaves no carrier bypass on path B" \
    "! ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q 'dev qru-b'"
  check "tunnel remains usable after candidate rollback" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "client process survives candidate rollback" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID'"
  check "the same TUN survives candidate rollback" \
    "test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "rollback does not enter the top-level reconnect loop" \
    "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

  wait "$PING_PID" 2>/dev/null || true
  PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
    "$WORK/ping.log" | tail -n1)
  check "continuous probe retained at least 140 of 150 packets during rollback" \
    "test -n '$PING_RX' && test '$PING_RX' -ge 140"
elif [ "$CASE" = supersede ]; then
  sleep 3
  check "path C reaches the server" \
    "ip netns exec $CLI_NS ping -I 10.41.4.2 -c1 -W2 10.41.3.2"
  ip netns exec "$RTR_NS" iptables -I FORWARD 1 -i qru-br -o qru-sr \
    -p udp --dport 4444 -j DROP
  check "candidate path B blackhole is active" \
    "ip netns exec $RTR_NS iptables -C FORWARD -i qru-br -o qru-sr -p udp --dport 4444 -j DROP"

  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 180 -W1 10.89.0.1 >"$WORK/ping.log" 2>&1 &
  PING_PID=$!
  ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 50
  if wait_for 100 "grep -q 'Linux roaming prepared candidate .* on qru-b' $WORK/client.log"; then
    ok "Linux observer prepared blackholed path B"
  else
    bad "Linux observer did not prepare path B"
  fi

  # Start observing C as soon as B crosses PREPARE; the UDP actor still binds and emits B's
  # PATH_INIT independently through SO_BINDTODEVICE, so this deterministically overlaps both.
  ip netns exec "$CLI_NS" ip route replace default via 10.41.4.1 dev qru-c metric 25
  if wait_for 25 "grep -q 'UDP PATH_INIT sent for candidate' $WORK/client.log"; then
    ok "client started validation on superseded path B"
  else
    bad "client did not start validation on path B"
  fi
  if wait_for 100 "grep -q 'Linux roaming prepared candidate .* on qru-c' $WORK/client.log"; then
    ok "Linux observer prepared replacement path C"
  else
    bad "Linux observer did not prepare path C"
  fi
  if wait_for 150 "grep -q 'UDP make-before-break committed candidate' $WORK/client.log"; then
    ok "replacement path C committed after superseding B"
  else
    bad "replacement path C did not commit"
  fi

  check "platform rolled back B before preparing C" \
    "grep -q 'Linux roaming rolled back superseded candidate' $WORK/client.log"
  check "UDP actor discarded the superseded live candidate" \
    "grep -q 'UDP candidate .* superseded before validation completed' $WORK/client.log"
  check "supersede completed before B exhausted its retry budget" \
    "! grep -q 'UDP path candidate .* expired' $WORK/client.log"
  check "server challenged only reachable path C" \
    "grep -q 'UDP PATH_CHALLENGE sent.*to 10.41.4.2:' $WORK/server.log && ! grep -q 'UDP PATH_CHALLENGE sent.*to 10.41.2.2:' $WORK/server.log"
  check "server committed only reachable path C" \
    "grep -q 'UDP PATH_COMMIT.*to 10.41.4.2:' $WORK/server.log && ! grep -q 'UDP PATH_COMMIT.*to 10.41.2.2:' $WORK/server.log"
  check "client published exactly one candidate commit" \
    "test \"\$(grep -c 'UDP make-before-break committed candidate' $WORK/client.log)\" -eq 1"
  check "carrier bypass moved directly from A to C" \
    "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.4.1 dev qru-c'"
  check "no stale carrier bypass remains on A or B" \
    "! ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -Eq 'dev qru-(a|b)'"

  ip netns exec "$CLI_NS" ip link set qru-a down
  ip netns exec "$CLI_NS" ip link set qru-b down
  sleep 2
  check "tunnel survives removal of superseded paths A and B" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "client process survives supersede without reconnect" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID'"
  check "the same TUN survives supersede" \
    "test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "supersede does not enter the top-level reconnect loop" \
    "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

  wait "$PING_PID" 2>/dev/null || true
  PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
    "$WORK/ping.log" | tail -n1)
  check "continuous probe retained at least 170 of 180 packets during supersede" \
    "test -n '$PING_RX' && test '$PING_RX' -ge 170"
else
sleep 3
ip netns exec "$CLI_NS" ping -n -i 0.2 -c 150 -W1 10.89.0.1 >"$WORK/ping.log" 2>&1 &
PING_PID=$!
ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 50

if wait_for 150 "grep -q 'UDP make-before-break committed candidate' $WORK/client.log"; then
  ok "route change committed an authenticated UDP candidate"
else
  bad "route change did not commit an authenticated UDP candidate"
fi
check "Linux observer prepared path B" \
  "grep -q 'Linux roaming prepared candidate .* on qru-b' $WORK/client.log"
check "client sent PATH_INIT on candidate path" \
  "grep -q 'UDP PATH_INIT sent for candidate' $WORK/client.log"
check "server sent PATH_CHALLENGE" \
  "grep -q 'UDP PATH_CHALLENGE sent' $WORK/server.log"
check "server committed PATH_RESPONSE" \
  "grep -q 'UDP PATH_COMMIT' $WORK/server.log"
check "carrier bypass moved to path B" \
  "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.2.1 dev qru-b'"
check "no stale carrier bypass remains on path A" \
  "! ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q 'dev qru-a'"

ip netns exec "$CLI_NS" ip link set qru-a down
sleep 2
check "tunnel survives removal of old path A" \
  "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
check "client process survived without reconnect" \
  "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID'"
check "the same TUN instance survived handover" \
  "test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
check "handover did not enter the top-level reconnect loop" \
  "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

wait "$PING_PID" 2>/dev/null || true
PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
  "$WORK/ping.log" | tail -n1)
check "continuous probe retained at least 140 of 150 packets" \
  "test -n '$PING_RX' && test '$PING_RX' -ge 140"
fi

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
  echo "--- client.log (tail) ---"
  tail -n 160 "$WORK/client.log"
  echo "--- server.log (tail) ---"
  tail -n 160 "$WORK/server.log"
  echo "--- route state ---"
  ip netns exec "$CLI_NS" ip route show 2>/dev/null || true
  exit 1
fi

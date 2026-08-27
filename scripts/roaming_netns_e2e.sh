#!/usr/bin/env bash
# Linux TCP make-before-break integration test. Everything runs in three isolated network
# namespaces; no host route or production process is changed.
#
#                         10.40.1.0/24 (path A)
#                    +--------------------------------+
#                    |                                |
#   [qrm-cli] qrm-a--+--qrm-ar [qrm-rtr] qrm-sr------+--qrm-s [qrm-srv]
#             qrm-b--+--qrm-br           10.40.3.0/24
#                    |                                |
#                    +--------------------------------+
#                         10.40.2.0/24 (path B)
#
# The client starts on path A. A lower-metric default through path B must produce a prepared
# PathUpdate, authenticate a replacement carrier, commit the qeli-owned /32 through B, and keep
# the same process and TUN alive. Path A is then taken down to prove the new carrier is real.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-${BIN:-/opt/qeli-src/target/release/qeli}}
WORK=/tmp/qeli-roaming-netns
CLI_NS=qrm-cli
RTR_NS=qrm-rtr
SRV_NS=qrm-srv
PASS=0
FAIL=0

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
  ip netns pids "$CLI_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns pids "$SRV_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
  for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do
    ip netns del "$ns" 2>/dev/null
  done
  sleep 0.2
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK"
rm -f "$WORK"/*.log "$WORK"/*.conf

for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do ip netns add "$ns"; done
ip link add qrm-a type veth peer name qrm-ar
ip link add qrm-b type veth peer name qrm-br
ip link add qrm-s type veth peer name qrm-sr
ip link set qrm-a netns "$CLI_NS"
ip link set qrm-b netns "$CLI_NS"
ip link set qrm-ar netns "$RTR_NS"
ip link set qrm-br netns "$RTR_NS"
ip link set qrm-s netns "$SRV_NS"
ip link set qrm-sr netns "$RTR_NS"

ip netns exec "$CLI_NS" ip addr add 10.40.1.2/24 dev qrm-a
ip netns exec "$CLI_NS" ip addr add 10.40.2.2/24 dev qrm-b
ip netns exec "$RTR_NS" ip addr add 10.40.1.1/24 dev qrm-ar
ip netns exec "$RTR_NS" ip addr add 10.40.2.1/24 dev qrm-br
ip netns exec "$RTR_NS" ip addr add 10.40.3.1/24 dev qrm-sr
ip netns exec "$SRV_NS" ip addr add 10.40.3.2/24 dev qrm-s
for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do ip netns exec "$ns" ip link set lo up; done
ip netns exec "$CLI_NS" ip link set qrm-a up
ip netns exec "$CLI_NS" ip link set qrm-b up
ip netns exec "$RTR_NS" ip link set qrm-ar up
ip netns exec "$RTR_NS" ip link set qrm-br up
ip netns exec "$RTR_NS" ip link set qrm-sr up
ip netns exec "$SRV_NS" ip link set qrm-s up
ip netns exec "$RTR_NS" sysctl -qw net.ipv4.ip_forward=1

ip netns exec "$CLI_NS" ip route add default via 10.40.1.1 dev qrm-a metric 100
ip netns exec "$CLI_NS" ip route add default via 10.40.2.1 dev qrm-b metric 200
ip netns exec "$SRV_NS" ip route add default via 10.40.3.1 dev qrm-s

check "path A reaches the server" \
  "ip netns exec $CLI_NS ping -I 10.40.1.2 -c1 -W2 10.40.3.2"
check "path B reaches the server" \
  "ip netns exec $CLI_NS ping -I 10.40.2.2 -c1 -W2 10.40.3.2"

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
bind.port = 4443
bind.transport = tcp
tun.name = qrms0
tun.address = 10.88.0.1
tun.mtu = 1400
pool.cidr = 10.88.0.0/24
pool.exclude = 10.88.0.1
obf.mode = fake-tls
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
perf.connection.new_session_rate_max = 100
perf.connection.new_session_rate_window_secs = 60
EOF
: >"$WORK/users.conf"
"$BIN" add-client roam-user -p roam-pass-1234 -c "$WORK/server.conf" >/dev/null 2>&1
ip netns exec "$SRV_NS" "$BIN" server -c "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
wait_for 50 "ip netns exec $SRV_NS ss -lnt | grep -q ':4443'" || bad "server did not listen"

cat >"$WORK/client.conf" <<EOF
[qeli]
server = 10.40.3.2:4443
proto = tcp
user = roam-user
pass = roam-pass-1234
mode = fake-tls
dev = qrm0
bind_static = false
gateway = true
dns = off
allow_ipv6_leak = true
timeout = 5
[logging]
level = info
EOF
ip netns exec "$CLI_NS" "$BIN" client -c "$WORK/client.conf" >"$WORK/client.log" 2>&1 &
wait_for 100 "ip netns exec $CLI_NS ip link show qrm0" || bad "client TUN did not come up"

CLIENT_PID=$(ip netns pids "$CLI_NS" 2>/dev/null | head -n1)
TUN_IFINDEX=$(ip netns exec "$CLI_NS" cat /sys/class/net/qrm0/ifindex 2>/dev/null || true)
check "TCP handover capability was negotiated" \
  "grep -q 'TCP make-before-break negotiated' $WORK/client.log"
check "initial carrier bypass uses path A" \
  "ip netns exec $CLI_NS ip route show 10.40.3.2 | grep -q '^10.40.3.2 via 10.40.1.1 dev qrm-a'"
check "tunnel works before route change" \
  "ip netns exec $CLI_NS ping -c3 -W1 10.88.0.1"

# Give the observer enough time to establish its A baseline, then make B the physical default.
sleep 3
ip netns exec "$CLI_NS" ping -n -i 0.2 -c 150 -W1 10.88.0.1 >"$WORK/ping.log" 2>&1 &
PING_PID=$!
ip netns exec "$CLI_NS" ip route replace default via 10.40.2.1 dev qrm-b metric 50

if wait_for 150 "grep -q 'TCP make-before-break committed candidate' $WORK/client.log"; then
  ok "route change committed a make-before-break candidate"
else
  bad "route change did not commit a make-before-break candidate"
fi
check "Linux observer prepared path B" \
  "grep -q 'Linux roaming prepared candidate .* on qrm-b' $WORK/client.log"
check "carrier bypass moved to path B" \
  "ip netns exec $CLI_NS ip route show 10.40.3.2 | grep -q '^10.40.3.2 via 10.40.2.1 dev qrm-b'"
check "no stale carrier bypass remains on path A" \
  "! ip netns exec $CLI_NS ip route show 10.40.3.2 | grep -q 'dev qrm-a'"
check "server accepted and attached the replacement carrier from path B" \
  "grep 'Stream #0 JOINed session' $WORK/server.log | grep -q 'from 10.40.2.2:'"

# Remove the old physical path only after COMMIT. Traffic must continue on the candidate.
ip netns exec "$CLI_NS" ip link set qrm-a down
sleep 2
check "tunnel survives removal of old path A" \
  "ip netns exec $CLI_NS ping -c5 -W1 10.88.0.1"
check "client process survived without reconnect" \
  "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID'"
check "the same TUN instance survived handover" \
  "test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qrm0/ifindex)\" = '$TUN_IFINDEX'"
check "handover did not enter the top-level reconnect loop" \
  "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

wait "$PING_PID" 2>/dev/null || true
PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
  "$WORK/ping.log" | tail -n1)
check "continuous probe retained at least 140 of 150 packets" \
  "test -n '$PING_RX' && test '$PING_RX' -ge 140"

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
  echo "--- client.log (tail) ---"
  tail -n 120 "$WORK/client.log"
  echo "--- route state ---"
  ip netns exec "$CLI_NS" ip route show 2>/dev/null || true
  exit 1
fi

#!/usr/bin/env bash
# Isolated TCP roaming gate for a Linux exit node. A consumer sends real traffic through
# server -> exit -> WAN A, the exit moves its carrier/default to WAN B in the same session,
# and clean stop must remove rules for both WAN generations and restore leased sysctls.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-/var/tmp/qeli-exit-node-target/release/qeli}
WORK=/var/tmp/qeli-roaming-exit-node-netns
EXIT_NS=qre-exit
CONS_NS=qre-cons
RTR_NS=qre-rtr
SRV_NS=qre-srv
PASS=0
FAIL=0
EXIT_JOB_PID=
CONS_JOB_PID=
SERVER_JOB_PID=

ok() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check() {
  if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi
}
wait_for() {
  local attempts=$1 command=$2 i=0
  while [ "$i" -lt "$attempts" ]; do
    if eval "$command" >/dev/null 2>&1; then return 0; fi
    i=$((i + 1))
    sleep 0.2
  done
  return 1
}

cleanup() {
  for pid in "$EXIT_JOB_PID" "$CONS_JOB_PID" "$SERVER_JOB_PID"; do
    if [ -n "$pid" ]; then kill -9 "$pid" 2>/dev/null || true; fi
  done
  for pid in "$EXIT_JOB_PID" "$CONS_JOB_PID" "$SERVER_JOB_PID"; do
    if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || true; fi
  done
  for ns in "$EXIT_NS" "$CONS_NS" "$RTR_NS" "$SRV_NS"; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
  done
  sleep 0.2
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK"
rm -f "$WORK"/*.conf "$WORK"/*.log "$WORK"/*.sock "$WORK"/*.key \
  "$WORK"/*-known-hosts "$WORK"/*-device-id

for ns in "$EXIT_NS" "$CONS_NS" "$RTR_NS" "$SRV_NS"; do ip netns add "$ns"; done
ip link add qre-a type veth peer name qre-ar
ip link add qre-b type veth peer name qre-br
ip link add qre-c type veth peer name qre-cr
ip link add qre-s type veth peer name qre-sr
ip link set qre-a netns "$EXIT_NS"
ip link set qre-b netns "$EXIT_NS"
ip link set qre-c netns "$CONS_NS"
ip link set qre-ar netns "$RTR_NS"
ip link set qre-br netns "$RTR_NS"
ip link set qre-cr netns "$RTR_NS"
ip link set qre-s netns "$SRV_NS"
ip link set qre-sr netns "$RTR_NS"

ip netns exec "$EXIT_NS" ip addr add 10.43.1.2/24 dev qre-a
ip netns exec "$EXIT_NS" ip addr add 10.43.2.2/24 dev qre-b
ip netns exec "$CONS_NS" ip addr add 10.43.4.2/24 dev qre-c
ip netns exec "$RTR_NS" ip addr add 10.43.1.1/24 dev qre-ar
ip netns exec "$RTR_NS" ip addr add 10.43.2.1/24 dev qre-br
ip netns exec "$RTR_NS" ip addr add 10.43.4.1/24 dev qre-cr
ip netns exec "$RTR_NS" ip addr add 10.43.3.1/24 dev qre-sr
ip netns exec "$RTR_NS" ip addr add 198.18.0.1/32 dev lo
ip netns exec "$SRV_NS" ip addr add 10.43.3.2/24 dev qre-s
for ns in "$EXIT_NS" "$CONS_NS" "$RTR_NS" "$SRV_NS"; do
  ip netns exec "$ns" ip link set lo up
done
for spec in \
  "$EXIT_NS qre-a" "$EXIT_NS qre-b" "$CONS_NS qre-c" \
  "$RTR_NS qre-ar" "$RTR_NS qre-br" "$RTR_NS qre-cr" "$RTR_NS qre-sr" \
  "$SRV_NS qre-s"; do
  set -- $spec
  ip netns exec "$1" ip link set "$2" up
done
ip netns exec "$RTR_NS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$EXIT_NS" ip route add default via 10.43.1.1 dev qre-a metric 100
ip netns exec "$EXIT_NS" ip route add default via 10.43.2.1 dev qre-b metric 200
ip netns exec "$CONS_NS" ip route add default via 10.43.4.1 dev qre-c
ip netns exec "$SRV_NS" ip route add default via 10.43.3.1 dev qre-s

check "exit path A reaches the server" \
  "ip netns exec $EXIT_NS ping -I 10.43.1.2 -c1 -W2 10.43.3.2"
check "exit path B reaches the server" \
  "ip netns exec $EXIT_NS ping -I 10.43.2.2 -c1 -W2 10.43.3.2"
check "consumer reaches the server" \
  "ip netns exec $CONS_NS ping -c1 -W2 10.43.3.2"

BEFORE_FORWARD=$(ip netns exec "$EXIT_NS" cat /proc/sys/net/ipv4/ip_forward)
BEFORE_RP_ALL=$(ip netns exec "$EXIT_NS" cat /proc/sys/net/ipv4/conf/all/rp_filter)
BEFORE_RP_A=$(ip netns exec "$EXIT_NS" cat /proc/sys/net/ipv4/conf/qre-a/rp_filter)
BEFORE_RP_B=$(ip netns exec "$EXIT_NS" cat /proc/sys/net/ipv4/conf/qre-b/rp_filter)

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
identity_key = $WORK/identity.key
bind.address = 0.0.0.0
bind.port = 4553
bind.transport = tcp
roaming.enabled = true
tun.name = qres0
tun.address = 10.88.0.1
tun.mtu = 1400
pool.cidr = 10.88.0.0/24
pool.exclude = 10.88.0.1
routing.client_to_client = true
dns.enabled = false
obf.mode = fake-tls
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
perf.connection.new_session_rate_max = 100
perf.connection.new_session_rate_window_secs = 60
EOF
: >"$WORK/users.conf"
if ! printf '%s\n' 'exit-pass-1234' | "$BIN" add-client exit-user --password-stdin \
  --profiles roam --static-ip 10.88.0.2 -c "$WORK/server.conf" >"$WORK/add-exit.log" 2>&1; then
  bad "exit user creation"
  tail -n 60 "$WORK/add-exit.log"
  exit 1
fi
if ! printf '%s\n' 'consumer-pass-1234' | "$BIN" add-client consumer-user --password-stdin \
  --profiles roam --static-ip 10.88.0.3 -c "$WORK/server.conf" >"$WORK/add-consumer.log" 2>&1; then
  bad "consumer user creation"
  tail -n 60 "$WORK/add-consumer.log"
  exit 1
fi
sed -i '/^\[user:exit-user\]$/a client_subnet = 0.0.0.0/0' "$WORK/users.conf"
sed -i '/^\[user:consumer-user\]$/a route = 0.0.0.0/0' "$WORK/users.conf"

ip netns exec "$SRV_NS" env QELI_CONTROL_SOCKET="$WORK/control.sock" \
  "$BIN" server -c "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
SERVER_JOB_PID=$!
if wait_for 75 "ip netns exec $SRV_NS ss -lnt | grep -q ':4553'"; then
  ok "server listens in its namespace"
else
  bad "server listens in its namespace"
  tail -n 100 "$WORK/server.log"
  exit 1
fi

cat >"$WORK/exit.conf" <<EOF
[qeli]
server = 10.43.3.2:4553
proto = tcp
roaming = required
user = exit-user
pass = exit-pass-1234
mode = fake-tls
dev = qrex0
bind_static = false
gateway = false
exit_node = true
ipv6 = off
dns = off
timeout = 5
[logging]
level = info
EOF
chmod 600 "$WORK/exit.conf"
ip netns exec "$EXIT_NS" env QELI_KNOWN_HOSTS="$WORK/exit-known-hosts" \
  QELI_DEVICE_ID_FILE="$WORK/exit-device-id" \
  "$BIN" client -c "$WORK/exit.conf" >"$WORK/exit.log" 2>&1 &
EXIT_JOB_PID=$!
if wait_for 100 "ip netns exec $EXIT_NS ip link show qrex0"; then
  ok "exit client established its TUN"
else
  bad "exit client established its TUN"
  tail -n 120 "$WORK/exit.log"
  exit 1
fi

EXIT_PID=$(ip netns pids "$EXIT_NS" 2>/dev/null | head -n1)
EXIT_TUN_IFINDEX=$(ip netns exec "$EXIT_NS" cat /sys/class/net/qrex0/ifindex)

exit_rule_set() {
  local wan=$1
  ip netns exec "$EXIT_NS" iptables -t mangle -C FORWARD -i qrex0 -o "$wan" \
    -j MARK --set-xmark 0x51/0x51 -m comment --comment qeli-exit-node &&
  ip netns exec "$EXIT_NS" iptables -t nat -C POSTROUTING -o "$wan" \
    -m mark --mark 0x51/0x51 -j MASQUERADE -m comment --comment qeli-exit-node &&
  ip netns exec "$EXIT_NS" iptables -t filter -C FORWARD -i qrex0 -o "$wan" \
    -j ACCEPT -m comment --comment qeli-exit-node &&
  ip netns exec "$EXIT_NS" iptables -t filter -C FORWARD -i "$wan" -o qrex0 \
    -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment qeli-exit-node
}

check "initial exit firewall targets WAN A" "exit_rule_set qre-a"
check "initial exit firewall does not preinstall WAN B" "! exit_rule_set qre-b"
check "exit-node enabled forwarding" \
  "test \"\$(ip netns exec $EXIT_NS cat /proc/sys/net/ipv4/ip_forward)\" = 1"
check "exit-node relaxed RPF on WAN A" \
  "test \"\$(ip netns exec $EXIT_NS cat /proc/sys/net/ipv4/conf/qre-a/rp_filter)\" = 0"

cat >"$WORK/consumer.conf" <<EOF
[qeli]
server = 10.43.3.2:4553
proto = tcp
roaming = off
user = consumer-user
pass = consumer-pass-1234
mode = fake-tls
dev = qrec0
bind_static = false
gateway = true
ipv6 = off
dns = off
allow_ipv6_leak = true
timeout = 5
[logging]
level = info
EOF
chmod 600 "$WORK/consumer.conf"
ip netns exec "$CONS_NS" env QELI_KNOWN_HOSTS="$WORK/consumer-known-hosts" \
  QELI_DEVICE_ID_FILE="$WORK/consumer-device-id" \
  "$BIN" client -c "$WORK/consumer.conf" >"$WORK/consumer.log" 2>&1 &
CONS_JOB_PID=$!
if wait_for 100 "ip netns exec $CONS_NS ip link show qrec0"; then
  ok "consumer established its TUN"
else
  bad "consumer established its TUN"
  tail -n 120 "$WORK/consumer.log"
  exit 1
fi

check "consumer captures the test internet address into its TUN" \
  "ip netns exec $CONS_NS ip route get 198.18.0.1 | grep -q 'dev qrec0'"
check "exit kernel initially selects WAN A for internet egress" \
  "ip netns exec $EXIT_NS ip route get 198.18.0.1 | grep -q 'dev qre-a'"
check "consumer traffic exits through WAN A" \
  "ip netns exec $CONS_NS ping -c5 -W1 198.18.0.1"
check "WAN A MASQUERADE counter observed forwarded traffic" \
  "ip netns exec $EXIT_NS iptables -t nat -L POSTROUTING -v -n -x | awk '/qre-a/ && /qeli-exit-node/ { if (\$1 + 0 > 0) found=1 } END { exit !found }'"
check "exactly two clients completed full AUTH before roaming" \
  "test \"\$(grep -c \"connected on profile 'roam'\" $WORK/server.log || true)\" -eq 2"

sleep 3
ip netns exec "$EXIT_NS" ip route replace default via 10.43.2.1 dev qre-b metric 50
ip netns exec "$EXIT_NS" ip route replace default via 10.43.1.1 dev qre-a metric 200
if wait_for 150 "grep -q 'TCP make-before-break committed candidate' $WORK/exit.log"; then
  ok "exit node committed the make-before-break candidate"
else
  bad "exit node committed the make-before-break candidate"
fi

check "carrier bypass moved to WAN B" \
  "ip netns exec $EXIT_NS ip route show 10.43.3.2 | grep -q '^10.43.3.2 via 10.43.2.1 dev qre-b'"
check "exit kernel now selects WAN B for internet egress" \
  "ip netns exec $EXIT_NS ip route get 198.18.0.1 | grep -q 'dev qre-b'"
check "old WAN A rules remain for fail-safe drain" "exit_rule_set qre-a"
check "new WAN B exit firewall is installed before carrier publication" "exit_rule_set qre-b"
check "exit-node relaxed RPF on WAN B" \
  "test \"\$(ip netns exec $EXIT_NS cat /proc/sys/net/ipv4/conf/qre-b/rp_filter)\" = 0"
check "consumer traffic survives and exits through WAN B" \
  "ip netns exec $CONS_NS ping -c5 -W1 198.18.0.1"
check "WAN B MASQUERADE counter observed forwarded traffic" \
  "ip netns exec $EXIT_NS iptables -t nat -L POSTROUTING -v -n -x | awk '/qre-b/ && /qeli-exit-node/ { if (\$1 + 0 > 0) found=1 } END { exit !found }'"
check "exit process survived without reconnect" \
  "test -n '$EXIT_PID' && ip netns pids $EXIT_NS | grep -qx '$EXIT_PID'"
check "the same exit TUN survived handover" \
  "test \"\$(ip netns exec $EXIT_NS cat /sys/class/net/qrex0/ifindex)\" = '$EXIT_TUN_IFINDEX'"
check "handover performed no second full AUTH" \
  "test \"\$(grep -c \"connected on profile 'roam'\" $WORK/server.log || true)\" -eq 2"
check "handover did not enter the top-level reconnect loop" \
  "! grep -Eq 'Connection error|Reconnecting in' $WORK/exit.log"

kill -TERM "$EXIT_PID" 2>/dev/null || true
if wait_for 100 "! ip netns exec $EXIT_NS ip link show qrex0"; then
  ok "clean stop removed the exit TUN"
else
  bad "clean stop removed the exit TUN"
fi
if wait_for 100 "! ip netns pids $EXIT_NS | grep -qx '$EXIT_PID'"; then
  ok "clean stop completed the exit process"
else
  bad "clean stop completed the exit process"
fi
check "clean stop removed every IPv4 exit-node rule" \
  "! ip netns exec $EXIT_NS iptables-save | grep -q 'qeli-exit-node'"
check "clean stop restored ip_forward" \
  "test \"\$(ip netns exec $EXIT_NS cat /proc/sys/net/ipv4/ip_forward)\" = '$BEFORE_FORWARD'"
check "clean stop restored all-interface rp_filter" \
  "test \"\$(ip netns exec $EXIT_NS cat /proc/sys/net/ipv4/conf/all/rp_filter)\" = '$BEFORE_RP_ALL'"
check "clean stop restored WAN A rp_filter" \
  "test \"\$(ip netns exec $EXIT_NS cat /proc/sys/net/ipv4/conf/qre-a/rp_filter)\" = '$BEFORE_RP_A'"
check "clean stop restored WAN B rp_filter" \
  "test \"\$(ip netns exec $EXIT_NS cat /proc/sys/net/ipv4/conf/qre-b/rp_filter)\" = '$BEFORE_RP_B'"

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
  echo "--- exit.log (tail) ---"
  tail -n 160 "$WORK/exit.log"
  echo "--- consumer.log (tail) ---"
  tail -n 100 "$WORK/consumer.log"
  echo "--- server.log (tail) ---"
  tail -n 160 "$WORK/server.log"
  echo "--- exit routes/rules ---"
  ip netns exec "$EXIT_NS" ip route show 2>/dev/null || true
  ip netns exec "$EXIT_NS" iptables-save 2>/dev/null | grep -E 'qeli-exit-node|^\*|^COMMIT' || true
  exit 1
fi

#!/usr/bin/env bash
# One isolated IPv6 release-matrix cell. It proves that the outer carrier family is
# independent from the inner tunnel family and that full/split routing cannot leak the
# family the authenticated NetworkPlan did not grant.
set -u
set -o pipefail
export LC_ALL=C

BIN=${1:-target/release/qeli}
OUTER=${2:-4}
INNER=${3:-4}
TRANSPORT=${4:-tcp}
WIRE=${5:-fake-tls}
ROUTING=${6:-full}
FLAVOR=${7:-base}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

usage() {
  echo "usage: $0 <qeli-binary> <outer:4|6> <inner:4|6|dual> <tcp|udp> <fake-tls|quic> <full|split> [base|tap|legacy]" >&2
}

case "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" in
  [46]:4:tcp:fake-tls:full|[46]:6:tcp:fake-tls:full|\
  [46]:4:udp:fake-tls:full|[46]:6:udp:fake-tls:full|\
  [46]:4:udp:quic:full|[46]:6:udp:quic:full|\
  [46]:dual:tcp:fake-tls:split|[46]:dual:udp:fake-tls:split) ;;
  *) usage; exit 2 ;;
esac

case "$FLAVOR" in
  base) ;;
  tap) [ "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" = "4:6:tcp:fake-tls:full" ] || { usage; exit 2; } ;;
  legacy) [ "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" = "4:4:tcp:fake-tls:full" ] || { usage; exit 2; } ;;
  *) usage; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (network namespaces and TUN/NAT are required)" >&2
  exit 2
fi
for command in ip iptables ip6tables ping python3; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 2
  }
done
BIN=$(readlink -f "$BIN")
SERVER_BIN=$(readlink -f "${QELI_SERVER_BIN:-$BIN}")
CLIENT_BIN=$(readlink -f "${QELI_CLIENT_BIN:-$BIN}")
for executable in "$BIN" "$SERVER_BIN" "$CLIENT_BIN"; do
  if [ ! -x "$executable" ]; then
    echo "qeli binary is not executable: $executable" >&2
    exit 2
  fi
done

TAG=$(( $$ % 10000 ))
CLI_NS=qv6c${TAG}
RTR_NS=qv6r${TAG}
SRV_NS=qv6s${TAG}
CLI_IF=v6c${TAG}
RTR_C_IF=v6cr${TAG}
SRV_IF=v6s${TAG}
RTR_S_IF=v6sr${TAG}
TUN_IF=vpn${TAG}
PORT=$(( 4600 + TAG % 200 ))
WORK=/tmp/qeli-ipv6-${TAG}
SERVER_PID=
CLIENT_PID=
PASS=0
FAIL=0

ok() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check() {
  if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi
}
check_eventually() {
  if wait_for 25 "$2"; then ok "$1"; else bad "$1"; fi
}
wait_for() {
  local attempts=$1 command=$2 index=0
  while [ "$index" -lt "$attempts" ]; do
    if eval "$command" >/dev/null 2>&1; then return 0; fi
    index=$((index + 1))
    sleep 0.2
  done
  return 1
}
cleanup() {
  for pid in "$CLIENT_PID" "$SERVER_PID"; do
    if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || true; fi
  done
  sleep 0.2
  for pid in "$CLIENT_PID" "$SERVER_PID"; do
    if [ -n "$pid" ]; then kill -KILL "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
  done
  if [ "${QELI_KEEP_WORK:-0}" != 1 ]; then rm -rf -- "$WORK"; fi
}
trap cleanup EXIT

mkdir -p "$WORK"
for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do ip netns add "$ns"; done
ip link add "$CLI_IF" type veth peer name "$RTR_C_IF"
ip link add "$SRV_IF" type veth peer name "$RTR_S_IF"
ip link set "$CLI_IF" netns "$CLI_NS"
ip link set "$RTR_C_IF" netns "$RTR_NS"
ip link set "$SRV_IF" netns "$SRV_NS"
ip link set "$RTR_S_IF" netns "$RTR_NS"

for ns in "$CLI_NS" "$RTR_NS" "$SRV_NS"; do ip netns exec "$ns" ip link set lo up; done
ip netns exec "$CLI_NS" ip link set "$CLI_IF" up
ip netns exec "$RTR_NS" ip link set "$RTR_C_IF" up
ip netns exec "$RTR_NS" ip link set "$RTR_S_IF" up
ip netns exec "$SRV_NS" ip link set "$SRV_IF" up

ip netns exec "$CLI_NS" ip addr add 10.46.1.2/24 dev "$CLI_IF"
ip netns exec "$RTR_NS" ip addr add 10.46.1.1/24 dev "$RTR_C_IF"
ip netns exec "$RTR_NS" ip addr add 10.46.2.1/24 dev "$RTR_S_IF"
ip netns exec "$SRV_NS" ip addr add 10.46.2.2/24 dev "$SRV_IF"
ip netns exec "$CLI_NS" ip -6 addr add fd46:1::2/64 dev "$CLI_IF"
ip netns exec "$RTR_NS" ip -6 addr add fd46:1::1/64 dev "$RTR_C_IF"
ip netns exec "$RTR_NS" ip -6 addr add fd46:2::1/64 dev "$RTR_S_IF"
ip netns exec "$SRV_NS" ip -6 addr add fd46:2::2/64 dev "$SRV_IF"

ip netns exec "$CLI_NS" ip route add default via 10.46.1.1 dev "$CLI_IF"
ip netns exec "$CLI_NS" ip -6 route add default via fd46:1::1 dev "$CLI_IF"
ip netns exec "$SRV_NS" ip route add default via 10.46.2.1 dev "$SRV_IF"
ip netns exec "$SRV_NS" ip -6 route add default via fd46:2::1 dev "$SRV_IF"
ip netns exec "$RTR_NS" ip addr add 198.18.46.1/32 dev lo
ip netns exec "$RTR_NS" ip addr add 198.18.46.2/32 dev lo
ip netns exec "$RTR_NS" ip -6 addr add fd46:ffff::1/128 dev lo
ip netns exec "$RTR_NS" ip -6 addr add fd46:ffff::2/128 dev lo
ip netns exec "$RTR_NS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$RTR_NS" sysctl -qw net.ipv6.conf.all.forwarding=1

check "direct IPv4 topology works before the VPN" \
  "ip netns exec $CLI_NS ping -4 -c1 -W2 198.18.46.1"
if wait_for 50 "ip netns exec $CLI_NS ping -6 -c1 -W2 fd46:ffff::1"; then
  ok "direct IPv6 topology works before the VPN"
else
  bad "direct IPv6 topology works before the VPN"
fi

if [ "$OUTER" = 4 ]; then
  SERVER_AUTHORITY="10.46.2.2:$PORT"
  BIND_ADDRESS=10.46.2.2
else
  SERVER_AUTHORITY="[fd46:2::2]:$PORT"
  BIND_ADDRESS=fd46:2::2
fi

QUIC=false
if [ "$WIRE" = quic ]; then QUIC=true; fi
GATEWAY=false
SERVER_DEVICE_TYPE=tun
CLIENT_DEVICE_TYPE=tun
CLIENT_IPV4_PREFIX=${QELI_EXPECT_CLIENT_IPV4_PREFIX:-32}
CLIENT_IPV6_PREFIX=128
if [ "$FLAVOR" = tap ]; then
  SERVER_DEVICE_TYPE=tap
  CLIENT_DEVICE_TYPE=tap
  CLIENT_IPV6_PREFIX=64
fi
if [ "$ROUTING" = full ]; then GATEWAY=true; fi


TUN_CONFIG=
CLIENT_IPV6=off
USER_ARGS=(--static-ip 10.86.0.2)
ACTIVE_CHECKS=4
case "$INNER" in
  4)
    TUN_CONFIG="tun.ip_mode = ipv4
tun.address = 10.86.0.1
pool.cidr = 10.86.0.0/24
pool.exclude = 10.86.0.1
routing.nat.enabled = true
routing.nat.interface = $SRV_IF
routing.ipv6.mode = off"
    ;;
  6)
    TUN_CONFIG="tun.ip_mode = ipv6
tun.ipv6_address = fd86::1
pool.ipv6.cidr = fd86::/64
routing.nat.enabled = false
routing.ipv6.mode = nat66
routing.ipv6.interface = $SRV_IF"
    CLIENT_IPV6=required
    USER_ARGS=(--static-ipv6 fd86::2)
    ACTIVE_CHECKS=6
    ;;
  dual)
    TUN_CONFIG="tun.ip_mode = dual
tun.address = 10.86.0.1
tun.ipv6_address = fd86::1
pool.cidr = 10.86.0.0/24
pool.exclude = 10.86.0.1
pool.ipv6.cidr = fd86::/64
routing.nat.enabled = true
routing.nat.interface = $SRV_IF
routing.ipv6.mode = nat66
routing.ipv6.interface = $SRV_IF"
    CLIENT_IPV6=required
    USER_ARGS=(--static-ip 10.86.0.2 --static-ipv6 fd86::2)
    ACTIVE_CHECKS=dual
    ;;
esac

ROUTES=
if [ "$FLAVOR" = legacy ]; then
  TUN_CONFIG="tun.address = 10.86.0.1
pool.cidr = 10.86.0.0/24
pool.exclude = 10.86.0.1
routing.nat.enabled = true
routing.nat.interface = $SRV_IF"
fi
SERVER_ROAMING_LINE="roaming.enabled = true"
SERVER_DEVICE_LINE="tun.device_type = $SERVER_DEVICE_TYPE"
CLIENT_ROAMING_LINE="roaming = required"
CLIENT_DEVICE_LINE="device_type = $CLIENT_DEVICE_TYPE"
CLIENT_IPV6_LINE="ipv6 = $CLIENT_IPV6"
CLIENT_LEAK_LINES="allow_ipv4_leak = false
allow_ipv6_leak = false"
if [ "$FLAVOR" = legacy ]; then
  SERVER_ROAMING_LINE=
  SERVER_DEVICE_LINE=
  CLIENT_ROAMING_LINE=
  CLIENT_DEVICE_LINE=
  CLIENT_IPV6_LINE=
  CLIENT_LEAK_LINES=
fi

if [ "$ROUTING" = split ]; then
  ROUTES="route = 198.18.46.1/32
route = fd46:ffff::1/128"
fi

cat >"$WORK/server.conf" <<EOF
[auth]
users_file = $WORK/users.conf
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = info
[profile:matrix]
enabled = true
identity_key = $WORK/identity.key
bind.address = $BIND_ADDRESS
bind.port = $PORT
bind.transport = $TRANSPORT
$SERVER_ROAMING_LINE
tun.name = ${TUN_IF}s
tun.mtu = 1400
$SERVER_DEVICE_LINE
$TUN_CONFIG
routing.client_to_client = false
routing.forward_private = true
$ROUTES
dns.enabled = false
obf.mode = fake-tls
obf.quic.enabled = $QUIC
obf.quic.cid_length = 8
obf.quic.version = 1
obf.heartbeat.enabled = true
perf.connection.max_clients = 4
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0
EOF
: >"$WORK/users.conf"
if ! printf '%s\n' matrix-pass-1234 | "$SERVER_BIN" add-client matrix-user --password-stdin \
  --profiles matrix "${USER_ARGS[@]}" -c "$WORK/server.conf" >"$WORK/add-user.log" 2>&1; then
  bad "create matrix user"
  tail -n 80 "$WORK/add-user.log"
  exit 1
fi

SOCKET_ARGS=-lnt
if [ "$TRANSPORT" = udp ]; then SOCKET_ARGS=-lnu; fi
ip netns exec "$SRV_NS" env QELI_CONTROL_SOCKET="$WORK/control.sock" \
  "$SERVER_BIN" server -c "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
if wait_for 100 "ip netns exec $SRV_NS ss $SOCKET_ARGS | grep -q ':$PORT'"; then
  ok "server listens on outer IPv$OUTER/$TRANSPORT"
else
  bad "server listens on outer IPv$OUTER/$TRANSPORT"
  tail -n 120 "$WORK/server.log"
  exit 1
fi

cat >"$WORK/client.conf" <<EOF
[qeli]
server = $SERVER_AUTHORITY
proto = $TRANSPORT
$CLIENT_ROAMING_LINE
user = matrix-user
pass = matrix-pass-1234
mode = fake-tls
quic = $QUIC
dev = $TUN_IF
bind_static = false
$CLIENT_DEVICE_LINE
gateway = $GATEWAY
$CLIENT_IPV6_LINE
dns = off
mtu = 0
$CLIENT_LEAK_LINES
timeout = 8
[logging]
level = info
EOF
chmod 600 "$WORK/client.conf"
ip netns exec "$CLI_NS" env QELI_KNOWN_HOSTS="$WORK/known-hosts" \
  QELI_DEVICE_ID_FILE="$WORK/device-id" \
  "$CLIENT_BIN" client -c "$WORK/client.conf" >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!
if wait_for 150 "ip netns exec $CLI_NS ip link show $TUN_IF"; then
  ok "client established inner $INNER TUN"
else
  bad "client established inner $INNER TUN"
  tail -n 160 "$WORK/client.log"
  tail -n 100 "$WORK/server.log"
  exit 1
fi

if [ "$OUTER" = 4 ]; then
  check "carrier uses the requested outer IPv4 peer" \
    "ip netns exec $CLI_NS ss -${TRANSPORT:0:1}np | grep -q '10.46.2.2:$PORT'"
else
  check "carrier uses the requested outer IPv6 peer" \
    "ip netns exec $CLI_NS ss -${TRANSPORT:0:1}np | grep -q '\[fd46:2::2\]:$PORT'"
fi

if [ "$ACTIVE_CHECKS" = 4 ] || [ "$ACTIVE_CHECKS" = dual ]; then
  check_eventually "authenticated IPv4 address is installed" \
    "ip netns exec $CLI_NS ip -4 addr show dev $TUN_IF | grep -q '10.86.0.2/$CLIENT_IPV4_PREFIX'"
  check "IPv4 target route uses the tunnel" \
    "ip netns exec $CLI_NS ip -4 route get 198.18.46.1 | grep -q 'dev $TUN_IF'"
  check "inner IPv4 traffic crosses the tunnel" \
    "ip netns exec $CLI_NS ping -4 -c3 -W2 198.18.46.1"
fi
if [ "$ACTIVE_CHECKS" = 6 ] || [ "$ACTIVE_CHECKS" = dual ]; then
  check_eventually "authenticated IPv6 address is installed" \
    "ip netns exec $CLI_NS ip -6 addr show dev $TUN_IF | grep -q 'fd86::2/$CLIENT_IPV6_PREFIX'"
  check "IPv6 target route uses the tunnel" \
    "ip netns exec $CLI_NS ip -6 route get fd46:ffff::1 | grep -q 'dev $TUN_IF'"
  check "inner IPv6 traffic crosses the tunnel" \
    "ip netns exec $CLI_NS ping -6 -c3 -W2 fd46:ffff::1"
fi

  if [ "$FLAVOR" = tap ]; then
    check "client interface is a real TAP device" \
      "ip netns exec $CLI_NS ip tuntap show | grep -q '^$TUN_IF: tap'"
    if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/tap_ipv6_control_probe.py" \
      "$TUN_IF" fd86::2 fd86::1 64 >"$WORK/tap-control.log" 2>&1; then
      ok "TAP answers IPv6 NDP and Router Solicitation locally"
    else
      bad "TAP answers IPv6 NDP and Router Solicitation locally"
      cat "$WORK/tap-control.log" >&2
    fi
  fi
if [ "$ROUTING" = full ] && [ "$INNER" = 4 ]; then
  check "IPv6 cannot leak from an IPv4-only full tunnel" \
    "! ip netns exec $CLI_NS ping -6 -c1 -W1 fd46:ffff::1"
elif [ "$ROUTING" = full ] && [ "$INNER" = 6 ]; then
  check "IPv4 cannot leak from an IPv6-only full tunnel" \
    "! ip netns exec $CLI_NS ping -4 -c1 -W1 198.18.46.1"
elif [ "$ROUTING" = split ]; then
  check "unrelated IPv4 remains outside a split tunnel" \
    "ip netns exec $CLI_NS ip -4 route get 198.18.46.2 | grep -q 'dev $CLI_IF'"
  check "unrelated IPv6 remains outside a split tunnel" \
    "ip netns exec $CLI_NS ip -6 route get fd46:ffff::2 | grep -q 'dev $CLI_IF'"
  check "unrelated split IPv4 remains reachable" \
    "ip netns exec $CLI_NS ping -4 -c1 -W2 198.18.46.2"
  check "unrelated split IPv6 remains reachable" \
    "ip netns exec $CLI_NS ping -6 -c1 -W2 fd46:ffff::2"
fi

OLD_CLIENT_PID=$CLIENT_PID
kill -TERM "$CLIENT_PID" 2>/dev/null || true
if wait_for 100 "! ip netns pids $CLI_NS | grep -qx '$OLD_CLIENT_PID'"; then
  ok "client stopped cleanly"
else
  bad "client stopped cleanly"
fi
CLIENT_PID=
check "clean stop removed the TUN" "! ip netns exec $CLI_NS ip link show $TUN_IF"
check "clean stop restored direct IPv4 routing" \
  "ip netns exec $CLI_NS ping -4 -c1 -W2 198.18.46.1"
check "clean stop restored direct IPv6 routing" \
  "ip netns exec $CLI_NS ping -6 -c1 -W2 fd46:ffff::1"

echo "=== RESULT outer=$OUTER inner=$INNER transport=$TRANSPORT wire=$WIRE routing=$ROUTING: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
  echo "--- client.log ---" >&2
  tail -n 160 "$WORK/client.log" >&2 || true
  echo "--- server.log ---" >&2
  tail -n 120 "$WORK/server.log" >&2 || true
  exit 1
fi

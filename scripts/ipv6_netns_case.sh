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
  echo "usage: $0 <qeli-binary> <outer:4|6> <inner:4|6|dual> <tcp|udp> <fake-tls|quic> <full|split> [base|tap|tapdual|legacy|dns4|dns6|pmtu|mtu]" >&2
}

case "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" in
  [46]:4:tcp:fake-tls:full|[46]:6:tcp:fake-tls:full|\
  [46]:dual:tcp:fake-tls:full|\
  [46]:4:udp:fake-tls:full|[46]:6:udp:fake-tls:full|\
  [46]:4:udp:quic:full|[46]:6:udp:quic:full|\
  [46]:dual:tcp:fake-tls:split|[46]:dual:udp:fake-tls:split) ;;
  *) usage; exit 2 ;;
esac

case "$FLAVOR" in
  base) ;;
  tap) [ "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" = "4:6:tcp:fake-tls:full" ] || { usage; exit 2; } ;;
  tapdual) [ "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" = "4:dual:tcp:fake-tls:full" ] || { usage; exit 2; } ;;
  legacy) [ "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" = "4:4:tcp:fake-tls:full" ] || { usage; exit 2; } ;;
  dns4|dns6) [ "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" = "4:dual:tcp:fake-tls:full" ] || { usage; exit 2; } ;;
  pmtu) [ "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" = "4:6:udp:quic:full" ] || { usage; exit 2; } ;;
  mtu) [ "$OUTER:$INNER:$TRANSPORT:$WIRE:$ROUTING" = "4:6:udp:quic:full" ] || { usage; exit 2; } ;;
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
if [ "$FLAVOR" = dns4 ] || [ "$FLAVOR" = dns6 ]; then
  for command in mount unshare nsenter dbus-daemon busctl resolvectl; do
    command -v "$command" >/dev/null 2>&1 || { echo "required command is missing: $command" >&2; exit 2; }
  done
  RESOLVED_BIN=
  for path in /usr/lib/systemd/systemd-resolved /lib/systemd/systemd-resolved; do
    if [ -x "$path" ]; then RESOLVED_BIN=$path; break; fi
  done
  [ -n "$RESOLVED_BIN" ] || { echo "systemd-resolved is required for DNS integration" >&2; exit 2; }
  RESOLVECTL_REAL=$(command -v resolvectl)
  if [ ! -r "$SCRIPT_DIR/dns_test_server.py" ]; then
    echo "required DNS probe is missing: $SCRIPT_DIR/dns_test_server.py" >&2
    exit 2
  fi
fi
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
WORK=$(mktemp -d "${TMPDIR:-/tmp}/qeli-ipv6-XXXXXX") || exit 2
# Each test creates new namespaces; never reuse the host or another case's journal.
export STATE_DIRECTORY="$WORK/state"
mkdir -m 700 "$STATE_DIRECTORY" || exit 2
SERVER_PID=
CLIENT_PID=
DNS_PID=
CAPTURE_PID=
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
  if [ -n "$CAPTURE_PID" ]; then kill -TERM "$CAPTURE_PID" 2>/dev/null || true; wait "$CAPTURE_PID" 2>/dev/null || true; fi
  if [ -n "$DNS_PID" ]; then kill -TERM "$DNS_PID" 2>/dev/null || true; fi
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

if [ "$FLAVOR" = pmtu ] || [ "$FLAVOR" = mtu ]; then
  ip netns exec "$CLI_NS" ip link set "$CLI_IF" mtu 1280
  ip netns exec "$RTR_NS" ip link set "$RTR_C_IF" mtu 1280
fi
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

# Optional real mixed firewall/packet lifecycle checks, isolated by the outer runner.
mixed_firewall() {
  [ -n "${QELI_MIXED_FIREWALL_CONFIG:-}" ] || return 0
  if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/audit_client_mixed_firewall.py" "$1" \
      --work "$WORK" --tun "$TUN_IF" --interface "$CLI_IF" --routing "$ROUTING" \
      > "$WORK/mixed-$1.log" 2>&1; then
    ok "mixed firewall $1: real packets and foreign state"
  else
    bad "mixed firewall $1: real packets and foreign state"
    cat "$WORK/mixed-$1.log" >&2
    exit 1
  fi
}
if [ -n "${QELI_MIXED_FIREWALL_CONFIG:-}" ]; then
  ip netns exec "$RTR_NS" python3 "$SCRIPT_DIR/audit_client_mixed_firewall.py" echo --work "$WORK" \
    > "$WORK/echo.log" 2>&1 &
  mixed_firewall init
fi
DNS_UPSTREAM=
DNS_UPSTREAM_FAMILY=
if [ "$FLAVOR" = dns4 ]; then
  DNS_UPSTREAM=10.46.2.1
  DNS_UPSTREAM_FAMILY=4
elif [ "$FLAVOR" = dns6 ]; then
  DNS_UPSTREAM=fd46:2::1
  DNS_UPSTREAM_FAMILY=6
fi
if [ -n "$DNS_UPSTREAM" ]; then
  ip netns exec "$RTR_NS" python3 "$SCRIPT_DIR/dns_test_server.py" serve \
    --address "$DNS_UPSTREAM" --log "$WORK/dns-upstream.log" &
  DNS_PID=$!
  if wait_for 50 "ip netns exec $RTR_NS ss -lnu | grep -q ':53'"; then
    ok "deterministic IPv$DNS_UPSTREAM_FAMILY DNS upstream is listening"
  else
    bad "deterministic DNS upstream is listening"
    exit 1
  fi
fi

if [ "$OUTER" = 4 ]; then
  SERVER_AUTHORITY="10.46.2.2:$PORT"
  BIND_ADDRESS=10.46.2.2
else
  SERVER_AUTHORITY="[fd46:2::2]:$PORT"
  BIND_ADDRESS=fd46:2::2
fi
# Optional resolver regression. The enclosing private mount namespace must bind this
# file to /etc/hosts; each sequential cell publishes only its own carrier address.
if [ -n "${QELI_MATRIX_HOSTS_FILE:-}" ]; then
  python3 - <<'PY_CHECK_PRIVATE'
import os
parent = os.environ.get('QELI_CM_HOST_MNT')
current = os.stat('/proc/self/ns/mnt')
if not parent or parent == f'{current.st_dev}:{current.st_ino}':
    raise SystemExit('hostname fixture requires the enclosing private mount namespace')
PY_CHECK_PRIVATE
  [ "$?" = 0 ] || exit 2
  [ -f "$QELI_MATRIX_HOSTS_FILE" ] && [ "$QELI_MATRIX_HOSTS_FILE" -ef /etc/hosts ] || {
    echo 'hostname fixture requires the same privately mounted hosts file' >&2; exit 2;
  }
  printf '127.0.0.1 localhost\n::1 localhost\n%s qeli-matrix.test\n' "$BIND_ADDRESS" > "$QELI_MATRIX_HOSTS_FILE"
  SERVER_AUTHORITY="qeli-matrix.test:$PORT"
fi

# Optional Q21 wire observation runs only inside this fixture's router namespace.
if [ "${QELI_PACKET_AUDIT:-0}" = 1 ] && { [ "$FLAVOR" = pmtu ] || [ "$FLAVOR" = mtu ]; }; then
  ip netns exec "$RTR_NS" python3 "$SCRIPT_DIR/audit_outer_udp_capture.py" "$RTR_C_IF" \
    "$WORK/outer-capture.log" >"$WORK/outer-capture-process.log" 2>&1 &
  CAPTURE_PID=$!
  wait_for 25 "test -f $WORK/outer-capture.log.ready" || { echo 'carrier capture did not start' >&2; exit 2; }
fi
QUIC=false
if [ "$WIRE" = quic ]; then QUIC=true; fi
GATEWAY=false
SERVER_DEVICE_TYPE=tun
CLIENT_DEVICE_TYPE=tun
CLIENT_IPV4_PREFIX=${QELI_EXPECT_CLIENT_IPV4_PREFIX:-32}
CLIENT_IPV6_PREFIX=128
if [ "$FLAVOR" = tap ] || [ "$FLAVOR" = tapdual ]; then
  SERVER_DEVICE_TYPE=tap
  CLIENT_DEVICE_TYPE=tap
  CLIENT_IPV6_PREFIX=64
  [ "$FLAVOR" != tapdual ] || CLIENT_IPV4_PREFIX=24
fi
if [ "$ROUTING" = full ]; then GATEWAY=true; fi


TUN_CONFIG=
CLIENT_IPV6=off
USER_ARGS=(--static-ip 10.86.0.2)
ACTIVE_CHECKS=4
DNS_CONFIG="dns.enabled = false"
CLIENT_DNS=off
CLIENT_MTU=0
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
if [ -n "$DNS_UPSTREAM" ]; then
  DNS_CONFIG="dns.enabled = true
dns.listen = 10.86.0.1
dns.listen_ipv6 = fd86::1
dns.upstream = $DNS_UPSTREAM
dns.upstream_protocol = ${QELI_DNS_UPSTREAM_PROTOCOL:-udp}"
  CLIENT_DNS=tunnel
fi
if [ "$FLAVOR" = mtu ]; then
  CLIENT_MTU=1280
fi
CLIENT_KILL_SWITCH=false
if [ "$ROUTING" = full ] && [ -n "${QELI_MIXED_FIREWALL_CONFIG:-}" ]; then CLIENT_KILL_SWITCH=true; fi
if [ -n "$DNS_UPSTREAM" ] && [ "${QELI_DNS_KILL_SWITCH:-0}" = 1 ]; then CLIENT_KILL_SWITCH=true; fi
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
$DNS_CONFIG
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
dns = $CLIENT_DNS
kill_switch = $CLIENT_KILL_SWITCH
mtu = $CLIENT_MTU
$CLIENT_LEAK_LINES
timeout = 8
[logging]
level = info
EOF
chmod 600 "$WORK/client.conf"
# Fault injection is confined to the initial test client. Restarts use the plain
# binary; full-routing crash checks must be enabled before making a queue persist.
INITIAL_CLIENT_BIN=$CLIENT_BIN
PERSISTENT_CHECK=0
TUN_RELEASE_CAUSE=SIGKILL
if [ -n "${QELI_PERSIST_TUN_SHIM:-}" ] && [ "$ROUTING" = full ]; then
  if [ -n "$DNS_UPSTREAM" ]; then CRASH_ENABLED=${QELI_DNS_CRASH_CHECK:-0}; else CRASH_ENABLED=${QELI_ROUTE_CRASH_CHECK:-0}; fi
  [ "$CRASH_ENABLED" = 1 ] && [ -f "$QELI_PERSIST_TUN_SHIM" ] || { echo 'persistent test requires crash checks and a compiled test shim' >&2; exit 2; }
  PERSISTENT_CHECK=1
  TUN_RELEASE_CAUSE="operator removal after SIGKILL"
  INITIAL_CLIENT_BIN=$WORK/initial-client.sh
  cat >"$INITIAL_CLIENT_BIN" <<EOF
#!/bin/sh
exec env LD_PRELOAD="$QELI_PERSIST_TUN_SHIM" QELI_TEST_PERSIST_NAME="$TUN_IF" QELI_TEST_PERSIST_MARKER="$WORK/persist.ready" "$CLIENT_BIN" "\$@"
EOF
  chmod 700 "$INITIAL_CLIENT_BIN"
fi
persistent_before_release() {
  [ "$PERSISTENT_CHECK" = 1 ] || return 0
  local kind=tun
  local extra=()
  { [ "$FLAVOR" != tap ] && [ "$FLAVOR" != tapdual ]; } || kind=tap
  if [ -n "$DNS_UPSTREAM" ]; then extra=(--resolver-pid "$RESOLVER_PID" --dns-marker "$DNS_MARKER"); fi
  if python3 "$SCRIPT_DIR/audit_persistent_tun.py" --namespace "$CLI_NS" --tun "$TUN_IF" \
      --work "$WORK" --binary "$CLIENT_BIN" --owner-pid "$CRASH_CLIENT_PID" --kind "$kind" \
      "${extra[@]}" > "$WORK/persistent-check.log" 2>&1; then
    ok "persistent $kind refusal preserves state before explicit operator removal"
  else
    bad "persistent $kind refusal preserves state before explicit operator removal"
    cat "$WORK/persistent-check.log" >&2
    exit 1
  fi
}
if [ -n "$DNS_UPSTREAM" ]; then
  printf '%s\n' 'nameserver 127.0.0.53' >"$WORK/resolv.conf"
  cat >"$WORK/client-mount.sh" <<EOF
#!/bin/sh
set -eu
mount --make-rprivate /
mount --bind "$WORK/resolv.conf" /etc/resolv.conf
# Each client owns a real resolver and bus in this private mount/network context.
mount -t tmpfs tmpfs /run
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/qeli-matrix-bus
export SYSTEMD_LOG_TARGET=console SYSTEMD_LOG_LEVEL=info
printf '%s\n' '<busconfig><type>system</type><listen>unix:path=/run/qeli-matrix-bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>' > /run/qeli-dbus.conf
dbus-daemon --config-file=/run/qeli-dbus.conf --nofork --nopidfile >"$WORK/dbus.log" 2>&1 &
for attempt in \$(seq 1 50); do [ ! -S /run/qeli-matrix-bus ] || break; sleep 0.1; done
chmod 666 /run/qeli-matrix-bus
mkdir -p /run/systemd/resolve
chown systemd-resolve:systemd-resolve /run/systemd/resolve
"$RESOLVED_BIN" >"$WORK/resolved.log" 2>&1 &
printf '%s\n' "\$!" > "$WORK/resolved.pid"
ready=0
for attempt in \$(seq 1 100); do
  if busctl --system --auto-start=no call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner s org.freedesktop.resolve1 >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.1
done
[ "\$ready" = 1 ]
exec env QELI_KNOWN_HOSTS="$WORK/known-hosts" QELI_DEVICE_ID_FILE="$WORK/device-id" \
  "$INITIAL_CLIENT_BIN" client -c "$WORK/client.conf"
EOF
  chmod 700 "$WORK/client-mount.sh"
  ip netns exec "$CLI_NS" unshare --mount --propagation private \
    "$WORK/client-mount.sh" >"$WORK/client.log" 2>&1 &
else
  ip netns exec "$CLI_NS" env QELI_KNOWN_HOSTS="$WORK/known-hosts" \
    QELI_DEVICE_ID_FILE="$WORK/device-id" \
    "$INITIAL_CLIENT_BIN" client -c "$WORK/client.conf" >"$WORK/client.log" 2>&1 &
fi
CLIENT_PID=$!
if wait_for 150 "ip netns exec $CLI_NS ip link show $TUN_IF"; then
  ok "client established inner $INNER TUN"
else
  bad "client established inner $INNER TUN"
  tail -n 160 "$WORK/client.log"
  tail -n 100 "$WORK/server.log"
  exit 1
fi

if [ "$PERSISTENT_CHECK" = 1 ]; then
  ip netns exec "$CLI_NS" ip -j link show dev "$TUN_IF" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["ifindex"])' > "$WORK/persist.ifindex"
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
  check_eventually "IPv4 target route uses the tunnel" \
    "ip netns exec $CLI_NS ip -4 route get 198.18.46.1 | grep -q 'dev $TUN_IF'"
  check "inner IPv4 traffic crosses the tunnel" \
    "ip netns exec $CLI_NS ping -4 -c3 -W2 198.18.46.1"
fi
if [ "$ACTIVE_CHECKS" = 6 ] || [ "$ACTIVE_CHECKS" = dual ]; then
  check_eventually "authenticated IPv6 address is installed" \
    "ip netns exec $CLI_NS ip -6 addr show dev $TUN_IF | grep -q 'fd86::2/$CLIENT_IPV6_PREFIX'"
  check_eventually "IPv6 target route uses the tunnel" \
    "ip netns exec $CLI_NS ip -6 route get fd46:ffff::1 | grep -q 'dev $TUN_IF'"
  check "inner IPv6 traffic crosses the tunnel" \
    "ip netns exec $CLI_NS ping -6 -c3 -W2 fd46:ffff::1"
fi
if [ -n "$DNS_UPSTREAM" ]; then
  if [ "$CLIENT_KILL_SWITCH" = true ]; then
    for tool in iptables ip6tables; do
      check "DNS tunnel has an active $tool kill-switch" "ip netns exec $CLI_NS $tool -C OUTPUT -j QELI_KS_$TUN_IF && ip netns exec $CLI_NS $tool -C QELI_KS_$TUN_IF -j DROP"
    done
  fi
  DNS_INDEX=$(ip netns exec "$CLI_NS" ip -j link show dev "$TUN_IF" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["ifindex"])')
  case "$DNS_INDEX" in ''|*[!0-9]*|0) bad "DNS target has a valid numeric ifindex"; exit 1 ;; esac
  DNS_BOOT=$(cat /proc/sys/kernel/random/boot_id)
  DNS_NAMESPACE=$(ip netns exec "$CLI_NS" stat -Lc '%d-%i' /proc/self/ns/net)
  DNS_COOKIE=$(ip netns exec "$CLI_NS" python3 -c 'import socket,struct; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); print(struct.unpack("=Q",s.getsockopt(socket.SOL_SOCKET,getattr(socket,"SO_NETNS_COOKIE",71),8))[0])')
  DNS_MARKER="$STATE_DIRECTORY/dns-link-v2-$DNS_BOOT-$DNS_NAMESPACE-$DNS_COOKIE-$DNS_INDEX.state"
  check_eventually "DNS owns the current link marker" "test -f $DNS_MARKER"
  RESOLVER_PID=$(cat "$WORK/resolved.pid")
  check_eventually "real resolved reports both tunnel DNS servers" \
    "nsenter -t $RESOLVER_PID -m -n env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/qeli-matrix-bus $RESOLVECTL_REAL dns $DNS_INDEX | grep -Fq '10.86.0.1 fd86::1'"
  check_eventually "real resolved reports the catch-all domain" \
    "nsenter -t $RESOLVER_PID -m -n env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/qeli-matrix-bus $RESOLVECTL_REAL domain $DNS_INDEX | grep -Fq '~.'"
  if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/dns_test_server.py" query \
    --server 127.0.0.53 --name a-stub.release.test --type A --expect 192.0.2.80; then
    ok "A query crosses the real systemd-resolved stub and tunnel"
  else
    bad "A query crosses the real systemd-resolved stub and tunnel"
  fi
  if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/dns_test_server.py" query \
    --server 127.0.0.53 --name aaaa-stub.release.test --type AAAA --expect 2001:db8::80; then
    ok "AAAA query crosses the real systemd-resolved stub and tunnel"
  else
    bad "AAAA query crosses the real systemd-resolved stub and tunnel"
  fi
  if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/dns_test_server.py" query \
    --server 10.86.0.1 --name a-v4.release.test --type A --expect 192.0.2.80; then
    ok "A query resolves through the IPv4 tunnel DNS listener"
  else
    bad "A query resolves through the IPv4 tunnel DNS listener"
  fi
  if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/dns_test_server.py" query \
    --server 10.86.0.1 --name aaaa-v4.release.test --type AAAA --expect 2001:db8::80; then
    ok "AAAA query resolves through the IPv4 tunnel DNS listener"
  else
    bad "AAAA query resolves through the IPv4 tunnel DNS listener"
  fi
  if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/dns_test_server.py" query \
    --server fd86::1 --name a-v6.release.test --type A --expect 192.0.2.80; then
    ok "A query resolves through the IPv6 tunnel DNS listener"
  else
    bad "A query resolves through the IPv6 tunnel DNS listener"
  fi
  if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/dns_test_server.py" query \
    --server fd86::1 --name aaaa-v6.release.test --type AAAA --expect 2001:db8::80; then
    ok "AAAA query resolves through the IPv6 tunnel DNS listener"
  else
    bad "AAAA query resolves through the IPv6 tunnel DNS listener"
  fi
  for dns_server in 10.86.0.1 fd86::1; do
    for dns_type in A AAAA; do
      dns_expect=192.0.2.80; [ "$dns_type" = A ] || dns_expect=2001:db8::80
      if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/dns_test_server.py" query --tcp \
        --server "$dns_server" --name "tcp-$dns_type-${dns_server//:/-}.release.test" --type "$dns_type" --expect "$dns_expect"; then
        ok "TCP $dns_type via tunnel DNS $dns_server"
      else
        bad "TCP $dns_type via tunnel DNS $dns_server"
      fi
    done
    if ip netns exec "$CLI_NS" python3 "$SCRIPT_DIR/dns_test_server.py" query \
      --server "$dns_server" --name "tc.${dns_server//:/-}.release.test" --type A --expect 192.0.2.80; then
      ok "UDP query for TC fixture via tunnel DNS $dns_server"
    else
      bad "UDP query for TC fixture via tunnel DNS $dns_server"
    fi
  done
  if [ "${QELI_DNS_UPSTREAM_PROTOCOL:-udp}" = udp ]; then
    check "upstream TC caused a TCP retry" "grep -q 'transport=udp tc=1 .*qname=tc.' $WORK/dns-upstream.log && grep -q 'transport=tcp tc=0 .*qname=tc.' $WORK/dns-upstream.log"
  else
    check "forced TCP upstream sent no UDP queries" "grep -q 'transport=tcp' $WORK/dns-upstream.log && ! grep -q 'transport=udp' $WORK/dns-upstream.log"
  fi
  check_eventually "the configured IPv$DNS_UPSTREAM_FAMILY upstream received A and AAAA" \
    "grep -q 'qtype=A ' $WORK/dns-upstream.log && grep -q 'qtype=AAAA ' $WORK/dns-upstream.log"
fi
if [ "$FLAVOR" = pmtu ]; then
  check_eventually "uplink PMTU certified the 1280-byte outer path" \
    "grep -q 'UDP path probe: inner MTU 1400, uplink UDP payload budget' $WORK/client.log"
  check_eventually "downlink PMTU certified the 1280-byte outer path" \
    "grep -q 'reverse-probe certified UDP downlink budget.*(was 548)' $WORK/server.log"
  UPLINK_BUDGET=$(sed -n 's/.*uplink UDP payload budget \([0-9][0-9]*\).*/\1/p' "$WORK/client.log" | tail -n1)
  DOWNLINK_BUDGET=$(sed -n 's/.*reverse-probe certified UDP downlink budget \([0-9][0-9]*\).*/\1/p' "$WORK/server.log" | tail -n1)
  check "uplink budget fits the 1280-byte carrier" \
    "test -n '$UPLINK_BUDGET' && test '$UPLINK_BUDGET' -gt 548 && test '$UPLINK_BUDGET' -lt 1252"
  check "downlink budget fits the 1280-byte carrier" \
    "test -n '$DOWNLINK_BUDGET' && test '$DOWNLINK_BUDGET' -gt 548 && test '$DOWNLINK_BUDGET' -lt 1252"
  check "auto MTU keeps the negotiated 1400-byte inner TUN" \
    "test \"\$(ip netns exec $CLI_NS cat /sys/class/net/$TUN_IF/mtu)\" = 1400"
  check "a 1400-byte inner IPv6 packet crosses the certified path via DATA_FRAG" \
    "ip netns exec $CLI_NS ping -6 -M do -s 1352 -c3 -W2 fd46:ffff::1"
fi
if [ "$FLAVOR" = mtu ]; then
  check "client TUN uses the IPv6 minimum MTU" \
    "test \"\$(ip netns exec $CLI_NS cat /sys/class/net/$TUN_IF/mtu)\" = 1280"
  check "a full 1280-byte inner IPv6 packet crosses DATA_FRAG" \
    "ip netns exec $CLI_NS ping -6 -M do -s 1232 -c3 -W2 fd46:ffff::1"
  ip netns exec "$RTR_NS" ip -6 route replace fd86::/64 via fd46:2::2 dev "$RTR_S_IF"
  ip netns exec "$RTR_NS" ping -6 -M do -s 1300 -c1 -W2 fd86::2 \
    >"$WORK/ptb.log" 2>&1 || true
  check "oversized downlink receives ICMPv6 Packet Too Big with MTU 1280" \
    "grep -Eq 'Packet too big.*mtu.?=.?1280|mtu 1280' $WORK/ptb.log"
  check "downlink succeeds at the advertised 1280-byte MTU" \
    "ip netns exec $RTR_NS ping -6 -M do -s 1232 -c3 -W2 fd86::2"
fi


if [ -n "$CAPTURE_PID" ]; then
  touch "$WORK/outer-capture.log.stop"
  if wait "$CAPTURE_PID"; then ok "observed UDP carrier has both directions and no outer IP fragmentation";
  else bad "observed UDP carrier has both directions and no outer IP fragmentation"; fi
  CAPTURE_PID=
  cat "$WORK/outer-capture.log" 2>/dev/null || true
fi

  if [ "$FLAVOR" = tap ] || [ "$FLAVOR" = tapdual ]; then
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

mixed_firewall active

# Optional physical route recovery using a real SIGKILL and a fresh client process.
ROUTE_CRASH_CHECK=0
if [ "${QELI_ROUTE_CRASH_CHECK:-0}" = 1 ] && [ "$ROUTING" = full ] && [ -z "$DNS_UPSTREAM" ]; then
  ROUTE_CRASH_CHECK=1
  ip netns exec "$CLI_NS" ip route add 203.0.113.77 via 10.46.1.1 dev "$CLI_IF" proto static
  ip netns exec "$CLI_NS" ip route show exact 203.0.113.77 > "$WORK/operator-route-before-crash.txt"
  CRASH_CLIENT_PID=$CLIENT_PID
  kill -KILL "$CLIENT_PID"
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=
  persistent_before_release
  mixed_firewall crashed
  check_eventually "$TUN_RELEASE_CAUSE releases the original TUN" "! ip netns exec $CLI_NS ip link show $TUN_IF"
  check "SIGKILL leaves the physical carrier bypass" "ip netns exec $CLI_NS ip -$OUTER route show exact $BIND_ADDRESS | grep -q 'dev $CLI_IF'"
  if [ "${QELI_EXPECT_ROUTE_JOURNAL:-1}" = 1 ]; then
    check "SIGKILL retains the durable client route journal" "test -s '$STATE_DIRECTORY/client-routes.state' && grep -Fq '\"interface\":\"$TUN_IF\"' '$STATE_DIRECTORY/client-routes.state'"
    cp "$STATE_DIRECTORY/client-routes.state" "$WORK/routes-after-crash.state"
  fi
  ip netns exec "$CLI_NS" env QELI_KNOWN_HOSTS="$WORK/known-hosts" \
    QELI_DEVICE_ID_FILE="$WORK/device-id" \
    "$CLIENT_BIN" client -c "$WORK/client.conf" >"$WORK/client-route-restart.log" 2>&1 &
  CLIENT_PID=$!
  check_eventually "route restart creates a new TUN" "ip netns exec $CLI_NS ip link show $TUN_IF"
  if [ "$INNER" = 4 ]; then
    check_eventually "route restart carries authenticated IPv4 traffic" "ip netns exec $CLI_NS ping -4 -c1 -W2 198.18.46.1"
  else
    check_eventually "route restart carries authenticated IPv6 traffic" "ip netns exec $CLI_NS ping -6 -c1 -W2 fd46:ffff::1"
  fi
fi

# Optional crash-recovery stage uses the same real resolved/bus after SIGKILL.
if [ "${QELI_DNS_CRASH_CHECK:-0}" = 1 ] && [ -n "$DNS_UPSTREAM" ]; then
  CRASH_DNS_MARKER=$DNS_MARKER
  CRASH_DNS_INDEX=$DNS_INDEX
  cp "$DNS_MARKER" "$WORK/dns-before-crash.state"
  CRASH_CLIENT_PID=$CLIENT_PID
  kill -KILL "$CLIENT_PID"
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=
  persistent_before_release
  mixed_firewall crashed
  check_eventually "$TUN_RELEASE_CAUSE releases the client TUN" "! ip netns exec $CLI_NS ip link show $TUN_IF"
  check_eventually "$TUN_RELEASE_CAUSE removes DNS from real resolved with its link" \
    "nsenter -t $RESOLVER_PID -m -n env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/qeli-matrix-bus $RESOLVECTL_REAL dns > $WORK/resolved-after-crash.txt && ! grep -Fq 'Link $CRASH_DNS_INDEX (' $WORK/resolved-after-crash.txt"
  check "SIGKILL retains the original DNS ownership marker" "cmp $CRASH_DNS_MARKER $WORK/dns-before-crash.state"
  if [ "$CLIENT_KILL_SWITCH" = true ]; then
    for tool in iptables ip6tables; do
      check "SIGKILL retains the $tool kill-switch" "ip netns exec $CLI_NS $tool -C OUTPUT -j QELI_KS_$TUN_IF && ip netns exec $CLI_NS $tool -C QELI_KS_$TUN_IF -j DROP"
    done
  fi
  # Model the same nsfs inode with a different kernel generation. This does not
  # claim to force real inode reuse; startup must leave this evidence untouched.
  python3 - "$CRASH_DNS_MARKER" "$WORK" <<'PYDNS'
import json,sys
from pathlib import Path
source, work = Path(sys.argv[1]), Path(sys.argv[2])
record = json.loads(source.read_text())
record['link']['scope']['network_cookie'] += 1
scope, index = record['link']['scope'], record['link']['index']
foreign = source.parent / f"dns-link-v2-{scope['boot']}-{scope['device']}-{scope['inode']}-{scope['network_cookie']}-{index}.state"
foreign.write_text(json.dumps(record)); foreign.chmod(0o600)
(work/'foreign-marker-path').write_text(str(foreign))
(work/'foreign-marker-before.state').write_bytes(foreign.read_bytes())
record['version'] = 1
record['link']['scope'].pop('network_cookie')
legacy = source.parent / f"dns-link-v1-{scope['boot']}-{scope['device']}-{scope['inode']}-{index}.state"
legacy.write_text(json.dumps(record)); legacy.chmod(0o600)
(work/'legacy-marker-path').write_text(str(legacy))
(work/'legacy-marker-before.state').write_bytes(legacy.read_bytes())
PYDNS
  FOREIGN_DNS_MARKER=$(cat "$WORK/foreign-marker-path")
  LEGACY_DNS_MARKER=$(cat "$WORK/legacy-marker-path")
  nsenter -t "$RESOLVER_PID" -m -n env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/qeli-matrix-bus \
    QELI_KNOWN_HOSTS="$WORK/known-hosts" QELI_DEVICE_ID_FILE="$WORK/device-id" \
    "$CLIENT_BIN" client -c "$WORK/client.conf" >"$WORK/client-restart.log" 2>&1 &
  CLIENT_PID=$!
  check_eventually "restart retires only the absent original DNS marker" "test ! -e $CRASH_DNS_MARKER"
  check_eventually "restart creates a new client TUN" "ip netns exec $CLI_NS ip link show $TUN_IF"
  DNS_INDEX=$(ip netns exec "$CLI_NS" ip -j link show dev "$TUN_IF" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["ifindex"])')
  DNS_MARKER="$STATE_DIRECTORY/dns-link-v2-$DNS_BOOT-$DNS_NAMESPACE-$DNS_COOKIE-$DNS_INDEX.state"
  check_eventually "restart owns a new v2 DNS marker" "test -f $DNS_MARKER"
  check_eventually "restart restores tunnel DNS in real resolved" \
    "nsenter -t $RESOLVER_PID -m -n env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/qeli-matrix-bus $RESOLVECTL_REAL dns $DNS_INDEX | grep -Fq '10.86.0.1 fd86::1'"
  check "foreign namespace generation marker remains unchanged" "cmp $FOREIGN_DNS_MARKER $WORK/foreign-marker-before.state"
  check "legacy v1 evidence remains unchanged" "cmp $LEGACY_DNS_MARKER $WORK/legacy-marker-before.state"
  check_eventually "restart reports legacy evidence without adopting it" "grep -q 'Legacy DNS v1 marker' $WORK/client-restart.log"
  check "DNS queries work through the stub after restart" \
    "ip netns exec $CLI_NS python3 $SCRIPT_DIR/dns_test_server.py query --server 127.0.0.53 --name after-crash.release.test --type A --expect 192.0.2.80"
  if [ "$CLIENT_KILL_SWITCH" = true ]; then
    for tool in iptables ip6tables; do
      check "restart commits $tool protection and retires its guard" "ip netns exec $CLI_NS $tool -C OUTPUT -j QELI_KS_$TUN_IF && ip netns exec $CLI_NS $tool -C QELI_KS_$TUN_IF -j DROP && ! ip netns exec $CLI_NS $tool -C OUTPUT -m comment --comment qeli-ks-rebuild:$TUN_IF -j DROP"
    done
  fi
fi

if [ "$ROUTE_CRASH_CHECK" = 1 ] || { [ "${QELI_DNS_CRASH_CHECK:-0}" = 1 ] && [ -n "$DNS_UPSTREAM" ]; }; then
  mixed_firewall restarted
fi

# Optional operator replacement before clean stop. DNS crash cells already lost
# the original process journal, so they cannot prove this ownership regression.
ROUTE_IDENTITY_CHECK=0
if [ "${QELI_ROUTE_IDENTITY_CHECK:-0}" = 1 ] && [ "$ROUTE_CRASH_CHECK" = 0 ] && [ "$ROUTING" = full ] && [ -z "$DNS_UPSTREAM" ]; then
  ROUTE_IDENTITY_CHECK=1
  if [ "$OUTER" = 4 ]; then CARRIER_GATEWAY=10.46.1.1; else CARRIER_GATEWAY=fd46:1::1; fi
  check "client installed a carrier bypass before operator replacement" \
    "ip netns exec $CLI_NS ip -$OUTER route show exact $BIND_ADDRESS | grep -Fq 'via $CARRIER_GATEWAY dev $CLI_IF'"
  check "operator changes the carrier route to static" \
    "ip netns exec $CLI_NS ip -$OUTER route change $BIND_ADDRESS via $CARRIER_GATEWAY dev $CLI_IF proto static && ip netns exec $CLI_NS ip -$OUTER route show exact $BIND_ADDRESS > $WORK/operator-carrier-before.txt && grep -q 'proto static' $WORK/operator-carrier-before.txt"
fi

OLD_CLIENT_PID=$CLIENT_PID
kill -TERM "$CLIENT_PID" 2>/dev/null || true
if wait_for 100 "! ip netns pids $CLI_NS | grep -qx '$OLD_CLIENT_PID'"; then
  ok "client stopped cleanly"
else
  bad "client stopped cleanly"
fi
CLIENT_PID=
if [ "$ROUTE_CRASH_CHECK" = 1 ]; then
  check "stop after route recovery removes the carrier bypass" "test -z \"\$(ip netns exec $CLI_NS ip -$OUTER route show exact $BIND_ADDRESS)\""
  check "stop after route recovery removes IPv4 blackholes" "test -z \"\$(ip netns exec $CLI_NS ip -4 route show type blackhole)\""
  check "stop after route recovery removes IPv6 blackholes" "test -z \"\$(ip netns exec $CLI_NS ip -6 route show type blackhole)\""
  check "route recovery preserves the unrelated operator route" "ip netns exec $CLI_NS ip route show exact 203.0.113.77 > $WORK/operator-route-after-crash.txt && cmp $WORK/operator-route-before-crash.txt $WORK/operator-route-after-crash.txt"
  if [ "${QELI_EXPECT_ROUTE_JOURNAL:-1}" = 1 ]; then
    check "clean stop retires the recovered route records" "! grep -Fq '\"interface\":\"$TUN_IF\"' '$STATE_DIRECTORY/client-routes.state'"
  fi
fi
if [ "$ROUTE_IDENTITY_CHECK" = 1 ]; then
  check "clean stop preserves the operator carrier replacement" \
    "ip netns exec $CLI_NS ip -$OUTER route show exact $BIND_ADDRESS > $WORK/operator-carrier-after.txt && cmp $WORK/operator-carrier-before.txt $WORK/operator-carrier-after.txt"
fi
if [ -n "$DNS_UPSTREAM" ]; then
  check_eventually "clean stop reverted per-link DNS" \
    "nsenter -t $RESOLVER_PID -m -n env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/qeli-matrix-bus $RESOLVECTL_REAL dns > $WORK/resolved-after.txt && ! grep -Fq 'Link $DNS_INDEX (' $WORK/resolved-after.txt"
  check "clean stop removed the resolver ownership marker" \
    "test ! -e $DNS_MARKER"
fi
  if [ "$CLIENT_KILL_SWITCH" = true ]; then
    for tool in iptables ip6tables; do
      check "clean stop retires $tool kill-switch and recovery guard" "! ip netns exec $CLI_NS $tool -S QELI_KS_$TUN_IF && ! ip netns exec $CLI_NS $tool -C OUTPUT -m comment --comment qeli-ks-rebuild:$TUN_IF -j DROP"
    done
  fi
check "clean stop removed the TUN" "! ip netns exec $CLI_NS ip link show $TUN_IF"
check "clean stop restored direct IPv4 routing" \
  "ip netns exec $CLI_NS ping -4 -c1 -W2 198.18.46.1"
check "clean stop restored direct IPv6 routing" \
  "ip netns exec $CLI_NS ping -6 -c1 -W2 fd46:ffff::1"

mixed_firewall stopped

echo "=== RESULT outer=$OUTER inner=$INNER transport=$TRANSPORT wire=$WIRE routing=$ROUTING: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
  echo "--- client.log ---" >&2
  tail -n 160 "$WORK/client.log" >&2 || true
  echo "--- server.log ---" >&2
  tail -n 120 "$WORK/server.log" >&2 || true
  exit 1
fi

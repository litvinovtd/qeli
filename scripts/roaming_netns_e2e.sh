#!/usr/bin/env bash
# Linux TCP make-before-break integration test. Everything runs in three isolated network
# namespaces; no host route or production process is changed.
# QELI_ROAMING_DEVICE_TYPE selects a Linux tun or tap endpoint on both sides (default: tun).
# QELI_ROAMING_MULTIPATH_MODE selects single, fixed, or adaptive stream membership.
# The perf case may override QELI_ROAMING_SERVER_ENABLED and
# QELI_ROAMING_CLIENT_POLICY; success/soak keep their safe required defaults.
# resume injects a one-sided carrier reset inside the server grace; grace-expiry keeps replacement
# carriers blackholed until the server reaps the locator and the client performs a full AUTH.
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
CASE=${2:-${CASE:-success}}
WIRE_MODE=${3:-${QELI_ROAMING_TCP_WIRE_MODE:-fake-tls}}
DEVICE_TYPE=${QELI_ROAMING_DEVICE_TYPE:-tun}
MULTIPATH_MODE=${QELI_ROAMING_MULTIPATH_MODE:-single}
DEFAULT_CLIENT_ROAMING_POLICY=required
if [ "$CASE" = multinode ]; then
  DEFAULT_CLIENT_ROAMING_POLICY=auto
fi
SERVER_ROAMING_ENABLED=${QELI_ROAMING_SERVER_ENABLED:-true}
DEFAULT_SERVER_ROAMING_GRACE_SECS=30
SERVER_LOG_LEVEL=info
if [ "$CASE" = grace-expiry ]; then
  DEFAULT_SERVER_ROAMING_GRACE_SECS=3
  SERVER_LOG_LEVEL=debug
fi
SERVER_ROAMING_GRACE_SECS=${QELI_ROAMING_SERVER_GRACE_SECS:-$DEFAULT_SERVER_ROAMING_GRACE_SECS}
CLIENT_ROAMING_POLICY=${QELI_ROAMING_CLIENT_POLICY:-$DEFAULT_CLIENT_ROAMING_POLICY}
WORK=/tmp/qeli-roaming-netns-${WIRE_MODE}-${DEVICE_TYPE}-${MULTIPATH_MODE}
CLI_NS=qrm-cli
RTR_NS=qrm-rtr
SRV_NS=qrm-srv
PASS=0
FAIL=0
SERVER_JOB_PID=
SECONDARY_SERVER_JOB_PID=
CLIENT_JOB_PID=
TARGET_JOB_PID=
LOAD_JOB_PID=

usage() {
  echo "usage: $0 [qeli-binary] [success|resume|grace-expiry|soak|perf|multinode] [fake-tls|reality-tls|plain|obfs-ws|obfs-none|obfs-awg]" >&2
}

if [ "$#" -gt 3 ]; then
  usage
  exit 2
fi
case "$CASE" in
  success|resume|grace-expiry|soak|perf|multinode) ;;
  *)
    usage
    exit 2
    ;;
esac
case "$DEVICE_TYPE" in
  tun)
    EXPECTED_DEVICE_KIND=1
    ;;
  tap)
    EXPECTED_DEVICE_KIND=2
    ;;
  *)
    echo "QELI_ROAMING_DEVICE_TYPE must be tun or tap" >&2
    exit 2
    ;;
esac
case "$MULTIPATH_MODE" in
  single)
    MULTIPATH_ENABLED=false
    MULTIPATH_MAX_STREAMS=1
    MULTIPATH_ADAPTIVE=false
    ;;
  fixed)
    MULTIPATH_ENABLED=true
    MULTIPATH_MAX_STREAMS=3
    MULTIPATH_ADAPTIVE=false
    ;;
  adaptive)
    MULTIPATH_ENABLED=true
    MULTIPATH_MAX_STREAMS=3
    MULTIPATH_ADAPTIVE=true
    ;;
  *)
    echo "QELI_ROAMING_MULTIPATH_MODE must be single, fixed, or adaptive" >&2
    exit 2
    ;;
esac
case "$SERVER_ROAMING_ENABLED" in
  true|false) ;;
  *)
    echo "QELI_ROAMING_SERVER_ENABLED must be true or false" >&2
    exit 2
    ;;
esac
case "$SERVER_ROAMING_GRACE_SECS" in
  ''|*[!0-9]*)
    echo "QELI_ROAMING_SERVER_GRACE_SECS must be an integer from 1 to 3600" >&2
    exit 2
    ;;
esac
if [ "$SERVER_ROAMING_GRACE_SECS" -lt 1 ] || [ "$SERVER_ROAMING_GRACE_SECS" -gt 3600 ]; then
  echo "QELI_ROAMING_SERVER_GRACE_SECS must be from 1 to 3600" >&2
  exit 2
fi
case "$CLIENT_ROAMING_POLICY" in
  off|auto|required) ;;
  *)
    echo "QELI_ROAMING_CLIENT_POLICY must be off, auto, or required" >&2
    exit 2
    ;;
esac
case "$CASE" in
  perf) ;;
  multinode)
    if [ "$SERVER_ROAMING_ENABLED" != true ] || [ "$CLIENT_ROAMING_POLICY" != auto ] || [ "$WIRE_MODE" != fake-tls ]; then
      echo "multinode requires fake-tls, server roaming=true, and client roaming=auto" >&2
      exit 2
    fi
    ;;
  *)
    if [ "$SERVER_ROAMING_ENABLED" != true ] || [ "$CLIENT_ROAMING_POLICY" != required ]; then
      echo "roaming policy overrides are restricted to the perf case" >&2
      exit 2
    fi
    ;;
esac

SERVER_OBF_MODE=fake-tls
CLIENT_OBF_MODE=fake-tls
SERVER_OBF_EXTRA=
CLIENT_OBF_EXTRA=
AUTH_REQUIRE_KEY_PROOF=false
AUTH_BIND_STATIC=false
CLIENT_BIND_STATIC=false
REALITY_TARGET=false
case "$WIRE_MODE" in
  fake-tls) ;;
  reality-tls)
    SERVER_OBF_MODE=reality-tls
    CLIENT_OBF_MODE=reality-tls
    AUTH_REQUIRE_KEY_PROOF=true
    AUTH_BIND_STATIC=true
    CLIENT_BIND_STATIC=true
    REALITY_TARGET=true
    SERVER_OBF_EXTRA=$'obf.tls.server_name = www.microsoft.com\nobf.tls.reality_proxy.enabled = true\nobf.tls.reality_proxy.target = 10.40.3.1\nobf.tls.reality_proxy.target_port = 9443\nobf.tls.reality_proxy.short_ids = 0123456789abcdef\nobf.tls.reality_proxy.real_tls = true\nobf.tls.reality_proxy.handrolled = true'
    CLIENT_OBF_EXTRA=$'reality_sid = 0123456789abcdef\nsni = www.microsoft.com'
    ;;
  plain)
    SERVER_OBF_MODE=plain
    CLIENT_OBF_MODE=plain
    ;;
  obfs-ws)
    SERVER_OBF_MODE=obfs
    CLIENT_OBF_MODE=obfs
    SERVER_OBF_EXTRA=$'obf.obfs_key = roam-tcp-obfs-key-1234\nobf.obfs_fronting = websocket'
    CLIENT_OBF_EXTRA=$'obfs_key = roam-tcp-obfs-key-1234\nfront = websocket'
    ;;
  obfs-none)
    SERVER_OBF_MODE=obfs
    CLIENT_OBF_MODE=obfs
    SERVER_OBF_EXTRA=$'obf.obfs_key = roam-tcp-obfs-key-1234\nobf.obfs_fronting = none'
    CLIENT_OBF_EXTRA=$'obfs_key = roam-tcp-obfs-key-1234\nfront = none'
    ;;
  obfs-awg)
    SERVER_OBF_MODE=obfs
    CLIENT_OBF_MODE=obfs
    SERVER_OBF_EXTRA=$'obf.obfs_key = roam-tcp-obfs-key-1234\nobf.obfs_fronting = websocket\nobf.awg.enabled = true\nobf.awg.jc = 4\nobf.awg.jmin = 48\nobf.awg.jmax = 160'
    CLIENT_OBF_EXTRA=$'obfs_key = roam-tcp-obfs-key-1234\nfront = websocket\nawg = true\njc = 4\njmin = 48\njmax = 160'
    ;;
  *)
    usage
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

run_case_helper() {
  local helper=$1 entry=$2
  if [ ! -r "$helper" ]; then
    echo "required TCP roaming case helper is missing: $helper" >&2
    return 2
  fi
  # The validated case-specific helper is selected at runtime.
  # shellcheck disable=SC1090
  if ! . "$helper"; then
    echo "failed to load TCP roaming case helper: $helper" >&2
    return 2
  fi
  if ! type "$entry" >/dev/null 2>&1; then
    echo "TCP roaming case helper does not define $entry: $helper" >&2
    return 2
  fi
  "$entry"
}

cleanup() {
  for pid in "$CLIENT_JOB_PID" "$SERVER_JOB_PID" "$SECONDARY_SERVER_JOB_PID" "$TARGET_JOB_PID" "$LOAD_JOB_PID"; do
    if [ -n "$pid" ]; then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
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
rm -f "$WORK"/*.log "$WORK"/*.conf "$WORK"/*.key "$WORK"/*.crt \
  "$WORK"/*-known-hosts "$WORK"/*-device-id

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

if [ "$REALITY_TARGET" = true ]; then
  if ! openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
      -subj '/CN=www.microsoft.com' -keyout "$WORK/target.key" \
      -out "$WORK/target.crt" >/dev/null 2>&1; then
    bad "REALITY target certificate generation"
    exit 1
  fi
  ip netns exec "$RTR_NS" openssl s_server -4 -accept 10.40.3.1:9443 \
    -cert "$WORK/target.crt" -key "$WORK/target.key" -www -quiet \
    >"$WORK/target.log" 2>&1 &
  TARGET_JOB_PID=$!
  if wait_for 50 "ip netns exec $RTR_NS ss -lnt | grep -q ':9443'"; then
    ok "REALITY TLS target listens in the router namespace"
  else
    bad "REALITY TLS target listens in the router namespace"
    exit 1
  fi
fi

cat >"$WORK/server.conf" <<EOF
[auth]
users_file = $WORK/users.conf
require_client_key_proof = $AUTH_REQUIRE_KEY_PROOF
bind_static_to_session = $AUTH_BIND_STATIC
[web]
enabled = false
[logging]
level = $SERVER_LOG_LEVEL
[profile:roam]
enabled = true
identity_key = $WORK/identity.key
bind.address = 0.0.0.0
bind.port = 4443
bind.transport = tcp
roaming.enabled = $SERVER_ROAMING_ENABLED
roaming.grace_secs = $SERVER_ROAMING_GRACE_SECS
tun.name = qrms0
tun.device_type = $DEVICE_TYPE
tun.address = 10.88.0.1
tun.mtu = 1400
pool.cidr = 10.88.0.0/24
pool.exclude = 10.88.0.1
obf.mode = $SERVER_OBF_MODE
obf.multipath.enabled = $MULTIPATH_ENABLED
obf.multipath.max_streams = $MULTIPATH_MAX_STREAMS
obf.multipath.adaptive = $MULTIPATH_ADAPTIVE
$SERVER_OBF_EXTRA
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
perf.connection.new_session_rate_max = 100
perf.connection.new_session_rate_window_secs = 60
EOF
: >"$WORK/users.conf"
SERVER_PIN=
if [ "$REALITY_TARGET" = true ]; then
  SERVER_PIN=$("$BIN" show-identity --config "$WORK/server.conf" 2>&1 \
    | grep -Eo '[0-9a-f]{64}' | head -n1)
  if [ "${#SERVER_PIN}" -eq 64 ]; then
    ok "REALITY client obtained the exact pinned Qeli identity"
    CLIENT_OBF_EXTRA="${CLIENT_OBF_EXTRA}"$'\n'"key = $SERVER_PIN"
  else
    bad "REALITY client obtained the exact pinned Qeli identity"
    exit 1
  fi
fi
"$BIN" add-client roam-user -p roam-pass-1234 -c "$WORK/server.conf" >/dev/null 2>&1
ip netns exec "$SRV_NS" env QELI_CONTROL_SOCKET="$WORK/control.sock" "$BIN" server -c "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
SERVER_JOB_PID=$!
wait_for 50 "ip netns exec $SRV_NS ss -lnt | grep -q ':4443'" || bad "server did not listen"
wait_for 50 "ip netns exec $SRV_NS ip link show qrms0" || bad "server tunnel device did not come up"
check "server $DEVICE_TYPE device has the requested kernel kind" \
  "flags=\$(ip netns exec $SRV_NS cat /sys/class/net/qrms0/tun_flags); \
   test \$((flags & 3)) -eq $EXPECTED_DEVICE_KIND"
if [ "$CASE" = multinode ]; then
  sed \
    -e 's/^level = info$/level = debug/' \
    -e 's/^bind.port = 4443$/bind.port = 4444/' \
    -e 's/^tun.name = qrms0$/tun.name = qrms1/' \
    -e 's/^tun.address = 10\.88\.0\.1$/tun.address = 10.89.0.1/' \
    -e 's#^pool.cidr = 10\.88\.0\.0/24$#pool.cidr = 10.89.0.0/24#' \
    -e 's/^pool.exclude = 10\.88\.0\.1$/pool.exclude = 10.89.0.1/' \
    "$WORK/server.conf" >"$WORK/server-secondary.conf"
  ip netns exec "$SRV_NS" env QELI_CONTROL_SOCKET="$WORK/control-secondary.sock" \
    "$BIN" server -c "$WORK/server-secondary.conf" >"$WORK/server-secondary.log" 2>&1 &
  SECONDARY_SERVER_JOB_PID=$!
  if wait_for 50 "ip netns exec $SRV_NS ss -lnt | grep -q ':4444'"; then
    ok "secondary process listens with the shared identity on port 4444"
  else
    bad "secondary process did not listen on port 4444"
    exit 1
  fi
  wait_for 50 "ip netns exec $SRV_NS ip link show qrms1" || bad "secondary tunnel device did not come up"
  ip netns exec "$RTR_NS" iptables -t nat -A PREROUTING -i qrm-br -p tcp \
    -d 10.40.3.2 --dport 4443 -j DNAT --to-destination 10.40.3.2:4444
  check "path B is mapped to the independent secondary process" \
    "ip netns exec $RTR_NS iptables -t nat -C PREROUTING -i qrm-br -p tcp -d 10.40.3.2 --dport 4443 -j DNAT --to-destination 10.40.3.2:4444"
fi
if [ "$REALITY_TARGET" = true ]; then
  check "REALITY server borrowed the target TLS shape and certificate" \
    "grep -q 'borrowed TLS shape.*real cert chain: captured' $WORK/server.log"
  ip netns exec "$CLI_NS" timeout 10 openssl s_client -connect 10.40.3.2:4443 \
    -servername www.microsoft.com -showcerts </dev/null >"$WORK/decoy.log" 2>&1 || true
  check "non-Qeli TLS probe was bridged to the REALITY target" \
    "grep -Eq 'CN ?= ?www\.microsoft\.com' $WORK/decoy.log"
fi

cat >"$WORK/client.conf" <<EOF
[qeli]
server = 10.40.3.2:4443
proto = tcp
roaming = $CLIENT_ROAMING_POLICY
user = roam-user
pass = roam-pass-1234
mode = $CLIENT_OBF_MODE
$CLIENT_OBF_EXTRA
dev = qrm0
device_type = $DEVICE_TYPE
bind_static = $CLIENT_BIND_STATIC
gateway = true
dns = off
allow_ipv6_leak = true
timeout = 5
[logging]
level = info
EOF
ip netns exec "$CLI_NS" env QELI_KNOWN_HOSTS="$WORK/client-known-hosts" \
  QELI_DEVICE_ID_FILE="$WORK/client-device-id" \
  "$BIN" client -c "$WORK/client.conf" >"$WORK/client.log" 2>&1 &
CLIENT_JOB_PID=$!
wait_for 100 "ip netns exec $CLI_NS ip link show qrm0" || bad "client tunnel device did not come up"
check "client $DEVICE_TYPE device has the requested kernel kind" \
  "flags=\$(ip netns exec $CLI_NS cat /sys/class/net/qrm0/tun_flags); \
   test \$((flags & 3)) -eq $EXPECTED_DEVICE_KIND"

CLIENT_PID=$(ip netns pids "$CLI_NS" 2>/dev/null | head -n1)
TUN_IFINDEX=$(ip netns exec "$CLI_NS" cat /sys/class/net/qrm0/ifindex 2>/dev/null || true)
if [ "$SERVER_ROAMING_ENABLED" = true ] && [ "$CLIENT_ROAMING_POLICY" != off ]; then
  check "TCP handover capability was negotiated" \
    "grep -q 'TCP make-before-break negotiated' $WORK/client.log"
else
  check "TCP handover capability stayed disabled for the baseline" \
    "! grep -q 'TCP make-before-break negotiated' $WORK/client.log"
fi
check "initial carrier bypass uses path A" \
  "ip netns exec $CLI_NS ip route show 10.40.3.2 | grep -q '^10.40.3.2 via 10.40.1.1 dev qrm-a'"
check "tunnel works before route change" \
  "ip netns exec $CLI_NS ping -c3 -W1 10.88.0.1"

if [ "$MULTIPATH_MODE" = fixed ]; then
  if wait_for 100 "grep -q 'Multipath: 3 bonded stream(s) active (fixed)' $WORK/client.log"; then
    ok "fixed multipath opened all three logical slots before handover"
  else
    bad "fixed multipath did not open all three logical slots before handover"
  fi
  check "fixed multipath attached two secondary streams on path A" \
    "test \"\$(grep -c 'JOINed session.*from 10.40.1.2:' $WORK/server.log)\" -ge 2"
elif [ "$MULTIPATH_MODE" = adaptive ]; then
  ip netns exec "$SRV_NS" iperf3 -s -1 -B 10.88.0.1 -p 5201 >"$WORK/iperf-server.log" 2>&1 &
  LOAD_JOB_PID=$!
  sleep 1
  if ip netns exec "$CLI_NS" timeout 30 iperf3 -c 10.88.0.1 -p 5201 -t 18 -i 0 \
      >"$WORK/iperf-client.log" 2>&1; then
    ok "adaptive multipath received sustained tunnel load"
  else
    bad "adaptive multipath load failed"
  fi
  wait "$LOAD_JOB_PID" 2>/dev/null || true
  LOAD_JOB_PID=
  if wait_for 50 "grep -Eq 'Multipath adaptive: ramped to [2-9][0-9]* stream' $WORK/client.log"; then
    ok "adaptive multipath grew beyond the primary slot before handover"
  else
    bad "adaptive multipath did not grow beyond the primary slot before handover"
  fi
fi

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ "$CASE" = soak ]; then
  # shellcheck source=roaming_tcp_netns_soak_case.sh
  run_case_helper "$SCRIPT_DIR/roaming_tcp_netns_soak_case.sh" run_tcp_soak_case || exit $?
elif [ "$CASE" = perf ]; then
  # shellcheck source=roaming_tcp_netns_perf_case.sh
  run_case_helper "$SCRIPT_DIR/roaming_tcp_netns_perf_case.sh" run_tcp_perf_case || exit $?
elif [ "$CASE" = resume ] || [ "$CASE" = grace-expiry ]; then
  # shellcheck source=roaming_tcp_resume_netns_case.sh
  run_case_helper "$SCRIPT_DIR/roaming_tcp_resume_netns_case.sh" run_tcp_resume_case || exit $?
elif [ "$CASE" = multinode ]; then
  # shellcheck source=roaming_tcp_multinode_netns_case.sh
  run_case_helper "$SCRIPT_DIR/roaming_tcp_multinode_netns_case.sh" run_tcp_multinode_case || exit $?
else
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
if [ "$MULTIPATH_MODE" = fixed ]; then
  if wait_for 100 "grep -Eq 'TCP stream slot [0-9]+ resumed; 3/3 stream' $WORK/client.log"; then
    ok "fixed multipath restored all logical slots on path B"
  else
    bad "fixed multipath did not restore all logical slots on path B"
  fi
  check "fixed multipath secondary slots were reattached from path B" \
    "test \"\$(grep -Ec 'Stream #[12] JOINed session.*from 10.40.2.2:' $WORK/server.log)\" -ge 2"
elif [ "$MULTIPATH_MODE" = adaptive ]; then
  check "adaptive multipath retained at least one authenticated path-B carrier" \
    "grep -q 'Stream #0 JOINed session.*from 10.40.2.2:' $WORK/server.log"
  if wait_for 100 "grep -Eq 'TCP stream slot [0-9]+ resumed; (2/2|3/3) stream' $WORK/client.log"; then
    ok "adaptive multipath restored its learned width on path B"
  else
    bad "adaptive multipath did not restore its learned width on path B"
  fi
  check "adaptive multipath reattached a secondary slot from path B" \
    "grep -Eq 'Stream #[12] JOINed session.*from 10.40.2.2:' $WORK/server.log"
fi
check "the same tunnel device instance survived handover" \
  "test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qrm0/ifindex)\" = '$TUN_IFINDEX'"
check "handover did not enter the top-level reconnect loop" \
  "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

wait "$PING_PID" 2>/dev/null || true
PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
  "$WORK/ping.log" | tail -n1)
check "continuous probe retained at least 140 of 150 packets" \
  "test -n '$PING_RX' && test '$PING_RX' -ge 140"
fi

echo
echo "=== RESULT ($WIRE_MODE/$CASE/$DEVICE_TYPE/$MULTIPATH_MODE): $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
  echo "--- client.log (tail) ---"
  tail -n 120 "$WORK/client.log"
  echo "--- route state ---"
  ip netns exec "$CLI_NS" ip route show 2>/dev/null || true
  exit 1
fi

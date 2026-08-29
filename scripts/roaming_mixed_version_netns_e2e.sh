#!/usr/bin/env bash
# Live mixed-version roaming compatibility gate. Current and legacy binaries run only inside
# two temporary network namespaces; host routes and production/lab services are not changed.
set -u
set -o pipefail
export LC_ALL=C

CURRENT_BIN=${1:-${CURRENT_BIN:-/opt/qeli-src/target/release/qeli}}
LEGACY_BIN=${2:-${LEGACY_BIN:-/opt/qeli-exp/qeli-0.7.14-roaming-gate}}
WORK=/tmp/qeli-roaming-mixed-version
CLI_NS=qmv-cli
SRV_NS=qmv-srv
PASS=0
FAIL=0
SERVER_JOB_PID=
CLIENT_JOB_PID=

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

cleanup_namespaces() {
  ip netns pids "$CLI_NS" 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids "$SRV_NS" 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.2
  ip netns pids "$CLI_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns pids "$SRV_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
  if [ -n "$CLIENT_JOB_PID" ]; then wait "$CLIENT_JOB_PID" 2>/dev/null || true; fi
  if [ -n "$SERVER_JOB_PID" ]; then wait "$SERVER_JOB_PID" 2>/dev/null || true; fi
  ip netns del "$CLI_NS" 2>/dev/null
  ip netns del "$SRV_NS" 2>/dev/null
  SERVER_JOB_PID=
  CLIENT_JOB_PID=
}
trap cleanup_namespaces EXIT

if [ ! -x "$CURRENT_BIN" ] || [ ! -x "$LEGACY_BIN" ]; then
  echo "usage: $0 [current-feature-binary] [legacy-binary]" >&2
  exit 2
fi
CURRENT_VERSION=$("$CURRENT_BIN" --version 2>&1 | tail -n1)
LEGACY_VERSION=$("$LEGACY_BIN" --version 2>&1 | tail -n1)
case "$LEGACY_VERSION" in
  *0.7.14*) ;;
  *)
    echo "unexpected mixed-version pair: current='$CURRENT_VERSION' legacy='$LEGACY_VERSION'" >&2
    exit 2
    ;;
esac
if [ "$CURRENT_VERSION" = "$LEGACY_VERSION" ]; then
  echo "current and legacy binaries report the same version: '$CURRENT_VERSION'" >&2
  exit 2
fi

setup_namespaces() {
  cleanup_namespaces
  ip netns add "$CLI_NS"
  ip netns add "$SRV_NS"
  ip link add qmv-c type veth peer name qmv-s
  ip link set qmv-c netns "$CLI_NS"
  ip link set qmv-s netns "$SRV_NS"
  ip netns exec "$CLI_NS" ip addr add 10.42.0.2/24 dev qmv-c
  ip netns exec "$SRV_NS" ip addr add 10.42.0.1/24 dev qmv-s
  ip netns exec "$CLI_NS" ip link set lo up
  ip netns exec "$SRV_NS" ip link set lo up
  ip netns exec "$CLI_NS" ip link set qmv-c up
  ip netns exec "$SRV_NS" ip link set qmv-s up
}

run_case() {
  local label=$1 transport=$2 server_kind=$3 client_kind=$4 policy=$5 expected=$6
  local port socket_flag server_bin client_bin case_dir auth_pattern case_fail_before
  case_fail_before=$FAIL
  if [ "$transport" = tcp ]; then
    port=4451
    socket_flag=t
    auth_pattern="connected on profile 'mixed'"
  else
    port=4452
    socket_flag=u
    auth_pattern="authenticated on profile 'mixed'"
  fi
  if [ "$server_kind" = current ]; then server_bin=$CURRENT_BIN; else server_bin=$LEGACY_BIN; fi
  if [ "$client_kind" = current ]; then client_bin=$CURRENT_BIN; else client_bin=$LEGACY_BIN; fi

  echo
  echo "=== $label [$transport, server=$server_kind, client=$client_kind, policy=$policy] ==="
  setup_namespaces
  case_dir="$WORK/$label"
  mkdir -p "$case_dir"
  rm -f "$case_dir"/*.conf "$case_dir"/*.log

  {
    echo "[auth]"
    echo "users_file = $case_dir/users.conf"
    echo "require_client_key_proof = false"
    echo "bind_static_to_session = false"
    echo "[web]"
    echo "enabled = false"
    echo "[logging]"
    echo "level = info"
    echo "[profile:mixed]"
    echo "enabled = true"
    echo "bind.address = 0.0.0.0"
    echo "bind.port = $port"
    echo "bind.transport = $transport"
    if [ "$server_kind" = current ]; then echo "roaming.enabled = true"; fi
    echo "tun.name = qmvs0"
    echo "tun.address = 10.90.0.1"
    echo "tun.mtu = 1400"
    echo "pool.cidr = 10.90.0.0/24"
    echo "pool.exclude = 10.90.0.1"
    echo "dns.enabled = false"
    echo "obf.mode = fake-tls"
    echo "obf.quic.enabled = false"
    echo "perf.connection.max_clients = 8"
    echo "perf.connection.handshake_timeout_secs = 10"
  } >"$case_dir/server.conf"
  : >"$case_dir/users.conf"
  if ! "$server_bin" add-client mixed-user -p mixed-pass-1234 -c "$case_dir/server.conf" >"$case_dir/add-client.log" 2>&1; then
    bad "$label server config was rejected by $server_kind binary"
    tail -n 40 "$case_dir/add-client.log"
    return
  fi

  ip netns exec "$SRV_NS" env QELI_CONTROL_SOCKET="$case_dir/control.sock" "$server_bin" server -c "$case_dir/server.conf" >"$case_dir/server.log" 2>&1 &
  SERVER_JOB_PID=$!
  if ! wait_for 75 "ip netns exec $SRV_NS ss -ln$socket_flag | grep -q ':$port'"; then
    bad "$label server did not listen"
    tail -n 60 "$case_dir/server.log"
    return
  fi

  {
    echo "[qeli]"
    echo "server = 10.42.0.1:$port"
    echo "proto = $transport"
    if [ "$client_kind" = current ]; then
      echo "roaming = $policy"
    fi
    echo "user = mixed-user"
    echo "pass = mixed-pass-1234"
    echo "mode = fake-tls"
    echo "dev = qmv0"
    echo "bind_static = false"
    echo "gateway = true"
    echo "dns = off"
    echo "allow_ipv6_leak = true"
    echo "timeout = 5"
    echo "[logging]"
    echo "level = info"
  } >"$case_dir/client.conf"

  ip netns exec "$CLI_NS" "$client_bin" client -c "$case_dir/client.conf" >"$case_dir/client.log" 2>&1 &
  CLIENT_JOB_PID=$!

  if [ "$expected" = success ]; then
    if wait_for 100 "ip netns exec $CLI_NS ip link show qmv0"; then
      ok "$label established a TUN"
    else
      bad "$label did not establish a TUN"
    fi
    check "$label carries tunnel traffic" "ip netns exec $CLI_NS ping -c3 -W1 10.90.0.1"
    check "$label performed exactly one full AUTH" "test \"\$(grep -c \"$auth_pattern\" $case_dir/server.log || true)\" -eq 1"
    if [ "$client_kind" = current ]; then
      check "$label auto stayed on the legacy reconnect path" "! grep -Eq 'make-before-break negotiated|ROAMING transport=' $case_dir/client.log"
    fi
    if [ "$server_kind" = current ]; then
      check "$label current server did not enter roaming for a legacy client" "! grep -q 'ROAMING transport=' $case_dir/server.log"
    fi
  else
    if wait_for 100 "grep -Eq 'roaming is required but the server does not (advertise capability negotiation|support the authenticated capability extension)' $case_dir/client.log"; then
      ok "$label reports the missing authenticated capability contract"
    else
      bad "$label did not report the missing authenticated capability contract"
    fi
    sleep 3
    check "$label required policy never created a TUN" "! ip netns exec $CLI_NS ip link show qmv0"
    check "$label repeated only safe pre-AUTH negotiation" "test \"\$(grep -Ec 'roaming is required but the server does not (advertise capability negotiation|support the authenticated capability extension)' $case_dir/client.log || true)\" -ge 2"
    check "$label stopped every generation before full AUTH" "test \"\$(grep -c \"$auth_pattern\" $case_dir/server.log || true)\" -eq 0"
  fi

  if [ "$FAIL" -ne "$case_fail_before" ]; then
    echo "--- $label client.log (tail) ---"
    tail -n 60 "$case_dir/client.log"
    echo "--- $label server.log (tail) ---"
    tail -n 60 "$case_dir/server.log"
  fi
}

mkdir -p "$WORK"
for transport in tcp udp; do
  run_case "$transport-current-server-legacy-client" "$transport" current legacy legacy success
  run_case "$transport-legacy-server-current-auto" "$transport" legacy current auto success
  run_case "$transport-legacy-server-current-required" "$transport" legacy current required reject
done
cleanup_namespaces

echo
echo "=== MIXED-VERSION RESULT: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then exit 1; fi

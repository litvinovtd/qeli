#!/bin/bash
# netns integration test for the qeli client's routing/firewall layer.
#
# Why namespaces: the lab's server sits in the client's own subnet, so it is ON-LINK and
# the whole server-bypass path is skipped — the exact code that pins the encrypted path to
# the physical gateway is never exercised there. Here the server lives two hops away
# behind a router, which is the normal deployment and the only way to see that code run.
#
#   [qcli] veth-c ── veth-r1 [qrtr] veth-r2 ── veth-s [qsrv]
#          10.10.1.2/24   10.10.1.1/24  10.10.2.1/24  10.10.2.2/24
#
# `ip netns exec` bind-mounts /etc/netns/<ns>/hosts over /etc/hosts, so the client can be
# given a name that resolves to an UNREACHABLE address first and the real one second —
# which is how "the bypass must pin what the socket actually connected to" gets tested.
set -u

BIN=${BIN:-/opt/qeli-src/target/release/qeli}
WORK=/tmp/qeli-netns
PASS=0; FAIL=0

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

cleanup() {
  ip netns pids qcli 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns pids qsrv 2>/dev/null | xargs -r kill -9 2>/dev/null
  for ns in qcli qrtr qsrv; do ip netns del $ns 2>/dev/null; done
  rm -rf /etc/netns/qcli
  sleep 0.3
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK"

# ── topology ────────────────────────────────────────────────────────────────
for ns in qcli qrtr qsrv; do ip netns add $ns; done
ip link add veth-c type veth peer name veth-r1
ip link add veth-s type veth peer name veth-r2
ip link set veth-c  netns qcli
ip link set veth-r1 netns qrtr
ip link set veth-r2 netns qrtr
ip link set veth-s  netns qsrv

ip netns exec qcli ip addr add 10.10.1.2/24 dev veth-c
ip netns exec qrtr ip addr add 10.10.1.1/24 dev veth-r1
ip netns exec qrtr ip addr add 10.10.2.1/24 dev veth-r2
ip netns exec qsrv ip addr add 10.10.2.2/24 dev veth-s
for ns in qcli qrtr qsrv; do ip netns exec $ns ip link set lo up; done
ip netns exec qcli ip link set veth-c up
ip netns exec qrtr ip link set veth-r1 up
ip netns exec qrtr ip link set veth-r2 up
ip netns exec qsrv ip link set veth-s up

# default routes make the server genuinely OFF-LINK from the client
ip netns exec qcli ip route add default via 10.10.1.1
ip netns exec qsrv ip route add default via 10.10.2.1
ip netns exec qrtr sysctl -qw net.ipv4.ip_forward=1

# the name resolves to a DEAD address first, the live one second
mkdir -p /etc/netns/qcli
printf '127.0.0.1 localhost\n10.10.9.9 qserver\n10.10.2.2 qserver\n' > /etc/netns/qcli/hosts

check "router forwards: client reaches the server" \
      "ip netns exec qcli ping -c1 -W2 10.10.2.2"

# ── server ──────────────────────────────────────────────────────────────────
cat > "$WORK/server.conf" <<EOF
[auth]
users_file = $WORK/users.conf
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = info
[profile:t]
enabled = true
bind.address = 0.0.0.0
bind.port = 4443
bind.transport = tcp
tun.name = nstun
tun.address = 10.77.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.77.0.0/24
pool.exclude = 10.77.0.1
obf.mode = fake-tls
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
EOF
: > "$WORK/users.conf"
"$BIN" add-client nsuser -p nspass1234 -c "$WORK/server.conf" >/dev/null 2>&1
ip netns exec qsrv "$BIN" server -c "$WORK/server.conf" > "$WORK/server.log" 2>&1 &
sleep 3
check "server is listening in its namespace" \
      "ip netns exec qsrv ss -lnt | grep -q ':4443'"

# ── client: full tunnel, server addressed BY NAME ───────────────────────────
cat > "$WORK/client.conf" <<EOF
[qeli]
server = qserver:4443
proto = tcp
user = nsuser
pass = nspass1234
mode = fake-tls
dev = nsc0
bind_static = false
gateway = true
allow_ipv6_leak = true
[logging]
level = info
EOF
ip netns exec qcli "$BIN" client -c "$WORK/client.conf" > "$WORK/client.log" 2>&1 &
CLI_WAIT=0
while [ $CLI_WAIT -lt 20 ]; do
  ip netns exec qcli ip link show nsc0 >/dev/null 2>&1 && break
  CLI_WAIT=$((CLI_WAIT+1)); sleep 1
done

echo
echo "=== full tunnel, off-link server ==="
check "tunnel interface is up" "ip netns exec qcli ip link show nsc0"
check "both /1 halves installed" \
      "ip netns exec qcli ip route show | grep -q '^0.0.0.0/1' && ip netns exec qcli ip route show | grep -q '^128.0.0.0/1'"
check "traffic flows through the tunnel" \
      "ip netns exec qcli ping -c2 -W2 10.77.0.1"

echo
echo "=== #4: the bypass pins the address the socket actually used ==="
BYPASS=$(ip netns exec qcli ip route show | grep -E '^10\.10\.(2\.2|9\.9) ' || true)
echo "  bypass route: ${BYPASS:-<none>}"
check "a bypass route exists at all (needs an off-link server)" \
      "test -n \"\$(ip netns exec qcli ip route show | grep -E '^10\.10\.(2\.2|9\.9) ')\""
check "it pins the CONNECTED address 10.10.2.2" \
      "ip netns exec qcli ip route show | grep -q '^10.10.2.2 '"
check "it does NOT pin the dead first-resolved 10.10.9.9" \
      "! ip netns exec qcli ip route show | grep -q '^10.10.9.9 '"

echo
echo "=== #5: SIGTERM leaves nothing behind ==="
ip netns pids qcli 2>/dev/null | xargs -r kill -TERM 2>/dev/null
sleep 4
check "the tunnel interface is gone" "! ip netns exec qcli ip link show nsc0"
check "the /1 halves are gone" \
      "! ip netns exec qcli ip route show | grep -q '^0.0.0.0/1'"
check "the server bypass is gone" \
      "! ip netns exec qcli ip route show | grep -q '^10.10.2.2 '"
check "the physical default survived" \
      "ip netns exec qcli ip route show | grep -q '^default via 10.10.1.1'"

# ═══════════════════════════════════════════════════════════════════════════
# Part 2 — the scenarios that need more than one interface or more than one
# instance. All of it runs inside the namespace, which is also why the
# kill-switch can be exercised at all: a chain that drops everything is
# harmless here and cannot cut the operator's own SSH, the way it does on a
# real host.
# ═══════════════════════════════════════════════════════════════════════════

start_client() {  # $1=dev  $2=extra config lines
  local dev=$1 extra=$2
  cat > "$WORK/client-$dev.conf" <<EOF
[qeli]
server = 10.10.2.2:4443
proto = tcp
user = nsuser
pass = nspass1234
mode = fake-tls
dev = $dev
bind_static = false
gateway = true
$extra
[logging]
level = info
EOF
  ip netns exec qcli "$BIN" client -c "$WORK/client-$dev.conf" > "$WORK/client-$dev.log" 2>&1 &
  local w=0
  while [ $w -lt 20 ]; do
    ip netns exec qcli ip link show "$dev" >/dev/null 2>&1 && return 0
    w=$((w+1)); sleep 1
  done
  return 1
}

stop_clients() {
  ip netns pids qcli 2>/dev/null | xargs -r kill -TERM 2>/dev/null
  sleep 4
  ip netns pids qcli 2>/dev/null | xargs -r kill -9 2>/dev/null
  sleep 1
}

echo
echo "=== #2: IPv6 must not walk out of a full tunnel ==="
start_client nsc0 "allow_ipv6_leak = false" || bad "client did not come up (ipv6 case)"
check "::/1 is blackholed" \
      "ip netns exec qcli ip -6 route show | grep -q 'blackhole ::/1'"
check "8000::/1 is blackholed" \
      "ip netns exec qcli ip -6 route show | grep -q 'blackhole 8000::/1'"
stop_clients
check "the blackholes are lifted on disconnect (IPv6 must not stay dead)" \
      "! ip netns exec qcli ip -6 route show | grep -q 'blackhole ::/1'"

echo
echo "=== #2b: allow_ipv6_leak is a real opt-out ==="
start_client nsc0 "allow_ipv6_leak = true" || bad "client did not come up (opt-out case)"
check "no blackhole when the operator opted out" \
      "! ip netns exec qcli ip -6 route show | grep -q 'blackhole ::/1'"
stop_clients

echo
echo "=== #8: two instances must not wipe each other's kill-switch ==="
start_client nsc0 "allow_ipv6_leak = true
kill_switch = true" || bad "first instance did not come up"
check "instance A armed its own chain" \
      "ip netns exec qcli iptables -S | grep -q 'QELI_KS_nsc0'"
start_client nsc1 "allow_ipv6_leak = true
kill_switch = true" || bad "second instance did not come up"
check "instance B armed a SEPARATE chain" \
      "ip netns exec qcli iptables -S | grep -q 'QELI_KS_nsc1'"
check "instance A's chain SURVIVED B starting (the whole point of per-instance naming)" \
      "ip netns exec qcli iptables -S | grep -q 'QELI_KS_nsc0'"
check "A's allow rule for its own tunnel is still there" \
      "ip netns exec qcli iptables -S QELI_KS_nsc0 | grep -q 'o nsc0 -j ACCEPT'"
# stop only the SECOND one
ip netns exec qcli sh -c 'pkill -TERM -f "client-nsc1.conf"' 2>/dev/null
sleep 4
check "stopping B removed only B's chain" \
      "! ip netns exec qcli iptables -S | grep -q 'QELI_KS_nsc1'"
check "A is still protected after B stopped" \
      "ip netns exec qcli iptables -S | grep -q 'QELI_KS_nsc0'"
stop_clients

echo
echo "=== #9: in gateway mode the kill-switch must cover FORWARD ==="
# Routed traffic never traverses OUTPUT, so an OUTPUT-only chain leaves the LAN
# behind the client unprotected during a reconnect.
start_client nsc0 "allow_ipv6_leak = true
kill_switch = true
gateway_nat = true" || bad "gateway client did not come up"
check "the chain is hooked into OUTPUT" \
      "ip netns exec qcli iptables -S OUTPUT | grep -q 'j QELI_KS_nsc0'"
check "the chain is ALSO hooked into FORWARD" \
      "ip netns exec qcli iptables -S FORWARD | grep -q 'j QELI_KS_nsc0'"
stop_clients
check "both hooks are removed on a clean stop" \
      "! ip netns exec qcli iptables -S | grep -q 'QELI_KS_nsc0'"

echo
echo "=== a plain client must NOT hijack the host's FORWARD chain ==="
start_client nsc0 "allow_ipv6_leak = true
kill_switch = true" || bad "plain client did not come up"
check "no FORWARD hook without gateway mode" \
      "! ip netns exec qcli iptables -S FORWARD | grep -q 'j QELI_KS_nsc0'"
stop_clients
echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]

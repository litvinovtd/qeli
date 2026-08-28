#!/usr/bin/env bash
# Linux UDP+QUIC make-before-break integration tests. Everything runs in three isolated network
# namespaces; no host route or production process is changed. The success case commits path B;
# rollback blackholes B; supersede replaces that in-flight candidate with reachable path C;
# commit-race changes to C while the platform is still committing B; loss-replay drops the first
# PATH_CHALLENGE and PATH_COMMIT and requires fresh encrypted retries to finish the handover.
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
  success|rollback|supersede|commit-race|loss-replay) ;;
  *)
    echo "usage: $0 [qeli-binary] [success|rollback|supersede|commit-race|loss-replay]" >&2
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
rm -rf "$WORK/bin" "$WORK"/commit-race-*

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
CLIENT_ENV=()
if [ "$CASE" = commit-race ]; then
  REAL_IP=$(command -v ip)
  mkdir -p "$WORK/bin"
  cat >"$WORK/bin/ip" <<'EOF'
#!/bin/sh
REAL_IP=${QELI_TEST_REAL_IP:-/usr/sbin/ip}
if [ "${QELI_TEST_COMMIT_DELAY_INTERFACE:-}" != "" ] \
    && [ "$1" = route ] \
    && { [ "$2" = add ] || [ "$2" = replace ]; } \
    && [ "$3" = "${QELI_TEST_COMMIT_DELAY_REMOTE:-}" ]; then
  case " $* " in
    *" dev ${QELI_TEST_COMMIT_DELAY_INTERFACE} "*)
      if [ ! -e "${QELI_TEST_COMMIT_DELAY_DONE}" ]; then
        : >"${QELI_TEST_COMMIT_DELAY_WAITING}"
        wait_step=0
        while [ ! -e "${QELI_TEST_COMMIT_DELAY_RELEASE}" ] && [ "$wait_step" -lt 500 ]; do
          wait_step=$((wait_step + 1))
          sleep 0.02
        done
        : >"${QELI_TEST_COMMIT_DELAY_DONE}"
      fi
      ;;
  esac
fi
exec "$REAL_IP" "$@"
EOF
  chmod 755 "$WORK/bin/ip"
  CLIENT_ENV=(env "PATH=$WORK/bin:$PATH" "QELI_TEST_REAL_IP=$REAL_IP" \
    "QELI_TEST_COMMIT_DELAY_INTERFACE=qru-b" "QELI_TEST_COMMIT_DELAY_REMOTE=10.41.3.2" \
    "QELI_TEST_COMMIT_DELAY_WAITING=$WORK/commit-race-waiting" \
    "QELI_TEST_COMMIT_DELAY_RELEASE=$WORK/commit-race-release" \
    "QELI_TEST_COMMIT_DELAY_DONE=$WORK/commit-race-done")
fi
ip netns exec "$CLI_NS" "${CLIENT_ENV[@]}" "$BIN" client -c "$WORK/client.conf" >"$WORK/client.log" 2>&1 &
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

if [ "$CASE" = loss-replay ]; then
  sleep 3
  # In fake-tls mode these authenticated controls have fixed IPv4 lengths (outer datagram
  # sealing is exclusive to obfs mode): CHALLENGE = 20 IP + 8 UDP + 13 roaming + 5 TLS +
  # 12 nonce + 8 counter + 15 CONTROL_V2 + 24 body + 2 trailer + 16 tag = 123 bytes;
  # COMMIT has the same framing with a 16-byte body = 115 bytes.
  # Before validation, B can carry only PATH_* control, so the first matching server packet is
  # unambiguously the control under test. A huge nth period makes each rule a deterministic
  # one-shot without probabilistic netem loss.
  ip netns exec "$RTR_NS" iptables -I FORWARD 1 -i qru-sr -o qru-br \
    -p udp --sport 4444 -m length --length 123:123 \
    -m statistic --mode nth --every 100000 --packet 0 -j DROP
  ip netns exec "$RTR_NS" iptables -I FORWARD 1 -i qru-sr -o qru-br \
    -p udp --sport 4444 -m length --length 115:115 \
    -m statistic --mode nth --every 100000 --packet 0 -j DROP
  check "one-shot PATH_CHALLENGE loss rule is active" \
    "ip netns exec $RTR_NS iptables -C FORWARD -i qru-sr -o qru-br -p udp --sport 4444 -m length --length 123:123 -m statistic --mode nth --every 100000 --packet 0 -j DROP"
  check "one-shot PATH_COMMIT loss rule is active" \
    "ip netns exec $RTR_NS iptables -C FORWARD -i qru-sr -o qru-br -p udp --sport 4444 -m length --length 115:115 -m statistic --mode nth --every 100000 --packet 0 -j DROP"

  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 180 -W1 10.89.0.1 >"$WORK/ping.log" 2>&1 &
  PING_PID=$!
  ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 50

  if wait_for 200 "grep -q 'UDP make-before-break committed candidate' $WORK/client.log"; then
    ok "candidate committed after losing both server control flights"
  else
    bad "candidate did not recover from deterministic control loss"
  fi
  CHALLENGE_DROPS=$(ip netns exec "$RTR_NS" iptables-save -c | awk \
    '$0 ~ /--sport 4444/ && $0 ~ /--length 123/ && $0 ~ /-j DROP/ { gsub(/^\[/, "", $1); split($1, a, ":"); print a[1] }')
  COMMIT_DROPS=$(ip netns exec "$RTR_NS" iptables-save -c | awk \
    '$0 ~ /--sport 4444/ && $0 ~ /--length 115/ && $0 ~ /-j DROP/ { gsub(/^\[/, "", $1); split($1, a, ":"); print a[1] }')
  check "exactly one PATH_CHALLENGE datagram was dropped" \
    "test '$CHALLENGE_DROPS' = 1"
  check "exactly one PATH_COMMIT datagram was dropped" \
    "test '$COMMIT_DROPS' = 1"
  check "lost challenge caused a fresh PATH_INIT and challenge" \
    "test \"\$(grep -c 'UDP PATH_CHALLENGE sent' $WORK/server.log)\" -eq 2"
  check "lost commit caused an exact server commit replay" \
    "test \"\$(grep -c 'UDP PATH_COMMIT' $WORK/server.log)\" -eq 2 && grep -q 'UDP PATH_COMMIT sent' $WORK/server.log && grep -q 'UDP PATH_COMMIT replayed' $WORK/server.log"
  check "client published the candidate exactly once" \
    "test \"\$(grep -c 'UDP make-before-break committed candidate' $WORK/client.log)\" -eq 1"
  check "carrier bypass moved to path B after the retries" \
    "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.2.1 dev qru-b'"
  check "client process survives control loss without reconnect" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID'"
  check "the same TUN survives control loss" \
    "test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "control loss does not enter the top-level reconnect loop" \
    "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

  wait "$PING_PID" 2>/dev/null || true
  PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
    "$WORK/ping.log" | tail -n1)
  check "continuous probe retained at least 165 of 180 packets during both retries" \
    "test -n '$PING_RX' && test '$PING_RX' -ge 165"
elif [ "$CASE" = rollback ]; then
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
elif [ "$CASE" = commit-race ]; then
  sleep 3
  check "path C reaches the server" \
    "ip netns exec $CLI_NS ping -I 10.41.4.2 -c1 -W2 10.41.3.2"
  ip netns exec "$CLI_NS" ping -n -i 0.2 -c 240 -W1 10.89.0.1 >"$WORK/ping.log" 2>&1 &
  PING_PID=$!

  ip netns exec "$CLI_NS" ip route replace default via 10.41.2.1 dev qru-b metric 50
  if wait_for 150 "test -e $WORK/commit-race-waiting"; then
    ok "platform COMMIT for path B entered the deterministic delay"
  else
    bad "platform COMMIT for path B did not reach the deterministic delay"
  fi
  check "server authenticated path B before local platform COMMIT" \
    "grep -q 'UDP PATH_COMMIT.*to 10.41.2.2:' $WORK/server.log"
  check "client has not published B before platform ACK" \
    "! grep -q 'UDP make-before-break committed candidate' $WORK/client.log"

  # The route detector observes C while Linux COMMIT(B) owns the serialized platform executor.
  # It must not steal/cancel COMMIT(B); after B linearizes it may prepare and commit only C.
  ip netns exec "$CLI_NS" ip route replace default via 10.41.4.1 dev qru-c metric 25
  sleep 2
  check "replacement C cannot overtake the in-flight platform COMMIT" \
    "! grep -q 'Linux roaming prepared candidate .* on qru-c' $WORK/client.log"
  : >"$WORK/commit-race-release"

  if wait_for 100 "grep -q 'Linux roaming prepared candidate .* on qru-c' $WORK/client.log"; then
    ok "Linux observer prepared C after COMMIT(B) completed"
  else
    bad "Linux observer did not prepare C after COMMIT(B)"
  fi
  if wait_for 200 "test \"\$(grep -c 'UDP make-before-break committed candidate' $WORK/client.log)\" -ge 2"; then
    ok "client committed B and then C"
  else
    bad "client did not complete both ordered commits"
  fi

  B_ID=$(sed -n 's/.*Linux roaming prepared candidate \([0-9][0-9]*\) on qru-b.*/\1/p' \
    "$WORK/client.log" | head -n1)
  C_ID=$(sed -n 's/.*Linux roaming prepared candidate \([0-9][0-9]*\) on qru-c.*/\1/p' \
    "$WORK/client.log" | head -n1)
  check "candidate ids for B and C are distinct" \
    "test -n '$B_ID' && test -n '$C_ID' && test '$B_ID' != '$C_ID'"
  check "client published both exact candidates once" \
    "test \"\$(grep -c \"UDP make-before-break committed candidate $B_ID\" $WORK/client.log)\" -eq 1 && test \"\$(grep -c \"UDP make-before-break committed candidate $C_ID\" $WORK/client.log)\" -eq 1"
  B_COMMIT_LINE=$(grep -n "UDP make-before-break committed candidate $B_ID" "$WORK/client.log" \
    | head -n1 | cut -d: -f1)
  C_PREPARE_LINE=$(grep -n "Linux roaming prepared candidate $C_ID on qru-c" "$WORK/client.log" \
    | head -n1 | cut -d: -f1)
  check "B commit is published before C prepare" \
    "test -n '$B_COMMIT_LINE' && test -n '$C_PREPARE_LINE' && test '$B_COMMIT_LINE' -lt '$C_PREPARE_LINE'"
  check "server committed exactly B then C" \
    "test \"\$(grep -c 'UDP PATH_COMMIT' $WORK/server.log)\" -eq 2 && grep -q 'UDP PATH_COMMIT.*to 10.41.2.2:' $WORK/server.log && grep -q 'UDP PATH_COMMIT.*to 10.41.4.2:' $WORK/server.log"
  check "no candidate rollback occurred during commit linearization" \
    "! grep -Eq 'rollback completed|rolled back superseded candidate|superseded before platform commit' $WORK/client.log"
  check "carrier bypass ends on path C" \
    "ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -q '^10.41.3.2 via 10.41.4.1 dev qru-c'"
  check "no stale carrier bypass remains on A or B" \
    "! ip netns exec $CLI_NS ip route show 10.41.3.2 | grep -Eq 'dev qru-(a|b)'"

  ip netns exec "$CLI_NS" ip link set qru-a down
  ip netns exec "$CLI_NS" ip link set qru-b down
  sleep 2
  check "tunnel survives removal of both older paths" \
    "ip netns exec $CLI_NS ping -c5 -W1 10.89.0.1"
  check "client process survives ordered commits without reconnect" \
    "test -n '$CLIENT_PID' && ip netns pids $CLI_NS | grep -qx '$CLIENT_PID'"
  check "the same TUN survives the commit race" \
    "test -n '$TUN_IFINDEX' && test \"\$(ip netns exec $CLI_NS cat /sys/class/net/qru0/ifindex)\" = '$TUN_IFINDEX'"
  check "commit race does not enter the top-level reconnect loop" \
    "! grep -Eq 'Connection error|Reconnecting in' $WORK/client.log"

  wait "$PING_PID" 2>/dev/null || true
  PING_RX=$(awk -F, '/packets transmitted/ { value=$2; gsub(/[^0-9]/, "", value); print value }' \
    "$WORK/ping.log" | tail -n1)
  check "continuous probe retained at least 220 of 240 packets during the commit race" \
    "test -n '$PING_RX' && test '$PING_RX' -ge 220"
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

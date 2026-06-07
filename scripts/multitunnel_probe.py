#!/usr/bin/env python3
"""Decisive test for the multi-queue-TUN question: does the qeli SERVER spread
crypto across cores when handling MULTIPLE tunnels, or does the single TUN-pump
cap aggregate at ~1.5 cores regardless?

One qeli client uses a fixed tun name (vpn0), so two clients on one host collide.
We therefore run each client in its OWN network namespace on .11 (each gets its
own vpn0; reaches the server via a veth + MASQUERADE). Two users → two tunnels →
two decrypt tasks in the one server worker process.

  Case A: 1 tunnel uploading      → baseline (~1.5 core, ~589 Mbps expected)
  Case B: 2 tunnels uploading      → if ~2.0 core & ~2x throughput: crypto scales
                                      across connections (pump not yet the limit on
                                      2 cores). If still ~1.5 core & no gain: the
                                      single TUN-pump IS the bottleneck → multi-queue
                                      strongly justified.

Server worker CPU measured via /proc/<pid>/stat deltas (true, can exceed 100%).
  SERVER 10.66.116.10   CLIENT 10.66.116.11   (override via QELI_LAB_*)
"""
import os, sys, io, time, json, socket
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

_PW = os.environ.get("QELI_LAB_PASS", "")
SERVER = (os.environ.get("QELI_LAB_SERVER", "10.66.116.10"), "root", _PW)
CLIENT = (os.environ.get("QELI_LAB_CLIENT", "10.66.116.11"), "root", _PW)
BIN = "/usr/local/bin/qeli"
SRC_BIN = "/opt/qeli-src/target/release/qeli"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
PASS = "testpass123"
SIP = "10.9.0.1"
# Force a specific TUN queue count for an A/B: 1 = legacy single-pump, 2 = multi-queue,
# 0 = auto (=nproc). Set QELI_TUN_QUEUES to compare back-to-back.
QUEUES = os.environ.get("QELI_TUN_QUEUES", "0")


def conn(h):
    sk = socket.create_connection((h[0], 22), timeout=20)
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], sock=sk, look_for_keys=False, allow_agent=False, timeout=20)
    return c


def out(c, cmd, t=120):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def put(c, path, text):
    sf = c.open_sftp(); sf.putfo(io.BytesIO(text.encode()), path); sf.close()


SERVER_CONF = f"""[auth]
require_client_key_proof = false

[logging]
level = info
file = /var/log/qeli/server.log

[profile:bench]
identity_key = /etc/qeli/identity/bench.key
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = {SIP}
tun.netmask = 255.255.255.0
tun.mtu = 1400
tun.queues = {QUEUES}
pool.cidr = 10.9.0.0/24
pool.exclude = {SIP}
routing.forward_private = true
routing.nat.enabled = false
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.cloudflare.com
obf.padding.enabled = false
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
obf.quic.enabled = false
perf.tcp.nodelay = true
perf.connection.max_clients = 16
perf.connection.new_session_rate_max = 100
perf.connection.new_session_rate_window_secs = 60
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0

[user:bench1]
password_hash = {HASH}
enabled = true

[user:bench2]
password_hash = {HASH}
enabled = true
"""


def client_conf(user):
    return f"[qeli]\nserver = {SERVER[0]}:443\nproto = tcp\nuser = {user}\npass = {PASS}\nmode = fake-tls\n\n[logging]\nlevel = info\n"


def worker_jiffies(s):
    v = out(s, "j=0; for p in $(pgrep -x qeli); do "
               "a=$(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null); j=$((j+${a:-0})); done; echo $j")
    try:
        return int(v.strip())
    except ValueError:
        return 0


def sample_cpu(s, secs):
    clk = int(out(s, "getconf CLK_TCK") or "100")
    j0 = worker_jiffies(s); t0 = time.time()
    time.sleep(secs)
    j1 = worker_jiffies(s); dt = time.time() - t0
    return round((j1 - j0) / clk / dt * 100.0, 1)


def host_busy(c):
    """Aggregate host busy fraction from /proc/stat field deltas (0..100%, where
    100% = ALL cores fully busy). Used to tell whether a host is the bottleneck."""
    def snap():
        ln = out(c, "head -1 /proc/stat").split()[1:]
        v = list(map(int, ln)); idle = v[3] + v[4]; return sum(v), idle
    t0, i0 = snap(); time.sleep(5); t1, i1 = snap()
    dt, di = t1 - t0, i1 - i0
    return round((dt - di) / dt * 100.0, 1) if dt else 0.0


def _hsnap(c):
    v = list(map(int, out(c, "head -1 /proc/stat").split()[1:]))
    return sum(v), v[3] + v[4]  # (total, idle+iowait) jiffies


def sample_both(s, cl, secs):
    """Over the same window: server worker qeli CPU (%-of-one-core), server HOST
    busy (%-of-all-cores; 100 = every core full), client HOST busy (%-of-all)."""
    clk = int(out(s, "getconf CLK_TCK") or "100")
    sj0 = worker_jiffies(s)
    st0, si0 = _hsnap(s)
    ct0, ci0 = _hsnap(cl)
    t0 = time.time()
    time.sleep(secs)
    sj1 = worker_jiffies(s)
    st1, si1 = _hsnap(s)
    ct1, ci1 = _hsnap(cl)
    dt = time.time() - t0
    scpu = round((sj1 - sj0) / clk / dt * 100.0, 1)
    shost = round(((st1 - st0) - (si1 - si0)) / (st1 - st0) * 100.0, 1) if st1 != st0 else 0.0
    chost = round(((ct1 - ct0) - (ci1 - ci0)) / (ct1 - ct0) * 100.0, 1) if ct1 != ct0 else 0.0
    return scpu, shost, chost


def ns_setup(cl, i):
    ns, vh, vn, net = f"ns{i}", f"veth{i}h", f"veth{i}n", f"10.200.{i}"
    out(cl, f"ip netns del {ns} 2>/dev/null; ip link del {vh} 2>/dev/null; true")
    cmds = [
        f"ip netns add {ns}",
        f"ip link add {vh} type veth peer name {vn}",
        f"ip link set {vn} netns {ns}",
        f"ip addr add {net}.1/24 dev {vh}",
        f"ip link set {vh} up",
        f"ip netns exec {ns} ip addr add {net}.2/24 dev {vn}",
        f"ip netns exec {ns} ip link set {vn} up",
        f"ip netns exec {ns} ip link set lo up",
        f"ip netns exec {ns} ip route add default via {net}.1",
        f"iptables -t nat -C POSTROUTING -s {net}.0/24 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {net}.0/24 -j MASQUERADE",
        f"iptables -C FORWARD -s {net}.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD -s {net}.0/24 -j ACCEPT",
        f"iptables -C FORWARD -d {net}.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD -d {net}.0/24 -j ACCEPT",
    ]
    out(cl, "sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    for c in cmds:
        out(cl, c)
    # connectivity check ns -> server
    return out(cl, f"ip netns exec {ns} ping -c1 -W2 {SERVER[0]} >/dev/null 2>&1 && echo OK || echo FAIL")


def ns_teardown(cl, i):
    ns, vh, net = f"ns{i}", f"veth{i}h", f"10.200.{i}"
    out(cl, f"ip netns exec {ns} pkill -9 -x qeli 2>/dev/null; ip netns del {ns} 2>/dev/null; "
            f"ip link del {vh} 2>/dev/null; "
            f"iptables -t nat -D POSTROUTING -s {net}.0/24 -j MASQUERADE 2>/dev/null; "
            f"iptables -D FORWARD -s {net}.0/24 -j ACCEPT 2>/dev/null; "
            f"iptables -D FORWARD -d {net}.0/24 -j ACCEPT 2>/dev/null; true")


def start_client(cl, i, user):
    ns = f"ns{i}"
    put(cl, f"/etc/qeli/c{i}.conf", client_conf(user))
    out(cl, f"ip netns exec {ns} bash -c 'rm -f /tmp/qc{i}.log; nohup {BIN} client --config /etc/qeli/c{i}.conf >/tmp/qc{i}.log 2>&1 & echo ok'")


def main():
    print("=== qeli 2-tunnel aggregate probe (multi-queue justification) ===")
    s = conn(SERVER); cl = conn(CLIENT)
    print("server cores (nproc):", out(s, "nproc"))
    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true")
    out(s, f"install -m755 {SRC_BIN} {BIN}; mkdir -p /etc/qeli/identity /var/log/qeli")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close()
    out(cl, f"chmod 755 {BIN}; mkdir -p /etc/qeli")
    print("binary:", out(s, f"{BIN} --version"))

    put(s, "/etc/qeli/mt-server.conf", SERVER_CONF)
    out(s, "pkill -9 -x qeli; sleep 1; rm -f /var/log/qeli/server.log; "
           f"nohup {BIN} server --config /etc/qeli/mt-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    # 2 iperf3 servers on the tun IP, distinct ports (iperf3 -s runs one test/port).
    out(s, f"pkill -9 iperf3; sleep 1; "
           f"nohup iperf3 -s -B {SIP} -p 5201 >/tmp/is1.log 2>&1 & "
           f"nohup iperf3 -s -B {SIP} -p 5202 >/tmp/is2.log 2>&1 & echo ok"); time.sleep(1)

    print("setting up 2 network namespaces on client...")
    for i in (1, 2):
        print(f"  ns{i} -> server reachability:", ns_setup(cl, i))
    start_client(cl, 1, "bench1")
    start_client(cl, 2, "bench2")
    time.sleep(6)
    ok = True
    for i in (1, 2):
        log = out(cl, f"grep -E 'Auth OK|assigned IP' /tmp/qc{i}.log || true")
        print(f"  client {i}:", (log.splitlines() or ['(no Auth OK)'])[-1][:90])
        if "Auth OK" not in log:
            ok = False
    if not ok:
        print("CONNECT FAILED. client logs / server log:")
        print(out(cl, "tail -4 /tmp/qc1.log /tmp/qc2.log"))
        print(out(s, "tail -6 /tmp/qs.log /var/log/qeli/server.log"))
        for i in (1, 2): ns_teardown(cl, i)
        out(s, "pkill -9 iperf3; pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
        s.close(); cl.close(); return
    print("threads in worker:", out(s, "for p in $(pgrep -x qeli); do ps -L --no-headers -p $p; done | wc -l"))

    def thr(raw):
        try:
            return json.loads(raw)["end"]["sum_received"]["bits_per_second"] / 1e6
        except Exception:
            return 0.0

    # Case A: single tunnel (ns1) uploading
    print("\n--- Case A: 1 tunnel uploading ---")
    out(cl, f"ip netns exec ns1 bash -c 'rm -f /tmp/ipA.json; nohup iperf3 -c {SIP} -p 5201 -t 16 --json >/tmp/ipA.json 2>&1 & echo ok'")
    time.sleep(2); cpuA, shostA, chostA = sample_both(s, cl, 9); time.sleep(4)
    a = thr(out(cl, "cat /tmp/ipA.json 2>/dev/null"))
    print(f"  qeli {cpuA:.0f}%/one-core | SERVER-host {shostA:.0f}%/all | client-host {chostA:.0f}%/all | {a:.0f} Mbps")

    # Case B: two tunnels uploading simultaneously
    print("\n--- Case B: 2 tunnels uploading simultaneously ---")
    out(cl, f"ip netns exec ns1 bash -c 'rm -f /tmp/ipB1.json; nohup iperf3 -c {SIP} -p 5201 -t 18 --json >/tmp/ipB1.json 2>&1 & echo ok'")
    out(cl, f"ip netns exec ns2 bash -c 'rm -f /tmp/ipB2.json; nohup iperf3 -c {SIP} -p 5202 -t 18 --json >/tmp/ipB2.json 2>&1 & echo ok'")
    time.sleep(3); cpuB, shostB, chostB = sample_both(s, cl, 9); time.sleep(6)
    b1 = thr(out(cl, "cat /tmp/ipB1.json 2>/dev/null"))
    b2 = thr(out(cl, "cat /tmp/ipB2.json 2>/dev/null"))
    print(f"  qeli {cpuB:.0f}%/one-core | SERVER-host {shostB:.0f}%/all | client-host {chostB:.0f}%/all | {b1:.0f}+{b2:.0f}={b1+b2:.0f} Mbps")

    print("\n=== verdict ===")
    print(f"  1 tunnel : qeli {cpuA:.0f}% | server-host {shostA:.0f}%/all | client-host {chostA:.0f}%/all | {a:.0f} Mbps")
    print(f"  2 tunnels: qeli {cpuB:.0f}% | server-host {shostB:.0f}%/all | client-host {chostB:.0f}%/all | {b1+b2:.0f} Mbps")
    gain = (b1 + b2) / a if a else 0
    if shostB > 90:
        print(f"  → SERVER HOST SATURATED ({shostB:.0f}%/all-cores): the 2-core server is full of")
        print("    qeli + iperf3-server + kernel. iperf3 runs ON the server here, so this box")
        print("    CANNOT show the multi-queue win — the sink itself eats the spare cores. Need a")
        print("    setup where traffic is forwarded OFF the server (real NAT egress / bigger box).")
    elif gain >= 1.6 and cpuB > cpuA * 1.35:
        print(f"  → ~{gain:.1f}x, qeli engaged more cores ({cpuA:.0f}%→{cpuB:.0f}%): multi-queue scales. ✅")
    elif chostB > 90:
        print(f"  → client host maxed ({chostB:.0f}%) — client is the limiter, inconclusive for server.")
    else:
        print(f"  → ~{gain:.1f}x, server-host {shostB:.0f}%/all not saturated, qeli {cpuB:.0f}%: spare")
        print("    capacity unused → a serial stage still caps it. Investigate.")

    for i in (1, 2): ns_teardown(cl, i)
    out(s, "pkill -9 iperf3; pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()
    print("[done] lab restored (netns removed, qeli-server.service restarted)")


if __name__ == "__main__":
    main()

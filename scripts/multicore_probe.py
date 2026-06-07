#!/usr/bin/env python3
"""Empirically check whether qeli's data-plane crypto spreads across CPU cores.

A single qeli tunnel = one TCP connection. Inbound decrypt runs in a per-connection
reader task; outbound encrypt runs in the writer task — two independent tokio tasks.
With the multi-threaded runtime they can occupy two cores at once. So `iperf3
--bidir` over ONE tunnel exercises decrypt+encrypt simultaneously; if the server qeli
process then uses >100% CPU (more than one core), crypto is genuinely multi-core.

Measures the server worker's true CPU via /proc/<pid>/stat (utime+stime) deltas —
unlike `ps %cpu` (lifetime average), this captures the live per-interval load and
can exceed 100%. Compares idle / upload / download / bidir.

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
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0

[user:bench]
password_hash = {HASH}
enabled = true
"""

CLIENT_CONF = f"""[qeli]
server = {SERVER[0]}:443
proto = tcp
user = bench
pass = {PASS}
mode = fake-tls

[logging]
level = info
"""


def worker_jiffies(s):
    """Sum utime+stime (jiffies) across all qeli processes — the data-plane worker
    is the hot one. comm is the bare binary name (no spaces) so $14+$15 is safe."""
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
    return round((j1 - j0) / clk / dt * 100.0, 1)  # % of ONE core; >100 = multi-core


def iperf(cl, args, t=40):
    o = out(cl, f"iperf3 -c {SIP} {args} --json", t=t)
    try:
        e = json.loads(o)["end"]
        if "sum_bidir_reverse" in e or "--bidir" in args:
            up = e.get("sum_sent", {}).get("bits_per_second", 0) / 1e6
            dn = e.get("sum_received", {}).get("bits_per_second", 0) / 1e6
            return f"{up:.0f}↑ / {dn:.0f}↓ Mbps"
        return f"{e['sum_received']['bits_per_second']/1e6:.0f} Mbps"
    except Exception as ex:
        return f"err:{ex}"


def run_case(s, cl, name, iperf_args):
    # launch iperf3 in the background on the client, sample server CPU mid-run
    out(cl, f"rm -f /tmp/ip.json; nohup iperf3 -c {SIP} {iperf_args} -t 14 --json >/tmp/ip.json 2>&1 & echo ok")
    time.sleep(2)                      # let it ramp
    cpu = sample_cpu(s, 9)             # measure the steady-state window
    time.sleep(4)                      # let iperf finish
    raw = out(cl, "cat /tmp/ip.json 2>/dev/null")
    try:
        e = json.loads(raw)["end"]
        if "--bidir" in iperf_args:
            up = e["sum_sent"]["bits_per_second"] / 1e6
            dn = e["sum_received"]["bits_per_second"] / 1e6
            thr = f"{up:.0f}↑ / {dn:.0f}↓"
        elif "-R" in iperf_args:
            thr = f"{e['sum_received']['bits_per_second']/1e6:.0f}↓"
        else:
            thr = f"{e['sum_received']['bits_per_second']/1e6:.0f}↑"
    except Exception:
        thr = "n/a"
    cores = round(cpu / 100.0, 2)
    print(f"  {name:<22} server qeli CPU = {cpu:6.1f}%  (~{cores} core)   throughput {thr} Mbps")
    return cpu


def main():
    print("=== qeli data-plane multi-core probe ===")
    s = conn(SERVER); cl = conn(CLIENT)
    print("server cores (nproc):", out(s, "nproc"))
    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true")
    out(s, f"install -m755 {SRC_BIN} {BIN}; mkdir -p /etc/qeli/identity /var/log/qeli")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close()
    out(cl, f"chmod 755 {BIN}; mkdir -p /etc/qeli")
    print("binary:", out(s, f"{BIN} --version"))

    put(s, "/etc/qeli/mc-server.conf", SERVER_CONF)
    put(cl, "/etc/qeli/mc-client.conf", CLIENT_CONF)
    out(s, "pkill -9 -x qeli; sleep 1; rm -f /var/log/qeli/server.log; "
           f"nohup {BIN} server --config /etc/qeli/mc-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; sleep 1; "
            f"nohup {BIN} client --config /etc/qeli/mc-client.conf >/tmp/qc.log 2>&1 & echo ok")
    time.sleep(5)
    if "Auth OK" not in out(cl, "grep -E 'Auth OK' /tmp/qc.log || true"):
        print("CONNECT FAILED:", out(cl, "tail -5 /tmp/qc.log"), "||", out(s, "tail -5 /tmp/qs.log /var/log/qeli/server.log"))
        out(s, "pkill -9 -x qeli"); out(cl, "pkill -9 -x qeli"); s.close(); cl.close(); return
    print("tunnel up. workers:", out(s, "pgrep -x qeli | tr '\\n' ' '"),
          "| threads:", out(s, "for p in $(pgrep -x qeli); do ps -L --no-headers -p $p; done | wc -l"))
    out(s, f"pkill -9 iperf3; sleep 1; nohup iperf3 -s -B {SIP} >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)

    print("\nidle baseline:")
    print(f"  {'idle':<22} server qeli CPU = {sample_cpu(s,3):6.1f}%")
    print("\nload (single tunnel = single TCP connection):")
    up   = run_case(s, cl, "upload (decrypt)", "")
    dn   = run_case(s, cl, "download (encrypt)", "-R")
    bi   = run_case(s, cl, "bidir (decrypt+encrypt)", "--bidir")

    print("\n=== verdict ===")
    print(f"  upload≈{up:.0f}%  download≈{dn:.0f}%  bidir≈{bi:.0f}%")
    if bi > 115:
        print("  ✅ bidir > 100% → server crypto runs on MULTIPLE cores concurrently")
        print("     (decrypt reader-task + encrypt writer-task scheduled on separate cores).")
    elif bi > max(up, dn) * 1.3:
        print("  ✅ bidir clearly exceeds single-direction → crypto tasks run in parallel")
        print(f"     (additive: ~{up:.0f}+{dn:.0f}); box is fast enough that 2 tasks still fit under 200%.")
    else:
        print("  ⚠️ bidir ≈ single-direction → check: throughput-bound (not CPU) or serialized.")

    out(s, "pkill -9 iperf3"); out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null")
    out(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()
    print("[done] lab restored (qeli-server.service restarted)")


if __name__ == "__main__":
    main()

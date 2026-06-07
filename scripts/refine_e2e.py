#!/usr/bin/env python3
"""E2e for the two refinements: blocking-read TUN reader + multi-worker UDP
(SO_REUSEPORT). Also exercises the client `dev=` key — two clients on ONE host with
distinct tun names (qtcp, qudp), which the old fixed-`vpn0` could not do.

  SERVER 10.66.116.10   CLIENT 10.66.116.11   (override via QELI_LAB_*)
"""
import os, sys, io, time, socket
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

_PW = os.environ.get("QELI_LAB_PASS", "")
SERVER = (os.environ.get("QELI_LAB_SERVER", "10.66.116.10"), "root", _PW)
CLIENT = (os.environ.get("QELI_LAB_CLIENT", "10.66.116.11"), "root", _PW)
BIN = "/usr/local/bin/qeli"
SRC_BIN = "/opt/qeli-src/target/release/qeli"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
PASS = "testpass123"


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

[profile:tcp]
identity_key = /etc/qeli/identity/tcp.key
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = qsrv0
tun.address = 10.9.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.exclude = 10.9.0.1
routing.forward_private = true
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.interval_ms = 15000
perf.connection.max_clients = 16
perf.connection.new_session_rate_max = 100
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0

[profile:udp]
identity_key = /etc/qeli/identity/udp.key
bind.address = 0.0.0.0
bind.port = 4443
bind.transport = udp
tun.name = qsrv1
tun.address = 10.10.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.10.0.0/24
pool.exclude = 10.10.0.1
routing.forward_private = true
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.interval_ms = 15000
perf.connection.max_clients = 16
perf.connection.new_session_rate_max = 100
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0

[user:bench]
password_hash = {HASH}
enabled = true
"""


def client_conf(proto, port, dev):
    return (f"[qeli]\nserver = {SERVER[0]}:{port}\nproto = {proto}\nuser = bench\n"
            f"pass = {PASS}\nmode = fake-tls\ndev = {dev}\n\n[logging]\nlevel = info\n")


def worker_cpu(s, secs):
    clk = int(out(s, "getconf CLK_TCK") or "100")
    def j():
        return int(out(s, "x=0; for p in $(pgrep -x qeli); do a=$(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null); x=$((x+${a:-0})); done; echo $x") or 0)
    a = j(); time.sleep(secs); b = j()
    return round((b - a) / clk / secs * 100.0, 1)


def main():
    print("=== refine e2e: blocking-read + UDP multi-worker + client dev= ===")
    s = conn(SERVER); cl = conn(CLIENT)
    print("server cores:", out(s, "nproc"))
    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; true")
    out(s, f"install -m755 {SRC_BIN} {BIN}; mkdir -p /etc/qeli/identity /var/log/qeli")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close()
    out(cl, f"chmod 755 {BIN}; mkdir -p /etc/qeli")
    print("binary:", out(s, f"{BIN} --version"))

    put(s, "/etc/qeli/re-server.conf", SERVER_CONF)
    out(s, "ip link del qsrv0 2>/dev/null; ip link del qsrv1 2>/dev/null; "
           "pkill -9 -x qeli; sleep 1; rm -f /var/log/qeli/server.log; "
           f"nohup {BIN} server --config /etc/qeli/re-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(5)
    print("server listeners:", out(s, "ss -tlnp 2>/dev/null | grep -c ':443 '; ss -ulnp 2>/dev/null | grep -c ':4443 '") or "?",
          "(tcp443 / udp4443 counts)")
    err = out(s, "grep -iE 'error|panic|bail' /var/log/qeli/server.log /tmp/qs.log 2>/dev/null | head -3")
    if err:
        print("server errors:", err)

    # Two clients on ONE host, distinct tun names via dev= (impossible pre-fix).
    out(cl, "pkill -9 -x qeli; ip link del qtcp 2>/dev/null; ip link del qudp 2>/dev/null; sleep 1; true")
    put(cl, "/etc/qeli/c-tcp.conf", client_conf("tcp", 443, "qtcp"))
    put(cl, "/etc/qeli/c-udp.conf", client_conf("udp", 4443, "qudp"))
    out(cl, f"rm -f /tmp/ct.log; nohup {BIN} client --config /etc/qeli/c-tcp.conf >/tmp/ct.log 2>&1 & echo ok")
    out(cl, f"rm -f /tmp/cu.log; nohup {BIN} client --config /etc/qeli/c-udp.conf >/tmp/cu.log 2>&1 & echo ok")
    time.sleep(6)

    tcp_ok = out(cl, "grep -E 'Auth OK' /tmp/ct.log || true")
    udp_ok = out(cl, "grep -E 'Auth OK' /tmp/cu.log || true")
    print("TCP client:", (tcp_ok.splitlines() or ["FAIL"])[-1][:80])
    print("UDP client:", (udp_ok.splitlines() or ["FAIL"])[-1][:80])
    print("client interfaces:", out(cl, "ip -o link show 2>/dev/null | grep -oE 'q(tcp|udp)' | tr '\\n' ' '"))
    print("UDP workers on server:", out(s, "grep -c 'UDP worker' /var/log/qeli/server.log || echo 0"),
          "->", out(s, "grep -oE 'UDP worker [0-9]+' /var/log/qeli/server.log | sort -u | tr '\\n' ' '"))

    if "Auth OK" in tcp_ok:
        p = out(cl, "ping -c 4 -i 0.3 -W 2 10.9.0.1 2>&1 | tail -2")
        print("ping via TCP tunnel (qtcp):", p.splitlines()[-1] if p else "n/a")
    if "Auth OK" in udp_ok:
        p = out(cl, "ping -c 4 -i 0.3 -W 2 10.10.0.1 2>&1 | tail -2")
        print("ping via UDP tunnel (qudp):", p.splitlines()[-1] if p else "n/a")

    # Idle CPU: both tunnels up, no traffic. blocking-read => ~0 (no 1ms busy-poll).
    print("\nidle server qeli CPU (both tunnels up, no traffic):", worker_cpu(s, 5), "%/one-core")

    out(cl, "pkill -9 -x qeli; ip link del qtcp 2>/dev/null; ip link del qudp 2>/dev/null; true")
    out(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()
    print("[done] lab restored")


if __name__ == "__main__":
    main()

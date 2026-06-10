#!/usr/bin/env python3
"""Verify the UDP stale-session reap fix: a UDP client auths (creates a session),
is then killed; with idle_timeout=0 the OLD code left the session forever, the
NEW code reaps it on the RX-liveness window (3×hb, >=30s). Runs a throwaway UDP
server on .10 (steals the control socket; restored at the end). NOT user01."""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

QELI = "/opt/qeli-src/target/debug/qeli"
PUB = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
PORT = 8460
LOG = "/root/reality-test/srv-udpreap.log"

SERVER_CONF = f"""[web]
enabled = false
[auth]
users_file = /root/reality-test/users-e2e.conf
[profile:udp-reap]
enabled = true
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = udp
tun.name = udpr0
tun.address = 10.66.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1280
pool.cidr = 10.66.0.0/24
pool.exclude = 10.66.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 5000
perf.connection.idle_timeout_secs = 0
[logging]
level = info
file = {LOG}
"""

CLIENT_CONF = f"""[qeli]
server = 10.66.116.10:{PORT}
proto = udp
user = admin
pass = testpass123
mode = fake-tls
key = {PUB}
sni = www.microsoft.com
[logging]
level = info
file = /root/udpr-cli.log
"""


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h, username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
    return c


sc = conn("10.66.116.10"); cc = conn("10.66.116.11")
def S(cmd, t=90):
    i, o, e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=90):
    i, o, e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()


def list_admin():
    return S(f"{QELI} list-clients 2>&1 | grep -c admin")


try:
    sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), "/root/reality-test/server-udpreap.conf"); sf.close()
    S("ps -eo pid,args|grep server-udpreap.conf|grep -v grep|awk '{print $1}'|xargs -r kill -9 2>/dev/null; ip link del udpr0 2>/dev/null; rm -f " + LOG + "; sleep 1; true")
    ch = sc.get_transport().open_session()
    ch.exec_command(f"RUST_LOG=info setsid nohup {QELI} server -c /root/reality-test/server-udpreap.conf >/dev/null 2>&1 </dev/null & echo $! >/root/reality-test/srv-udpreap.pid")
    time.sleep(1); ch.close()
    up = any(f"listening on 0.0.0.0:{PORT}" in S(f"cat {LOG} 2>/dev/null") for _ in [time.sleep(1) or 1 for _ in range(15)])
    print("[server] udp :%d listening = %s (owns control socket)" % (PORT, up))

    # run the UDP client (split-tunnel, no routing) — it auths -> session created.
    import tempfile
    tmpbin = os.path.join(tempfile.gettempdir(), "qeli-udpr-bin")
    sf = sc.open_sftp(); sf.get(QELI, tmpbin); sf.close()
    sf = cc.open_sftp(); sf.put(tmpbin, "/root/qeli-udpr"); sf.putfo(io.BytesIO(CLIENT_CONF.encode()), "/root/udpr-cli.conf"); sf.close()
    C("chmod +x /root/qeli-udpr; pkill -9 -f 'qeli-udpr client' 2>/dev/null; rm -f /root/udpr-cli.log; ip link del udpr0 2>/dev/null; true")
    ch = cc.get_transport().open_session()
    ch.exec_command("RUST_LOG=info setsid nohup /root/qeli-udpr client -c /root/udpr-cli.conf </dev/null >/root/udpr-cli.out 2>&1 & echo $! >/root/udpr-cli.pid")
    time.sleep(1); ch.close()
    ok = False
    for _ in range(20):
        time.sleep(1)
        if "Auth OK" in C("cat /root/udpr-cli.log /root/udpr-cli.out 2>/dev/null"): ok = True; break
    time.sleep(2)
    n_before = list_admin()
    print(f"[connect] client Auth OK={ok} | sessions for admin (before kill) = {n_before}")

    # kill the client -> dead UDP session
    C("kill -9 $(cat /root/udpr-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'qeli-udpr client' 2>/dev/null; ip link del udpr0 2>/dev/null; true")
    print("[kill] client killed; reap window = max(3*5s, 30s) = 30s + up to 30s cleanup tick. Polling...")
    reaped = False
    for t in range(0, 80, 10):
        time.sleep(10)
        n = list_admin()
        print(f"   [t+{t+10:>2}s after kill] sessions for admin = {n}")
        if n == "0":
            reaped = True; print(f"   -> REAPED at ~{t+10}s"); break
    print("\n=== RESULT ===")
    print(f"  before kill: admin sessions = {n_before}")
    print(f"  after kill : reaped = {reaped}  (OLD behaviour with idle_timeout=0: would stay FOREVER)")
    print(f"  VERDICT: {'PASS — dead UDP session reaped on liveness window' if reaped and n_before != '0' else 'CHECK numbers'}")
finally:
    print("\n=== cleanup ===")
    C("kill -9 $(cat /root/udpr-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'qeli-udpr client' 2>/dev/null; ip link del udpr0 2>/dev/null; true")
    pid = S("cat /root/reality-test/srv-udpreap.pid 2>/dev/null")
    if pid: S(f"kill -9 {pid} 2>/dev/null; true")
    S("ps -eo pid,args|grep server-udpreap.conf|grep -v grep|awk '{print $1}'|xargs -r kill -9 2>/dev/null; ip link del udpr0 2>/dev/null; systemctl restart qeli-server.service >/dev/null 2>&1; true")
    print("[restored] lab systemd:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

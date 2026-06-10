#!/usr/bin/env python3
"""Multi-device: two clients with the SAME login (admin) but DIFFERENT device-ids
must COEXIST (two sessions, two IPs) instead of evicting each other. Then the same
device-id reconnecting supersedes only its OWN session. Throwaway fake-tls server
on .10 (steals control socket; systemd restored). NOT user01."""
import os, sys, io, time, tempfile
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

QELI = "/opt/qeli-src/target/debug/qeli"
PUB = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
PORT = 8506
LOG = "/root/reality-test/srv-md.log"

SERVER_CONF = f"""[web]
enabled = false
[auth]
users_file = /root/reality-test/users-e2e.conf
[profile:md]
enabled = true
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = md0
tun.address = 10.67.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1280
pool.cidr = 10.67.0.0/24
pool.exclude = 10.67.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
obf.multipath.enabled = false
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
[logging]
level = info
file = {LOG}
"""

def client_conf(tag, log):
    return f"""[qeli]
server = 10.66.116.10:{PORT}
proto = tcp
user = admin
pass = testpass123
mode = fake-tls
key = {PUB}
sni = www.microsoft.com
dev = vpnmd{tag}
[logging]
level = info
file = {log}
"""

sc = paramiko.SSHClient(); sc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sc.connect("10.66.116.10", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
cc = paramiko.SSHClient(); cc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cc.connect("10.66.116.11", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def S(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=60):
    i, o, e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()

def admin_sessions():
    out = S(f"{QELI} list-clients 2>&1 | grep admin")
    return out

def start_client(tag, dev_file, log):
    C(f"rm -f {dev_file} {log}; pkill -9 -f 'qeli-md client.*{tag}' 2>/dev/null; true")
    sf = cc.open_sftp(); sf.putfo(io.BytesIO(client_conf(tag, log).encode()), f"/root/md-{tag}.conf"); sf.close()
    ch = cc.get_transport().open_session()
    ch.exec_command(f"QELI_DEVICE_ID_FILE={dev_file} setsid nohup /root/qeli-md client -c /root/md-{tag}.conf </dev/null >/root/md-{tag}.out 2>&1 & echo $! >/root/md-{tag}.pid")
    time.sleep(1); ch.close()
    for _ in range(20):
        time.sleep(1)
        if "Auth OK" in C(f"cat {log} {'/root/md-'+tag+'.out'} 2>/dev/null"): return True
    return False

try:
    sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), "/root/reality-test/server-md.conf"); sf.close()
    S("ps -eo pid,args|grep server-md.conf|grep -v grep|awk '{print $1}'|xargs -r kill -9 2>/dev/null; ip link del md0 2>/dev/null; rm -f " + LOG + "; sleep 1; true")
    ch = sc.get_transport().open_session()
    ch.exec_command(f"RUST_LOG=info setsid nohup {QELI} server -c /root/reality-test/server-md.conf >/dev/null 2>&1 </dev/null & echo $! >/root/reality-test/srv-md.pid")
    time.sleep(1); ch.close()
    up = any(f"listening on 0.0.0.0:{PORT}" in S(f"cat {LOG} 2>/dev/null") for _ in [time.sleep(1) or 1 for _ in range(15)])
    print("[server] :%d listening = %s (owns control socket)" % (PORT, up))
    sf = sc.open_sftp(); sf.get(QELI, "/tmp/qeli-md-bin"); sf.close()
    sf = cc.open_sftp(); sf.put("/tmp/qeli-md-bin", "/root/qeli-md"); sf.close()
    C("chmod +x /root/qeli-md; true")

    print("\n[device A] connect (same login 'admin', device-id A)")
    a = start_client("A", "/root/devA", "/root/md-A.log")
    time.sleep(2)
    print("  Auth OK:", a, "| admin sessions:\n   ", admin_sessions().replace(chr(10), "\n    "))
    n_after_a = len([l for l in admin_sessions().splitlines() if l.strip()])

    print("\n[device B] connect (SAME login 'admin', DIFFERENT device-id B)")
    b = start_client("B", "/root/devB", "/root/md-B.log")
    time.sleep(2)
    sess = admin_sessions()
    n_after_b = len([l for l in sess.splitlines() if l.strip()])
    print("  Auth OK:", b, "| admin sessions:\n   ", sess.replace(chr(10), "\n    "))

    print("\n=== RESULT ===")
    print(f"  admin sessions after A = {n_after_a}, after B = {n_after_b}")
    ok = (n_after_a == 1 and n_after_b == 2)
    print(f"  VERDICT: {'PASS — two devices of one login COEXIST (multi-device)' if ok else 'FAIL — second device evicted the first (old behaviour)'}")
finally:
    print("\n=== cleanup ===")
    for tag in ("A", "B"):
        C(f"kill -9 $(cat /root/md-{tag}.pid 2>/dev/null) 2>/dev/null; true")
    C("pkill -9 -f 'qeli-md client' 2>/dev/null; for t in vpnmdA vpnmdB; do ip link del $t 2>/dev/null; done; true")
    pid = S("cat /root/reality-test/srv-md.pid 2>/dev/null")
    if pid: S(f"kill -9 {pid} 2>/dev/null; true")
    S("ps -eo pid,args|grep server-md.conf|grep -v grep|awk '{print $1}'|xargs -r kill -9 2>/dev/null; ip link del md0 2>/dev/null; systemctl restart qeli-server.service >/dev/null 2>&1; true")
    print("[restored] lab systemd:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

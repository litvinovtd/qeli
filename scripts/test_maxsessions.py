#!/usr/bin/env python3
"""Per-user max_sessions cap with device-id. admin has max_sessions=2: devices A,B
coexist (2 sessions); device C (3rd) evicts the OLDEST (A) -> still 2, now B+C.
Throwaway fake-tls server on .10 (steals control socket; systemd restored). NOT user01."""
import os, sys, io, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

QELI = "/opt/qeli-src/target/debug/qeli"
PUB = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
PORT = 8507
LOG = "/root/reality-test/srv-ms.log"
USERS = "/root/reality-test/users-ms.conf"

SERVER_CONF = f"""[web]
enabled = false
[auth]
users_file = {USERS}
[profile:ms]
enabled = true
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = ms0
tun.address = 10.68.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1280
pool.cidr = 10.68.0.0/24
pool.exclude = 10.68.0.1
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
dev = vpnms{tag}
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

def admin_ips():
    out = S(f"{QELI} list-clients 2>&1 | grep admin")
    ips = []
    for l in out.splitlines():
        m = re.search(r"10\.68\.0\.\d+", l)
        if m: ips.append(m.group(0))
    return sorted(ips)

def start(tag, dev_file, log):
    C(f"rm -f {dev_file} {log}; true")
    sf = cc.open_sftp(); sf.putfo(io.BytesIO(client_conf(tag, log).encode()), f"/root/ms-{tag}.conf"); sf.close()
    ch = cc.get_transport().open_session()
    ch.exec_command(f"QELI_DEVICE_ID_FILE={dev_file} setsid nohup /root/qeli-md client -c /root/ms-{tag}.conf </dev/null >/root/ms-{tag}.out 2>&1 & true")
    time.sleep(1); ch.close()
    for _ in range(20):
        time.sleep(1)
        if "Auth OK" in C(f"cat {log} /root/ms-{tag}.out 2>/dev/null"): return True
    return False

try:
    # users file: take e2e users, force admin max_sessions=2
    base = S("cat /root/reality-test/users-e2e.conf")
    lines, out = base.splitlines(), []
    for l in lines:
        out.append(l)
        if l.strip().lower() == "[user:admin]":
            out.append("max_sessions = 2")
    users = "\n".join(out) + "\n"
    sf = sc.open_sftp(); sf.putfo(io.BytesIO(users.encode()), USERS); sf.close()
    print("[users] admin max_sessions=2 injected:", "max_sessions = 2" in users)

    sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), "/root/reality-test/server-ms.conf"); sf.close()
    S("ps -eo pid,args|grep server-ms.conf|grep -v grep|awk '{print $1}'|xargs -r kill -9 2>/dev/null; ip link del ms0 2>/dev/null; rm -f " + LOG + "; sleep 1; true")
    ch = sc.get_transport().open_session()
    ch.exec_command(f"RUST_LOG=info setsid nohup {QELI} server -c /root/reality-test/server-ms.conf >/dev/null 2>&1 </dev/null & true")
    time.sleep(1); ch.close()
    up = any(f"listening on 0.0.0.0:{PORT}" in S(f"cat {LOG} 2>/dev/null") for _ in [time.sleep(1) or 1 for _ in range(15)])
    print("[server] :%d listening = %s" % (PORT, up))

    print("\n[A] connect"); start("A", "/root/msdevA", "/root/ms-A.log"); time.sleep(1.5)
    ipsA = admin_ips(); print("  admin IPs:", ipsA)
    print("[B] connect"); start("B", "/root/msdevB", "/root/ms-B.log"); time.sleep(1.5)
    ipsB = admin_ips(); print("  admin IPs:", ipsB)
    print("[C] connect (3rd device — must evict oldest A=10.68.0.2)"); start("C", "/root/msdevC", "/root/ms-C.log"); time.sleep(2)
    ipsC = admin_ips(); print("  admin IPs:", ipsC)

    print("\n=== RESULT ===")
    cap_ok = (len(ipsB) == 2 and len(ipsC) == 2)
    evicted_oldest = ("10.68.0.2" not in ipsC)
    print(f"  after A={len(ipsA)}, B={len(ipsB)}, C={len(ipsC)} (cap=2)")
    print(f"  oldest (10.68.0.2 / device A) evicted after C: {evicted_oldest}")
    print(f"  VERDICT: {'PASS — cap holds at 2, oldest device evicted (newest wins)' if cap_ok and evicted_oldest else 'FAIL'}")
    print("[evict log]", S(f"grep -E 'session cap|evicting oldest' {LOG} 2>/dev/null | tail -3"))
finally:
    print("\n=== cleanup ===")
    C("pkill -9 -f 'qeli-md client' 2>/dev/null; for t in vpnmsA vpnmsB vpnmsC; do ip link del $t 2>/dev/null; done; true")
    S("ps -eo pid,args|grep server-ms.conf|grep -v grep|awk '{print $1}'|xargs -r kill -9 2>/dev/null; ip link del ms0 2>/dev/null; systemctl restart qeli-server.service >/dev/null 2>&1; true")
    print("[restored] lab systemd:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

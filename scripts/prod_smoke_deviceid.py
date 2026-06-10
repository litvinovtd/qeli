#!/usr/bin/env python3
"""PROD smoke for device-id over the REAL reality-tls:443 transport. Two clients on
.11, SAME login user05 (NOT user01 — phone's user), DIFFERENT device-ids -> must
COEXIST as two sessions on prod. Confirms the device-id byte survives REALITY and
multi-device works on the live server. Clients only auth+create a session (tun won't
route from a plain host — that's fine, we check sessions via prod list-clients)."""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PROD = "222.167.246.143"
USER, PW = "user05", "5BHTtlxqhkjQgwRr"
KEY = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"
RSID = "2699764da5df00bc"

def conf(tag, log):
    return f"""[qeli]
server = {PROD}:443
proto = tcp
user = {USER}
pass = {PW}
mode = reality-tls
key = {KEY}
sni = www.microsoft.com
reality_sid = {RSID}
dev = vpnpd{tag}
[logging]
level = info
file = {log}
"""

pc = paramiko.SSHClient(); pc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
pc.connect(PROD, username="root", password=os.environ["QELI_PROD_PASS"], timeout=30, look_for_keys=False, allow_agent=False)
cc = paramiko.SSHClient(); cc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cc.connect("10.66.116.11", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def P(cmd, t=60):
    i, o, e = pc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=60):
    i, o, e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()

def u05():
    return [l for l in P(f"/usr/local/bin/qeli list-clients 2>&1 | grep {USER}").splitlines() if l.strip()]

def start(tag, dev_file, log):
    C(f"rm -f {dev_file} {log}; true")
    sf = cc.open_sftp(); sf.putfo(io.BytesIO(conf(tag, log).encode()), f"/root/pd-{tag}.conf"); sf.close()
    ch = cc.get_transport().open_session()
    ch.exec_command(f"QELI_DEVICE_ID_FILE={dev_file} setsid nohup /root/qeli-md client -c /root/pd-{tag}.conf </dev/null >/root/pd-{tag}.out 2>&1 & true")
    time.sleep(1); ch.close()
    for _ in range(25):
        time.sleep(1)
        if "Auth OK" in C(f"cat {log} /root/pd-{tag}.out 2>/dev/null"): return True
    return False

try:
    print("[prod] running sha:", P("sha256sum /usr/local/bin/qeli | cut -c1-12"), "| sessions now:", len(u05()))
    print("\n[device A] user05 + device-id A -> reality-tls:443")
    a = start("A", "/root/pdevA", "/root/pd-A.log"); time.sleep(2)
    sa = u05(); print("  Auth OK:", a, "| user05 sessions:", len(sa))
    for l in sa: print("    ", l)
    print("\n[device B] SAME user05 + DIFFERENT device-id B -> reality-tls:443")
    b = start("B", "/root/pdevB", "/root/pd-B.log"); time.sleep(2)
    sb = u05(); print("  Auth OK:", b, "| user05 sessions:", len(sb))
    for l in sb: print("    ", l)
    print("\n=== RESULT ===")
    ok = (len(sa) == 1 and len(sb) == 2)
    print(f"  after A={len(sa)}, after B={len(sb)} -> {'PASS — multi-device LIVE on prod reality-tls' if ok else 'CHECK above'}")
    if not a or not b:
        print("  [client log tail A]", C("tail -4 /root/pd-A.out /root/pd-A.log 2>/dev/null"))
        print("  [client log tail B]", C("tail -4 /root/pd-B.out /root/pd-B.log 2>/dev/null"))
finally:
    print("\n=== cleanup ===")
    C("pkill -9 -f 'qeli-md client' 2>/dev/null; for t in vpnpdA vpnpdB; do ip link del $t 2>/dev/null; done; true")
    time.sleep(2)
    print("[prod sessions after client kill]", len(u05()), "(will reap as RX dies)")
    pc.close(); cc.close()

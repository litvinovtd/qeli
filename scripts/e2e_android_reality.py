#!/usr/bin/env python3
"""п.3 e2e — Android client (fresh libqeli.so, post-п.2) over REALITY hand-rolled
TLS 1.3 against the .10 e2e server (target www.microsoft.com → AES-256/SHA-384).

Flow:
  .10: (re)start the `e2e` profile server (server-e2e.conf, handrolled, 8503).
  .11: inject a single reality-tls JSON profile into com.qeli, drive Connect via
       uiautomator, then verify on the server: "hand-rolled TLS established"
       (NOT a bridge) + "AUTH OK user=admin" + assigned tun IP, and finally a
       server->client ping through the tunnel (e2e0 -> 10.60.0.x).
  cleanup: stop the app, kill the e2e server by pid, restore qeli-server.service.
"""
import os
import sys, io, time, re, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko
from xml.sax.saxutils import escape

SRV = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
CLI = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
ADB = "/root/android-sdk/platform-tools/adb"
QELI = "/opt/qeli-src/target/debug/qeli"
SRVCONF = "/root/reality-test/server-e2e.conf"
SRVLOG = "/root/reality-test/srv-e2e.log"
SRVIP = "10.66.116.10"
PORT = 8503
PUBKEY = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
SHORTID = "0123456789abcdef"
SNI = "www.microsoft.com"
TUNIF = "e2e0"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV); cc = conn(CLI)
def ssh(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def csh(cmd, t=60):
    i, o, e = cc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def a(cmd, t=60):
    return csh(f"{ADB} {cmd}", t)
def launch_srv(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()


# ── A. (re)start the e2e server on .10 ───────────────────────────────────────
print("=== A. start e2e server on .10 ===")
old = ssh("cat /root/reality-test/srv.pid 2>/dev/null").strip()
if old:
    ssh(f"kill -9 {old} 2>/dev/null; true")
ssh("pkill -9 -f 'reality-test/server-e2e.conf' 2>/dev/null; sleep 1; true")
ssh(f"rm -f {SRVLOG}; true")
launch_srv(f"RUST_LOG=info setsid nohup {QELI} server -c {SRVCONF} "
           f">/root/reality-test/srv.out 2>&1 < /dev/null & echo $! >/root/reality-test/srv.pid")
ok = False
for _ in range(15):
    time.sleep(1)
    lg = ssh(f"cat {SRVLOG} 2>/dev/null")
    if "listening on 0.0.0.0:8503" in lg:
        ok = True; break
pin = ssh(f"grep -o 'public key (pin on client): [0-9a-f]*' {SRVLOG} | head -1")
print(f"[srv] listening={ok}  {pin}")
if not ok:
    print(ssh(f"tail -15 {SRVLOG}; cat /root/reality-test/srv.out"))
    sc.close(); cc.close(); sys.exit(1)
assert PUBKEY in (pin or ""), "server pubkey != pinned key!"

# ── B. inject the reality-tls profile + drive Connect on the emulator ─────────
print("\n=== B. inject reality-tls profile + connect ===")
cfg = {
    "name": "REALITY e2e",
    "server": {"address": SRVIP, "port": PORT, "protocol": "tcp"},
    "auth": {"username": "admin", "password": "testpass123", "server_public_key": PUBKEY},
    "routing": {"mode": "full-tunnel", "add_default_gateway": True},
    "dns": {"servers": ["1.1.1.1"]},
    "obfuscation": {"mode": "reality-tls", "sni": SNI, "reality_short_id": SHORTID},
}
profiles = {"active": 0, "profiles": [{"name": "REALITY e2e", "json": json.dumps(cfg)}]}
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <string name="profiles_json">' + escape(json.dumps(profiles)) + "</string>\n</map>\n")
a("shell am force-stop com.qeli")
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")
sf = cc.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
a("push /root/vpn.xml /data/local/tmp/vpn.xml")
a("shell run-as com.qeli mkdir shared_prefs 2>/dev/null; true")
a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")

base = int(ssh(f"wc -l < {SRVLOG}") or 0)
a("logcat -c")
a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
a("shell input tap 160 370"); print("tapped Connect @160,370"); time.sleep(4)
cur = a("shell uiautomator dump /sdcard/u.xml && cat /sdcard/u.xml")
if "vpndialogs" in cur or "connection request" in cur.lower():
    # accept consent: tap OK/Allow by scanning bounds
    for label in ("OK", "Allow", "Start now"):
        m = re.search(r'(?:text|content-desc)="' + label + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', cur)
        if m:
            x = (int(m.group(1)) + int(m.group(3))) // 2; y = (int(m.group(2)) + int(m.group(4))) // 2
            a(f"shell input tap {x} {y}"); print(f"consent: tapped {label} @{x},{y}"); break
time.sleep(10)

# ── C. verify on the server ──────────────────────────────────────────────────
print("\n=== C. verify ===")
cl = a("logcat -d -s VpnSvc:D | grep -iE 'REALITY|Handshake|Auth OK|established|ERR|FATAL|Exception' | tail -12")
print("client logcat:\n" + (cl or "(none)"))
new = ssh(f"tail -n +{base+1} {SRVLOG}")
for kw in ("hand-rolled TLS established", "Qeli client detected", "AUTH OK", "bridging non-Qeli", "IP:"):
    hit = [l for l in new.splitlines() if kw in l]
    print(f"  [{kw}] -> {hit[-1].strip() if hit else 'MISS'}")
m = re.search(r"IP: (10\.60\.\d+\.\d+)", new)
if m:
    print(f"\n[ping] server->client {m.group(1)} via {TUNIF}:")
    print(ssh(f"ping -c4 -W2 -I {TUNIF} {m.group(1)} | tail -3"))
else:
    print("[ping] no assigned IP found — skipping")

# ── D. cleanup ───────────────────────────────────────────────────────────────
print("\n=== D. cleanup ===")
a("shell am force-stop com.qeli")
pid = ssh("cat /root/reality-test/srv.pid 2>/dev/null").strip()
if pid:
    ssh(f"kill -9 {pid} 2>/dev/null; true")
print("[srv] e2e worker killed; restoring systemd:", ssh("systemctl restart qeli-server.service && echo OK")[:40])
sc.close(); cc.close()
print("[done]")

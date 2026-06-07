#!/usr/bin/env python3
"""п.3 e2e (hybrid) — Android client over REALITY hand-rolled TLS against a
cloudflare-borrowed server: cloudflare → TLS_AES_128_GCM_SHA256 + PQ
X25519MLKEM768, so this exercises the *hybrid ML-KEM decapsulation* path in the
fresh libqeli.so (the microsoft run only covered AES-256/SHA-384, no PQ).

Creates a cloudflare handrolled profile bound on 0.0.0.0:8504, reads its REALITY
pubkey from the startup log, pins it into the Android profile, drives Connect and
verifies AUTH OK + a server->client tunnel ping."""
import os
import sys, io, time, re, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko
from xml.sax.saxutils import escape

SRV = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
CLI = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
ADB = "/root/android-sdk/platform-tools/adb"
QELI = "/opt/qeli-src/target/debug/qeli"
SRVIP = "10.66.116.10"
PORT = 8504
SHORTID = "0123456789abcdef"
SNI = "www.cloudflare.com"
TUNIF = "cfe2e0"
CONF = "/root/reality-test/server-cf-e2e.conf"
LOG = "/root/reality-test/srv-cf-e2e.log"
PIDF = "/root/reality-test/srv-cf.pid"

SERVER_CONF = f"""[web]
enabled = false
[auth]
users_file = /root/reality-test/users-e2e.conf
[profile:cfe2e]
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = {TUNIF}
tun.address = 10.61.0.1
tun.netmask = 255.255.255.0
pool.cidr = 10.61.0.0/24
pool.exclude = 10.61.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.reality_proxy.enabled = true
obf.tls.reality_proxy.target = www.cloudflare.com
obf.tls.reality_proxy.target_port = 443
obf.tls.reality_proxy.short_ids = {SHORTID}
obf.tls.reality_proxy.real_tls = true
obf.tls.reality_proxy.handrolled = true
[logging]
level = debug
file = {LOG}
"""


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV); cc = conn(CLI)
def ssh(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def a(cmd, t=60):
    i, o, e = cc.exec_command(f"{ADB} {cmd}", timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def launch_srv(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()


# ── A. write conf + start the cloudflare e2e server ──────────────────────────
print("=== A. start cloudflare e2e server on .10 ===")
sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), CONF); sf.close()
old = ssh(f"cat {PIDF} 2>/dev/null").strip()
if old:
    ssh(f"kill -9 {old} 2>/dev/null; true")
ssh(f"pkill -9 -f 'server-cf-e2e.conf' 2>/dev/null; rm -f {LOG}; sleep 1; true")
launch_srv(f"RUST_LOG=debug setsid nohup {QELI} server -c {CONF} "
           f">/root/reality-test/srv-cf.out 2>&1 < /dev/null & echo $! >{PIDF}")
ok = False
for _ in range(20):  # cloudflare probe at startup (8s timeout) makes this slower
    time.sleep(1)
    lg = ssh(f"cat {LOG} 2>/dev/null")
    if f"listening on 0.0.0.0:{PORT}" in lg:
        ok = True; break
borrow = ssh(f"grep -o 'borrowed TLS shape.*' {LOG} | head -1")
pin_line = ssh(f"grep -o 'public key (pin on client): [0-9a-f]*' {LOG} | head -1")
m = re.search(r"([0-9a-f]{64})", pin_line)
pubkey = m.group(1) if m else None
print(f"[srv] listening={ok}  pubkey={pubkey}")
print(f"[srv] {borrow}")
if not ok or not pubkey:
    print(ssh(f"tail -20 {LOG}; cat /root/reality-test/srv-cf.out"))
    sc.close(); cc.close(); sys.exit(1)

# ── B. inject cloudflare reality-tls profile + connect ───────────────────────
print("\n=== B. inject + connect ===")
cfg = {
    "name": "REALITY cf",
    "server": {"address": SRVIP, "port": PORT, "protocol": "tcp"},
    "auth": {"username": "admin", "password": "testpass123", "server_public_key": pubkey},
    "routing": {"mode": "full-tunnel", "add_default_gateway": True},
    "dns": {"servers": ["1.1.1.1"]},
    "obfuscation": {"mode": "reality-tls", "sni": SNI, "reality_short_id": SHORTID},
}
profiles = {"active": 0, "profiles": [{"name": "REALITY cf", "json": json.dumps(cfg)}]}
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <string name="profiles_json">' + escape(json.dumps(profiles)) + "</string>\n</map>\n")
a("shell am force-stop com.qeli")
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")
sf = cc.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
a("push /root/vpn.xml /data/local/tmp/vpn.xml")
a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")

base = int(ssh(f"wc -l < {LOG}") or 0)
a("logcat -c")
a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
a("shell input tap 160 370"); print("tapped Connect @160,370"); time.sleep(4)
cur = a("shell uiautomator dump /sdcard/u.xml && cat /sdcard/u.xml")
for label in ("OK", "Allow", "Start now"):
    mm = re.search(r'(?:text|content-desc)="' + label + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', cur)
    if mm:
        x = (int(mm.group(1)) + int(mm.group(3))) // 2; y = (int(mm.group(2)) + int(mm.group(4))) // 2
        a(f"shell input tap {x} {y}"); print(f"consent: tapped {label}"); break
time.sleep(10)

# ── C. verify ────────────────────────────────────────────────────────────────
print("\n=== C. verify (hybrid) ===")
cl = a("logcat -d -s VpnSvc:D | grep -iE 'REALITY|Auth OK|established|ERR|FATAL|Exception' | tail -10")
print("client logcat:\n" + (cl or "(none)"))
new = ssh(f"tail -n +{base+1} {LOG}")
for kw in ("Qeli client detected", "hand-rolled TLS established", "AUTH OK", "bridging non-Qeli", "IP:"):
    hit = [l for l in new.splitlines() if kw in l]
    print(f"  [{kw}] -> {hit[-1].strip() if hit else 'MISS'}")
m = re.search(r"IP: (10\.61\.\d+\.\d+)", new)
if m:
    print(f"\n[ping] server->client {m.group(1)} via {TUNIF}:")
    print(ssh(f"ping -c4 -W2 -I {TUNIF} {m.group(1)} | tail -3"))
else:
    print("[ping] no IP — skipping")

# ── D. cleanup ───────────────────────────────────────────────────────────────
print("\n=== D. cleanup ===")
a("shell am force-stop com.qeli")
pid = ssh(f"cat {PIDF} 2>/dev/null").strip()
if pid:
    ssh(f"kill -9 {pid} 2>/dev/null; true")
print("[srv] restore systemd:", ssh("systemctl restart qeli-server.service && echo OK")[:20])
sc.close(); cc.close()
print("[done]")

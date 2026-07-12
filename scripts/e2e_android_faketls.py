#!/usr/bin/env python3
"""Android-client e2e for the fake-tls (default TCP) profile: emulator (com.qeli)
on .11 -> fake-tls server on .10 (TCP :8443). Installs the freshly-built APK,
injects a fake-tls JSON profile, drives Connect, verifies Auth OK + assigned IP +
a server->client ping through the tunnel. Leaves the canonical :443 service alone.
"""
import os, sys, io, time, re, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko
from xml.sax.saxutils import escape

PW = os.environ.get("QELI_LAB_PASS", "")
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
ADB = "/root/android-sdk/platform-tools/adb"
QELI = "/opt/qeli-src/target/release/qeli"
APK = "/root/android-project/app/build/outputs/apk/debug/app-debug.apk"
DIR = "/root/ftls-test"
CONF = f"{DIR}/server-ftls.conf"
LOG = f"{DIR}/srv-ftls.log"
PORT = 8443
TUNIF = "ftls0"
NET = "10.62.0"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
USER, PASS = "admin", "testpass123"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV); cc = conn(CLI)
def ssh(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def csh(cmd, t=120):
    i, o, e = cc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def a(cmd, t=120):
    return csh(f"{ADB} {cmd}", t)
def launch_srv(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()


SERVER_CONF = f"""[auth]
require_client_key_proof = false

[logging]
level = info
file = {LOG}

[profile:ftls]
identity_key = {DIR}/id.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = {TUNIF}
tun.address = {NET}.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = {NET}.0/24
pool.exclude = {NET}.1
routing.forward_private = true
routing.nat.enabled = true
dns.enabled = true
dns.listen = {NET}.1
dns.upstream = 1.1.1.1
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
obf.padding.enabled = true

[user:{USER}]
password_hash = {HASH}
enabled = true
"""


def ui_dump():
    for _ in range(4):
        d = a("exec-out uiautomator dump /dev/tty 2>/dev/null")
        if "<hierarchy" in d or "<node" in d:
            return d
        time.sleep(1.5)
    return ""


def find_tap(labels, dump=None):
    if dump is None:
        dump = ui_dump()
    for lb in labels:
        m = re.search(r'(?:text|content-desc)="' + re.escape(lb) + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', dump, re.I)
        if m:
            x = (int(m.group(1)) + int(m.group(3))) // 2; y = (int(m.group(2)) + int(m.group(4))) // 2
            a(f"shell input tap {x} {y}"); print(f"  tapped '{lb}' @{x},{y}")
            return True
    return False


# ── 0. install the freshly-built APK ─────────────────────────────────────────
print("=== 0. install rebuilt APK ===")
print("  ", a(f"install -r -d {APK}", t=180).strip()[-60:])
print("  installed:", a("shell dumpsys package com.qeli | grep -E 'versionName|versionCode' | head -2"))

# ── A. fake-tls server on .10 ────────────────────────────────────────────────
print("\n=== A. start fake-tls server on .10 ===")
ssh(f"mkdir -p {DIR}; pkill -9 -f 'ftls-test' 2>/dev/null; sleep 2; ip link del {TUNIF} 2>/dev/null; rm -f {LOG}; true")
ssh("sysctl -w net.ipv4.ip_forward=1 >/dev/null; true")
sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), CONF); sf.close()
pub = ""
for line in ssh(f"{QELI} show-identity --config {CONF} 2>&1").splitlines():
    m = re.search(r"[0-9a-f]{64}", line)
    if m: pub = m.group(0); break
print("[srv] server pubkey:", pub or "??")
launch_srv(f"RUST_LOG=info setsid nohup {QELI} server -c {CONF} >{DIR}/srv.out 2>&1 </dev/null & echo $! >{DIR}/srv.pid")
up = False
for _ in range(15):
    time.sleep(1)
    if ssh(f"ss -tlnp | grep -c ':{PORT}'").strip() not in ("", "0"):
        up = True; break
t0 = ""
for _ in range(8):
    t0 = ssh(f"ip -br a show {TUNIF} 2>/dev/null")
    if NET in t0: break
    time.sleep(1)
print("[srv] tcp :%d listening = %s | %s = %s" % (PORT, up, TUNIF, t0.strip() or "NOT-UP"))
if not up or not pub or NET not in t0:
    print(ssh(f"tail -20 {LOG} {DIR}/srv.out")); sc.close(); cc.close(); sys.exit(1)

# ── B. inject fake-tls profile + connect ─────────────────────────────────────
print("\n=== B. inject fake-tls profile + connect ===")
cfg = {
    "name": "FAKE-TLS e2e",
    "server": {"address": SRV[0], "port": PORT, "protocol": "tcp"},
    "auth": {"username": USER, "password": PASS, "server_public_key": pub},
    "routing": {"mode": "full-tunnel", "add_default_gateway": True},
    "dns": {"servers": ["1.1.1.1"]},
    "obfuscation": {"mode": "fake-tls"},
}
profiles = {"active": 0, "profiles": [{"name": cfg["name"], "json": json.dumps(cfg)}]}
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <string name="profiles_json">' + escape(json.dumps(profiles)) + "</string>\n</map>\n")
a("shell am force-stop com.qeli")
a("shell pm clear com.qeli")
a("shell appops set com.qeli ACTIVATE_VPN allow 2>/dev/null; true")
a("shell appops set com.qeli ACTIVATE_PLATFORM_VPN allow 2>/dev/null; true")
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS 2>/dev/null; true")
cf = cc.open_sftp(); cf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); cf.close()
a("push /root/vpn.xml /data/local/tmp/vpn.xml")
a("shell run-as com.qeli mkdir shared_prefs 2>/dev/null; true")
a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")

base = int(ssh(f"wc -l < {LOG}") or 0)
a("logcat -c")
a("shell am start -n com.qeli/.MainActivity"); time.sleep(7)
scr = ui_dump()
print("  [profile on screen]:", "FAKE-TLS e2e" in scr,
      "| [Connect present]:", bool(re.search(r'(?:text|content-desc)="(?:Connect|Подключить)', scr, re.I)))
if not find_tap(["Connect", "Подключить", "Подключиться", "CONNECT", "Tap to connect"], scr):
    print("  Connect not found -> fixed tap @160,370"); a("shell input tap 160 370")

authok = False; cip = None
for i in range(18):
    time.sleep(2)
    new = ssh(f"tail -n +{base+1} {LOG}")
    if not authok and "AUTH OK" in new:
        authok = True; print(f"  [srv] AUTH OK (~{2*(i+1)}s)")
    m = re.search(r"(%s\.\d+)" % NET.replace('.', r'\.'), new)
    if m and not m.group(1).endswith(".1"):
        cip = m.group(1); break

# ── C. verify ────────────────────────────────────────────────────────────────
print("\n=== C. verify ===")
lc = a("logcat -d | grep -iE 'VpnSvc|Auth OK|assigned|Established|error|exception' | tail -14")
print("client logcat:\n" + (lc or "(none)"))
new = ssh(f"tail -n +{base+1} {LOG}")
print("server log (new, tail):\n" + ("\n".join(new.splitlines()[-8:]) or "(empty)"))
cip = cip or f"{NET}.2"
print(f"\n[ping] server -> client {cip} via {TUNIF}:")
ping = ssh(f"ping -c4 -W2 -I {TUNIF} {cip} 2>&1 | tail -4")
print(ping)
mrx = re.search(r"(\d+) received", ping)
passed = authok and bool(mrx) and int(mrx.group(1)) > 0

# ── D. cleanup ───────────────────────────────────────────────────────────────
print("\n=== D. cleanup ===")
a("shell am force-stop com.qeli")
pid = ssh(f"cat {DIR}/srv.pid 2>/dev/null").strip()
if pid: ssh(f"kill -9 {pid} 2>/dev/null; true")
ssh(f"pkill -9 -f '{CONF}' 2>/dev/null; ip link del {TUNIF} 2>/dev/null; true")
sc.close(); cc.close()
print("\n================ RESULT:", "PASS (fake-tls tunnel up, ping OK)" if passed else "SEE LOGS ABOVE", "================")

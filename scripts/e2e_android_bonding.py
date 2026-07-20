#!/usr/bin/env python3
"""0.7.12 Android adaptive-bonding e2e: does the ramp fire on DOWNLOAD-only load?

The 0.7.12 fix made the Kotlin ramp read bytesUp+bytesDown; before it, the
decision was keyed on the upload counter alone, so the archetypal case -- a big
download over an idle uplink -- never grew past one stream on Android.

Flow: emulator (com.qeli) on .11 -> fake-tls server on .10 with
obf.multipath.{enabled,adaptive}=true, max_streams=4. After Auth OK the server
pumps /dev/zero into the tunnel and the phone swallows it with `nc | dd`, giving
download-only load; then logcat is checked for the ramp lines.
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
DIR = "/root/bond-test"
CONF = f"{DIR}/server-bond.conf"
LOG = f"{DIR}/srv-bond.log"
PORT = 8443
TUNIF = "bond0"
NET = "10.64.0"
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

[profile:bond]
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
obf.multipath.enabled = true
obf.multipath.max_streams = 4
obf.multipath.adaptive = true

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
ssh(f"mkdir -p {DIR}; pkill -9 -f 'bond-test' 2>/dev/null; sleep 2; ip link del {TUNIF} 2>/dev/null; rm -f {LOG}; true")
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
    "name": "BONDING e2e",
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
print("  [profile on screen]:", "BONDING e2e" in scr,
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

# ── C. download-only load, then read the ramp ────────────────────────────────
print("\n=== C. download-only load (server -> phone) ===")
print("  auth ok:", authok, "| client ip:", cip or "?")
lc0 = a("logcat -d | grep -i 'multipath' | tail -3")
print("  push seen by the app:", (lc0 or "(none)").strip()[:160])

# Server pumps zeros; the phone drains them. Pure download: the uplink carries
# only ACKs, which is exactly the shape the old upload-keyed ramp was blind to.
ssh(f"pkill -x nc 2>/dev/null; (setsid nohup sh -c 'while true; do nc -l -p 9100 < /dev/zero; done' >/dev/null 2>&1 &); sleep 1; true")
print("  pumping for 45s...")
a(f"shell 'timeout 45 nc {NET}.1 9100 | dd of=/dev/null bs=64k' 2>&1", t=90)
time.sleep(3)

print("\n=== D. verify ramp ===")
ramp = a("logcat -d | grep -i 'multipath' | tail -12")
print("client logcat (multipath):\n" + (ramp or "(none)"))
ramped = [int(x) for x in re.findall(r"ramped to (\d+) stream", ramp or "")]
plateau = [int(x) for x in re.findall(r"plateau at (\d+) stream", ramp or "")]
peak = max(ramped) if ramped else 1
# The emulator is NAT'd behind .11, so bonded streams show up as extra
# ESTABLISHED connections from .11 to the server port.
conns = ssh(f"ss -tan 'sport = :{PORT}' | grep -c ESTAB")
print(f"\n  ramp events : {ramped or 'none'}")
print(f"  plateau     : {plateau or 'none'}")
print(f"  peak streams: {peak}   (must be >1 -- this is the regression guard)")
print(f"  ESTAB conns on the server port: {conns.strip()}")
new = ssh(f"tail -n +{base+1} {LOG}")
print("  server saw:", "\n    ".join([l for l in new.splitlines() if "stream" in l.lower()][-3:]) or "(no stream lines)")
passed = authok and peak > 1

# ── E. cleanup ───────────────────────────────────────────────────────────────
print("\n=== E. cleanup ===")
a("shell am force-stop com.qeli")
ssh("pkill -x nc 2>/dev/null; true")
pid = ssh(f"cat {DIR}/srv.pid 2>/dev/null").strip()
if pid: ssh(f"kill -9 {pid} 2>/dev/null; true")
ssh(f"pkill -9 -f '{CONF}' 2>/dev/null; ip link del {TUNIF} 2>/dev/null; true")
sc.close(); cc.close()
print("\n============ RESULT:", f"PASS (download-only ramped to {peak} streams)" if passed
      else f"FAIL (peak {peak} stream(s) under download-only load)", "============")

#!/usr/bin/env python3
"""Clean reality-tls prod throughput via the Android EMULATOR (same realtls .so
as the phone, proper VpnService tun) over .11's wired link. Baseline download
(no VPN) vs through reality-tls(prod:443). Isolates whether prod/protocol caps
throughput (vs the phone's mobile path / phone CPU)."""
import os, sys, io, time, re, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko
from xml.sax.saxutils import escape

ADB = "/root/android-sdk/platform-tools/adb"
DLURL = "http://speed.hetzner.de/100MB.bin"   # plain HTTP, toybox-wget friendly
DLSECS = 12
PUBKEY = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"
SID = "2699764da5df00bc"

lc = paramiko.SSHClient(); lc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
lc.connect("10.66.116.11", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
pc = paramiko.SSHClient(); pc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
pc.connect("222.167.246.143", username="root", password=os.environ["QELI_PROD_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def L(c, t=120):
    i, o, e = lc.exec_command(c, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def P(c, t=60):
    i, o, e = pc.exec_command(c, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def a(c, t=120): return L(f"{ADB} {c}", t)

def measure_download(tag):
    a("shell rm -f /sdcard/dl.bin 2>/dev/null")
    a(f"shell 'toybox timeout {DLSECS} toybox wget -O /sdcard/dl.bin {DLURL} 2>/dev/null; true'", t=DLSECS+15)
    sz = a("shell toybox stat -c %s /sdcard/dl.bin 2>/dev/null").strip()
    try:
        mbps = round(int(sz) * 8 / DLSECS / 1e6, 1)
        print(f"  [{tag}] {int(sz)/1e6:.1f} MB in {DLSECS}s = {mbps} Mbps")
        return mbps
    except Exception:
        print(f"  [{tag}] download failed (size='{sz}')"); return None

print("=== 0. baseline download (NO VPN, emulator -> .11 -> internet) ===")
a("shell am force-stop com.qeli"); time.sleep(2)
base = measure_download("baseline")

print("\n=== 1. inject prod reality-tls profile (full-tunnel) + connect ===")
cfg = {"name": "PROD reality-tls",
       "server": {"address": "222.167.246.143", "port": 443, "protocol": "tcp"},
       "auth": {"username": "user01", "password": "NA4BLbbHIpIpyJ5y", "server_public_key": PUBKEY},
       "routing": {"mode": "full-tunnel", "add_default_gateway": True},
       "dns": {"servers": ["1.1.1.1"]},
       "obfuscation": {"mode": "reality-tls", "sni": "www.microsoft.com", "reality_short_id": SID}}
profiles = {"active": 0, "profiles": [{"name": "PROD reality-tls", "json": json.dumps(cfg)}]}
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <string name="profiles_json">' + escape(json.dumps(profiles)) + "</string>\n</map>\n")
a("shell am force-stop com.qeli")
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")
sf = lc.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
a("push /root/vpn.xml /data/local/tmp/vpn.xml")
a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")
pbase = int(P("wc -l < /var/log/qeli/server.log") or 0)
a("logcat -c")
a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
a("shell input tap 160 370"); time.sleep(4)
cur = a("shell uiautomator dump /sdcard/u.xml && cat /sdcard/u.xml")
for label in ("OK", "Allow", "Start now"):
    m = re.search(r'(?:text|content-desc)="' + label + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', cur)
    if m:
        x = (int(m.group(1))+int(m.group(3)))//2; y = (int(m.group(2))+int(m.group(4)))//2
        a(f"shell input tap {x} {y}"); print(f"  consent: {label}"); break
time.sleep(9)
cl = a("logcat -d -s VpnSvc:D | grep -iE 'Auth OK|established|REALITY|ERR|Exception' | tail -5")
print("  client:", (cl.replace(chr(10), " | ") or "(none)"))
srv = P(f"tail -n +{pbase+1} /var/log/qeli/server.log | grep -iE 'AUTH OK|connected on profile' | tail -2")
print("  server:", (srv.replace(chr(10), " | ") or "(no AUTH)"))

print("\n=== 2. download THROUGH reality-tls prod ===")
vpn = measure_download("reality-tls prod")

print("\n=== 3. cleanup ===")
a("shell am force-stop com.qeli")
print("\n================ RESULT ================")
print(f"  baseline (no VPN):     {base} Mbps")
print(f"  reality-tls -> PROD:   {vpn} Mbps")
if base and vpn: print(f"  tunnel keeps {round(100*vpn/base)}% of the wired link")
lc.close(); pc.close()

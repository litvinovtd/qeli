"""Inject test profiles into the Android app's SharedPreferences (for lab
testing without the file-picker UI). Builds a valid vpn.xml and pushes it.
"""
import os
import sys, io, json, base64
from xml.sax.saxutils import escape
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

HOST = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
ADB = "/root/android-sdk/platform-tools/adb"
SERVER_KEY = sys.argv[1] if len(sys.argv) > 1 else "PASTE_KEY"
SERVER_IP = "10.66.116.10"

XK = b"Vpn0bfusc@t3d!"
def obf(p):
    b = p.encode()
    x = bytes((c ^ XK[i % len(XK)]) for i, c in enumerate(b))
    return base64.b64encode(x).decode()

maxobf = {
    "name": "MaxObf (reality)",
    "server": {"address": SERVER_IP, "port": 443, "protocol": "tcp",
               "connection_timeout_secs": 30,
               "reconnect": {"enabled": True, "max_retries": -1, "base_delay_secs": 1, "max_delay_secs": 60}},
    "auth": {"username": "phone", "password": "testpass123", "server_public_key": SERVER_KEY},
    "tun": {"mtu": 1400},
    "routing": {"mode": "full-tunnel", "add_default_gateway": True, "include": [], "exclude": []},
    "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
    "obfuscation": {"mode": "fake-tls", "sni": "www.microsoft.com",
                    "padding": {"enabled": True, "min_bytes": 40, "max_bytes": 400},
                    "heartbeat": {"enabled": True, "interval_ms": 15000, "data_size_bytes": 64, "jitter_ms": 5000},
                    "quic": {"enabled": False}}}

profiles = {"active": 1, "profiles": [
    {"name": "Lab default", "address": SERVER_IP, "port": 443, "username": "admin", "pw": obf("testpass123")},
    {"name": "MaxObf (reality)", "address": SERVER_IP, "port": 443, "username": "phone",
     "pw": obf("testpass123"), "json": json.dumps(maxobf)},
]}

pj = json.dumps(profiles)
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
       "<map>\n"
       '    <string name="profiles_json">' + escape(pj) + "</string>\n"
       "</map>\n")

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20, look_for_keys=False, allow_agent=False)
def rc(cmd, t=60):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()

rc(f"{ADB} shell am force-stop com.qeli")
sf = c.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
# Push to a world-readable tmp, then copy into the app's data dir AS THE APP
# USER via run-as (debug build) so ownership + SELinux context are correct —
# a root-pushed file the app uid can't read leaves prefs empty.
print("push:", rc(f"{ADB} push /root/vpn.xml /data/local/tmp/vpn.xml"))
rc(f"{ADB} shell chmod 644 /data/local/tmp/vpn.xml")
rc(f"{ADB} shell run-as com.qeli mkdir shared_prefs")  # no-op if it exists
print("cp:", rc(f"{ADB} shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml") or "(ok)")
rc(f"{ADB} shell run-as com.qeli chmod 660 shared_prefs/vpn.xml")
# validate XML parses and key present (read back AS the app user)
back = rc(f"{ADB} shell run-as com.qeli cat shared_prefs/vpn.xml")
import xml.dom.minidom as md
try:
    md.parseString(back); print("XML valid: yes")
except Exception as ex:
    print("XML valid: NO ->", ex)
print("key present:", SERVER_KEY in back)
c.close()

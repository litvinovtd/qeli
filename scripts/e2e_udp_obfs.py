#!/usr/bin/env python3
"""E2E for UDP obfs: emulator connects in proto=udp mode=obfs, verify Auth OK +
tunnel ping, and tcpdump the wire to confirm datagrams carry no TLS/QUIC
structure (obfs XOR makes them look random)."""
import os
import paramiko, time, io, json, re
from xml.sax.saxutils import escape

def conn(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=os.environ.get("QELI_LAB_PASS", ""), timeout=20, look_for_keys=False, allow_agent=False)
    return c
cc = conn("10.66.116.11"); sc = conn("10.66.116.10")
ADB = "/root/android-sdk/platform-tools/adb"
def a(cmd, t=60):
    i, o, e = cc.exec_command(ADB + " " + cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def s(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()

cfg = json.dumps({"name": "UDP obfs", "server": {"address": "10.66.116.10", "port": 1443, "protocol": "udp"},
                  "auth": {"username": "phone", "password": "testpass123"},
                  "routing": {"mode": "full-tunnel", "add_default_gateway": True},
                  "dns": {"servers": ["1.1.1.1"]},
                  "obfuscation": {"mode": "obfs", "obfs_key": "testsecret123", "quic": {"enabled": False}}})
prof = {"active": 0, "profiles": [{"name": "UDP obfs", "json": cfg}]}
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <string name="profiles_json">' + escape(json.dumps(prof)) + "</string>\n</map>\n")
a("shell am force-stop com.qeli"); time.sleep(1)
sf = cc.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
a("push /root/vpn.xml /data/local/tmp/vpn.xml")
a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")

# start a short tcpdump on the server for udp:1443 (capture wire bytes in hex)
sc.exec_command("timeout 14 tcpdump -i any -n -X udp port 1443 -c 6 > /tmp/obfs_cap.txt 2>&1 &")
a("logcat -c"); a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
a("shell input tap 160 370"); time.sleep(10)

cl = a("logcat -d -s VpnSvc:D | grep -iE 'obfs mode|Auth OK|TUN ready|parse error|ERR' | tail -8")
print("=== client logcat ===\n" + (cl or "(none)"))
ipm = re.search(r"Auth OK, IP (10\.9\.1\.\d+)", cl)
if ipm:
    print("=== server->client ping (vpn1) ===")
    print(s(f"ping -c3 -W2 -I vpn1 {ipm.group(1)} | tail -2"))
print("\n=== server journald (udp auth) ===")
print(s("journalctl -u qeli-server --no-pager -n 30 -o cat | grep -iE 'AUTH OK UDP|connected' | tail -3"))
print("\n=== wire capture (first bytes of obfs datagrams — should look random, no 16 03 / TLS, no QUIC flags) ===")
time.sleep(3)
print(s("grep -E '0x0000:' /tmp/obfs_cap.txt | head -4"))
a("shell am force-stop com.qeli")
cc.close(); sc.close()

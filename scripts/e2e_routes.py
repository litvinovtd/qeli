#!/usr/bin/env python3
"""Verify the OK-parse fix: server pushes a route + obfs params; the client must
parse them (no 'routes parse error'), add the route, apply pushed obfs, and the
tunnel must still carry traffic."""
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

# 1. add an advertised route to [profile:tcp] (under the section) and restart
conf = s("cat /etc/qeli/server.conf")
if "192.168.99.0/24" not in conf:
    lines = conf.splitlines(); out = []
    for ln in lines:
        out.append(ln)
        if ln.strip() == "[profile:tcp]":
            out.append("route = 192.168.99.0/24 gateway=10.9.0.1")
    sf = sc.open_sftp()
    with sf.open("/etc/qeli/server.conf", "w") as f: f.write("\n".join(out) + "\n")
    sf.close()
print("restart:", s("systemctl restart qeli-server; sleep 3; systemctl is-active qeli-server"))

# 2. inject TCP profile (phone) active and connect
SRVIP = "10.66.116.10"
cfg = json.dumps({"name": "TCP test", "server": {"address": SRVIP, "port": 443, "protocol": "tcp"},
                  "auth": {"username": "phone", "password": "testpass123"},
                  "routing": {"mode": "full-tunnel", "add_default_gateway": True},
                  "dns": {"servers": ["1.1.1.1"]},
                  "obfuscation": {"mode": "fake-tls", "sni": "www.cloudflare.com"}})
prof = {"active": 0, "profiles": [{"name": "TCP test", "json": cfg}]}
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <string name="profiles_json">' + escape(json.dumps(prof)) + "</string>\n</map>\n")
a("shell am force-stop com.qeli"); time.sleep(1)
sf = cc.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
a("push /root/vpn.xml /data/local/tmp/vpn.xml")
a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")
a("logcat -c"); a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
a("shell input tap 160 370"); time.sleep(10)

# 3. client logcat — the proof
cl = a("logcat -d -s VpnSvc:D | grep -iE 'Auth OK|pushed route|Applied server-pushed|routes parse error|TUN ready' | tail -10")
print("\n=== client logcat ===\n" + (cl or "(none)"))

# 4. the pushed route present in the device routing table (via the tun)?
print("\n=== device route for 192.168.99.0/24 ===")
print(a("shell ip route | grep 192.168.99 || echo '(not in ip route)'"))

# 5. data plane still works
ip = re.search(r"Auth OK, IP (10\.9\.0\.\d+)", cl)
if ip:
    print("\n=== server->client ping", ip.group(1), "===")
    print(s(f"ping -c3 -W2 -I vpn0 {ip.group(1)} | tail -2"))
a("shell am force-stop com.qeli")
cc.close(); sc.close()

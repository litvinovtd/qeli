#!/usr/bin/env python3
"""E2E for the keyed OK format + route_local_networks on Android:
 - TCP profile with route_local_networks=true: keyed parse OK, pushed route +
   RFC1918 routed, tunnel works.
 - UDP profile with route_local_networks=false: keyed parse OK on UDP, tunnel
   works, NO local-network routing."""
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

# server: ensure tcp profile advertises a route, restart
conf = s("cat /etc/qeli/server.conf")
if "192.168.99.0/24" not in conf:
    out = []
    for ln in conf.splitlines():
        out.append(ln)
        if ln.strip() == "[profile:tcp]":
            out.append("route = 192.168.99.0/24 gateway=10.9.0.1")
    sf = sc.open_sftp()
    with sf.open("/etc/qeli/server.conf", "w") as f: f.write("\n".join(out) + "\n")
    sf.close()
    print("restart:", s("systemctl restart qeli-server; sleep 3; systemctl is-active qeli-server"))

SRVIP = "10.66.116.10"
def cfg(name, port, proto, local):
    return json.dumps({"name": name, "server": {"address": SRVIP, "port": port, "protocol": proto},
                       "auth": {"username": "phone", "password": "testpass123"},
                       "routing": {"mode": "full-tunnel", "add_default_gateway": True, "route_local_networks": local},
                       "dns": {"servers": ["1.1.1.1"]},
                       "obfuscation": {"mode": "fake-tls", "sni": "www.cloudflare.com"}})

def inject(active, profiles):
    pj = json.dumps({"active": active, "profiles": profiles})
    xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
           '    <string name="profiles_json">' + escape(pj) + "</string>\n</map>\n")
    a("shell am force-stop com.qeli"); time.sleep(1)
    sf = cc.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
    a("push /root/vpn.xml /data/local/tmp/vpn.xml")
    a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")
    a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")

profs = [{"name": "TCP local", "json": cfg("TCP local", 443, "tcp", True)},
         {"name": "UDP plain", "json": cfg("UDP plain", 1443, "udp", False)}]

def run(active, label, tun):
    inject(active, profs)
    a("logcat -c"); a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
    a("shell input tap 160 370"); time.sleep(10)
    cl = a("logcat -d -s VpnSvc:D | grep -iE 'Auth OK|pushed route|Routing local|Applied server-pushed|parse error|TUN ready' | tail -10")
    print(f"\n===== {label} =====\n" + (cl or "(none)"))
    ipm = re.search(r"Auth OK, IP (10\.9\.[01]\.\d+)", cl)
    if ipm:
        print("ping:", s(f"ping -c3 -W2 -I {tun} {ipm.group(1)} | tail -2"))
    a("shell am force-stop com.qeli"); time.sleep(2)

run(0, "TCP (route_local_networks=true)", "vpn0")
run(1, "UDP (route_local_networks=false)", "vpn1")
# cleanup: drop the test route again
conf = s("cat /etc/qeli/server.conf")
sf = sc.open_sftp()
with sf.open("/etc/qeli/server.conf", "w") as f:
    f.write("\n".join(l for l in conf.splitlines() if "192.168.99.0/24" not in l) + "\n")
sf.close()
s("systemctl restart qeli-server")
print("\n[cleanup] test route removed, server restarted")
cc.close(); sc.close()

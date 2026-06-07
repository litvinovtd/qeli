#!/usr/bin/env python3
"""E2E for TCP obfs on Android: set the server's [profile:tcp] to obf.mode=obfs,
connect the emulator in proto=tcp mode=obfs, verify Auth OK + tunnel ping (which
proves the stateful pure-Kotlin ChaCha20 keystream matches the Rust server),
then restore fake-tls."""
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

# stop the rust client on .11 (it speaks fake-tls; would spam failed handshakes)
s_kill = cc.exec_command("pkill -9 -f 'qeli client' 2>/dev/null; true")
# 1. set [profile:tcp] -> obfs
conf = s("cat /etc/qeli/server.conf")
if "obf.mode = obfs" not in conf:
    lines = conf.splitlines(); out = []
    for ln in lines:
        out.append(ln)
        if ln.strip() == "[profile:tcp]":
            out += ["obf.mode = obfs", "obf.obfs_key = testsecret123"]
    sf = sc.open_sftp()
    with sf.open("/etc/qeli/server.conf", "w") as f: f.write("\n".join(out) + "\n")
    sf.close()
print("restart:", s("systemctl restart qeli-server; sleep 3; systemctl is-active qeli-server"))

# 2. inject emulator profile (tcp + obfs) and connect
cfg = json.dumps({"name": "TCP obfs", "server": {"address": "10.66.116.10", "port": 443, "protocol": "tcp"},
                  "auth": {"username": "phone", "password": "testpass123"},
                  "routing": {"mode": "full-tunnel", "add_default_gateway": True},
                  "dns": {"servers": ["1.1.1.1"]},
                  "obfuscation": {"mode": "obfs", "obfs_key": "testsecret123"}})
prof = {"active": 0, "profiles": [{"name": "TCP obfs", "json": cfg}]}
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <string name="profiles_json">' + escape(json.dumps(prof)) + "</string>\n</map>\n")
a("shell am force-stop com.qeli"); time.sleep(1)
sf = cc.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
a("push /root/vpn.xml /data/local/tmp/vpn.xml")
a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")
a("logcat -c"); a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
a("shell input tap 160 370"); time.sleep(10)

cl = a("logcat -d -s VpnSvc:D | grep -iE 'obfs|Auth OK|TUN ready|ERR|FATAL' | tail -8")
print("=== client logcat ===\n" + (cl or "(none)"))
print("=== server journald (tcp auth) ===")
print(s("journalctl -u qeli-server --no-pager --since '-40sec' -o cat | grep -iE 'AUTH OK|connected on profile' | tail -3"))
ipm = re.search(r"Auth OK, IP (10\.9\.0\.\d+)", cl)
if ipm:
    print("=== server->client ping (vpn0) ===")
    print(s(f"ping -c3 -W2 -I vpn0 {ipm.group(1)} | tail -2"))

# 3. restore [profile:tcp] to fake-tls + restart, bring rust client back
a("shell am force-stop com.qeli")
conf = s("cat /etc/qeli/server.conf")
lines = [l for l in conf.splitlines() if l.strip() not in ("obf.mode = obfs", "obf.obfs_key = testsecret123")]
sf = sc.open_sftp()
with sf.open("/etc/qeli/server.conf", "w") as f: f.write("\n".join(lines) + "\n")
sf.close()
print("\n[restore] tcp->fake-tls, restart:", s("systemctl restart qeli-server; sleep 2; systemctl is-active qeli-server"))
ch = cc.get_transport().open_session()
ch.exec_command("cd /root/qeli && RUST_LOG=info setsid nohup ./target/debug/qeli client -c test_e2e/qeli.conf >> /root/qeli_client.log 2>&1 < /dev/null &")
time.sleep(2); ch.close()
print("[restore] rust client restarted")
cc.close(); sc.close()

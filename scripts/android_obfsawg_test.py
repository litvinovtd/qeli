#!/usr/bin/env python3
"""Drive the 0.7.6 Android app on the lab emulator to connect to the PROD
obfs-awg profile (:243, AmneziaWG junk jc=4) and prove whether it sends the junk
(reaches AUTH OK) or stalls at the handshake like the user's phone.

Uses user08 (NOT lae, the phone) so the phone's reality-tls session is untouched.
Injects the profile via SharedPreferences, pre-grants VPN consent via appops, taps
Connect via uiautomator bounds, then reads logcat + the prod server log.
"""
import os, sys, io, json, base64, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
PWP = os.environ.get("QELI_PROD_PASS", "")
ADB = "/root/android-sdk/platform-tools/adb"
PROD = "YOUR_PROD_HOST"
PUB = "010045e56dc5dad8d54b5b8e4a9792ed4e12cf33f80421d45c0d0d48dda9260b"

XK = b"Vpn0bfusc@t3d!"
def obf(p):
    x = bytes((c ^ XK[i % len(XK)]) for i, c in enumerate(p.encode()))
    return base64.b64encode(x).decode()


def conn(ip, pw):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=pw, timeout=25, look_for_keys=False, allow_agent=False)
    return c


def main():
    cl = conn("10.66.116.11", PW)
    def a(cmd, t=60):  # adb shell wrapper
        _i, o, e = cl.exec_command(f"{ADB} {cmd}", timeout=t)
        return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()

    cfg = {
        "server": {"address": PROD, "port": 243, "protocol": "tcp"},
        "auth": {"username": "user08", "password": "aoV6bCeVRnNM4v1k",
                 "server_public_key": PUB, "bind_static_to_session": True},
        "routing": {"mode": "split-tunnel", "add_default_gateway": False},
        "obfuscation": {"mode": "obfs", "obfs_key": "cf61795367f10bdf59b075c32c9cf92d",
                        "fronting": "websocket",
                        "awg": {"enabled": True, "jc": 4, "jmin": 40, "jmax": 200}},
    }
    profiles = {"active": 0, "profiles": [
        {"name": "obfs-awg PROD", "address": PROD, "port": 243, "username": "user08",
         "pw": obf("aoV6bCeVRnNM4v1k"), "json": json.dumps(cfg)}]}
    from xml.sax.saxutils import escape
    xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
           '    <string name="profiles_json">' + escape(json.dumps(profiles)) + "</string>\n</map>\n")

    print("app ver:", a("shell dumpsys package com.qeli | grep versionName").strip())
    a("shell am force-stop com.qeli")
    sf = cl.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
    a("push /root/vpn.xml /data/local/tmp/vpn.xml")
    a("shell run-as com.qeli mkdir shared_prefs 2>/dev/null; true")
    a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")
    print("profile injected; key present:", PUB in a("shell run-as com.qeli cat shared_prefs/vpn.xml"))
    # pre-grant VPN consent so no system dialog blocks the connect
    a("shell appops set com.qeli ACTIVATE_VPN allow 2>/dev/null; true")
    a("logcat -c")
    a("shell am start -n com.qeli/.MainActivity")
    time.sleep(4)
    # find & tap the Connect button via uiautomator bounds
    a("shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; true")
    ui = a("shell cat /sdcard/ui.xml")
    tapped = False
    for m in re.finditer(r'text="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui):
        if re.search(r"connect", m.group(1), re.I) and "disconnect" not in m.group(1).lower():
            x = (int(m.group(2)) + int(m.group(4))) // 2; y = (int(m.group(3)) + int(m.group(5))) // 2
            a(f"shell input tap {x} {y}"); print(f"tapped '{m.group(1)}' @ {x},{y}"); tapped = True; break
    if not tapped:
        print("Connect button not found; UI text nodes:", re.findall(r'text="([^"]+)"', ui)[:15])
    # wait for handshake/auth
    time.sleep(10)
    print("\n=== emulator logcat (qeli) ===")
    lc = a("logcat -d -v brief 2>/dev/null | grep -iE 'qeli|junk|awg|auth|obfs|handshake|connect|error|assigned' | tail -25")
    print(lc or "(no qeli logcat lines)")
    a("shell am force-stop com.qeli")
    cl.close()

    # prod server log — did the emulator reach AUTH on obfs-awg?
    p = conn(PROD, PWP)
    def r(cmd, t=40):
        _i, o, e = p.exec_command(cmd, timeout=t); return (o.read() + e.read()).decode("utf-8", "replace").strip()
    print("\n=== PROD server.log — obfs-awg last 12 (emulator egress 54.37.87.56) ===")
    print(r("grep -iE \"obfs-awg\" /var/log/qeli/server.log 2>/dev/null | tail -12"))
    p.close()


if __name__ == "__main__":
    main()

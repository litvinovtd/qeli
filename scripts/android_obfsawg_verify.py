#!/usr/bin/env python3
"""Full verification of BOTH Android fixes on the lab emulator against PROD obfs-awg:
  1. WS-framing: obfs+websocket data now frames → reaches AUTH OK / gets an IP.
  2. network-callback: the session HOLDS — no self-triggered "Network changed" loop
     (own tun no longer counted as a network change).

Installs the freshly built APK, clean profile store (pm clear → legacy inject →
migration), pre-grants perms (no dialogs), taps the ring, then observes ~28s and
counts reconnect churn in both the VpnSvc log and the PROD server log. user08.
"""
import os, sys, io, json, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW  = os.environ.get("QELI_LAB_PASS", "")
PWP = os.environ.get("QELI_PROD_PASS", "")
ADB = "/root/android-sdk/platform-tools/adb"
PROD = "YOUR_PROD_HOST"
PUB = "010045e56dc5dad8d54b5b8e4a9792ed4e12cf33f80421d45c0d0d48dda9260b"
APK_LOCAL = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli-android\dist\app-debug.apk"


def conn(ip, pw):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=pw, timeout=25, look_for_keys=False, allow_agent=False)
    return c


def main():
    cl = conn("10.66.116.11", PW)
    def sh(cmd, t=180):
        _i, o, e = cl.exec_command(cmd, timeout=t)
        return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()
    def a(cmd, t=180): return sh(f"{ADB} {cmd}", t)

    # 0. install fresh APK
    sf = cl.open_sftp(); sf.put(APK_LOCAL, "/root/app-debug.apk"); sf.close()
    print("[install]", a("install -r /root/app-debug.apk") or "(ok)")
    print("app ver:", a("shell dumpsys package com.qeli | grep versionName").strip())

    # 1. clean slate → legacy->encrypted migration will run
    a("shell pm clear com.qeli")

    # 2. legacy plaintext profile (json config w/ awg) — migrated on first launch
    cfg = {
        "server": {"address": PROD, "port": 243, "protocol": "tcp"},
        "auth": {"username": "user08", "password": "aoV6bCeVRnNM4v1k",
                 "server_public_key": PUB, "bind_static_to_session": True},
        "routing": {"mode": "split-tunnel", "add_default_gateway": False},
        "obfuscation": {"mode": "obfs", "obfs_key": "cf61795367f10bdf59b075c32c9cf92d",
                        "fronting": "websocket",
                        "awg": {"enabled": True, "jc": 4, "jmin": 40, "jmax": 200}},
    }
    profiles = {"active": 0, "profiles": [{"name": "obfs-awg PROD", "json": json.dumps(cfg)}]}
    from xml.sax.saxutils import escape
    xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
           '    <string name="profiles_json">' + escape(json.dumps(profiles)) + "</string>\n</map>\n")
    sf = cl.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
    a("push /root/vpn.xml /data/local/tmp/vpn.xml")
    a("shell run-as com.qeli mkdir -p shared_prefs 2>/dev/null; true")
    a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")

    # 3. pre-grant perms (no notif / VPN dialogs)
    a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS 2>/dev/null; true")
    a("shell appops set com.qeli ACTIVATE_VPN allow 2>/dev/null; true")
    a("logcat -c")
    a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)

    # dismiss any lingering dialog, dump main screen
    a("shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; true")
    ui = a("shell cat /sdcard/ui.xml")
    if 'text="ALLOW"' in ui:
        for m in re.finditer(r'text="ALLOW"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui):
            x = (int(m.group(1)) + int(m.group(3))) // 2; y = (int(m.group(2)) + int(m.group(4))) // 2
            a(f"shell input tap {x} {y}"); time.sleep(1)
            a("shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; true"); ui = a("shell cat /sdcard/ui.xml"); break
    print("profile loaded:", "obfs-awg" in ui.lower())

    # 4. tap the TAP TO CONNECT ring
    for m in re.finditer(r'text="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui):
        if re.search(r"tap to connect", m.group(1), re.I):
            x = (int(m.group(2)) + int(m.group(4))) // 2; y = (int(m.group(3)) + int(m.group(5))) // 2
            a(f"shell input tap {x} {y}"); print(f"tapped '{m.group(1)}' @ {x},{y}"); break
    else:
        print("TAP TO CONNECT not found:", re.findall(r'text="([^"]+)"', ui))

    # 5. observe ~28s for stability
    time.sleep(28)
    trace = a("logcat -d 2>/dev/null | grep -aE 'VpnSvc' | tail -60")
    print("\n=== VpnSvc trace (tail) ===")
    print("\n".join(trace.splitlines()[-22:]) or "(none)")
    n_auth  = len(re.findall(r"Auth OK", trace))
    n_netch = len(re.findall(r"Network changed", trace))
    n_conn  = len(re.findall(r"Connecting TCP", trace))
    # final UI state
    a("shell uiautomator dump /sdcard/ui3.xml >/dev/null 2>&1; true")
    ui3 = a("shell cat /sdcard/ui3.xml")
    state = [t for t in re.findall(r'text="([^"]+)"', ui3) if t.upper() in ("CONNECTED", "DISCONNECTED", "CONNECTING")]
    print(f"\n>>> Auth OK count={n_auth}  |  'Network changed' count={n_netch}  |  Connecting attempts={n_conn}")
    print(">>> final UI state:", state[:3])
    a("shell am force-stop com.qeli")
    cl.close()

    # 6. prod: churn = many AUTH OK in a short window means the loop persists
    p = conn(PROD, PWP)
    _i, o, _e = p.exec_command("grep -iE 'obfs-awg' /var/log/qeli/server.log | tail -14", timeout=30)
    print("\n=== PROD obfs-awg tail ===\n" + o.read().decode("utf-8", "replace").strip())
    p.close()


if __name__ == "__main__":
    main()

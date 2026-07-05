#!/usr/bin/env python3
"""Deterministic obfs-awg connect check: pre-grant perms (no dialogs), verify the
FRESH apk is installed, launch, tap the 'TAP TO CONNECT' ring, capture the full
VpnSvc handshake trace + prod AUTH."""
import os, sys, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
PWP = os.environ.get("QELI_PROD_PASS", "")
ADB = "/root/android-sdk/platform-tools/adb"
PROD = "YOUR_PROD_HOST"


def conn(ip, pw):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=pw, timeout=25, look_for_keys=False, allow_agent=False)
    return c


cl = conn("10.66.116.11", PW)
def a(cmd, t=90):
    _i, o, e = cl.exec_command(f"{ADB} {cmd}", timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()

# 0. confirm the freshly-built apk is the installed one (size match)
apk_dev = a("shell stat -c%s $(pm path com.qeli | sed s/package://) 2>/dev/null").strip()
print("installed apk size:", apk_dev, "(local build 20062362)")

a("shell am force-stop com.qeli"); time.sleep(1)
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS 2>/dev/null; true")
a("shell appops set com.qeli ACTIVATE_VPN allow 2>/dev/null; true")
a("logcat -c")
a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)

# dismiss any lingering dialog (ALLOW), then dump the main screen
a("shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; true")
ui = a("shell cat /sdcard/ui.xml")
if "send you notifications" in ui or ">ALLOW<" in ui or 'text="ALLOW"' in ui:
    for m in re.finditer(r'text="ALLOW"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui):
        x = (int(m.group(1)) + int(m.group(3))) // 2; y = (int(m.group(2)) + int(m.group(4))) // 2
        a(f"shell input tap {x} {y}"); print("dismissed notif dialog"); break
    time.sleep(1); a("shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; true"); ui = a("shell cat /sdcard/ui.xml")

print("UI text nodes:", re.findall(r'text="([^"]+)"', ui)[:16])
picked = False
for m in re.finditer(r'text="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui):
    if re.search(r"tap to connect", m.group(1), re.I):
        x = (int(m.group(2)) + int(m.group(4))) // 2; y = (int(m.group(3)) + int(m.group(5))) // 2
        a(f"shell input tap {x} {y}"); print(f"tapped '{m.group(1)}' @ {x},{y}"); picked = True; break
if not picked:
    print("TAP TO CONNECT not found; nodes:", re.findall(r'text="([^"]+)"', ui))

time.sleep(15)
print("\n=== VpnSvc handshake trace ===")
trace = a("logcat -d 2>/dev/null | grep -aE 'VpnSvc|AndroidRuntime.*qeli|E/AndroidRuntime' | tail -50")
print(trace or "(none)")
a("shell am force-stop com.qeli")
cl.close()

p = conn(PROD, PWP)
_i, o, _e = p.exec_command("grep -iE 'obfs-awg' /var/log/qeli/server.log | tail -8", timeout=30)
print("\n=== PROD obfs-awg tail ===\n" + o.read().decode("utf-8", "replace").strip())
p.close()

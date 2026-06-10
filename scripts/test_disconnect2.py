#!/usr/bin/env python3
"""Disconnect-during-blocked-connect, using the existing :9999 plain profile on the
emulator. DROP .10:9999 so connect() hangs; connect (status stuck Connecting); tap
Disconnect; assert it returns to Disconnected without an app restart."""
import os, sys, time, re
sys.path.insert(0, "scripts")
import android_ui as A
import paramiko

lc = paramiko.SSHClient(); lc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
lc.connect("10.66.116.10", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def L(cmd):
    i, o, e = lc.exec_command(cmd, timeout=30); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()

def status():
    return [t for t in A.texts() if t in ("Connecting", "Connected", "Disconnected", "TAP TO CONNECT", "TAP TO DISCONNECT")]

try:
    print("[setup] DROP .10:9999:", L("iptables -C INPUT -p tcp --dport 9999 -j DROP 2>/dev/null || iptables -I INPUT -p tcp --dport 9999 -j DROP; echo ok"))
    A.adb("shell am force-stop com.qeli"); time.sleep(1)
    A.adb("shell monkey -p com.qeli -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1"); time.sleep(3)
    ui = A.dump()
    if "background" in ui.lower() and "ALLOW" in ui:
        A.adb("shell input tap 256 426"); time.sleep(1)
        A.adb("shell monkey -p com.qeli -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1"); time.sleep(2)
    # Profiles tab, activate a :9999 profile
    A.tap_text("Profiles", A.dump(), partial=False); time.sleep(1.5)
    ui = A.dump(); tapped = False
    for nd in re.findall(r"<node[^>]*>", ui):
        rid = (re.search(r'resource-id="([^"]*)"', nd) or [None, ""])[1]
        tm = re.search(r'text="([^"]*)"', nd); bm = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', nd)
        if rid.endswith("rowSub") and tm and "9999" in tm.group(1) and bm:
            a, b, c2, d = map(int, bm.groups()); A.adb(f"shell input tap {(a+c2)//2} {(b+d)//2}"); tapped = True; break
    print("[profile] activated :9999:", tapped)
    time.sleep(1.2)
    A.tap_text("Connection", A.dump(), partial=False); time.sleep(1.2)
    print("[active]", [t for t in A.texts() if "9999" in t or "10.66" in t][:2])
    # CONNECT
    A.adb("shell input tap 160 300"); time.sleep(2)
    ui = A.dump()
    if "connection request" in ui.lower() or "vpn connection" in ui.lower():
        A.tap_text("OK", ui, partial=False) or A.tap_text("ALLOW", ui, partial=False); time.sleep(2)
    # wait for Connecting (blocked on DROP)
    blocked = False
    for _ in range(8):
        time.sleep(2)
        s = status()
        if "Connecting" in s or "TAP TO DISCONNECT" in s: blocked = True; break
        if "Connected" in s: break
    print(f"[connect] status (want Connecting, blocked): {status()} | blocked={blocked}")
    if not blocked:
        print("  !! never entered Connecting — test inconclusive"); sys.exit(0)

    # THE TEST: tap Disconnect while connect() is blocked
    print("[action] tap Disconnect while connect() is blocked on DROPped :9999 ...")
    A.adb("shell input tap 160 300");
    ok = False
    for t in range(0, 16, 2):
        time.sleep(2)
        s = status()
        done = "Disconnected" in s or "TAP TO CONNECT" in s
        print(f"   [t+{t+2}s] status={s} disconnected={done}")
        if done: ok = True; break
    print("\n=== RESULT ===")
    print(f"  VERDICT: {'PASS — Disconnect interrupts the stuck connect (no app restart)' if ok else 'FAIL — still stuck'}")
finally:
    print("\n[cleanup] remove DROP:", L("iptables -D INPUT -p tcp --dport 9999 -j DROP 2>/dev/null; echo ok"))
    try:
        A.adb("shell input tap 160 300"); time.sleep(1)
    except Exception: pass
    lc.close()

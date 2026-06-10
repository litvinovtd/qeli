#!/usr/bin/env python3
"""Verify Disconnect interrupts a blocked connect: point the app at a DROPped port
(SYN silently dropped -> blocking connect() hangs for minutes), connect (status
stuck CONNECTING), then tap Disconnect. OLD code: stuck until app restart. NEW:
the socket is published before connect, so Disconnect closes it -> connect throws
-> retry loop exits -> Disconnected."""
import os, sys, time, re
sys.path.insert(0, "scripts")
import android_ui as A
import paramiko

DROP_PORT = 9999
LINK = f"qeli://admin:testpass123@10.66.116.10:{DROP_PORT}?proto=tcp&mode=plain&key=e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"

lc = paramiko.SSHClient(); lc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
lc.connect("10.66.116.10", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def L(cmd, t=30):
    i, o, e = lc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()

def editext(ui):
    m = re.search(r'<node[^>]*class="android.widget.EditText"[^>]*text="([^"]*)"', ui)
    return (m.group(1) if m else "").replace("&amp;", "&")

try:
    print("[setup] DROP on .10:%d:" % DROP_PORT,
          L(f"iptables -C INPUT -p tcp --dport {DROP_PORT} -j DROP 2>/dev/null || iptables -I INPUT -p tcp --dport {DROP_PORT} -j DROP; echo ok"))
    print("[apk]", A.adb("install -r -d /root/android-project/app/build/outputs/apk/debug/app-debug.apk 2>&1 | tail -1"))
    A.adb("shell am force-stop com.qeli"); time.sleep(1)
    A.adb("shell monkey -p com.qeli -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1"); time.sleep(3)
    ui = A.dump()
    if "background" in ui.lower() and "ALLOW" in ui:
        A.adb("shell input tap 256 426"); time.sleep(1)
        A.adb("shell monkey -p com.qeli -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1"); time.sleep(2)
    # import the plain :9999 profile
    A.tap_text("Profiles", A.dump(), partial=False); time.sleep(1.2)
    A.tap_text("IMPORT", A.dump(), partial=False); time.sleep(1.2)
    A.tap_text("Paste qeli", A.dump()); time.sleep(1.2)
    et = re.search(r'<node[^>]*class="android.widget.EditText"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', A.dump())
    x1, y1, x2, y2 = map(int, et.groups()); A.adb(f"shell input tap {(x1+x2)//2} {(y1+y2)//2}"); time.sleep(1)
    # Type ONCE (input lands first time; re-verifying + re-typing concatenates).
    A.sh(A.ADB + ' shell "input text ' + chr(39) + LINK + chr(39) + '"'); time.sleep(2)
    print("   link in field exact:", editext(A.dump()) == LINK)
    A.tap_text("SAVE", A.dump(), partial=False); time.sleep(2)
    # show all profiles + activate the :9999 one
    ui = A.dump()
    rows = []
    for nd in re.findall(r"<node[^>]*>", ui):
        rid = (re.search(r'resource-id="([^"]*)"', nd) or [None, ""])[1]
        tm = re.search(r'text="([^"]*)"', nd)
        bm = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', nd)
        if rid.endswith("rowSub") and tm and bm:
            rows.append((tm.group(1), [int(x) for x in bm.groups()]))
    print("   profile rows:", [r[0] for r in rows])
    activated = False
    for txt, b in rows:
        if "9999" in txt:
            A.adb(f"shell input tap {(b[0]+b[2])//2} {(b[1]+b[3])//2}"); activated = True; break
    print("   activated :9999 profile:", activated)
    time.sleep(1.2)
    A.tap_text("Connection", A.dump(), partial=False); time.sleep(1.2)
    print("   active profile:", [t for t in A.texts() if "9999" in t or "10.66" in t][:2])
    A.adb("shell input tap 160 300"); time.sleep(2)  # CONNECT
    ui = A.dump()
    if "connection request" in ui.lower() or "vpn connection" in ui.lower():
        A.tap_text("OK", ui, partial=False) or A.tap_text("ALLOW", ui, partial=False); time.sleep(2)
    # poll until Connecting (or timeout)
    st1 = []
    for _ in range(6):
        time.sleep(2)
        st1 = [t for t in A.texts() if t in ("Connecting", "Connected", "Disconnected", "TAP TO CONNECT", "TAP TO DISCONNECT")]
        if "Connecting" in st1 or "TAP TO DISCONNECT" in st1: break
    print(f"\n[during connect] status (want Connecting, blocked on DROPped :9999): {st1}")

    # NOW tap Disconnect — the key test
    print("[action] tapping Disconnect while connect() is blocked...")
    A.adb("shell input tap 160 300"); time.sleep(1)
    reaped = False
    for t in range(0, 16, 3):
        time.sleep(3)
        st = A.texts()
        disc = "Disconnected" in st or "TAP TO CONNECT" in st
        print(f"   [t+{t+3}s] disconnected={disc} | status={[x for x in st if x in ('Connecting','Connected','Disconnected','TAP TO CONNECT','TAP TO DISCONNECT')]}")
        if disc: reaped = True; break
    print("\n=== RESULT ===")
    print(f"  Disconnect during blocked connect worked: {reaped}")
    print(f"  VERDICT: {'PASS — button stops the stuck reconnect (no app restart needed)' if reaped else 'FAIL — still stuck'}")
finally:
    print("\n=== cleanup ===")
    try: A.adb("shell input tap 160 300"); time.sleep(1)  # ensure disconnected
    except Exception: pass
    print("  remove DROP:", L(f"iptables -D INPUT -p tcp --dport {DROP_PORT} -j DROP 2>/dev/null; echo ok"))
    lc.close()

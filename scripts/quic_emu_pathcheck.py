#!/usr/bin/env python3
"""Pinpoint where the emulator's udp-quic ClientHello is lost.
Phase 1: connect once to grant the VPN consent.
Phase 2: start tcpdump on both ends, THEN trigger a fresh ClientHello inside the
window (consent already granted -> immediate send). Reports .11 egress vs .10
ingress -> tells emulator-SLIRP-drop from server-drop."""
import os, sys, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab_common import connect, run, LAB_SRV, LAB_CLI

s = connect(LAB_SRV); c = connect(LAB_CLI)
ADB = "/root/android-sdk/platform-tools/adb"
def a(cmd, t=90): return run(c, f"{ADB} {cmd}", timeout=t)

def tap(labels):
    d = a("exec-out uiautomator dump /dev/tty 2>/dev/null")
    for lb in labels:
        m = re.search(r'(?:text|content-desc)="' + re.escape(lb) + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', d, re.I)
        if m:
            x = (int(m.group(1))+int(m.group(3)))//2; y = (int(m.group(2))+int(m.group(4)))//2
            a(f"shell input tap {x} {y}"); return f"{lb}@{x},{y}"
    return None

print("srv up:", run(s, "pgrep -f 'quic-test/server-quic.conf'|tr '\\n' ' '||echo NONE"))

# ── Phase 1: connect once to grant the VPN consent ───────────────────────────
a("shell am force-stop com.qeli"); time.sleep(1)
a("shell am start -n com.qeli/.MainActivity"); time.sleep(7)
print("p1 connect:", tap(["Connect", "Подключить"]) or "tap 160,260 fallback" or a("shell input tap 160 260"))
time.sleep(3)
print("p1 consent:", tap(["OK", "Allow", "Start now", "ОК", "Разрешить"]) or "none")
time.sleep(6)

# ── Phase 2: captures first, then a fresh send inside the window ──────────────
a("shell am force-stop com.qeli"); time.sleep(1)
a("logcat -c")
base = int(run(s, "wc -l < /root/quic-test/srv-quic.log") or 0)
ch10 = s.get_transport().open_session(); ch10.exec_command("timeout 35 tcpdump -ni any 'udp port 8449' 2>/dev/null | head -12 >/root/quic-test/p10.out; echo d")
ch11 = c.get_transport().open_session(); ch11.exec_command("timeout 35 tcpdump -ni any 'udp and host 10.66.116.10 and port 8449' 2>/dev/null | head -12 >/root/p11.out; echo d")
time.sleep(2)  # let tcpdump attach
a("shell am start -n com.qeli/.MainActivity"); time.sleep(6)
print("p2 connect:", tap(["Connect", "Подключить"]) or (a("shell input tap 160 260") or "tap 160,260"))
time.sleep(3)
tap(["OK", "Allow", "ОК", "Разрешить"])  # in case consent re-appears
time.sleep(24)

print("\n=== app logcat (window) ===\n" + a("logcat -d | grep -E 'ClientHello sent|Connecting UDP|Poll timed|Auth OK|QUIC' | tail -6"))
p11 = run(c, "grep -c IP /root/p11.out 2>/dev/null||echo 0")
p10 = run(s, "grep -c IP /root/quic-test/p10.out 2>/dev/null||echo 0")
print("\n=== .11 egress -> .10:8449  pkts:", p11, "===")
print(run(c, "cat /root/p11.out 2>/dev/null||echo none"))
print("\n=== .10 ingress udp/8449  pkts:", p10, "===")
print(run(s, "cat /root/quic-test/p10.out 2>/dev/null||echo none"))
print("\n=== server handshake delta ===")
print(run(s, f"tail -n +{base+1} /root/quic-test/srv-quic.log | grep -iE 'handshake|Auth|assigned|QUIC' | tail -5 || echo none"))

verdict = ("app-not-sending" if "ClientHello sent" not in a("logcat -d | grep -c ClientHello >/dev/null; logcat -d|grep ClientHello|tail -1")
           else "SLIRP-drops-UDP (egress=0)" if p11.strip() == "0"
           else "lost .11->.10 (egress>0, ingress=0)" if p10.strip() == "0"
           else "reaches server")
print("\nVERDICT:", verdict)
s.close(); c.close()

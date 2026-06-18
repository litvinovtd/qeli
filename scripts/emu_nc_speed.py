#!/usr/bin/env python3
"""reality-tls prod DOWNLOAD throughput via the Android emulator (.so client),
measured server-side: prod streams /dev/zero over the tunnel to the emulator
(nc), and we sample prod vpn0 tx_bytes -> Mbps, plus prod qeli CPU. Emulator is
on .11's wired link (clean), so this isolates the prod/protocol ceiling vs the
phone's mobile path."""
import os, sys, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

ADB = "/root/android-sdk/platform-tools/adb"
WIN = 12

lc = paramiko.SSHClient(); lc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
lc.connect("10.66.116.11", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
pc = paramiko.SSHClient(); pc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
pc.connect("YOUR_PROD_HOST", username="root", password=os.environ["QELI_PROD_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def L(c, t=120):
    i, o, e = lc.exec_command(c, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def P(c, t=60):
    i, o, e = pc.exec_command(c, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def a(c, t=120): return L(f"{ADB} {c}", t)
def Pbg(c):
    ch = pc.get_transport().open_session(); ch.exec_command(c); time.sleep(0.3); ch.close()
def Lbg(c):
    ch = lc.get_transport().open_session(); ch.exec_command(c); time.sleep(0.3); ch.close()

try:
    P("iptables -C INPUT -i vpn+ -j ACCEPT 2>/dev/null || iptables -I INPUT -i vpn+ -j ACCEPT")
    wpid = P("pgrep -f 'qeli _worker' | head -1")

    # (re)connect emulator to prod reality-tls (profile already in shared_prefs)
    a("shell am force-stop com.qeli"); time.sleep(1)
    a("logcat -c")
    a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
    a("shell input tap 160 370"); time.sleep(4)
    cur = a("shell uiautomator dump /sdcard/u.xml && cat /sdcard/u.xml")
    for label in ("OK", "Allow", "Start now"):
        m = re.search(r'(?:text|content-desc)="' + label + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', cur)
        if m:
            x = (int(m.group(1))+int(m.group(3)))//2; y = (int(m.group(2))+int(m.group(4)))//2
            a(f"shell input tap {x} {y}"); break
    time.sleep(8)
    okc = a("logcat -d -s VpnSvc:D | grep -c 'Auth OK'")
    print("[emulator connected]", "yes" if okc.strip() not in ("0","") else "NO", "| recent:",
          a("logcat -d -s VpnSvc:D | grep -iE 'Auth OK|established' | tail -1"))

    # prod streams zeros on 10.9.0.1:9999; emulator receives -> /dev/null
    P("pkill -9 nc 2>/dev/null; true")
    Pbg(f"timeout {WIN+3} bash -lc 'cat /dev/zero | nc -l -p 9999' >/dev/null 2>&1")
    time.sleep(1)
    Lbg(f"{ADB} shell 'toybox timeout {WIN+1} nc 10.9.0.1 9999 > /dev/null 2>&1'")
    # sample prod vpn0 tx + qeli CPU over WIN seconds
    def tx():
        v = P("cat /sys/class/net/vpn0/statistics/tx_bytes")
        try: return int(v)
        except: return 0
    def wj():
        s = P(f"cat /proc/{wpid}/stat").split(); return (int(s[13])+int(s[14])) if len(s)>14 else 0
    def tj(): return sum(int(x) for x in P("head -1 /proc/stat").split()[1:])
    samples=[]; cpu=[]
    pb, pj, ptj = tx(), wj(), tj()
    for _ in range(WIN):
        time.sleep(1)
        nb, nj, ntj = tx(), wj(), tj()
        samples.append(round((nb-pb)*8/1e6,1))
        cpu.append(round(100.0*(nj-pj)/(ntj-ptj),1) if ntj>ptj else 0.0)
        pb, pj, ptj = nb, nj, ntj
    peak = max(samples) if samples else 0
    sust = sorted(samples)[len(samples)//2] if samples else 0
    print(f"\n>>> reality-tls DOWNLOAD (prod->emulator, .so client, wired):")
    print(f"    per-sec Mbps: {samples}")
    print(f"    peak={peak} Mbps  median={sust} Mbps")
    print(f">>> prod qeli worker CPU%: {cpu}  (max={max(cpu) if cpu else '?'}, 1 core=100%)")
finally:
    P("pkill -9 nc 2>/dev/null; iptables -D INPUT -i vpn+ -j ACCEPT 2>/dev/null; true")
    a("shell am force-stop com.qeli")
    print("[cleaned] prod active:", P("systemctl is-active qeli.service"))
    lc.close(); pc.close()

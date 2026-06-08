#!/usr/bin/env python3
"""Localize the reality-tls under-load stall: server-side vs .so-client-side.
prod streams zeros over the tunnel to the emulator; per second we sample BOTH
the tunnel throughput (vpn0 tx) AND the outer :443 TCP connection's Send-Q /
bytes_acked / cwnd. Send-Q grows + acked freezes => client(.so) not draining;
Send-Q stays 0 + tun tx freezes => server not writing the tun stream."""
import os, sys, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

ADB = "/root/android-sdk/platform-tools/adb"; WIN = 14
lc = paramiko.SSHClient(); lc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
lc.connect("10.66.116.11", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
pc = paramiko.SSHClient(); pc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
pc.connect("222.167.246.143", username="root", password=os.environ["QELI_PROD_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def L(c,t=120):
    i,o,e=lc.exec_command(c,timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def P(c,t=60):
    i,o,e=pc.exec_command(c,timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def a(c,t=120): return L(f"{ADB} {c}",t)
def Pbg(c):
    ch=pc.get_transport().open_session(); ch.exec_command(c); time.sleep(0.3); ch.close()
def Lbg(c):
    ch=lc.get_transport().open_session(); ch.exec_command(c); time.sleep(0.3); ch.close()

try:
    P("iptables -C INPUT -i vpn+ -j ACCEPT 2>/dev/null || iptables -I INPUT -i vpn+ -j ACCEPT")
    a("shell am force-stop com.qeli"); time.sleep(1); a("logcat -c")
    a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
    a("shell input tap 160 370"); time.sleep(4)
    cur=a("shell uiautomator dump /sdcard/u.xml && cat /sdcard/u.xml")
    for label in ("OK","Allow","Start now"):
        m=re.search(r'(?:text|content-desc)="'+label+r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',cur)
        if m:
            a(f"shell input tap {(int(m.group(1))+int(m.group(3)))//2} {(int(m.group(2))+int(m.group(4)))//2}"); break
    time.sleep(8)
    eip = P("ss -tnH 'sport = :443' | grep -v 127.0.0.1 | head -1 | awk '{print $4, $5}'")
    print("[emu connected]", a("logcat -d -s VpnSvc:D | grep -iE 'Auth OK' | tail -1"))

    P("pkill -9 nc 2>/dev/null; true")
    Pbg(f"timeout {WIN+3} bash -lc 'cat /dev/zero | nc -l -p 9999' >/dev/null 2>&1")
    time.sleep(1)
    Lbg(f"{ADB} shell 'toybox timeout {WIN+1} nc 10.9.0.1 9999 > /dev/null 2>&1'")
    print(f"{'t':>3} {'tun_Mbps':>8} {'sendq':>8} {'acked_d':>9} {'cwnd':>6} {'unacked':>8} {'rwnd':>8} {'retr':>6}")
    def tx():
        v=P("cat /sys/class/net/vpn0/statistics/tx_bytes"); return int(v) if v.isdigit() else 0
    pb=tx(); pack=None
    for t in range(WIN):
        time.sleep(1)
        nb=tx(); tun=round((nb-pb)*8/1e6,1); pb=nb
        # the phone/emulator outer conn = the non-loopback :443 established
        ss=P("ss -tniH 'sport = :443' 2>/dev/null | grep -vE '127.0.0.1' | head -8")
        # pick the line with the biggest Send-Q or bytes_acked
        best=""; bestv=-1
        lines=ss.split('\n')
        for idx in range(0,len(lines)):
            ln=lines[idx]
            mq=re.match(r'\S+\s+\d+\s+(\d+)',ln)
            if mq and int(mq.group(1))>=0 and ('cwnd' in (lines[idx+1] if idx+1<len(lines) else '') or 'cwnd' in ln):
                pass
        blk=ss
        sendq=re.findall(r'^\S+\s+\d+\s+(\d+)',ss,re.M)
        sq=max([int(x) for x in sendq],default=0)
        acked=re.search(r'bytes_acked:(\d+)',ss); ackv=int(acked.group(1)) if acked else 0
        ackd = (ackv-pack) if pack is not None else 0; pack=ackv
        cwnd=re.search(r'cwnd:(\d+)',ss); un=re.search(r'unacked:(\d+)',ss); rw=re.search(r'rcv_space:(\d+)',ss); rt=re.search(r'retrans:\d+/(\d+)',ss)
        print(f"{t:>3} {tun:>8} {sq:>8} {round(ackd/1e6,2):>9} {(cwnd.group(1) if cwnd else '-'):>6} {(un.group(1) if un else '-'):>8} {(rw.group(1) if rw else '-'):>8} {(rt.group(1) if rt else '0'):>6}")
finally:
    P("pkill -9 nc 2>/dev/null; iptables -D INPUT -i vpn+ -j ACCEPT 2>/dev/null; true")
    a("shell am force-stop com.qeli")
    print("[done] prod", P("systemctl is-active qeli.service"))
    lc.close(); pc.close()

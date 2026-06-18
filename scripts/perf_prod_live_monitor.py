#!/usr/bin/env python3
"""Live-monitor PROD during the user's real phone reality-tls download (~90s).
Per second: qeli worker CPU%, vpn0 tun throughput (byte delta), and the active
:443 TCP connection stats (cwnd / retransmits / delivery_rate / rtt). Reveals
whether the 12 Mbps ceiling is prod CPU, TCP-over-TCP (retrans/low cwnd), or
neither (client-side)."""
import os, sys, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("YOUR_PROD_HOST", username="root", password=os.environ["QELI_PROD_PASS"],
          timeout=25, look_for_keys=False, allow_agent=False)
def r(cmd, t=15):
    i, o, e = c.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()

wpid = r("pgrep -f 'qeli _worker' | head -1")
ncpu = int(r("nproc") or 1)
print(f"[prod] qeli worker pid={wpid}, nproc={ncpu}; monitoring 90s — START A PHONE SPEEDTEST NOW")
print(f"{'t':>3} {'cpu%':>6} {'tun_Mbps':>9} {'conns':>5} {'cwnd':>6} {'retrans':>8} {'deliv_Mbps':>11} {'rtt_ms':>7}")

def worker_jiffies():
    s = r(f"cat /proc/{wpid}/stat 2>/dev/null")
    f = s.split()
    return (int(f[13]) + int(f[14])) if len(f) > 14 else None  # utime+stime
def total_jiffies():
    return sum(int(x) for x in r("head -1 /proc/stat").split()[1:])
def tun_bytes():
    v = r("cat /sys/class/net/vpn0/statistics/tx_bytes /sys/class/net/vpn0/statistics/rx_bytes 2>/dev/null").split()
    return (int(v[0]) + int(v[1])) if len(v) == 2 else 0

pj, ptj, pb = worker_jiffies(), total_jiffies(), tun_bytes()
maxcpu = maxtun = 0.0
tot_retrans0 = None
for t in range(1, 91):
    time.sleep(1)
    nj, ntj, nb = worker_jiffies(), total_jiffies(), tun_bytes()
    cpu = round(100.0 * ncpu * (nj - pj) / (ntj - ptj), 1) if (nj and pj and ntj > ptj) else 0.0
    tun_mbps = round((nb - pb) * 8 / 1e6, 1)
    pj, ptj, pb = nj, ntj, nb
    maxcpu = max(maxcpu, cpu); maxtun = max(maxtun, tun_mbps)
    # active :443 conn stats (the phone). pick the established one with most bytes.
    ss = r("ss -tniH state established '( sport = :443 )' 2>/dev/null")
    nconn = len([l for l in ss.splitlines() if ":443" in l])
    cwnd = re.search(r"cwnd:(\d+)", ss); retr = re.search(r"retrans:\d+/(\d+)", ss)
    deliv = re.search(r"delivery_rate (\d+)bps", ss); rtt = re.search(r"\brtt:([\d.]+)", ss)
    cwnd_v = cwnd.group(1) if cwnd else "-"
    retr_v = retr.group(1) if retr else "0"
    deliv_v = round(int(deliv.group(1))/1e6, 1) if deliv else "-"
    rtt_v = rtt.group(1) if rtt else "-"
    if t % 3 == 0 or tun_mbps > 1:
        print(f"{t:>3} {cpu:>6} {tun_mbps:>9} {nconn:>5} {cwnd_v:>6} {retr_v:>8} {str(deliv_v):>11} {rtt_v:>7}")

print(f"\n[summary] peak qeli CPU = {maxcpu}%  (1 core = 100%) | peak tun throughput = {maxtun} Mbps")
print("[interpretation] CPU~100% -> prod data-plane bound | high retrans/low cwnd -> TCP-over-TCP/mobile loss | both low + low tun -> client-side bottleneck")
c.close()

#!/usr/bin/env python3
"""Phase A — gather facts for the reality-tls throughput investigation.
READ-ONLY on prod (no config changes, no restarts). Collects:
  • prod qeli config (profiles, modes, transport, MTU, reality settings) + version
  • prod NIC MTU, listening qeli ports, iperf3 availability
  • lab(.11)→prod baseline: RTT/loss, path-MTU (DF probe), traceroute hops, iperf3
"""
import os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PROD = ("YOUR_PROD_HOST", "root", os.environ.get("QELI_PROD_PASS", ""))
LAB11 = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=60):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


print("########## PROD YOUR_PROD_HOST (read-only) ##########")
try:
    p = conn(PROD)
    print("[qeli version]", run(p, "qeli --version 2>/dev/null || /usr/local/bin/qeli --version 2>/dev/null || ls -la /usr/local/bin/qeli /usr/bin/qeli 2>/dev/null"))
    print("[qeli proc]", run(p, "ps -eo pid,args | grep '[q]eli' | head -5"))
    print("[config files]", run(p, "ls -la /etc/qeli/ 2>/dev/null"))
    cfg = run(p, "for f in /etc/qeli/*.conf; do echo \"### $f\"; cat \"$f\"; echo; done 2>/dev/null")
    print("[configs]\n" + cfg)
    print("[listening ports]", run(p, "ss -ltnp | grep -i qeli || ss -ltn | head -15"))
    print("[NIC mtu]", run(p, "ip -o link show | grep -vE 'lo:|tun|qeli' | awk '{print $2, $0}' | grep -oE 'mtu [0-9]+' | sort -u; ip route get 8.8.8.8 2>/dev/null | head -1"))
    print("[tun ifaces]", run(p, "ip -o -d link show type tun 2>/dev/null | grep -oE '^[0-9]+: [a-z0-9]+|mtu [0-9]+' | tr '\\n' ' '"))
    print("[iperf3]", run(p, "which iperf3 || echo NO-iperf3"))
    print("[cpu/aes]", run(p, "grep -m1 'model name' /proc/cpuinfo; grep -m1 -o 'aes' /proc/cpuinfo || echo no-aes-flag; nproc"))
    p.close()
except Exception as ex:
    print("PROD connect failed:", ex)

print("\n########## LAB .11 -> PROD baseline ##########")
try:
    l = conn(LAB11)
    print("[ping x10]", run(l, "ping -c10 -i0.2 YOUR_PROD_HOST | tail -3"))
    print("[path-MTU DF probe] (largest payload that passes without fragmentation)")
    # binary-ish sweep of DF payloads; 1472 = 1500 MTU. find largest that succeeds
    for sz in (1472, 1452, 1422, 1400, 1352, 1300, 1200):
        r = run(l, f"ping -c1 -W2 -M do -s {sz} YOUR_PROD_HOST | grep -qE '1 received' && echo OK || echo FAIL")
        print(f"   payload {sz} (pkt {sz+28}): {r}")
        if r == "OK":
            print(f"   => path MTU >= {sz+28}"); break
    print("[traceroute]", run(l, "traceroute -n -m 20 -w 2 YOUR_PROD_HOST 2>/dev/null | tail -16 || mtr -n -c5 -r YOUR_PROD_HOST 2>/dev/null | tail -16 || echo no-traceroute"))
    print("[iperf3 on .11]", run(l, "which iperf3 || echo NO-iperf3"))
    l.close()
except Exception as ex:
    print("LAB .11 connect failed:", ex)

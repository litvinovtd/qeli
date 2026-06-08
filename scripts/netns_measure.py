#!/usr/bin/env python3
"""Clean reality-tls tunnel throughput: netns client on .11 -> PROD, with the
qeli-client tun bugs worked around (set p2p peer + MTU 1280). iperf3 both ways to
prod's tun IP over the clean internet path (RTT 32ms, 0% loss). Also samples prod
qeli CPU. This is the clean server-side ceiling number the phone can't isolate."""
import os, sys, io, time, json, threading
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

NS = "qns"; QCLI = "/root/qeli-l3/qeli"
INI = """[qeli]
server = 222.167.246.143:443
proto = tcp
user = user01
pass = NA4BLbbHIpIpyJ5y
key = 7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057
mode = reality-tls
sni = www.microsoft.com
reality_sid = 2699764da5df00bc
[logging]
level = info
file = /root/perf-cli.log
"""
pc = paramiko.SSHClient(); pc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
pc.connect("222.167.246.143", username="root", password=os.environ["QELI_PROD_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
lc = paramiko.SSHClient(); lc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
lc.connect("10.66.116.11", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def P(c, t=120):
    i, o, e = pc.exec_command(c, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def L(c, t=180):
    i, o, e = lc.exec_command(c, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def NSX(c, t=180): return L(f"ip netns exec {NS} {c}", t)
def mbps(j):
    try: return round(json.loads(j)["end"]["sum_received"]["bits_per_second"]/1e6, 1)
    except Exception: return None

egress = L("ip route get 222.167.246.143 | grep -oE 'dev [a-z0-9]+' | awk '{print $2}' | head -1")
try:
    P("pkill -9 iperf3 2>/dev/null; sleep 1; iperf3 -s -D --logfile /root/iperf3.log; iptables -I INPUT -i vpn+ -j ACCEPT; sleep 1; true")
    wpid = P("pgrep -f 'qeli _worker' | head -1")
    # netns
    L(f"ip netns del {NS} 2>/dev/null; ip link del veth0 2>/dev/null; true")
    L(f"ip netns add {NS}; ip link add veth0 type veth peer name veth1; ip link set veth1 netns {NS}")
    L("ip addr add 10.200.0.1/24 dev veth0; ip link set veth0 up")
    NSX("ip addr add 10.200.0.2/24 dev veth1"); NSX("ip link set veth1 up"); NSX("ip link set lo up"); NSX("ip route add default via 10.200.0.1")
    L("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    L(f"iptables -t nat -C POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE")
    sf = lc.open_sftp(); sf.putfo(io.BytesIO(INI.encode()), "/root/perf-cli.conf"); sf.close()
    L("kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; rm -f /root/perf-cli.log /root/perf-cli.out; true")
    L(f"ip netns exec {NS} nohup {QCLI} client -c /root/perf-cli.conf </dev/null >/root/perf-cli.out 2>&1 & echo $! >/root/perf-cli.pid")
    up = False
    for _ in range(20):
        time.sleep(1)
        if "TUN vpn0 is up" in L("cat /root/perf-cli.log /root/perf-cli.out 2>/dev/null"): up = True; break
    time.sleep(2)  # let it settle before touching the tun
    # work around client tun bugs: proper p2p peer + match prod tun mtu 1280
    NSX("ip addr del 10.9.0.2/24 dev vpn0 2>/dev/null; ip addr add 10.9.0.2 peer 10.9.0.1 dev vpn0; ip link set vpn0 mtu 1280; true")
    print("[tun up]", up, "| [vpn0]", NSX("ip addr show vpn0 | grep -E 'inet |peer'; ip link show vpn0|grep -oE 'mtu [0-9]+'"))
    print("[ping 10.9.0.1]", NSX("ping -c4 -i0.3 -W2 10.9.0.1 | tail -2"))

    cpu = []
    def sample():
        pj = None; ptj = None
        for _ in range(22):
            s = P(f"cat /proc/{wpid}/stat 2>/dev/null").split()
            tj = sum(int(x) for x in P("head -1 /proc/stat").split()[1:])
            j = (int(s[13])+int(s[14])) if len(s) > 14 else None
            if pj is not None and tj > ptj and j is not None:
                cpu.append(round(100.0*(j-pj)/(tj-ptj), 1))
            pj, ptj = j, tj
            time.sleep(1)
    th = threading.Thread(target=sample); th.start()
    dn = NSX("iperf3 -c 10.9.0.1 -t 10 -O 1 -R -J --connect-timeout 8000 2>/dev/null", t=40)
    up_j = NSX("iperf3 -c 10.9.0.1 -t 10 -O 1 -J --connect-timeout 8000 2>/dev/null", t=40)
    th.join()
    print(f"\n>>> reality-tls TUNNEL (netns .11 -> PROD, clean path, MTU1280):  DOWN {mbps(dn)} | UP {mbps(up_j)} Mbps")
    print(f">>> prod qeli worker CPU% during transfer: max={max(cpu) if cpu else '?'} avg={round(sum(cpu)/len(cpu),1) if cpu else '?'}")
    print("[outer conn]", P(f"ss -tniH 'sport = :443' 2>/dev/null | grep -oE 'cwnd:[0-9]+|retrans:[0-9]+/[0-9]+|delivery_rate [0-9]+bps|bbr' | tr '\\n' ' '"))
finally:
    L("kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; true")
    L(f"ip netns del {NS} 2>/dev/null; ip link del veth0 2>/dev/null; iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE 2>/dev/null; true")
    P("pkill -9 iperf3 2>/dev/null; iptables -D INPUT -i vpn+ -j ACCEPT 2>/dev/null; true")
    print("[prod active]", P("systemctl is-active qeli.service"))
    pc.close(); lc.close()

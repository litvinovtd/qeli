#!/usr/bin/env python3
"""Decisive bottleneck test: reality-tls tunnel throughput lab(.11 netns)->PROD
while sampling the prod qeli worker CPU. Tells us whether 12 Mbps is the prod
single-core userspace data-plane ceiling (CPU-bound) or a network/TCP-over-TCP
effect.

netns isolates the client tun so host routing/SSH is untouched. The netns reaches
prod via a veth + MASQUERADE on .11. iperf3 runs inside the netns to prod's tun IP
(10.9.0.1) — pure .11<->prod reality-tls tunnel, clean path (RTT 32ms, 0% loss)."""
import os, sys, io, time, json, threading
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

NS = "qns"
QCLI = "/root/qeli-l3/qeli"
INI = """[qeli]
server = YOUR_PROD_HOST:443
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


def C(h, p):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h, username="root", password=p, timeout=25, look_for_keys=False, allow_agent=False)
    return c


pc = C("YOUR_PROD_HOST", os.environ["QELI_PROD_PASS"])
lc = C("10.66.116.11", os.environ["QELI_LAB_PASS"])
def P(cmd, t=120):
    i, o, e = pc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def L(cmd, t=180):
    i, o, e = lc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def NSX(cmd, t=180):
    return L(f"ip netns exec {NS} {cmd}", t)

try:
    # prod: iperf3 + allow tun INPUT; find qeli worker pid
    P("pkill -9 iperf3 2>/dev/null; sleep 1; iperf3 -s -D --logfile /root/iperf3.log; iptables -I INPUT -i vpn+ -j ACCEPT; sleep 1; true")
    wpid = P("pgrep -f 'qeli _worker' | head -1")
    print("[prod qeli worker pid]", wpid, "| iperf3", P("ss -ltn|grep -q :5201 && echo up"))

    # .11: netns + veth + NAT
    egress = L("ip route get YOUR_PROD_HOST | grep -oE 'dev [a-z0-9]+' | awk '{print $2}' | head -1")
    L(f"ip netns del {NS} 2>/dev/null; ip link del veth0 2>/dev/null; true")
    L(f"ip netns add {NS}")
    L(f"ip link add veth0 type veth peer name veth1")
    L(f"ip link set veth1 netns {NS}")
    L(f"ip addr add 10.200.0.1/24 dev veth0; ip link set veth0 up")
    NSX("ip addr add 10.200.0.2/24 dev veth1"); NSX("ip link set veth1 up"); NSX("ip link set lo up")
    NSX("ip route add default via 10.200.0.1")
    L("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    L(f"iptables -t nat -C POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE")
    # DNS for netns (server is an IP so not needed, but harmless)
    sf = lc.open_sftp(); sf.putfo(io.BytesIO(INI.encode()), "/root/perf-cli.conf"); sf.close()
    L("rm -f /root/perf-cli.log /root/perf-cli.out; true")
    L(f"ip netns exec {NS} nohup {QCLI} client -c /root/perf-cli.conf </dev/null >/root/perf-cli.out 2>&1 & echo $! >/root/perf-cli.pid; sleep 0.5")
    up = False
    for _ in range(20):
        time.sleep(1)
        if "TUN vpn0 is up" in L("cat /root/perf-cli.log /root/perf-cli.out 2>/dev/null"): up = True; break
    print("[netns tunnel up]", up)
    # proper p2p peer inside netns + match server MTU 1280
    NSX("ip addr del 10.9.0.2/24 dev vpn0 2>/dev/null; ip addr add 10.9.0.2 peer 10.9.0.1 dev vpn0; ip link set vpn0 mtu 1280; true")
    print("[netns vpn0]", NSX("ip addr show vpn0 | grep -E 'inet |peer'; ip link show vpn0|grep -oE 'mtu [0-9]+'"))
    print("[ping 10.9.0.1]", NSX("ping -c3 -i0.3 -W2 10.9.0.1 | tail -2"))

    # sample prod CPU of the qeli worker during a download
    cpu_samples = []
    def sample():
        for _ in range(12):
            v = P(f"top -b -n1 -p {wpid} 2>/dev/null | tail -1 | awk '{{print $9}}'", t=15)
            try: cpu_samples.append(float(v))
            except: pass
            time.sleep(1)
    th = threading.Thread(target=sample); th.start()
    dn = NSX("iperf3 -c 10.9.0.1 -t 10 -O 1 -R -J --connect-timeout 8000 2>/dev/null", t=40)
    up_j = NSX("iperf3 -c 10.9.0.1 -t 8 -O 1 -J --connect-timeout 8000 2>/dev/null", t=40)
    th.join()
    def mbps(j):
        try: return round(json.loads(j)["end"]["sum_received"]["bits_per_second"]/1e6, 1)
        except: return None
    print(f"\n[reality-tls TUNNEL .11<->prod, clean path]  DOWN {mbps(dn)} | UP {mbps(up_j)} Mbps")
    print(f"[prod qeli worker CPU% during DL]  max={max(cpu_samples) if cpu_samples else '?'}  samples={cpu_samples}")
    print("[prod load]", P("cat /proc/loadavg"))
finally:
    print("\n[cleanup]")
    L("kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; true")
    L(f"ip netns del {NS} 2>/dev/null; ip link del veth0 2>/dev/null; true")
    egress = L("ip route get YOUR_PROD_HOST | grep -oE 'dev [a-z0-9]+' | awk '{print $2}' | head -1")
    L(f"iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE 2>/dev/null; true")
    P("pkill -9 iperf3 2>/dev/null; iptables -D INPUT -i vpn+ -j ACCEPT 2>/dev/null; true")
    print("[prod active]", P("systemctl is-active qeli.service"), "| :443", P("ss -ltn|grep -q :443 && echo up"))
    pc.close(); lc.close()

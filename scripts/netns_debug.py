#!/usr/bin/env python3
"""Root-cause why the qeli CLI client can't sustain a tunnel data-plane on .11.
Sets up a netns client to PROD reality-tls, captures the FULL client log + exit
reason + checks the tun in BOTH namespaces + process liveness."""
import os, sys, io, time
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
level = debug
file = /root/perf-cli.log
"""
lc = paramiko.SSHClient(); lc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
lc.connect("10.66.116.11", username="root", password=os.environ["QELI_LAB_PASS"], timeout=25, look_for_keys=False, allow_agent=False)
def L(cmd, t=120):
    i, o, e = lc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def NSX(cmd, t=120):
    return L(f"ip netns exec {NS} {cmd}", t)

# setup netns
egress = L("ip route get YOUR_PROD_HOST | grep -oE 'dev [a-z0-9]+' | awk '{print $2}' | head -1")
L(f"ip netns del {NS} 2>/dev/null; ip link del veth0 2>/dev/null; true")
L(f"ip netns add {NS}; ip link add veth0 type veth peer name veth1; ip link set veth1 netns {NS}")
L(f"ip addr add 10.200.0.1/24 dev veth0; ip link set veth0 up")
NSX("ip addr add 10.200.0.2/24 dev veth1"); NSX("ip link set veth1 up"); NSX("ip link set lo up")
NSX("ip route add default via 10.200.0.1")
L("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
L(f"iptables -t nat -C POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE")
print("[netns reaches prod?]", NSX("timeout 5 bash -c 'echo > /dev/tcp/YOUR_PROD_HOST/443' && echo TCP-OK || echo TCP-FAIL"))

sf = lc.open_sftp(); sf.putfo(io.BytesIO(INI.encode()), "/root/perf-cli.conf"); sf.close()
L("kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; rm -f /root/perf-cli.log /root/perf-cli.out; true")
L(f"ip netns exec {NS} nohup {QCLI} client -c /root/perf-cli.conf </dev/null >/root/perf-cli.out 2>&1 & echo $! >/root/perf-cli.pid; sleep 0.5")
time.sleep(7)
pid = L("cat /root/perf-cli.pid")
print("[client pid alive?]", L(f"ps -o pid,stat,etime,cmd -p {pid} 2>/dev/null | tail -1 || echo DEAD/EXITED"))
print("[tun in netns qns]", NSX("ip -o link show | grep -E 'vpn|tun' || echo none"))
print("[tun in host ns]", L("ip -o link show | grep -E 'vpn[0-9]|tun' || echo none"))
print("===== FULL CLIENT LOG =====")
print(L("cat /root/perf-cli.out /root/perf-cli.log 2>/dev/null | tail -40"))
# cleanup
L("kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; true")
L(f"ip netns del {NS} 2>/dev/null; ip link del veth0 2>/dev/null; iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE 2>/dev/null; true")
print("[cleaned]")
lc.close()

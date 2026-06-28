#!/usr/bin/env python3
"""True 2-server load: .11(user02) + .10(user03), both reality-tls -> PROD, each to
its OWN iperf3 server port (5201/5202) so they transfer simultaneously. Shows prod
single-core saturation under combined load. NEVER user01 (the phone)."""
import os, sys, io, time, json, threading, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PROD_IP = "YOUR_PROD_HOST"
BIN = "/root/qeli-perf"
EGRESS_IP = "54.37.87.56"
LINK = "qeli://U:P@YOUR_PROD_HOST:443?proto=tcp&mode=reality-tls&key=7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057&sni=www.microsoft.com&rsid=CHANGEME-short-id"


def ini(user, pw):
    return ("[qeli]\nserver = YOUR_PROD_HOST:443\nproto = tcp\n"
            f"user = {user}\npass = {pw}\nmode = reality-tls\n"
            "key = 7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057\n"
            "sni = www.microsoft.com\nreality_sid = 2699764da5df00bc\n"
            "[logging]\nlevel = info\nfile = /root/perf-cli.log\n")


def conn(ip, pw):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=pw, timeout=25, look_for_keys=False, allow_agent=False)
    return c


pc = conn(PROD_IP, os.environ["QELI_PROD_PASS"])
c10 = conn("10.66.116.10", os.environ["QELI_LAB_PASS"])
c11 = conn("10.66.116.11", os.environ["QELI_LAB_PASS"])
def P(cmd, t=120):
    i, o, e = pc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def run(c, cmd, t=180):
    i, o, e = c.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def mbps(j):
    try: return round(json.loads(j)["end"]["sum_received"]["bits_per_second"] / 1e6, 1)
    except Exception: return None
def qj():
    t = 0
    for pid in P("pgrep -x qeli").split():
        s = P(f"cat /proc/{pid}/stat 2>/dev/null").split()
        if len(s) > 14: t += int(s[13]) + int(s[14])
    return t
def tj(): return sum(int(x) for x in P("head -1 /proc/stat").split()[1:])


def setup(c, ns, sub, egress):
    run(c, f"ip netns del {ns} 2>/dev/null; ip link del v{ns}0 2>/dev/null; true")
    run(c, f"ip netns add {ns}; ip link add v{ns}0 type veth peer name v{ns}1; ip link set v{ns}1 netns {ns}")
    run(c, f"ip addr add {sub}.1/24 dev v{ns}0; ip link set v{ns}0 up")
    run(c, f"ip netns exec {ns} ip addr add {sub}.2/24 dev v{ns}1; ip netns exec {ns} ip link set v{ns}1 up; ip netns exec {ns} ip link set lo up; ip netns exec {ns} ip route add default via {sub}.1")
    run(c, "sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    run(c, f"iptables -t nat -C POSTROUTING -s {sub}.0/24 -o {egress} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {sub}.0/24 -o {egress} -j MASQUERADE")


def start(c, ns, conf):
    sf = c.open_sftp(); sf.putfo(io.BytesIO(conf.encode()), "/root/perf-cli.conf"); sf.close()
    run(c, "kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; rm -f /root/perf-cli.log /root/perf-cli.out; true")
    ch = c.get_transport().open_session()
    ch.exec_command(f"ip netns exec {ns} nohup {BIN} client -c /root/perf-cli.conf </dev/null >/root/perf-cli.out 2>&1 & echo $! >/root/perf-cli.pid")
    time.sleep(1); ch.close()
    for _ in range(35):
        time.sleep(1)
        m = re.search(r"assigned IP: (10\.9\.0\.\d+)", run(c, "cat /root/perf-cli.log 2>/dev/null"))
        if m and "TUN vpn0 is up" in run(c, "cat /root/perf-cli.log"): return m.group(1)
    return None


def fix_and_wait(c, ns, ip):
    run(c, f"ip netns exec {ns} sh -c 'ip addr del {ip}/24 dev vpn0 2>/dev/null; ip addr add {ip} peer 10.9.0.1 dev vpn0; ip link set vpn0 mtu 1280; true'")
    for _ in range(20):
        if "1 received" in run(c, f"ip netns exec {ns} ping -c1 -W2 10.9.0.1 2>/dev/null"): return True
        time.sleep(2)
    return False


eg11 = eg10 = None
try:
    eg11 = run(c11, f"ip route get {PROD_IP}|grep -oE 'dev [a-z0-9]+'|awk '{{print $2}}'|head -1")
    eg10 = run(c10, f"ip route get {PROD_IP}|grep -oE 'dev [a-z0-9]+'|awk '{{print $2}}'|head -1")
    P("pkill -9 iperf3 2>/dev/null; sleep 1; iperf3 -s -p 5201 -D --logfile /root/ip1.log; iperf3 -s -p 5202 -D --logfile /root/ip2.log; "
      "iptables -C INPUT -i vpn+ -j ACCEPT 2>/dev/null || iptables -I INPUT -i vpn+ -j ACCEPT; sleep 1; true")
    setup(c11, "qns", "10.200.0", eg11); setup(c10, "qns10", "10.201.0", eg10)
    ip11 = start(c11, "qns", ini("user02", "CHANGEME"))
    ip10 = start(c10, "qns10", ini("user03", "Xgso4Huk3c4O5GrU"))
    print("assigned IPs: .11 ->", ip11, "| .10 ->", ip10)
    r11 = fix_and_wait(c11, "qns", ip11); r10 = fix_and_wait(c10, "qns10", ip10)
    print("data-plane ready: .11", r11, "| .10", r10)
    print("ESTAB :443 from lab egress:", P(f"ss -tnH '( sport = :443 )'|grep {EGRESS_IP}|grep -c ESTAB"))

    # baseline idle CPU
    pj, ptj = qj(), tj(); time.sleep(2); base = round(100.0*(qj()-pj)/(tj()-ptj), 1)
    cpu = []
    def sample():
        pj, ptj = qj(), tj()
        for _ in range(13):
            time.sleep(1); j, t = qj(), tj()
            if t > ptj: cpu.append(round(100.0*(j-pj)/(t-ptj), 1))
            pj, ptj = j, t
    out = {}
    def dl(c, ns, port, key):
        out[key] = run(c, f"ip netns exec {ns} iperf3 -c 10.9.0.1 -p {port} -t 10 -O 1 -R -J --connect-timeout 8000 2>/dev/null", t=45)
    th = threading.Thread(target=sample); th.start()
    t11 = threading.Thread(target=dl, args=(c11, "qns", 5201, "11"))
    t10 = threading.Thread(target=dl, args=(c10, "qns10", 5202, "10"))
    t11.start(); t10.start(); t11.join(); t10.join(); th.join()
    d11, d10 = mbps(out["11"]), mbps(out["10"])
    print("\n=== COMBINED 2-SERVER LOAD (reality-tls, both download simultaneously) ===")
    print(f"  DOWN .11(user02) = {d11} Mbps")
    print(f"  DOWN .10(user03) = {d10} Mbps")
    print(f"  AGGREGATE = {round((d11 or 0)+(d10 or 0),1)} Mbps")
    print(f"  prod qeli CPU: idle baseline={base}% | under load max={max(cpu) if cpu else '?'}% avg={round(sum(cpu)/len(cpu),1) if cpu else '?'}%")
    print(f"  prod RSS = {P(chr(39)+'ps -o rss= -C qeli'+chr(39)+' 2>/dev/null')}")  # kb list
    print("  prod load/mem:", P("uptime | grep -oE 'load average.*'; free -m | awk '/Mem/{print \"  mem used \"$3\"/\"$2\" MB\"}'"))
finally:
    print("\n=== restore ===")
    for c, ns, sub, eg in ((c11, "qns", "10.200.0", eg11), (c10, "qns10", "10.201.0", eg10)):
        run(c, f"kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; ip netns del {ns} 2>/dev/null; ip link del v{ns}0 2>/dev/null; true")
        if eg: run(c, f"iptables -t nat -D POSTROUTING -s {sub}.0/24 -o {eg} -j MASQUERADE 2>/dev/null; true")
    P("pkill -9 iperf3 2>/dev/null; iptables -D INPUT -i vpn+ -j ACCEPT 2>/dev/null; true")
    print("[prod]", P("systemctl is-active qeli.service"))
    pc.close(); c10.close(); c11.close()

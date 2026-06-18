#!/usr/bin/env python3
"""Full per-mode throughput + prod-CPU load sweep: lab -> PROD over the real
internet path, every one of the 9 prod profiles, then a combined 2-server
(.10+.11) load test on reality-tls. Client runs in a netns (tun isolated, host
SSH untouched) with the known tun-setup workaround (p2p peer + MTU 1280). iperf3
both ways to the profile's prod tun gateway = pure tunnel goodput; prod qeli CPU
is sampled throughout. Uses user02/user03 — NEVER user01 (the phone)."""
import os, sys, io, time, json, threading, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PROD_IP = "YOUR_PROD_HOST"
PROD_PW = os.environ["QELI_PROD_PASS"]
LAB_PW = os.environ["QELI_LAB_PASS"]
SRC_BIN = "/opt/qeli-src/target/release/qeli"   # built on .10
BIN = "/root/qeli-perf"
LAB_EGRESS = "54.37.87.56"

# user02 qeli:// links per mode (host/port/mode/key/sni/rsid/obfs/front/quic).
LINKS = {
 "reality-tls": "qeli://user02:CHANGEME@YOUR_PROD_HOST:443?proto=tcp&mode=reality-tls&key=7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057&sni=www.microsoft.com&rsid=2699764da5df00bc",
 "reality":     "qeli://user02:CHANGEME@YOUR_PROD_HOST:8443?proto=tcp&mode=fake-tls&key=5adb67cf8b59353e933019b3cf3e94d519f327314376b0518cfc3185ed473c4a&sni=www.microsoft.com",
 "fake-tls":    "qeli://user02:CHANGEME@YOUR_PROD_HOST:8444?proto=tcp&mode=fake-tls&key=1a28ba06187c405fa8a120d084fd9c73759f6b1898bd7436b70e64367e13970f&sni=www.microsoft.com",
 "obfs-ws":     "qeli://user02:CHANGEME@YOUR_PROD_HOST:8445?proto=tcp&mode=obfs&key=9ff84595e60f1c9b93effd22c9308f6e804c1c5fd2c0b6a61fd400758cae3430&sni=www.microsoft.com&obfs=qeli-ws-2644ecd4e59c97911c0a&front=websocket",
 "obfs-none":   "qeli://user02:CHANGEME@YOUR_PROD_HOST:8446?proto=tcp&mode=obfs&key=c13e7a7019d7f764624fabec882cf02db31d3445169d87b5497e21e6a8cdd638&obfs=qeli-none-aa3a8c9fc354e28e2e79&front=none",
 "plain":       "qeli://user02:CHANGEME@YOUR_PROD_HOST:8447?proto=tcp&mode=plain&key=776c2ef930c55c8bd6525eaa203146f09a7bedfad8bbbdff7145096e165d952e",
 "udp-fake-tls":"qeli://user02:CHANGEME@YOUR_PROD_HOST:8448?proto=udp&mode=fake-tls&key=4751051ab2d18e343c4e117e2ebd24a252a1b7316bdea0cafa32d6bf3b374329&sni=www.microsoft.com",
 "udp-quic":    "qeli://user02:CHANGEME@YOUR_PROD_HOST:8449?proto=udp&mode=fake-tls&key=2fb814a24863df913c31e864308acc38a0376118280861ab13200d2b7c9cd51c&sni=www.microsoft.com&quic=1",
 "udp-obfs":    "qeli://user02:CHANGEME@YOUR_PROD_HOST:8450?proto=udp&mode=obfs&key=402b6855f8d40853c6f825224289c8ec9a631d5bf78a838fc6149db8e527d92a&obfs=qeli-udpobfs-a5015d038a1120ddb2db",
}
ORDER = ["reality-tls", "reality", "fake-tls", "obfs-ws", "obfs-none", "plain",
         "udp-fake-tls", "udp-quic", "udp-obfs"]
GW = {"reality-tls": "10.9.0.1", "reality": "10.9.1.1", "fake-tls": "10.9.2.1",
      "obfs-ws": "10.9.3.1", "obfs-none": "10.9.4.1", "plain": "10.9.5.1",
      "udp-fake-tls": "10.9.6.1", "udp-quic": "10.9.7.1", "udp-obfs": "10.9.8.1"}


def link_to_ini(link, user="user02", pw="CHANGEME"):
    q = link.split("?", 1)
    auth, hostport = q[0].replace("qeli://", "").split("@", 1)
    u, p = auth.split(":", 1)
    params = dict(kv.split("=", 1) for kv in q[1].split("&") if "=" in kv)
    lines = ["[qeli]", f"server = {hostport}", f"proto = {params.get('proto','tcp')}",
             f"user = {user}", f"pass = {pw}", f"mode = {params['mode']}"]
    if params.get("key"): lines.append(f"key = {params['key']}")
    if params.get("sni"): lines.append(f"sni = {params['sni']}")
    if params.get("rsid"): lines.append(f"reality_sid = {params['rsid']}")
    if params.get("obfs"): lines.append(f"obfs_key = {params['obfs']}")
    if params.get("front"): lines.append(f"front = {params['front']}")
    if params.get("quic") == "1": lines.append("quic = true")
    lines += ["[logging]", "level = info", "file = /root/perf-cli.log"]
    return "\n".join(lines) + "\n"


def conn(ip, pw):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=pw, timeout=25, look_for_keys=False, allow_agent=False)
    return c


pc = conn(PROD_IP, PROD_PW)
c10 = conn("10.66.116.10", LAB_PW)
c11 = conn("10.66.116.11", LAB_PW)
def P(cmd, t=120):
    i, o, e = pc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def run(c, cmd, t=180):
    i, o, e = c.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()


def mbps(j):
    try: return round(json.loads(j)["end"]["sum_received"]["bits_per_second"] / 1e6, 1)
    except Exception: return None


def qeli_cpu_jiffies():
    tot = 0
    for pid in P("pgrep -x qeli").split():
        s = P(f"cat /proc/{pid}/stat 2>/dev/null").split()
        if len(s) > 14: tot += int(s[13]) + int(s[14])
    return tot


def total_jiffies():
    return sum(int(x) for x in P("head -1 /proc/stat").split()[1:])


def sample_cpu(out, secs):
    pj = qeli_cpu_jiffies(); ptj = total_jiffies()
    for _ in range(secs):
        time.sleep(1)
        j = qeli_cpu_jiffies(); tj = total_jiffies()
        if tj > ptj: out.append(round(100.0 * (j - pj) / (tj - ptj), 1))
        pj, ptj = j, tj


def setup_netns(c, ns, egress):
    run(c, f"ip netns del {ns} 2>/dev/null; ip link del v{ns}0 2>/dev/null; true")
    run(c, f"ip netns add {ns}; ip link add v{ns}0 type veth peer name v{ns}1; ip link set v{ns}1 netns {ns}")
    sub = "10.201.0" if ns == "qns10" else "10.200.0"
    run(c, f"ip addr add {sub}.1/24 dev v{ns}0; ip link set v{ns}0 up")
    run(c, f"ip netns exec {ns} ip addr add {sub}.2/24 dev v{ns}1; ip netns exec {ns} ip link set v{ns}1 up; ip netns exec {ns} ip link set lo up; ip netns exec {ns} ip route add default via {sub}.1")
    run(c, "sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    run(c, f"iptables -t nat -C POSTROUTING -s {sub}.0/24 -o {egress} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {sub}.0/24 -o {egress} -j MASQUERADE")
    return sub


def start_client(c, ns, ini, port, is_udp):
    sf = c.open_sftp(); sf.putfo(io.BytesIO(ini.encode()), "/root/perf-cli.conf"); sf.close()
    run(c, "kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; rm -f /root/perf-cli.log /root/perf-cli.out; true")
    ch = c.get_transport().open_session()
    ch.exec_command(f"ip netns exec {ns} nohup {BIN} client -c /root/perf-cli.conf </dev/null >/root/perf-cli.out 2>&1 & echo $! >/root/perf-cli.pid")
    time.sleep(1); ch.close()
    ip = None
    for _ in range(35):
        time.sleep(1)
        log = run(c, "cat /root/perf-cli.log /root/perf-cli.out 2>/dev/null")
        m = re.search(r"assigned IP: (10\.9\.\d+\.\d+)", log)
        if m and "TUN vpn0 is up" in log:
            ip = m.group(1); break
    return ip


def fix_tun(c, ns, ip, gw):
    run(c, f"ip netns exec {ns} sh -c 'ip addr del {ip}/24 dev vpn0 2>/dev/null; ip addr add {ip} peer {gw} dev vpn0; ip link set vpn0 mtu 1280; true'")


def wait_ready(c, ns, gw, tries=20):
    """Poll the tunnel data-plane until the prod tun gateway answers a ping. The
    client blocks ~25s on its DNS setup (resolvectl) before the data-plane starts,
    so we must wait for actual readiness, not just 'TUN up'."""
    for _ in range(tries):
        out = run(c, f"ip netns exec {ns} ping -c1 -W2 {gw} 2>/dev/null")
        if "1 received" in out or "1 packets received" in out:
            return True
        time.sleep(2)
    return False


results = []
egress = None
try:
    # binary -> .10 (already there) + .11
    print("[binary] sha:", run(c10, f"sha256sum {SRC_BIN}|cut -c1-16"))
    run(c10, f"cp {SRC_BIN} {BIN}; chmod +x {BIN}")
    sf = c10.open_sftp(); sf.get(SRC_BIN, "/tmp/qeli-perf-bin"); sf.close()
    sf = c11.open_sftp(); sf.put("/tmp/qeli-perf-bin", BIN); sf.close()
    run(c11, f"chmod +x {BIN}")
    egress = run(c11, f"ip route get {PROD_IP} | grep -oE 'dev [a-z0-9]+' | awk '{{print $2}}' | head -1")
    egress10 = run(c10, f"ip route get {PROD_IP} | grep -oE 'dev [a-z0-9]+' | awk '{{print $2}}' | head -1")
    print("[egress] .11 dev:", egress, "| .10 dev:", egress10)

    # prod: iperf3 server + accept tun traffic
    P("pkill -9 iperf3 2>/dev/null; sleep 1; iperf3 -s -D --logfile /root/iperf3.log; iptables -C INPUT -i vpn+ -j ACCEPT 2>/dev/null || iptables -I INPUT -i vpn+ -j ACCEPT; sleep 1; true")
    print("[prod] cpu cores:", P("nproc"), "| rss baseline:", P("ps -o rss= -C qeli | awk '{s+=$1} END{print s/1024\" MB\"}'"))

    # ── per-mode sweep on .11 ────────────────────────────────────────────────
    for mode in ORDER:
        is_udp = mode.startswith("udp")
        ini = link_to_ini(LINKS[mode])
        port = int(LINKS[mode].split("@YOUR_PROD_HOST:")[1].split("?")[0])
        setup_netns(c11, "qns", egress)
        ip = start_client(c11, "qns", ini, port, is_udp)
        if not ip:
            tail = run(c11, "tail -3 /root/perf-cli.log /root/perf-cli.out")
            print(f"\n### {mode}: CONNECT FAILED\n  {tail[:300]}")
            results.append((mode, None, None, None, 0))
            run(c11, "kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; ip netns del qns 2>/dev/null; true")
            continue
        time.sleep(2)
        fix_tun(c11, "qns", ip, GW[mode])
        ready = wait_ready(c11, "qns", GW[mode])   # waits past the DNS-setup delay
        ping = run(c11, f"ip netns exec qns ping -c3 -i0.3 -W2 {GW[mode]} | tail -1")
        # By now the data-plane is up; TCP multipath secondaries (max_streams=4) have
        # also opened, so the reading reflects the real prod config.
        streams = int(P(f"ss -tnH '( sport = :{port} )' | grep {LAB_EGRESS} | grep -c ESTAB") or 0) if not is_udp else 1
        if not ready:
            print(f"  [{mode:13}] data-plane NOT ready (DNS delay?) — skipping iperf3")
        cpu = []
        th = threading.Thread(target=sample_cpu, args=(cpu, 22)); th.start()
        dn = run(c11, f"ip netns exec qns iperf3 -c {GW[mode]} -t 9 -O 1 -R -J --connect-timeout 8000 2>/dev/null", t=45)
        up = run(c11, f"ip netns exec qns iperf3 -c {GW[mode]} -t 9 -O 1 -J --connect-timeout 8000 2>/dev/null", t=45)
        th.join()
        d, u = mbps(dn), mbps(up)
        cmax = max(cpu) if cpu else None
        results.append((mode, d, u, cmax, streams))
        print(f"  [{mode:13}] streams={streams} DOWN={d} UP={u} Mbps | prodCPU max={cmax}% | {ping.split('=')[-1].strip() if '=' in ping else ping[:40]}")
        run(c11, "kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; ip netns del qns 2>/dev/null; ip link del vqns0 2>/dev/null; true")
        time.sleep(2)

    # ── combined 2-server load on reality-tls (.11 user02 + .10 user03) ──────
    print("\n[combined] reality-tls from .11(user02) + .10(user03) simultaneously")
    ini11 = link_to_ini(LINKS["reality-tls"], "user02", "CHANGEME")
    ini10 = link_to_ini(LINKS["reality-tls"], "user03", "Xgso4Huk3c4O5GrU")
    setup_netns(c11, "qns", egress); setup_netns(c10, "qns10", egress10)
    ip11 = start_client(c11, "qns", ini11, 443, False)
    ip10 = start_client(c10, "qns10", ini10, 443, False)
    print("  assigned IPs: .11 ->", ip11, "| .10 ->", ip10)
    if ip11: fix_tun(c11, "qns", ip11, "10.9.0.1")
    if ip10: fix_tun(c10, "qns10", ip10, "10.9.0.1")
    r11 = wait_ready(c11, "qns", "10.9.0.1"); r10 = wait_ready(c10, "qns10", "10.9.0.1")
    print("  data-plane ready: .11", r11, "| .10", r10)
    nconn = int(P(f"ss -tnH '( sport = :443 )' | grep {LAB_EGRESS} | grep -c ESTAB") or 0)
    print(f"  ESTABLISHED on :443 from lab egress: {nconn}")
    cpu = []
    th = threading.Thread(target=sample_cpu, args=(cpu, 14)); th.start()
    out = {}
    def dl(c, ns, key):
        out[key] = run(c, f"ip netns exec {ns} iperf3 -c 10.9.0.1 -t 10 -O 1 -R -J --connect-timeout 8000 2>/dev/null", t=45)
    t11 = threading.Thread(target=dl, args=(c11, "qns", "11")); t10 = threading.Thread(target=dl, args=(c10, "qns10", "10"))
    t11.start(); t10.start(); t11.join(); t10.join(); th.join()
    d11, d10 = mbps(out.get("11")), mbps(out.get("10"))
    print(f"  DOWN .11={d11} + .10={d10} = {round((d11 or 0)+(d10 or 0),1)} Mbps aggregate | prod CPU max={max(cpu) if cpu else '?'}% avg={round(sum(cpu)/len(cpu),1) if cpu else '?'}%")
    print("  prod RSS:", P("ps -o rss= -C qeli | awk '{s+=$1} END{print s/1024\" MB\"}'"), "| BBR:", P("ss -tiH 'sport = :443'|grep -oE 'bbr|cubic'|head -1"))

    # ── report ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("PER-MODE REPORT (lab .11 netns -> PROD, tunnel goodput, real internet)")
    print("=" * 72)
    print(f"{'mode':14} {'streams':7} {'DOWN Mbps':10} {'UP Mbps':9} {'prodCPU%':8}")
    for m, d, u, cm, st in results:
        print(f"{m:14} {st!s:7} {d!s:10} {u!s:9} {cm!s:8}")
finally:
    print("\n=== restore ===")
    for c, ns in ((c11, "qns"), (c10, "qns10")):
        run(c, f"kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; ip netns del {ns} 2>/dev/null; ip link del v{ns}0 2>/dev/null; true")
    if egress:
        run(c11, f"iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -o {egress} -j MASQUERADE 2>/dev/null; true")
        run(c10, f"iptables -t nat -D POSTROUTING -s 10.201.0.0/24 -o $(ip route get {PROD_IP}|grep -oE 'dev [a-z0-9]+'|awk '{{print $2}}'|head -1) -j MASQUERADE 2>/dev/null; true")
    P("pkill -9 iperf3 2>/dev/null; iptables -D INPUT -i vpn+ -j ACCEPT 2>/dev/null; true")
    print("[prod qeli]", P("systemctl is-active qeli.service"), "| clients now:", P("/usr/local/bin/qeli list-clients 2>&1 | grep -c user0"))
    pc.close(); c10.close(); c11.close()

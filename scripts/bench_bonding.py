#!/usr/bin/env python3
"""Multipath bonding THROUGHPUT test (the number the article was missing).

Brings up one multipath fake-tls profile on the lab server (:8505) twice —
max_streams=1 (bonding off) and max_streams=4 (fixed bonding) — and measures
iperf3 download through the tunnel under `tc netem` that emulates a real
(lossy, latent) link. netem is applied ONLY to traffic toward the client
(.11) via a filtered prio band, so the control SSH is untouched.

The point: on a clean LAN, TCP-over-TCP doesn't degrade and bonding ~does
nothing; on a link with loss+RTT a single inner stream stalls (head-of-line),
while N parallel outer TCP connections aggregate. This quantifies that.

Run from the local machine:  source scripts/lab_env.sh && python scripts/bench_bonding.py
"""
import os, sys, io, time, json, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ["QELI_LAB_PASS"]
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
CLIENT_IP = CLI[0]
BIN = "/opt/qeli-src/target/release/qeli"      # server binary (lives on .10 only)
CLI_BIN = "/root/qeli-bond"                     # copied to .11 (no /opt/qeli-src there)
IDENTITY = "/etc/qeli/identity/e2e.key"        # reused from test_multipath_bonding.py
PUBKEY = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
USERS = "/root/reality-test/users-e2e.conf"    # admin / testpass123
PORT = 8505
SIP = "10.62.0.1"                              # server tun IP
SRV_LOG = "/root/bond-srv.log"
CLI_LOG = "/root/bond-cli.log"

# netem link profiles applied to download direction (server -> client):
#   (label, one-way delay ms, loss %)   delay 0 & loss 0 == clean (no netem)
NETEM = [
    ("clean",             0,   0.0),
    ("rtt40ms_loss0.05",  20,  0.05),
    ("rtt80ms_loss0.1",   40,  0.1),
    ("rtt80ms_loss0.3",   40,  0.3),
]


def server_conf(max_streams):
    return f"""[web]
enabled = false
[auth]
users_file = {USERS}
[logging]
level = info
file = {SRV_LOG}
[profile:mp]
enabled = true
identity_key = {IDENTITY}
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = mp0
tun.address = {SIP}
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.62.0.0/24
pool.exclude = {SIP}
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
obf.multipath.enabled = true
obf.multipath.max_streams = {max_streams}
obf.multipath.adaptive = false
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
perf.tcp.nodelay = true
perf.tcp.keepalive_secs = 60
perf.tun.read_buffer_size = 65535
perf.connection.max_clients = 16
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0
"""


CLIENT_CONF = f"""[qeli]
server = {SRV[0]}:{PORT}
proto = tcp
user = admin
pass = testpass123
key = {PUBKEY}
mode = fake-tls
sni = www.microsoft.com
[logging]
level = info
file = {CLI_LOG}
"""


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV); cc = conn(CLI)
def S(cmd, t=120):
    _i, o, e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=120):
    _i, o, e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def Sbg(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()
def Cbg(cmd):
    ch = cc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()
def putS(path, text):
    sf = sc.open_sftp(); sf.putfo(io.BytesIO(text.encode()), path); sf.close()


DEV = S(f"ip -o route get {CLIENT_IP} | grep -oP 'dev \\K\\S+'").strip()


def set_netem(delay_ms, loss_pct):
    S(f"tc qdisc del dev {DEV} root 2>/dev/null; true")
    if delay_ms == 0 and loss_pct == 0:
        return
    S(f"tc qdisc add dev {DEV} root handle 1: prio bands 4 "
      f"priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1")
    S(f"tc qdisc add dev {DEV} parent 1:4 handle 40: netem delay {delay_ms}ms loss {loss_pct}%")
    S(f"tc filter add dev {DEV} parent 1:0 protocol ip prio 1 u32 "
      f"match ip dst {CLIENT_IP}/32 flowid 1:4")


def clear_netem():
    S(f"tc qdisc del dev {DEV} root 2>/dev/null; true")


def iperf_down():
    # -P 8: eight parallel inner flows. Multipath pins each flow (flow_hash) to ONE
    # bonded stream, so bonding only helps with several concurrent flows (like a
    # browser's 6+ TLS) — a single flow can't use more than one stream by design.
    o = C(f"timeout 50 iperf3 -c {SIP} -t 15 -i 0 -P 8 -R --json", t=70)
    try:
        e = json.loads(o)["end"]
        return {"mbps": round(e["sum_received"]["bits_per_second"] / 1e6, 1),
                "retr": e["sum_sent"].get("retransmits")}
    except Exception as ex:
        return {"error": str(ex), "raw": o[:160]}


def start_server(max_streams):
    S(f"ps -eo pid,args | grep 'profile:mp\\|bond-srv\\|{PORT}' | grep -v grep | awk '{{print $1}}' | xargs -r kill -9 2>/dev/null; "
      f"pkill -9 -f 'server -c /root/bond-srv.conf' 2>/dev/null; ip link del mp0 2>/dev/null; rm -f {SRV_LOG}; sleep 1; true")
    putS("/root/bond-srv.conf", server_conf(max_streams))
    Sbg(f"RUST_LOG=info setsid nohup {BIN} server -c /root/bond-srv.conf >/dev/null 2>&1 </dev/null & echo $! >/root/bond-srv.pid")
    for _ in range(20):
        time.sleep(1)
        if f"listening on 0.0.0.0:{PORT}" in S(f"cat {SRV_LOG} 2>/dev/null"):
            return True
    print("  SERVER FAILED:\n", S(f"tail -15 {SRV_LOG}")); return False


def start_client(expect_streams):
    C(f"pkill -9 -f 'bond-cli.conf' 2>/dev/null; ip link del mp0 2>/dev/null; rm -f {CLI_LOG} /var/lib/qeli/known_hosts; sleep 1; true")
    Cbg(f"RUST_LOG=info nohup {CLI_BIN} client -c /root/bond-cli.conf </dev/null >/root/bond-cli.out 2>&1 & echo $! >/root/bond-cli.pid")
    for _ in range(15):
        time.sleep(1.5)
        if "Auth OK" in C(f"grep -E 'Auth OK' {CLI_LOG} 2>/dev/null || true"):
            break
    else:
        print("  CLIENT FAILED:\n", C(f"tail -12 {CLI_LOG} /root/bond-cli.out")); return 0
    time.sleep(4)  # let fixed bonding open the rest
    estab = S(f"ss -tnH '( sport = :{PORT} )' | grep -c ESTAB")
    return int(estab or 0)


def teardown():
    C("kill -9 $(cat /root/bond-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'bond-cli.conf' 2>/dev/null; ip link del mp0 2>/dev/null; true")
    S("kill -9 $(cat /root/bond-srv.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'bond-srv.conf' 2>/dev/null; ip link del mp0 2>/dev/null; true")


results = {}
try:
    print(f"[lab] server={SRV[0]} client={CLIENT_IP} dev(to client)={DEV} bin={BIN}")
    print(f"[lab] iperf3: srv={S('iperf3 -v 2>&1 | head -1')} | tc={S('tc -V 2>&1')}")
    # .11 has no /opt/qeli-src: copy the server binary over and write the client conf
    import tempfile
    lp = os.path.join(tempfile.gettempdir(), "qeli-bond")
    sf = sc.open_sftp(); sf.get(BIN, lp); sf.close()
    cf = cc.open_sftp(); cf.put(lp, CLI_BIN); cf.putfo(io.BytesIO(CLIENT_CONF.encode()), "/root/bond-cli.conf"); cf.close()
    C(f"chmod +x {CLI_BIN}; true")
    print(f"[lab] client bin -> {CLI_BIN}: {C(CLI_BIN + ' --version 2>&1 | head -1')}")
    # one persistent iperf3 server on the tun IP (re-bound each tunnel below)
    for N in (1, 4):
        if not start_server(N):
            continue
        S(f"pkill -9 iperf3 2>/dev/null; sleep 1; nohup iperf3 -s -B {SIP} >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)
        nstreams = start_client(N)
        print(f"\n=== max_streams={N} -> {nstreams} ESTABLISHED outer TCP on :{PORT} ===")
        if nstreams == 0:
            teardown(); continue
        for label, d, l in NETEM:
            set_netem(d, l)
            time.sleep(4)  # let TCP congestion settle under the new link
            r = iperf_down()
            clear_netem()
            results[(N, label)] = r
            print(f"  [{label:>18}]  download = {r}")
        teardown()

    print("\n\n================  BONDING THROUGHPUT (download, Mbps)  ================")
    print(f"{'link profile':>18} | {'1 stream':>10} | {'4 streams':>10} | {'gain':>6}")
    print("-" * 56)
    for label, d, l in NETEM:
        a = results.get((1, label), {}); b = results.get((4, label), {})
        m1 = a.get("mbps"); m4 = b.get("mbps")
        gain = f"{m4/m1:.2f}x" if (m1 and m4) else "—"
        print(f"{label:>18} | {str(m1):>10} | {str(m4):>10} | {gain:>6}")
    print("\nraw:", json.dumps({f"{k[0]}/{k[1]}": v for k, v in results.items()}, ensure_ascii=False))
finally:
    print("\n=== cleanup ===")
    clear_netem()
    teardown()
    S(f"pkill -9 iperf3 2>/dev/null; ip link del mp0 2>/dev/null; systemctl restart qeli-server.service >/dev/null 2>&1; true")
    print("[restored] netem cleared on", DEV, "| systemd qeli:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

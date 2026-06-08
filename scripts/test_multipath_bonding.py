#!/usr/bin/env python3
"""P1 multipath bonding mechanism test: lab reality-tls server with
multipath.max_streams=4; the freshly-built client connects (mode=reality-tls,
fixed bonding) and must open 4 parallel connections that the server aggregates
into ONE session (one tun IP). Verifies the JOIN protocol end to end — server
logs 1 AUTH + 3 JOINs for one IP; client logs '4 bonded stream(s) active'."""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

SRV = ("10.66.116.10", "root", os.environ["QELI_LAB_PASS"])
CLI = ("10.66.116.11", "root", os.environ["QELI_LAB_PASS"])
QELI_SRC = "/opt/qeli-src/target/debug/qeli"
CONF = "/root/reality-test/server-mp.conf"
LOG = "/root/reality-test/srv-mp.log"
PIDF = "/root/reality-test/srv-mp.pid"
PORT = 8505
PUBKEY = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"

SERVER_CONF = f"""[web]
enabled = false
[auth]
users_file = /root/reality-test/users-e2e.conf
[profile:mp]
enabled = true
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = mp0
tun.address = 10.62.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1280
pool.cidr = 10.62.0.0/24
pool.exclude = 10.62.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.reality_proxy.enabled = true
obf.tls.reality_proxy.target = www.microsoft.com
obf.tls.reality_proxy.target_port = 443
obf.tls.reality_proxy.short_ids = 0123456789abcdef
obf.tls.reality_proxy.real_tls = true
obf.tls.reality_proxy.handrolled = true
obf.multipath.enabled = true
obf.multipath.max_streams = 4
obf.multipath.adaptive = false
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
[logging]
level = info
file = {LOG}
"""

CLIENT_CONF = f"""[qeli]
server = 10.66.116.10:{PORT}
proto = tcp
user = admin
pass = testpass123
key = {PUBKEY}
mode = reality-tls
reality_sid = 0123456789abcdef
sni = www.microsoft.com
[logging]
level = info
file = /root/mp-cli.log
"""


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV); cc = conn(CLI)
def S(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=60):
    i, o, e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def Sbg(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()
def Cbg(cmd):
    ch = cc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()

try:
    # 1. server with multipath
    sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), CONF); sf.close()
    old = S(f"cat {PIDF} 2>/dev/null")
    if old: S(f"kill -9 {old} 2>/dev/null; true")
    S(f"ps -eo pid,args | grep 'server-mp.conf' | grep -v grep | awk '{{print $1}}' | xargs -r kill -9 2>/dev/null; rm -f {LOG}; sleep 1; true")
    Sbg(f"RUST_LOG=info setsid nohup {QELI_SRC} server -c {CONF} >/dev/null 2>&1 < /dev/null & echo $! >{PIDF}")
    ok = False
    for _ in range(20):
        time.sleep(1)
        if f"listening on 0.0.0.0:{PORT}" in S(f"cat {LOG} 2>/dev/null"): ok = True; break
    print("[server] multipath profile listening:", ok)
    print("[server] mp config:", S(f"grep -c 'multipath' {CONF}"), "lines")
    if not ok:
        print(S(f"tail -15 {LOG}")); sys.exit(1)

    # 2. copy fresh binary to client + write client conf
    print("[client] copying fresh binary to .11 ...")
    sf = sc.open_sftp(); sf.get(QELI_SRC, "/tmp/qeli-mp"); sf.close()
    sf = cc.open_sftp(); sf.put("/tmp/qeli-mp", "/root/qeli-mp"); sf.putfo(io.BytesIO(CLIENT_CONF.encode()), "/root/mp-cli.conf"); sf.close()
    C("chmod +x /root/qeli-mp; pkill -9 -f 'qeli-mp client' 2>/dev/null; rm -f /root/mp-cli.log /root/mp-cli.out; true")

    # 3. run client (fixed multipath → should open 4 streams)
    sbase = int(S(f"wc -l < {LOG}") or 0)
    Cbg("RUST_LOG=info nohup /root/qeli-mp client -c /root/mp-cli.conf </dev/null >/root/mp-cli.out 2>&1 & echo $! >/root/mp-cli.pid")
    prev = 0
    for t in (5, 12, 20, 30):
        time.sleep(t - prev); prev = t
        conns = S(f"ss -tnH '( sport = :{PORT} )' | grep -c ESTAB")
        print(f"  [t={t:>2}s] ESTABLISHED on :{PORT} = {conns}")

    # 4. verify
    print("\n=== CLIENT LOG (full tail) ===")
    print(C("tail -25 /root/mp-cli.log 2>/dev/null; echo '--- stderr/out ---'; tail -15 /root/mp-cli.out 2>/dev/null"))
    print("\n=== SERVER LOG (this session) ===")
    new = S(f"tail -n +{sbase+1} {LOG}")
    for kw in ("connected on profile", "JOINed session", "AUTH OK"):
        hits = [l for l in new.splitlines() if kw in l]
        print(f"  [{kw}] x{len(hits)}")
        for h in hits[-4:]:
            print("     ", h.split(" qeli")[-1].strip()[:110])
    conns = S(f"ss -tnH '( sport = :{PORT} )' | grep -c ESTAB")
    print(f"\n[server] ESTABLISHED connections on :{PORT}: {conns}  (expect ~4 for one bonded session)")
finally:
    print("\n=== cleanup ===")
    C("kill -9 $(cat /root/mp-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'qeli-mp client' 2>/dev/null; true")
    for t in ["mp0"]:
        C(f"ip link del {t} 2>/dev/null; true")
    pid = S(f"cat {PIDF} 2>/dev/null")
    if pid: S(f"kill -9 {pid} 2>/dev/null; true")
    S("ip link del mp0 2>/dev/null; systemctl restart qeli-server.service >/dev/null 2>&1; true")
    print("[restored] lab systemd:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

#!/usr/bin/env python3
"""Prove stream bonding works on the non-reality TCP modes (fake-tls, obfs, plain).
One lab server with 3 multipath profiles; the freshly-built CLI client connects in
each mode (user admin, NOT user01) and must open 4 connections that the server
aggregates into ONE session — verified by 1 AUTH + 3 JOINs per mode in the log."""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

SRV = ("10.66.116.10", "root", os.environ["QELI_LAB_PASS"])
CLI = ("10.66.116.11", "root", os.environ["QELI_LAB_PASS"])
QELI = "/opt/qeli-src/target/debug/qeli"
CONF = "/root/reality-test/server-allmodes.conf"
LOG = "/root/reality-test/srv-allmodes.log"
PIDF = "/root/reality-test/srv-allmodes.pid"
PUB = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
PSK = "qeli-test-psk-allmodes-001122"

# mode -> (profile name, port, tun, subnet, client extra ini lines)
MODES = {
    "fake-tls": (8506, "ftls0", "10.63.0", []),
    "obfs":     (8507, "obfs0", "10.64.0", []),
    "plain":    (8508, "pln0",  "10.65.0", []),
}

def profile(mode):
    port, tun, sub, _ = MODES[mode]
    obf = {
        "fake-tls": "obf.mode = fake-tls\nobf.tls.server_name = www.microsoft.com",
        "obfs":     f"obf.mode = obfs\nobf.obfs_key = {PSK}\nobf.obfs_fronting = none",
        "plain":    "obf.mode = plain",
    }[mode]
    return f"""[profile:{mode}]
enabled = true
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {port}
bind.transport = tcp
tun.name = {tun}
tun.address = {sub}.1
tun.netmask = 255.255.255.0
tun.mtu = 1280
pool.cidr = {sub}.0/24
pool.exclude = {sub}.1
dns.enabled = false
{obf}
obf.multipath.enabled = true
obf.multipath.max_streams = 4
obf.multipath.adaptive = false
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
"""

SERVER_CONF = "[web]\nenabled = false\n[auth]\nusers_file = /root/reality-test/users-e2e.conf\n" \
    + "".join(profile(m) for m in MODES) + f"[logging]\nlevel = info\nfile = {LOG}\n"

def client_conf(mode):
    port, tun, sub, _ = MODES[mode]
    base = f"[qeli]\nserver = 10.66.116.10:{port}\nproto = tcp\nuser = admin\npass = testpass123\nmode = {mode}\n"
    if mode == "obfs":
        base += f"obfs_key = {PSK}\nfront = none\n"
    if mode in ("fake-tls", "plain"):
        base += f"key = {PUB}\n"
    if mode == "fake-tls":
        base += "sni = www.microsoft.com\n"
    base += f"[logging]\nlevel = info\nfile = /root/mp-{mode}.log\n"
    return base


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV); cc = conn(CLI)
def S(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=60):
    i, o, e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def Cbg(cmd):
    ch = cc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()

try:
    sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), CONF); sf.close()
    S("ps -eo pid,args | grep server-allmodes.conf | grep -v grep | awk '{print $1}' | xargs -r kill -9 2>/dev/null; "
      "for t in ftls0 obfs0 pln0; do ip link del $t 2>/dev/null; done; rm -f " + LOG + "; sleep 1; true")
    chp = sc.get_transport().open_session()
    chp.exec_command(f"RUST_LOG=info setsid nohup {QELI} server -c {CONF} >/dev/null 2>&1 </dev/null & echo $! >{PIDF}")
    time.sleep(1); chp.close()
    up = False
    for _ in range(20):
        time.sleep(1)
        lg = S(f"cat {LOG} 2>/dev/null")
        if all(f"listening on 0.0.0.0:{MODES[m][0]}" in lg for m in MODES): up = True; break
    print("[server] all 3 multipath profiles listening:", up)
    if not up:
        print(S(f"tail -20 {LOG}")); sys.exit(1)

    # fresh binary to client
    sf = sc.open_sftp(); sf.get(QELI, "/tmp/qeli-am"); sf.close()
    sf = cc.open_sftp(); sf.put("/tmp/qeli-am", "/root/qeli-am"); sf.close()
    C("chmod +x /root/qeli-am; true")

    for mode in MODES:
        port, tun, sub, _ = MODES[mode]
        sf = cc.open_sftp(); sf.putfo(io.BytesIO(client_conf(mode).encode()), f"/root/mp-{mode}.conf"); sf.close()
        C(f"pkill -9 -f 'qeli-am client' 2>/dev/null; rm -f /root/mp-{mode}.log /root/mp-{mode}.out; ip link del {tun}c 2>/dev/null; true")
        sbase = int(S(f"wc -l < {LOG}") or 0)
        Cbg(f"RUST_LOG=info nohup /root/qeli-am client -c /root/mp-{mode}.conf </dev/null >/root/mp-{mode}.out 2>&1 & echo $! >/root/mp-{mode}.pid")
        # wait for bonding (CLI tun setup + ~25s resolvectl delay before secondaries)
        conns = 0
        for _ in range(9):
            time.sleep(5)
            conns = int(S(f"ss -tnH '( sport = :{port} )' | grep -c ESTAB") or 0)
            if conns >= 4: break
        new = S(f"tail -n +{sbase+1} {LOG}")
        auth = len([l for l in new.splitlines() if "AUTH OK" in l])
        joins = len([l for l in new.splitlines() if "JOINed session" in l])
        cli = C(f"grep -iE 'bonded stream|active \\(fixed\\)|JOIN|error|panic' /root/mp-{mode}.log /root/mp-{mode}.out 2>/dev/null | tail -3")
        print(f"\n=== {mode} (:{port}) ===")
        print(f"  server: AUTH={auth} JOINs={joins} | ESTAB :{port}={conns}  (expect AUTH=1 JOINs=3 ESTAB=4)")
        print(f"  client: {cli[:300]}")
        C(f"kill -9 $(cat /root/mp-{mode}.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'qeli-am client' 2>/dev/null; ip link del {tun}c 2>/dev/null; true")
        time.sleep(2)
finally:
    print("\n=== cleanup ===")
    pid = S(f"cat {PIDF} 2>/dev/null")
    if pid: S(f"kill -9 {pid} 2>/dev/null; true")
    S("ps -eo pid,args | grep server-allmodes.conf | grep -v grep | awk '{print $1}' | xargs -r kill -9 2>/dev/null; "
      "for t in ftls0 obfs0 pln0; do ip link del $t 2>/dev/null; done; "
      "systemctl restart qeli-server.service >/dev/null 2>&1; true")
    print("[restored] lab systemd:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

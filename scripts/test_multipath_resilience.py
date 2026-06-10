#!/usr/bin/env python3
"""Loss-resilience: a multipath client opens 4 bonded streams; we kill ONE of the
4 server-side connections mid-tunnel and assert the tunnel SURVIVES on the
remaining 3 (no full reconnect). Old behaviour: any stream death tears the whole
tunnel down. New: a stream death is fatal only when it was the last one."""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

SRV = ("10.66.116.10", "root", os.environ["QELI_LAB_PASS"])
CLI = ("10.66.116.11", "root", os.environ["QELI_LAB_PASS"])
QELI = "/opt/qeli-src/target/debug/qeli"
PUB = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
PORT = 8506
LOG = "/root/reality-test/srv-res.log"

SERVER_CONF = f"""[web]
enabled = false
[auth]
users_file = /root/reality-test/users-e2e.conf
[profile:fake-tls]
enabled = true
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = res0
tun.address = 10.63.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1280
pool.cidr = 10.63.0.0/24
pool.exclude = 10.63.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
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
mode = fake-tls
key = {PUB}
sni = www.microsoft.com
[logging]
level = info
file = /root/res-cli.log
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
def Cbg(cmd):
    ch = cc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()

try:
    sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), "/root/reality-test/server-res.conf"); sf.close()
    S("ps -eo pid,args|grep server-res.conf|grep -v grep|awk '{print $1}'|xargs -r kill -9 2>/dev/null; ip link del res0 2>/dev/null; rm -f " + LOG + "; sleep 1; true")
    ch = sc.get_transport().open_session()
    ch.exec_command(f"RUST_LOG=info setsid nohup {QELI} server -c /root/reality-test/server-res.conf >/dev/null 2>&1 </dev/null & echo $! >/root/reality-test/srv-res.pid")
    time.sleep(1); ch.close()
    up = any(f"listening on 0.0.0.0:{PORT}" in S(f"cat {LOG} 2>/dev/null") for _ in [time.sleep(1) or 1 for _ in range(15)])
    print("[server] :%d listening = %s" % (PORT, up))

    sf = sc.open_sftp(); sf.get(QELI, "/tmp/qeli-res"); sf.close()
    sf = cc.open_sftp(); sf.put("/tmp/qeli-res", "/root/qeli-res"); sf.putfo(io.BytesIO(CLIENT_CONF.encode()), "/root/res-cli.conf"); sf.close()
    C("chmod +x /root/qeli-res; pkill -9 -f 'qeli-res client' 2>/dev/null; rm -f /root/res-cli.log; ip link del res0c 2>/dev/null; true")
    Cbg("RUST_LOG=info nohup /root/qeli-res client -c /root/res-cli.conf </dev/null >/root/res-cli.out 2>&1 & echo $! >/root/res-cli.pid")

    # wait for 4 bonded streams
    conns = 0
    for _ in range(9):
        time.sleep(5)
        conns = int(S(f"ss -tnH '( sport = :{PORT} )' | grep -c ESTAB") or 0)
        if conns >= 4: break
    print(f"[setup] ESTABLISHED on :{PORT} = {conns} (want 4)")
    auth_before = int(S(f"grep -c 'AUTH OK' {LOG}") or 0)

    # pick one client source port (peer = column $5 = 10.66.116.11:<srcport>) and
    # KILL just that one connection from the server side.
    ports = S(f"ss -tnH '( sport = :{PORT} )' | grep ESTAB | awk '{{print $5}}' | sed 's/.*://'").split()
    victim = ports[0] if ports else None
    print(f"[kill] client src ports = {ports}; killing ONE: {victim}")
    if victim:
        # ss -K closes the matching socket (needs INET_DIAG_DESTROY).
        out = S(f"ss -K dst 10.66.116.11 dport = {victim} 2>&1; echo rc=$?")
        print("   ss -K:", out.replace(chr(10), ' | ')[:160])

    time.sleep(8)
    after = int(S(f"ss -tnH '( sport = :{PORT} )' | grep -c ESTAB") or 0)
    auth_after = int(S(f"grep -c 'AUTH OK' {LOG}") or 0)
    cli_tail = C("grep -iE 'stream lost|remain|Auth OK|reconnect|bonded' /root/res-cli.log 2>/dev/null | tail -5")

    print("\n=== RESULT ===")
    print(f"  ESTABLISHED after kill: {after}  (resilient => 3; OLD behaviour => 0 then 4 after reconnect)")
    print(f"  server AUTH OK count: before={auth_before} after={auth_after}  (no reconnect => unchanged)")
    print("  client log:")
    for l in cli_tail.splitlines(): print("    ", l)
    verdict = "PASS (tunnel survived on remaining streams)" if (after == 3 and auth_after == auth_before) else "see numbers above"
    print(f"  VERDICT: {verdict}")
finally:
    print("\n=== cleanup ===")
    C("kill -9 $(cat /root/res-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'qeli-res client' 2>/dev/null; ip link del res0c 2>/dev/null; true")
    pid = S("cat /root/reality-test/srv-res.pid 2>/dev/null")
    if pid: S(f"kill -9 {pid} 2>/dev/null; true")
    S("ps -eo pid,args|grep server-res.conf|grep -v grep|awk '{print $1}'|xargs -r kill -9 2>/dev/null; ip link del res0 2>/dev/null; systemctl restart qeli-server.service >/dev/null 2>&1; true")
    print("[restored] lab systemd:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

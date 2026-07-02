#!/usr/bin/env python3
"""E2E for the blocked-IPs feature (CLI list-blocked / unblock / unblock --all).

Starts a test server (fake-tls :8507, brute_force.max_attempts=2), drives a
client on .11 with a WRONG password so its IP gets hard-locked, then exercises
the new control-socket commands via the CLI binary.
"""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ["QELI_LAB_PASS"]
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
CLIENT_IP = CLI[0]
SRV_BIN = "/opt/qeli-src/target/release/qeli"
CLI_BIN = "/root/qeli-blk"
PUBKEY = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
PORT = 8507
SOCK = "/var/run/qeli/control.sock"

SERVER_CONF = f"""[web]
enabled = false
[auth]
users_file = /root/reality-test/users-e2e.conf
brute_force.max_attempts = 2
brute_force.window_secs = 300
brute_force.lockout_secs = 120
[logging]
level = info
file = /root/blk-srv.log
[profile:blk]
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = blk0
tun.address = 10.88.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.88.0.0/24
pool.exclude = 10.88.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
"""

CLIENT_CONF = f"""[qeli]
server = 10.66.116.10:{PORT}
proto = tcp
user = admin
pass = WRONG-PASSWORD
key = {PUBKEY}
mode = fake-tls
sni = www.microsoft.com
[logging]
level = info
file = /root/blk-cli.log
"""

def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c

sc = conn(SRV); cc = conn(CLI)
def S(cmd, t=60):
    _i,o,e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=60):
    _i,o,e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def Sbg(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()
def Cbg(cmd):
    ch = cc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()

PASS = []
def check(name, ok, detail=""):
    PASS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail[:200]})" if detail and not ok else ""))

def lb():
    return S(f"{SRV_BIN} list-blocked --socket {SOCK}")

def lockout_count():
    return int(S("grep -c 'AUTH LOCKOUT (ip)' /root/blk-srv.log 2>/dev/null || echo 0") or 0)

def lock_client():
    """Run the wrong-password client until a NEW lockout is logged (max_attempts=2)."""
    before = lockout_count()
    C(f"pkill -9 -f 'blk-cli.conf' 2>/dev/null; rm -f /root/blk-cli.log; true")
    Cbg(f"RUST_LOG=info nohup {CLI_BIN} client -c /root/blk-cli.conf </dev/null >/root/blk-cli.out 2>&1 & echo $! >/root/blk-cli.pid")
    for _ in range(20):
        time.sleep(1.5)
        if lockout_count() > before:
            break
    C("kill -9 $(cat /root/blk-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'blk-cli.conf' 2>/dev/null; true")

try:
    print("[setup] stopping systemd server to free the control socket")
    S("systemctl stop qeli-server.service 2>/dev/null; sleep 1; true")
    sc.open_sftp().putfo(io.BytesIO(SERVER_CONF.encode()), "/root/blk-srv.conf")
    S("pkill -9 -f 'blk-srv.conf' 2>/dev/null; ip link del blk0 2>/dev/null; rm -f /root/blk-srv.log; sleep 1; true")
    Sbg(f"RUST_LOG=info setsid nohup {SRV_BIN} server -c /root/blk-srv.conf >/dev/null 2>&1 </dev/null & echo $! >/root/blk-srv.pid")
    up = any(f"listening on 0.0.0.0:{PORT}" in S("cat /root/blk-srv.log 2>/dev/null") for _ in [time.sleep(1) for _ in range(12)])
    print("[server] listening:", up)
    if not up:
        print(S("tail -15 /root/blk-srv.log")); sys.exit(1)

    # binary onto client
    import tempfile
    lp = os.path.join(tempfile.gettempdir(), "qeli-blk")
    sf = sc.open_sftp(); sf.get(SRV_BIN, lp); sf.close()
    cf = cc.open_sftp(); cf.put(lp, CLI_BIN); cf.putfo(io.BytesIO(CLIENT_CONF.encode()), "/root/blk-cli.conf"); cf.close()
    C(f"chmod +x {CLI_BIN}; true")

    # sanity: list-blocked empty at start
    print("\n=== initial state ===")
    out0 = lb()
    check("list-blocked empty initially", "No blocked IPs" in out0, out0)

    # error paths (deterministic, no lock needed)
    print("\n=== unblock validation ===")
    check("unblock invalid IP → error", "not a valid IP" in S(f"{SRV_BIN} unblock notanip --socket {SOCK}"))
    check("unblock non-blocked IP → 'was not blocked'", "was not blocked" in S(f"{SRV_BIN} unblock 9.9.9.9 --socket {SOCK}"))
    check("unblock --all on empty → cleared 0", "cleared 0" in S(f"{SRV_BIN} unblock --all --socket {SOCK}"))

    # trigger a real lockout
    print("\n=== trigger lockout (wrong password ×2) ===")
    lock_client()
    print("  server AUTH lines:", S("grep -E 'AUTH FAIL|AUTH LOCKOUT|AUTH attempt' /root/blk-srv.log | tail -4"))
    out1 = lb()
    print("  list-blocked:\n" + out1)
    check("list-blocked shows client IP after lockout", CLIENT_IP in out1, out1)

    # unblock the single IP
    print("\n=== unblock the locked IP ===")
    u = S(f"{SRV_BIN} unblock {CLIENT_IP} --socket {SOCK}")
    check("unblock <ip> → OK: unblocked", "unblocked" in u, u)
    check("list-blocked empty after unblock", "No blocked IPs" in lb())

    # re-lock, then unblock --all
    print("\n=== re-lock then unblock --all ===")
    lock_client()
    check("re-locked (client IP present)", CLIENT_IP in lb())
    ua = S(f"{SRV_BIN} unblock --all --socket {SOCK}")
    check("unblock --all → cleared ≥1", "cleared" in ua and "cleared 0" not in ua, ua)
    check("list-blocked empty after clear-all", "No blocked IPs" in lb())

    print("\n================ RESULT ================")
    print(f"  {sum(PASS)}/{len(PASS)} checks passed")
finally:
    print("\n=== cleanup ===")
    C("kill -9 $(cat /root/blk-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'blk-cli.conf' 2>/dev/null; true")
    S("kill -9 $(cat /root/blk-srv.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'blk-srv.conf' 2>/dev/null; ip link del blk0 2>/dev/null; true")
    S("systemctl restart qeli-server.service >/dev/null 2>&1; sleep 1; true")
    print("[restored] systemd qeli:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

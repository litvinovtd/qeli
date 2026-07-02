#!/usr/bin/env python3
"""Regression test for "kicked user stays in the panel / can't reconnect".

Root cause: the control-plane `kick` only sent a cooperative channel signal; a
stream task blocked on `write_all` to a half-dead client never received it, so
the session lingered in list-clients and its pool IP stayed held. The fix makes
kick authoritatively drop the session from the registry and free the IP up front.

  A) NORMAL client  — kick removes the session; the client auto-reconnects.
  B) STUCK client   — frozen + flooded so the server stream blocks on write; kick
                      must STILL remove it (this is the reported bug).
"""
import os, sys, io, time, tempfile
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ["QELI_LAB_PASS"]
SRV_BIN = "/opt/qeli-src/target/release/qeli"
CLI_BIN = "/root/qeli-kick"
CONF = "/etc/qeli/kick-e2e.conf"
UFILE = "/etc/qeli/kick-users.conf"
LOG = "/var/log/qeli/kick-srv.log"
PROF = 8562
U1PW = "u1-kick-pw"
SOCK = "/var/run/qeli/control.sock"
CIP = "10.80.0.2"

CONF_TEXT = f"""[web]
enabled = false
[auth]
users_file = {UFILE}
brute_force.max_attempts = 100
[logging]
level = info
file = {LOG}
[profile:k]
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PROF}
bind.transport = tcp
tun.name = k0
tun.address = 10.80.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.80.0.0/24
pool.exclude = 10.80.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 16
perf.connection.handshake_timeout_secs = 10
"""

def client_conf(pubkey):
    return f"""[qeli]
server = 10.66.116.10:{PROF}
proto = tcp
user = u1
pass = {U1PW}
key = {pubkey}
mode = fake-tls
sni = www.microsoft.com
dev = kcli0
[logging]
level = info
file = /root/kick-cli.log
"""

sc = paramiko.SSHClient(); sc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sc.connect("10.66.116.10", username="root", password=PW, timeout=25, look_for_keys=False, allow_agent=False)
cc = paramiko.SSHClient(); cc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cc.connect("10.66.116.11", username="root", password=PW, timeout=25, look_for_keys=False, allow_agent=False)
def S(cmd,t=60):
    _i,o,e=sc.exec_command(cmd,timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd,t=60):
    _i,o,e=cc.exec_command(cmd,timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def Sbg(cmd):
    ch=sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()
def Cbg(cmd):
    ch=cc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()

PASS=[]
def check(n,ok,d=""):
    PASS.append(bool(ok)); print(f"  [{'PASS' if ok else 'FAIL'}] {n}"+(f"  ({d[:200]})" if d and not ok else ""))

def src():
    """Source addr of the (only) u1 session in list-clients, or '' if none."""
    return S(f"{SRV_BIN} list-clients --socket {SOCK} 2>&1 | grep -oE '10\\.66\\.116\\.11:[0-9]+' | head -1")

def start_client():
    C("pkill -9 -f 'kick-cli.conf' 2>/dev/null; ip link del kcli0 2>/dev/null; rm -f /root/kick-cli.log; sleep 1; true")
    Cbg(f"RUST_LOG=info nohup {CLI_BIN} client -c /root/kick-cli.conf </dev/null >/root/kick-cli.out 2>&1 & echo $! >/root/kc.pid")
    for _ in range(12):
        time.sleep(1.2)
        s=src()
        if s: return s
    return ""

try:
    print("[setup]")
    S("systemctl stop qeli-server.service 2>/dev/null; mkdir -p /var/log/qeli; pkill -9 -f 'kick-e2e.conf'; pkill -9 -f _worker; sleep 1; ip link del k0 2>/dev/null; rm -f "+LOG+" "+UFILE+"; true")
    C("pkill -9 -f 'kick-cli.conf' 2>/dev/null; ip link del kcli0 2>/dev/null; true")
    sc.open_sftp().putfo(io.BytesIO(CONF_TEXT.encode()), CONF)
    S(f"{SRV_BIN} add-client u1 --password '{U1PW}' --config {CONF} 2>&1 | head -1")
    Sbg(f"RUST_LOG=info setsid nohup {SRV_BIN} server -c {CONF} >/dev/null 2>&1 </dev/null & echo $! >/root/ks.pid")
    up=any(f"listening on 0.0.0.0:{PROF}" in S(f"cat {LOG} 2>/dev/null") for _ in [time.sleep(1) for _ in range(15)])
    check("server up", up)
    if not up: print(S(f"tail -20 {LOG}")); sys.exit(1)
    PUB=S(f"grep -oE 'pin on client.: [0-9a-f]{{64}}' {LOG} | tail -1 | grep -oE '[0-9a-f]{{64}}'")
    lp=os.path.join(tempfile.gettempdir(),"qeli-kick"); sf=sc.open_sftp(); sf.get(SRV_BIN,lp); sf.close()
    cf=cc.open_sftp(); cf.put(lp,CLI_BIN); cf.putfo(io.BytesIO(client_conf(PUB).encode()),"/root/kick-cli.conf"); cf.close(); C(f"chmod +x {CLI_BIN}")

    print("\n=== A) NORMAL client: kick removes session, client reconnects ===")
    s0=start_client()
    check("client connected", bool(s0), s0)
    print("  before kick, session:", s0)
    print("  kick:", S(f"{SRV_BIN} kick u1 --socket {SOCK} 2>&1"))
    gone=False
    for _ in range(6):
        time.sleep(1)
        if src()!=s0: gone=True; break
    check("original session removed by kick", gone, f"still {s0}")
    time.sleep(3)
    check("client reconnected (new session present)", bool(src()) and src()!=s0, f"src now {src()}")

    print("\n=== B) STUCK client (frozen + flooded): kick must still remove it ===")
    C("pkill -9 -f 'kick-cli.conf'; ip link del kcli0 2>/dev/null; true"); time.sleep(1)
    sb=start_client()
    check("stuck-test client connected", bool(sb), sb)
    kc=C("cat /root/kc.pid").strip()
    C(f"kill -STOP {kc} && echo ok")               # freeze: stops reading its socket
    Sbg(f"ping -f -s 1400 -w 6 {CIP} >/dev/null 2>&1 &")  # fill the stuck stream's write buffer
    time.sleep(6)
    print("  frozen+flooded session before kick:", src(), "(uptime should be growing)")
    print("  kick:", S(f"{SRV_BIN} kick u1 --socket {SOCK} 2>&1"))
    removed=False
    for i in range(8):
        time.sleep(1)
        if not src(): removed=True; print(f"  +{i+1}s: session GONE"); break
    check("STUCK session removed by kick (the fix)", removed, f"LINGERS: {src()}")
    C(f"kill -CONT {kc} 2>/dev/null; kill -9 {kc} 2>/dev/null; true")

    print("\n================ RESULT ================")
    print(f"  {sum(PASS)}/{len(PASS)} checks passed")
    print("  server kick log:"); print("   "+"\n   ".join(S(f"grep -E 'CONTROL|disconnect|AUTH OK' {LOG} | tail -8").splitlines()))
    sys.exit(0 if all(PASS) else 1)
finally:
    print("\n=== cleanup ===")
    C("kill -9 $(cat /root/kc.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'kick-cli.conf' 2>/dev/null; ip link del kcli0 2>/dev/null; true")
    S("kill -9 $(cat /root/ks.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'kick-e2e.conf' 2>/dev/null; pkill -9 -f 'ping -f' 2>/dev/null; ip link del k0 2>/dev/null; rm -f "+CONF+" "+UFILE+" "+LOG+"; true")
    S("systemctl restart qeli-server.service >/dev/null 2>&1; sleep 1; true")
    print("[restored] systemd qeli:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

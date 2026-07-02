#!/usr/bin/env python3
"""Repro for "panel edits to a user's allowed-profiles don't take effect".

Two profiles (pa :8532, pb :8533) share one identity key. A user with an empty
profiles list may use both; restricting it to [pa] must DENY it on pb. We drive
the change through the PANEL API and verify the data-plane WORKER actually
enforces it (server log AUTH OK vs AUTH DENIED), for BOTH:
  * FILE-BASED users (no inline [user:*]) — expected to work;
  * INLINE users ([user:*] in the server config) — the suspected bug, where the
    worker reloads from inline config and ignores the panel-written users file.
"""
import os, sys, io, time, tempfile
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ["QELI_LAB_PASS"]
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
SRV_BIN = "/opt/qeli-src/target/release/qeli"
CLI_BIN = "/root/qeli-url"
PUBKEY = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
CONF = "/etc/qeli/reloadtest.conf"          # under /etc/qeli (panel write whitelist)
UFILE = "/etc/qeli/reloadtest-users.conf"
LOG = "/root/reload-srv.log"
PANEL = 8531
PA, PB = 8532, 8533
ADMIN = "reload-admin-pw"
U1PW = "u1-secret-pw"
BASE = f"http://127.0.0.1:{PANEL}"
ORG = f"-H 'Origin: {BASE}' -H 'Referer: {BASE}/'"
JAR = "/root/reload-jar.txt"

PROFILES = f"""
[profile:pa]
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PA}
bind.transport = tcp
tun.name = ura0
tun.address = 10.86.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.86.0.0/24
pool.exclude = 10.86.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
[profile:pb]
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PB}
bind.transport = tcp
tun.name = urb0
tun.address = 10.85.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.85.0.0/24
pool.exclude = 10.85.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
"""

def conf_file_based():
    return f"""[web]
enabled = false
bind = 127.0.0.1
port = {PANEL}
[auth]
users_file = {UFILE}
brute_force.max_attempts = 100
brute_force.window_secs = 300
brute_force.lockout_secs = 30
[logging]
level = info
file = {LOG}
{PROFILES}"""

def conf_inline(u1_hash):
    # Same, but with an INLINE [user:*] u1 (profiles empty = all). users_file still set.
    return f"""[web]
enabled = false
bind = 127.0.0.1
port = {PANEL}
[auth]
users_file = {UFILE}
brute_force.max_attempts = 100
brute_force.window_secs = 300
brute_force.lockout_secs = 30
[user:u1]
password_hash = {u1_hash}
enabled = true
[logging]
level = info
file = {LOG}
{PROFILES}"""

def client_conf(port):
    return f"""[qeli]
server = 10.66.116.10:{port}
proto = tcp
user = u1
pass = {U1PW}
key = {PUBKEY}
mode = fake-tls
sni = www.microsoft.com
[logging]
level = info
file = /root/reload-cli.log
"""

sc = paramiko.SSHClient(); sc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sc.connect(SRV[0], username=SRV[1], password=SRV[2], timeout=25, look_for_keys=False, allow_agent=False)
cc = paramiko.SSHClient(); cc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cc.connect(CLI[0], username=CLI[1], password=CLI[2], timeout=25, look_for_keys=False, allow_agent=False)

def S(cmd, t=60):
    _i,o,e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=60):
    _i,o,e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def Sbg(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()
def Cbg(cmd):
    ch = cc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()

def curl(path, method="GET", body=None, read=False):
    p = ["curl","-s","--max-time","15","-X",method]
    if read: p += ["-b",JAR]
    if method=="POST" or method=="PUT" or method=="DELETE":
        if not read: p += ["-c",JAR]
        p += [ORG,"-H 'Content-Type: application/json'"]
        if body is not None: p += ["--data",f"'{body}'"]
    return S(" ".join(p+[f"'{BASE}{path}'"]))

PASS=[]
def check(name, ok, detail=""):
    PASS.append(bool(ok)); print(f"  [{'PASS' if ok else 'FAIL'}] {name}"+(f"  ({detail[:260]})" if detail and not ok else ""))

def start_server():
    S("pkill -9 -f 'reloadtest.conf' 2>/dev/null; ip link del ura0 2>/dev/null; ip link del urb0 2>/dev/null; rm -f "+LOG+"; sleep 1; true")
    Sbg(f"RUST_LOG=info setsid nohup {SRV_BIN} server -c {CONF} >/dev/null 2>&1 </dev/null & echo $! >/root/reload-srv.pid")
    for _ in range(20):
        time.sleep(1)
        if S(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {BASE}/login")=="200" \
           and "listening on 0.0.0.0:%d"%PB in S(f"cat {LOG} 2>/dev/null"):
            return True
    return False

def login():
    return '"ok":true' in curl("/api/login","POST",f'{{"username":"admin","password":"{ADMIN}"}}')

def auth_attempt(port, tag):
    """Run the client against `port`, return the last AUTH line for the attempt."""
    n0 = int(S(f"wc -l < {LOG} 2>/dev/null || echo 0") or 0)
    cc.exec_command  # noop
    C("pkill -9 -f 'reload-cli.conf' 2>/dev/null; rm -f /root/reload-cli.log; true")
    cf = cc.open_sftp(); cf.putfo(io.BytesIO(client_conf(port).encode()), "/root/reload-cli.conf"); cf.close()
    Cbg(f"RUST_LOG=info nohup {CLI_BIN} client -c /root/reload-cli.conf </dev/null >/root/reload-cli.out 2>&1 & echo $! >/root/reload-cli.pid")
    line=""
    for _ in range(10):
        time.sleep(1.2)
        new = S(f"tail -n +{n0+1} {LOG} 2>/dev/null | grep -E 'AUTH (OK|DENIED|FAIL)' | grep -F 'user=u1' | tail -1")
        if new:
            line=new; break
    C("kill -9 $(cat /root/reload-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'reload-cli.conf' 2>/dev/null; true")
    print(f"    [{tag}] {line[:150] or '(no auth line seen)'}")
    return line

try:
    print("[setup] stop systemd, stage client binary")
    S("systemctl stop qeli-server.service 2>/dev/null; sleep 1; true")
    lp = os.path.join(tempfile.gettempdir(),"qeli-url"); sf=sc.open_sftp(); sf.get(SRV_BIN,lp); sf.close()
    cf=cc.open_sftp(); cf.put(lp,CLI_BIN); cf.close(); C(f"chmod +x {CLI_BIN}; true")

    # ============ SCENARIO 1: FILE-BASED users (should work) ============
    print("\n==================== SCENARIO 1: FILE-BASED ====================")
    S("rm -f "+UFILE+"; true")
    sc.open_sftp().putfo(io.BytesIO(conf_file_based().encode()), CONF)
    S(f"{SRV_BIN} set-web-password --username admin --password '{ADMIN}' --config {CONF} >/dev/null 2>&1; true")
    check("server up (file-based)", start_server())
    check("panel login", login())
    # create u1 with NO profile restriction (all profiles)
    cr = curl("/api/users","POST",f'{{"username":"u1","password":"{U1PW}","enabled":true,"profiles":[]}}',read=True)
    check("create u1 (all profiles)", '"ok":true' in cr, cr)
    time.sleep(1.5)
    l_pb_before = auth_attempt(PB, "u1 -> pb, unrestricted")
    check("u1 allowed on pb before restriction", "AUTH OK" in l_pb_before, l_pb_before)
    # restrict u1 to [pa] via panel
    up = curl("/api/users/u1","PUT",'{"profiles":["pa"]}',read=True)
    check("edit u1 profiles=[pa]", '"ok":true' in up, up)
    time.sleep(1.5)
    l_pb_after = auth_attempt(PB, "u1 -> pb, restricted to pa")
    check("FILE-BASED: edit APPLIES — u1 now DENIED on pb", "AUTH DENIED" in l_pb_after, l_pb_after)
    l_pa = auth_attempt(PA, "u1 -> pa, restricted to pa")
    check("u1 still allowed on pa", "AUTH OK" in l_pa, l_pa)

    # ============ SCENARIO 2: INLINE users (suspected bug) ============
    print("\n==================== SCENARIO 2: INLINE [user:*] ====================")
    # reuse u1's hash from the file the panel just wrote, so inline u1 has the same password
    u1_hash = S(f"awk '/\\[user:u1\\]/{{f=1}} f&&/password_hash/{{print $3; exit}}' {UFILE}")
    print("  inline u1 hash:", (u1_hash[:32]+"...") if u1_hash else "(none)")
    check("recovered u1 hash from users file", u1_hash.startswith("$argon2"))
    # Clean slate: drop the users file so u1 starts UNRESTRICTED from the inline
    # config (scenario 1 left a [pa] restriction in the file).
    S("rm -f "+UFILE+"; true")
    sc.open_sftp().putfo(io.BytesIO(conf_inline(u1_hash).encode()), CONF)
    S(f"{SRV_BIN} set-web-password --username admin --password '{ADMIN}' --config {CONF} >/dev/null 2>&1; true")
    # ensure the users FILE still restricts u1 to [pa] (from scenario 1) — the panel state
    check("server up (inline)", start_server())
    check("panel login (inline)", login())
    l_in_before = auth_attempt(PB, "inline u1 -> pb (inline=all)")
    check("inline u1 allowed on pb at start", "AUTH OK" in l_in_before, l_in_before)
    # now edit via panel to restrict to [pa] (writes the FILE)
    up2 = curl("/api/users/u1","PUT",'{"profiles":["pa"]}',read=True)
    check("edit inline-u1 profiles=[pa] via panel", '"ok":true' in up2, up2)
    time.sleep(1.5)
    l_in_after = auth_attempt(PB, "inline u1 -> pb after panel restrict")
    # FIXED: the users file (panel edit) now wins over inline, so u1 is DENIED on pb.
    check("INLINE (FIXED): panel edit now APPLIES — u1 DENIED on pb", "AUTH DENIED" in l_in_after, l_in_after)
    l_in_pa = auth_attempt(PA, "inline u1 -> pa after panel restrict")
    check("inline u1 still allowed on pa", "AUTH OK" in l_in_pa, l_in_pa)

    print("\n================ RESULT ================")
    print(f"  {sum(PASS)}/{len(PASS)} checks passed")
    print("  Verdict: panel edits apply for BOTH file-based and inline [user:*] configs (file wins)." if all(PASS) else "  See failures above.")
    sys.exit(0 if all(PASS) else 1)
finally:
    print("\n=== cleanup ===")
    C("kill -9 $(cat /root/reload-cli.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'reload-cli.conf' 2>/dev/null; true")
    S("kill -9 $(cat /root/reload-srv.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'reloadtest.conf' 2>/dev/null; ip link del ura0 2>/dev/null; ip link del urb0 2>/dev/null; rm -f "+JAR+" "+CONF+" "+UFILE+" "+LOG+"; true")
    S("systemctl restart qeli-server.service >/dev/null 2>&1; sleep 1; true")
    print("[restored] systemd qeli:", S("systemctl is-active qeli-server.service"))
    sc.close(); cc.close()

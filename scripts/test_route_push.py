#!/usr/bin/env python3
"""Route-push matrix test: server `route = ...` lines x client `route_local`.

For each case: start a fake-tls server on .10 with the given profile route line(s),
connect the Rust CLI client on .11 with the given route_local, then read the
client's routing table + its warnings. Answers "when does route push NOT work".
"""
import os, sys, io, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
QELI = "/opt/qeli-src/target/release/qeli"
BIN_CLI = "/usr/local/bin/qeli"
DIR = "/root/rt-test"
CONF = f"{DIR}/server-rt.conf"
LOG = f"{DIR}/srv-rt.log"
PORT = 8444
TUNIF = "rt0"
NET = "10.63.0"
CDEV = "rtcli0"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
USER, PASS = "admin", "testpass123"
TARGET = "172.16.20.0/24"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV); cc = conn(CLI)
def ssh(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def csh(cmd, t=60):
    i, o, e = cc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def launch(c, cmd):
    ch = c.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()


def server_conf(route_lines):
    routes = "\n".join(route_lines)
    return f"""[auth]
require_client_key_proof = false

[logging]
level = debug
file = {LOG}

[profile:rt]
identity_key = {DIR}/id.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = {TUNIF}
tun.address = {NET}.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = {NET}.0/24
pool.exclude = {NET}.1
routing.forward_private = true
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
{routes}

[user:{USER}]
password_hash = {HASH}
enabled = true
"""


def client_conf(pub, route_local):
    return f"""[qeli]
server = {SRV[0]}:{PORT}
proto = tcp
user = {USER}
pass = {PASS}
key = {pub}
mode = fake-tls
sni = www.microsoft.com
dns = off
dev = {CDEV}
route_local = {str(route_local).lower()}

[logging]
level = debug
"""


# install the current binary on the client once
ssh(f"install -m755 {QELI} {BIN_CLI}")
sf = sc.open_sftp(); buf = io.BytesIO(); sf.getfo(QELI, buf); sf.close()
cf = cc.open_sftp(); buf.seek(0); cf.putfo(buf, BIN_CLI); cf.close()
csh(f"chmod 755 {BIN_CLI}; mkdir -p /etc/qeli")
ssh(f"mkdir -p {DIR}")

CASES = [
    # (name, server route lines, client route_local, what we expect)
    ("A. correct CIDR, client route_local=FALSE (default)", [f"route = {TARGET}"], False,
     "pushed but IGNORED by client (silent)"),
    ("B. correct CIDR, client route_local=TRUE", [f"route = {TARGET}"], True,
     "route installed"),
    ("C. USER'S LINE: subnet in gateway=, quoted", [f'route = " gateway={TARGET} metric=100"'], True,
     "empty cidr -> client rejects"),
    ("D. CIDR + explicit gateway + metric", [f"route = {TARGET} gateway={NET}.1 metric=50"], True,
     "route installed, metric 50"),
    ("E. two routes (repeatable key)", [f"route = {TARGET}", "route = 192.168.77.0/24"], True,
     "both installed"),
    ("F. cidr= form", [f"route = cidr={TARGET} metric=77"], True,
     "route installed, metric 77"),
]

results = []
for name, routes, rlocal, expect in CASES:
    print("\n" + "=" * 78)
    print(f"### {name}")
    print(f"    server: {routes}   | client route_local={rlocal}   | expect: {expect}")
    # clean
    ssh(f"pkill -9 -f 'rt-test' 2>/dev/null; sleep 1; ip link del {TUNIF} 2>/dev/null; rm -f {LOG}; true")
    csh(f"pkill -9 -x qeli 2>/dev/null; sleep 1; ip link del {CDEV} 2>/dev/null; "
        f"ip route del {TARGET} 2>/dev/null; ip route del 192.168.77.0/24 2>/dev/null; true")
    # server
    sfp = sc.open_sftp(); sfp.putfo(io.BytesIO(server_conf(routes).encode()), CONF); sfp.close()
    pub = ""
    for line in ssh(f"{QELI} show-identity --config {CONF} 2>&1").splitlines():
        m = re.search(r"[0-9a-f]{64}", line)
        if m: pub = m.group(0); break
    launch(sc, f"RUST_LOG=debug setsid nohup {QELI} server -c {CONF} >{DIR}/srv.out 2>&1 </dev/null & echo $! >{DIR}/srv.pid")
    up = False
    for _ in range(12):
        time.sleep(1)
        if ssh(f"ss -tlnp | grep -c ':{PORT}'").strip() not in ("", "0"):
            up = True; break
    if not up:
        print("  !! server failed to bind"); print(ssh(f"tail -5 {LOG} {DIR}/srv.out")); continue
    # client
    ccf = cc.open_sftp(); ccf.putfo(io.BytesIO(client_conf(pub, rlocal).encode()), "/etc/qeli/rt-client.conf"); ccf.close()
    launch(cc, f"RUST_LOG=debug setsid nohup {BIN_CLI} client -c /etc/qeli/rt-client.conf >/tmp/rtc.log 2>&1 </dev/null & echo ok")
    authed = False
    for _ in range(12):
        time.sleep(1)
        if "Auth OK" in csh("grep -c 'Auth OK' /tmp/rtc.log >/dev/null 2>&1 && grep 'Auth OK' /tmp/rtc.log || true"):
            authed = True; break
    time.sleep(2)
    tbl = csh(f"ip route show | grep -E '{TARGET}|192.168.77.0/24' || echo '(no pushed route in table)'")
    logs = csh("grep -iE 'pushed route|Routing local networks|invalid CIDR|invalid gateway|Failed to (parse|route)' /tmp/rtc.log | tail -5 || true")
    print(f"  auth: {'OK' if authed else 'FAILED'}")
    print(f"  client routing table:\n    " + tbl.replace("\n", "\n    "))
    print(f"  client route logs:\n    " + (logs.replace("\n", "\n    ") if logs else "(none)"))
    got = TARGET in tbl
    results.append((name, got, expect))
    # teardown
    csh(f"pkill -9 -x qeli 2>/dev/null; sleep 1; ip link del {CDEV} 2>/dev/null; true")
    ssh(f"pkill -9 -f 'rt-test' 2>/dev/null; ip link del {TUNIF} 2>/dev/null; true")

print("\n" + "=" * 78)
print("SUMMARY — is the pushed route in the client's table?")
for name, got, expect in results:
    print(f"  [{'YES' if got else 'NO '}] {name}   (expected: {expect})")
csh(f"ip route del {TARGET} 2>/dev/null; ip route del 192.168.77.0/24 2>/dev/null; true")
sc.close(); cc.close()

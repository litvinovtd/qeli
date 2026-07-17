#!/usr/bin/env python3
"""Panel end-to-end: add a route + DNS to a profile THROUGH THE WEB PANEL API,
prove it lands in the config correctly, is rejected when malformed, and actually
reaches a connected client. Also compares the panel's qeli:// link with the CLI's.

  .10  qeli server + panel (127.0.0.1:8081), profile 'p'
  .11  Rust CLI client
"""
import os, sys, io, json, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
QELI = "/opt/qeli-src/target/release/qeli"
BIN_CLI = "/usr/local/bin/qeli"
DIR = "/etc/qeli/paneltest"
CONF = f"{DIR}/server.conf"
USERS = f"{DIR}/users.conf"
PORT, PANEL = 8447, 8081
TUNIF, NET, CDEV = "pr0", "10.64.0", "prcli0"
ADMINPW = "PanelPass123!"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
USER, UPASS = "alice", "testpass123"
TARGET, DNSPUSH = "172.16.20.0/24", "10.64.0.53"


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

R = []
def check(name, ok, detail=""):
    R.append(ok); print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))

SERVER_CONF = f"""[auth]
users_file = {USERS}
require_client_key_proof = false

[web]
enabled = true
bind = 127.0.0.1
port = {PANEL}
username = admin

[logging]
level = info

[profile:p]
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
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com

[user:{USER}]
password_hash = {HASH}
enabled = true
"""

print("=== 0. server + panel on .10 ===")
# NB: the pkill MUST be its own command. Any command that also mentions the DIR path
# ("/root/panel-rt") would have "panel-rt" in its OWN cmdline, so `pkill -f` matches
# and SIGKILLs the very shell running it — the rest of the line then never executes.
# Alone, the `[p]` bracket keeps the pattern from matching its own literal argument.
ssh("pkill -9 -f '[p]aneltest' 2>/dev/null; true")
ssh(f"sleep 1; ip link del {TUNIF} 2>/dev/null; rm -rf {DIR}; mkdir -p {DIR}; true")
sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), CONF)
sf.putfo(io.BytesIO(f"[user:{USER}]\npassword_hash = {HASH}\nenabled = true\n".encode()), USERS); sf.close()
print("  set-web-password:", ssh(f"{QELI} set-web-password --username admin --password '{ADMINPW}' --config {CONF} 2>&1 | tail -1")[:70])
launch(sc, f"RUST_LOG=info setsid nohup {QELI} server -c {CONF} >{DIR}/srv.out 2>&1 </dev/null & echo $! >{DIR}/srv.pid")
for _ in range(15):
    time.sleep(1)
    if ssh(f"ss -tlnp | grep -c ':{PANEL}'").strip() not in ("", "0"): break
J = f"{DIR}/jar"
lg = ssh(f"curl -s -c {J} -X POST -H 'Content-Type: application/json' "
         f"-d '{{\"username\":\"admin\",\"password\":\"{ADMINPW}\"}}' http://127.0.0.1:{PANEL}/api/login")
check("panel login", '"ok":true' in lg or "true" in lg, lg[:70])


def get_cfg():
    raw = ssh(f"curl -s -b {J} http://127.0.0.1:{PANEL}/api/config")
    return json.loads(raw)["config"]

def put_cfg(cfg):
    body = json.dumps({"config": cfg})
    sfp = sc.open_sftp(); sfp.putfo(io.BytesIO(body.encode()), f"{DIR}/body.json"); sfp.close()
    return ssh(f"curl -s -b {J} -X PUT -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:{PANEL}' "
               f"--data @{DIR}/body.json http://127.0.0.1:{PANEL}/api/config")

print("\n=== 1. panel: add a GOOD route + DNS push to the profile ===")
cfg = get_cfg()
cfg["profiles"][0]["routing"]["advertised_routes"] = [{"cidr": TARGET, "metric": 100}]
cfg["profiles"][0]["dns"]["push_servers"] = [DNSPUSH]
res = put_cfg(cfg)
check("panel accepted the good route+dns", '"ok":true' in res, res[:120])
ini = ssh(f"grep -E '^route|push_servers' {CONF} || echo '(none)'")
print("  written INI lines:", ini.replace("\n", " | "))
check("INI has a correct `route = <cidr>` line", re.search(rf"^route = {re.escape(TARGET)}", ini, re.M) is not None, ini[:80])
check("INI has dns.push_servers", DNSPUSH in ini, ini[:80])

print("\n=== 2. panel: REJECT a malformed route (the real-world bug) ===")
bad_cases = [
    ("empty CIDR + subnet in gateway", [{"cidr": "", "gateway": TARGET, "metric": 100}]),
    ("CIDR without prefix", [{"cidr": "172.16.20.0", "metric": 100}]),
    ("gateway is a subnet", [{"cidr": TARGET, "gateway": "192.168.1.0/24"}]),
]
for name, routes in bad_cases:
    c2 = get_cfg(); c2["profiles"][0]["routing"]["advertised_routes"] = routes
    r = put_cfg(c2)
    rejected = '"ok":false' in r or '"error"' in r
    check(f"rejected: {name}", rejected, (r[:150] if not rejected else r[r.find('error'):][:110]))

print("\n=== 3. does the panel-authored route+DNS reach a client? ===")
# reload the server so it re-reads the config the panel wrote
ssh(f"kill -9 $(cat {DIR}/srv.pid) 2>/dev/null; true")
ssh("pkill -9 -f '[p]aneltest' 2>/dev/null; true")
ssh(f"sleep 1; ip link del {TUNIF} 2>/dev/null; true")
launch(sc, f"RUST_LOG=info setsid nohup {QELI} server -c {CONF} >{DIR}/srv.out 2>&1 </dev/null & echo $! >{DIR}/srv.pid")
for _ in range(12):
    time.sleep(1)
    if ssh(f"ss -tlnp | grep -c ':{PORT}'").strip() not in ("", "0"): break
pub = ""
for line in ssh(f"{QELI} show-identity --config {CONF} 2>&1").splitlines():
    m = re.search(r"[0-9a-f]{64}", line)
    if m: pub = m.group(0); break
ssh(f"install -m755 {QELI} {BIN_CLI}")
s2 = sc.open_sftp(); buf = io.BytesIO(); s2.getfo(QELI, buf); s2.close()
c2f = cc.open_sftp(); buf.seek(0); c2f.putfo(buf, BIN_CLI); c2f.close()
csh(f"chmod 755 {BIN_CLI}; mkdir -p /etc/qeli")
# NOTE: dns=off would ignore the pushed resolver; use the default dns=tunnel path but
# keep the client's resolv.conf restorable.
cconf = f"""[qeli]
server = {SRV[0]}:{PORT}
proto = tcp
user = {USER}
pass = {UPASS}
key = {pub}
mode = fake-tls
sni = www.microsoft.com
dev = {CDEV}

[logging]
level = debug
"""
csh("cp /etc/resolv.conf /root/resolv.bak 2>/dev/null; true")
cf = cc.open_sftp(); cf.putfo(io.BytesIO(cconf.encode()), "/etc/qeli/pr-client.conf"); cf.close()
csh(f"pkill -9 -x qeli 2>/dev/null; ip link del {CDEV} 2>/dev/null; ip route del {TARGET} 2>/dev/null; true")
launch(cc, f"RUST_LOG=debug setsid nohup {BIN_CLI} client -c /etc/qeli/pr-client.conf >/tmp/prc.log 2>&1 </dev/null & echo ok")
for _ in range(12):
    time.sleep(1)
    if "Auth OK" in csh("grep 'Auth OK' /tmp/prc.log || true"): break
time.sleep(2)
tbl = csh(f"ip route show | grep '{TARGET}' || echo '(absent)'")
check("panel-authored route IS in the client's table", TARGET in tbl, tbl)
print("    ", tbl)
rc = csh("cat /etc/resolv.conf 2>/dev/null | head -3")
check("panel-authored DNS push reached the client resolver", DNSPUSH in rc, rc.replace("\n", " "))
print("     resolv.conf:", rc.replace("\n", " "))
print("     client log:", csh("grep -iE 'Pushed route applied|DNS' /tmp/prc.log | tail -3"))

print("\n=== 4. qeli:// link — panel vs CLI (neither carries dns/routes: by design) ===")
# /api/share is a POST taking a JSON body (HashMap<String,String>), not a GET query.
plink = ssh(f"curl -s -b {J} -X POST -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:{PANEL}' "
            f"-d '{{\"profile\":\"p\",\"user\":\"{USER}\"}}' http://127.0.0.1:{PANEL}/api/share | head -c 500")
m = re.search(r"qeli://[^\"\\s]+", plink)
plink_uri = m.group(0) if m else "(none)"
print("  panel link:", plink_uri[:110])
clink = ssh(f"{QELI} add-client linkcheck --config {CONF} 2>&1 | grep -oE 'qeli://[^ ]+' | head -1")
print("  CLI link  :", (clink or "(none)")[:110])
for tag, uri in (("panel", plink_uri), ("CLI", clink)):
    if uri.startswith("qeli://"):
        check(f"{tag} link carries NO dns/route (by design — those are pushed)",
              ("dns=" not in uri) and ("route" not in uri), uri[:80])

print("\n=== cleanup ===")
csh(f"pkill -9 -x qeli 2>/dev/null; ip link del {CDEV} 2>/dev/null; ip route del {TARGET} 2>/dev/null; "
    f"cp /root/resolv.bak /etc/resolv.conf 2>/dev/null; true")
ssh(f"kill -9 $(cat {DIR}/srv.pid) 2>/dev/null; true")
ssh("pkill -9 -f '[p]aneltest' 2>/dev/null; true")
ssh(f"ip link del {TUNIF} 2>/dev/null; rm -rf {DIR}; true")
sc.close(); cc.close()
print("\n" + "=" * 66)
print(f"RESULT: {sum(R)}/{len(R)} checks passed")

#!/usr/bin/env python3
"""Matrix test for EVERY field the server pushes at auth (handler.rs::build_auth_ok)
and each of its branches.

Fields: client_ip, server_ip, prefix, mtu, dns, dns_port, routes, obfuscation,
session_token, max_streams, multipath_adaptive.

Each case boots a server with a specific config, connects the Rust CLI client on
.11, then asserts BOTH the client's `server push:` log lines AND the real system
state it produced (ip/prefix, MTU, routes, resolv.conf).
"""
import os, sys, io, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
QELI = "/opt/qeli-src/target/release/qeli"
BIN = "/usr/local/bin/qeli"
DIR = "/etc/qeli/pmx"
CONF = f"{DIR}/s.conf"
PORT, TUN, DEV = 8452, "pmx0", "pmxc0"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
USER, UPASS = "u", "testpass123"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


s = conn(SRV); c = conn(CLI)
def ssh(cmd, t=60):
    i, o, e = s.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def csh(cmd, t=60):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def bg(cl, cmd):
    ch = cl.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()


def server_conf(net="10.70.0", pool=None, mtu=1400, dns="dns.enabled = false",
                extra="", user_extra=""):
    pool = pool or f"{net}.0/24"
    return f"""[auth]
require_client_key_proof = false

[logging]
level = info

[profile:p]
identity_key = {DIR}/id.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = {TUN}
tun.address = {net}.1
tun.netmask = 255.255.255.0
tun.mtu = {mtu}
pool.cidr = {pool}
pool.exclude = {net}.1
{dns}
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
{extra}

[user:{USER}]
password_hash = {HASH}
enabled = true
{user_extra}
"""


def client_conf(pub, extra=""):
    return f"""[qeli]
server = {SRV[0]}:{PORT}
proto = tcp
user = {USER}
pass = {UPASS}
key = {pub}
mode = fake-tls
sni = www.microsoft.com
dev = {DEV}
{extra}

[logging]
level = info
"""


def run_case(name, sconf, cextra=""):
    """Boot server+client with the given config; return (push_log, state)."""
    ssh(f"pkill -9 -f '[p]mx/s.conf' 2>/dev/null; true")
    ssh(f"rm -rf {DIR}; mkdir -p {DIR}; ip link del {TUN} 2>/dev/null; true")
    sf = s.open_sftp(); sf.putfo(io.BytesIO(sconf.encode()), CONF); sf.close()
    pub = ""
    for l in ssh(f"{QELI} show-identity --config {CONF} 2>&1").splitlines():
        m = re.search(r"[0-9a-f]{64}", l)
        if m: pub = m.group(0); break
    bg(s, f"setsid nohup {QELI} server -c {CONF} >{DIR}/o.log 2>&1 </dev/null &")
    up = False
    for _ in range(12):
        time.sleep(1)
        if ssh(f"ss -tlnp | grep -c ':{PORT}'").strip() not in ("", "0"): up = True; break
    if not up:
        return "(server failed)", {}, ssh(f"tail -5 {DIR}/o.log")
    cf = c.open_sftp(); cf.putfo(io.BytesIO(client_conf(pub, cextra).encode()), "/etc/qeli/pmx.conf"); cf.close()
    csh(f"pkill -9 -x qeli 2>/dev/null; sleep 1; ip link del {DEV} 2>/dev/null; true")
    bg(c, f"setsid nohup {BIN} client -c /etc/qeli/pmx.conf >/tmp/pmx.log 2>&1 </dev/null &")
    for _ in range(12):
        time.sleep(1)
        if "Auth OK" in csh("grep 'Auth OK' /tmp/pmx.log || true"): break
    time.sleep(2)
    log = csh("grep -iE 'server push|pushed route|Auth OK' /tmp/pmx.log || true")
    state = {
        "addr": csh(f"ip -br addr show dev {DEV} 2>/dev/null | awk '{{print $3}}'"),
        "mtu": csh(f"ip link show {DEV} 2>/dev/null | grep -oE 'mtu [0-9]+'"),
        "routes": csh("ip route show | grep -E '10.15.|172.31.|192.168.88.' || true"),
        "dns": csh("grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | head -2"),
    }
    csh(f"pkill -9 -x qeli 2>/dev/null; sleep 1; ip link del {DEV} 2>/dev/null; "
        f"ip route del 10.15.0.0/24 2>/dev/null; ip route del 172.31.0.0/16 2>/dev/null; "
        f"ip route del 192.168.88.0/24 2>/dev/null; cp /root/resolv.bak /etc/resolv.conf 2>/dev/null; true")
    ssh(f"pkill -9 -f '[p]mx/s.conf' 2>/dev/null; ip link del {TUN} 2>/dev/null; true")
    return log, state, ""


R = []
def check(field, case, ok, detail):
    R.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {field:14} | {case}")
    if not ok: print(f"         -> {detail[:300]}")


ssh(f"install -m755 {QELI} {BIN}")
sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(QELI, buf); sf.close()
cf = c.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close()
csh(f"chmod 755 {BIN}; mkdir -p /etc/qeli; cp /etc/resolv.conf /root/resolv.bak 2>/dev/null; true")

print("=== PUSH MATRIX: every build_auth_ok field x its branches ===\n")

# ── client_ip + prefix ───────────────────────────────────────────────────────
log, st, _ = run_case("pool /24", server_conf(net="10.70.0"))
check("client_ip", "allocated from pool.cidr /24", st["addr"].startswith("10.70.0."), f"{st}")
check("prefix", "/24 pool -> prefix 24", st["addr"].endswith("/24") and "ip=10.70.0" in log, f"addr={st['addr']}")

log, st, _ = run_case("pool /16", server_conf(net="10.71.0", pool="10.71.0.0/16"))
check("prefix", "/16 pool -> prefix 16 (not assumed /24)", st["addr"].endswith("/16"), f"addr={st['addr']} log={log[:160]}")

log, st, _ = run_case("static_ip", server_conf(net="10.72.0", user_extra="static_ip = 10.72.0.55"))
check("client_ip", "per-user static_ip wins", st["addr"].startswith("10.72.0.55"), f"addr={st['addr']}")

log, st, _ = run_case("reservation", server_conf(net="10.73.0", extra=f"pool.reservation.{USER} = 10.73.0.77"))
check("client_ip", "profile pool.reservation.<user>", st["addr"].startswith("10.73.0.77"), f"addr={st['addr']}")

# ── mtu ──────────────────────────────────────────────────────────────────────
log, st, _ = run_case("mtu adopt", server_conf(net="10.74.0", mtu=1350))
check("mtu", "client mtu=0 (auto) adopts pushed 1350", "mtu 1350" in st["mtu"] and "mtu 1350 APPLIED" in log, f"{st['mtu']} | {log[:160]}")

log, st, _ = run_case("mtu client wins", server_conf(net="10.75.0", mtu=1350), cextra="mtu = 1280")
check("mtu", "client mtu=1280 overrides pushed 1350", "mtu 1280" in st["mtu"] and "IGNORED" in log, f"{st['mtu']} | {log[:200]}")

# ── dns + dns_port ───────────────────────────────────────────────────────────
log, st, _ = run_case("dns push_servers", server_conf(net="10.76.0",
                      dns="dns.enabled = true\ndns.listen = 10.76.0.1\ndns.push_servers = 9.9.9.9"))
check("dns", "push_servers wins over the proxy listen IP", "9.9.9.9" in st["dns"] and "DNS 9.9.9.9" in log, f"{st['dns']} | {log[:160]}")

log, st, _ = run_case("dns proxy", server_conf(net="10.77.0",
                      dns="dns.enabled = true\ndns.listen = 10.77.0.1"))
check("dns", "no push_servers + dns.enabled -> proxy listen IP", "10.77.0.1" in st["dns"], f"{st['dns']} | {log[:160]}")

log, st, _ = run_case("dns none", server_conf(net="10.78.0", dns="dns.enabled = false"))
check("dns", "no push_servers + proxy off -> nothing pushed", "no DNS sent" in log, f"{log[:200]}")

log, st, _ = run_case("dns port", server_conf(net="10.79.0",
                      dns="dns.enabled = true\ndns.listen = 10.79.0.1\ndns.port = 5353"))
check("dns_port", "custom dns.port surfaced in the push", "10.79.0.1:5353" in log, f"{log[:200]}")

log, st, _ = run_case("dns client off", server_conf(net="10.80.0",
                      dns="dns.enabled = true\ndns.listen = 10.80.0.1"), cextra="dns = off")
check("dns", "client dns=off -> pushed resolver IGNORED (warned)", "IGNORED" in log and "dns = off" in log, f"{log[:220]}")

# ── routes ───────────────────────────────────────────────────────────────────
log, st, _ = run_case("routes profile", server_conf(net="10.81.0", extra="route = 172.31.0.0/16"))
check("routes", "profile route = pushed + applied", "172.31.0.0/16" in st["routes"], f"{st['routes']} | {log[:160]}")

log, st, _ = run_case("routes personal", server_conf(net="10.82.0",
                      extra="route = 172.31.0.0/16", user_extra="route = 192.168.88.0/24"))
ok = "192.168.88.0/24" in st["routes"] and "172.31.0.0/16" not in st["routes"]
check("routes", "personal route OVERRIDES profile (not merged)", ok, f"{st['routes']}")

log, st, _ = run_case("routes fallback", server_conf(net="10.83.0", extra="route = 172.31.0.0/16", user_extra=""))
check("routes", "no personal routes -> profile routes used", "172.31.0.0/16" in st["routes"], f"{st['routes']}")

# ── obfuscation ──────────────────────────────────────────────────────────────
log, st, _ = run_case("obf flags", server_conf(net="10.84.0",
                      extra="obf.padding.enabled = false\nobf.heartbeat.enabled = false\n"
                            "obf.traffic_normalization.enabled = true"))
ok = "padding=false" in log and "heartbeat=false" in log and "normalization=true" in log
check("obfuscation", "padding/heartbeat/normalization pushed verbatim", ok, f"{log[:220]}")

# ── multipath ────────────────────────────────────────────────────────────────
log, st, _ = run_case("multipath on", server_conf(net="10.85.0",
                      extra="obf.multipath.enabled = true\nobf.multipath.max_streams = 4\nobf.multipath.adaptive = true"))
check("max_streams", "multipath.enabled -> max_streams=4, adaptive=true",
      "max_streams=4" in log and "adaptive=true" in log, f"{log[:220]}")

log, st, _ = run_case("multipath off", server_conf(net="10.86.0", extra="obf.multipath.max_streams = 4"))
check("max_streams", "multipath disabled -> max_streams=1 (cap ignored)", "streams=1" in log, f"{log[:200]}")

csh("cp /root/resolv.bak /etc/resolv.conf 2>/dev/null; true")
ssh(f"rm -rf {DIR}; true")
s.close(); c.close()
print("\n" + "=" * 68)
print(f"RESULT: {sum(R)}/{len(R)} push checks passed")

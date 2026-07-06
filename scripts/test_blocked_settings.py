#!/usr/bin/env python3
"""E2E for the web-panel brute-force settings editor (Blocked IPs tab).

Serves the qeli panel on loopback (.10), logs in over curl, then exercises
GET/POST /api/blocked/settings. Verifies:
  * the three [auth] brute_force keys are patched into the on-disk config
    IN PLACE, with a hand-written comment preserved (surgical, not a rewrite);
  * `set-web-password` (the refactored shared set_section_keys) also preserves
    the comment;
  * the new values read back through the API;
  * the change is applied live (server logs the update);
  * out-of-range values are rejected.
"""
import os, sys, io, time, tempfile, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ["QELI_LAB_PASS"]
SRV = ("10.66.116.10", "root", PW)
BIN = "/opt/qeli-src/target/release/qeli"
# Must live under /etc/qeli — the panel's config-write guard (ALLOWED_CONFIG_DIRS)
# refuses to write anywhere else, exactly as put_config does.
CONF = "/etc/qeli/blkset-e2e.conf"
LOG = "/root/blkset-srv.log"
PANEL_PORT = 8523
PROF_PORT = 8524
ADMIN_PW = "e2e-admin-pw-9182"
BASE = f"http://127.0.0.1:{PANEL_PORT}"
ORIGIN = f"-H 'Origin: {BASE}' -H 'Referer: {BASE}/'"
JAR = "/root/blkset-jar.txt"
COMMENT = "; PRESERVE-THIS-COMMENT-blkset"

CONF_TEXT = f"""[web]
enabled = false
bind = 127.0.0.1
port = {PANEL_PORT}
[auth]
{COMMENT}
users_file = /root/reality-test/users-e2e.conf
brute_force.max_attempts = 5
brute_force.window_secs = 300
brute_force.lockout_secs = 900
[logging]
level = info
file = {LOG}
[profile:blkset]
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PROF_PORT}
bind.transport = tcp
tun.name = blkset0
tun.address = 10.87.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.87.0.0/24
pool.exclude = 10.87.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
"""


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV)


def S(cmd, t=60):
    _i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def Sbg(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()


PASS = []
def check(name, ok, detail=""):
    PASS.append(bool(ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail[:300]})" if detail and not ok else ""))


def curl(path, method="GET", body=None, jar_read=False):
    parts = ["curl", "-s", "--max-time", "15", "-X", method]
    if jar_read:
        parts += ["-b", JAR]
    if method == "POST":
        parts += ["-c", JAR] if not jar_read else []
        parts += [ORIGIN, "-H 'Content-Type: application/json'"]
        if body is not None:
            parts += ["--data", f"'{body}'"]
    return S(" ".join(parts + [f"'{BASE}{path}'"]))


try:
    if not S("command -v curl >/dev/null 2>&1 && echo yes"):
        print("[SKIP] curl not present on the lab host"); sys.exit(2)

    print("[setup] stopping systemd server, writing panel config")
    S("systemctl stop qeli-server.service 2>/dev/null; sleep 1; true")
    S("pkill -9 -f 'blkset-e2e.conf' 2>/dev/null; ip link del blkset0 2>/dev/null; rm -f " + LOG + " " + JAR + "; sleep 1; true")
    sc.open_sftp().putfo(io.BytesIO(CONF_TEXT.encode()), CONF)

    # set-web-password: sets [web] user/hash/enabled — via the refactored shared
    # comment-preserving helper. Prove it kept the [auth] comment untouched.
    swp = S(f"{BIN} set-web-password --username admin --password '{ADMIN_PW}' --config {CONF}")
    print("  set-web-password:", swp.split(chr(10))[0][:120])
    conf_after_swp = S(f"cat {CONF}")
    check("set-web-password preserved the [auth] comment", COMMENT in conf_after_swp)
    check("set-web-password enabled the panel", "enabled = true" in conf_after_swp)

    print("[server] starting supervisor+panel")
    Sbg(f"RUST_LOG=info setsid nohup {BIN} server -c {CONF} >/dev/null 2>&1 </dev/null & echo $! >/root/blkset-srv.pid")
    up = False
    for _ in range(20):
        time.sleep(1)
        if S(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {BASE}/login") == "200":
            up = True; break
    check("panel reachable on loopback", up)
    if not up:
        print(S(f"tail -20 {LOG}")); sys.exit(1)

    print("\n=== login ===")
    login = curl("/api/login", "POST", f'{{"username":"admin","password":"{ADMIN_PW}"}}')
    check("login ok", '"ok":true' in login, login)

    print("\n=== GET initial settings (two policies) ===")
    g0 = curl("/api/blocked/settings", "GET", jar_read=True)
    print("  settings:", g0)
    try:
        s0 = json.loads(g0)["settings"]
    except Exception as ex:
        s0 = {}; check("GET returns parseable JSON with settings", False, f"{ex}: {g0}")
    vpn0, pan0 = s0.get("vpn", {}), s0.get("panel", {})
    check("GET has separate vpn + panel policies", bool(vpn0) and bool(pan0), g0)
    check("vpn defaults (enabled/5/300/900)",
          vpn0.get("enabled") is True and vpn0.get("max_attempts") == 5
          and vpn0.get("window_secs") == 300 and vpn0.get("lockout_secs") == 900, str(vpn0))
    check("panel defaults (enabled/5/300/900)",
          pan0.get("enabled") is True and pan0.get("max_attempts") == 5
          and pan0.get("window_secs") == 300 and pan0.get("lockout_secs") == 900, str(pan0))

    print("\n=== POST both policies (vpn 3/60/120 on; panel 7/120/600 OFF) ===")
    body = ('{"vpn":{"enabled":true,"max_attempts":3,"window_secs":60,"lockout_secs":120},'
            '"panel":{"enabled":false,"max_attempts":7,"window_secs":120,"lockout_secs":600}}')
    p1 = curl("/api/blocked/settings", "POST", body, jar_read=True)
    check("POST accepted", '"ok":true' in p1, p1)

    conf_now = S(f"cat {CONF}")
    # VPN policy patched under [auth]
    check("[auth] patched: enabled=true", "brute_force.enabled = true" in conf_now, conf_now)
    check("[auth] patched: max_attempts=3", "brute_force.max_attempts = 3" in conf_now, conf_now)
    check("[auth] patched: window_secs=60", "brute_force.window_secs = 60" in conf_now)
    check("[auth] patched: lockout_secs=120", "brute_force.lockout_secs = 120" in conf_now)
    check("[auth] comment still preserved after POST", COMMENT in conf_now)
    check("no duplicate max_attempts=3 key", conf_now.count("brute_force.max_attempts = 3") == 1, conf_now)
    # Panel policy patched under [web]
    check("[web] patched: enabled=false", "brute_force.enabled = false" in conf_now, conf_now)
    check("[web] patched: max_attempts=7", "brute_force.max_attempts = 7" in conf_now, conf_now)
    check("[web] patched: window_secs=120", "brute_force.window_secs = 120" in conf_now)
    check("[web] patched: lockout_secs=600", "brute_force.lockout_secs = 600" in conf_now)

    g1 = curl("/api/blocked/settings", "GET", jar_read=True)
    s1 = json.loads(g1)["settings"]
    check("GET reflects vpn 3/60/120 enabled",
          s1["vpn"] == {"enabled": True, "max_attempts": 3, "window_secs": 60, "lockout_secs": 120}, str(s1.get("vpn")))
    check("GET reflects panel 7/120/600 DISABLED",
          s1["panel"] == {"enabled": False, "max_attempts": 7, "window_secs": 120, "lockout_secs": 600}, str(s1.get("panel")))

    check("server logged the VPN-auth live update",
          "VPN-auth brute-force policy updated via panel" in S(f"grep -F 'VPN-auth brute-force policy updated via panel' {LOG} | tail -1"))
    check("server logged the panel-login live update",
          "panel-login brute-force policy updated via panel" in S(f"grep -F 'panel-login brute-force policy updated via panel' {LOG} | tail -1"))

    print("\n=== validation (per-surface, fails before any write) ===")
    v0 = curl("/api/blocked/settings", "POST", '{"vpn":{"max_attempts":0,"window_secs":60,"lockout_secs":120}}', jar_read=True)
    check("vpn max_attempts=0 rejected", '"ok":false' in v0 and "between 1 and 10000" in v0, v0)
    vw = curl("/api/blocked/settings", "POST", '{"panel":{"max_attempts":5,"window_secs":0,"lockout_secs":120}}', jar_read=True)
    check("panel window_secs=0 rejected", '"ok":false' in vw and "panel:" in vw, vw)
    vl = curl("/api/blocked/settings", "POST", '{"vpn":{"max_attempts":5,"window_secs":60,"lockout_secs":9999999}}', jar_read=True)
    check("vpn lockout_secs over 30d rejected", '"ok":false' in vl, vl)
    ve = curl("/api/blocked/settings", "POST", '{}', jar_read=True)
    check("empty body rejected", '"ok":false' in ve, ve)
    # config must be unchanged by the rejected writes
    check("rejected writes did not touch the config",
          "brute_force.max_attempts = 3" in S(f"cat {CONF}") and "brute_force.max_attempts = 7" in S(f"cat {CONF}"))

    print("\n=== back-compat: legacy flat body → VPN surface ===")
    pl = curl("/api/blocked/settings", "POST", '{"max_attempts":4,"window_secs":90,"lockout_secs":150}', jar_read=True)
    check("legacy flat POST accepted", '"ok":true' in pl, pl)
    slg = json.loads(curl("/api/blocked/settings", "GET", jar_read=True))["settings"]
    check("legacy flat body updated VPN (4/90/150)",
          slg["vpn"]["max_attempts"] == 4 and slg["vpn"]["window_secs"] == 90, str(slg.get("vpn")))
    check("legacy flat body left panel untouched (still 7)",
          slg["panel"]["max_attempts"] == 7, str(slg.get("panel")))

    print("\n=== unauthenticated access blocked ===")
    ua = S(f"curl -s --max-time 10 {ORIGIN} -H 'Content-Type: application/json' --data '{{\"vpn\":{{\"max_attempts\":9,\"window_secs\":9,\"lockout_secs\":9}}}}' -X POST {BASE}/api/blocked/settings")
    check("POST without session is rejected", '"ok":true' not in ua, ua)
    check("unauth POST did not change config", "brute_force.max_attempts = 4" in S(f"cat {CONF}"))

    print("\n================ RESULT ================")
    print(f"  {sum(PASS)}/{len(PASS)} checks passed")
    sys.exit(0 if all(PASS) else 1)
finally:
    print("\n=== cleanup ===")
    S("kill -9 $(cat /root/blkset-srv.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'blkset-e2e.conf' 2>/dev/null; ip link del blkset0 2>/dev/null; rm -f " + JAR + " " + CONF + " " + LOG + "; true")
    S("systemctl restart qeli-server.service >/dev/null 2>&1; sleep 1; true")
    print("[restored] systemd qeli:", S("systemctl is-active qeli-server.service"))
    sc.close()

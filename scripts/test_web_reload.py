#!/usr/bin/env python3
"""E2E for #4: web-panel settings apply LIVE (no full restart).

Changes the admin password through the panel (GET /api/config -> set
web.password_hash -> PUT /api/config) and verifies WITHOUT restarting the
supervisor: the old session cookie is rejected, the old password no longer logs
in, and the new password does. Proves state.live_web is hot-reloaded.
"""
import os, sys, io, time, json, tempfile
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ["QELI_LAB_PASS"]
SRV = ("10.66.116.10", "root", PW)
BIN = "/opt/qeli-src/target/release/qeli"
CONF = "/etc/qeli/webreload-e2e.conf"
UFILE = "/etc/qeli/webreload-users.conf"
LOG = "/var/log/qeli/webreload-srv.log"   # inside the panel's log-path whitelist
PANEL = 8541
PROF = 8542
P1 = "admin-pw-ONE"
P2 = "admin-pw-TWO-changed"
BASE = f"http://127.0.0.1:{PANEL}"
ORG = f"-H 'Origin: {BASE}' -H 'Referer: {BASE}/'"
J1 = "/root/webreload-j1.txt"   # session under P1
J2 = "/root/webreload-j2.txt"   # session under P2

CONF_TEXT = f"""[web]
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
[profile:wr]
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PROF}
bind.transport = tcp
tun.name = wr0
tun.address = 10.84.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.84.0.0/24
pool.exclude = 10.84.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
"""

sc = paramiko.SSHClient(); sc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sc.connect(SRV[0], username=SRV[1], password=SRV[2], timeout=25, look_for_keys=False, allow_agent=False)

def S(cmd, t=60):
    _i,o,e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def Sbg(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()

PASS=[]
def check(name, ok, detail=""):
    PASS.append(bool(ok)); print(f"  [{'PASS' if ok else 'FAIL'}] {name}"+(f"  ({detail[:260]})" if detail and not ok else ""))

def curl(path, method="GET", body=None, jar=None, save_jar=None, code_only=False):
    p = ["curl","-s","--max-time","15"]
    if code_only: p += ["-o","/dev/null","-w","%{http_code}"]
    p += ["-X",method]
    if jar: p += ["-b",jar]
    if save_jar: p += ["-c",save_jar]
    if method in ("POST","PUT","DELETE"):
        p += [ORG,"-H 'Content-Type: application/json'"]
        if body is not None: p += ["--data",f"@-"]  # read body from stdin (avoid quoting hell)
    cmd = " ".join(p+[f"'{BASE}{path}'"])
    if body is not None and method in ("POST","PUT","DELETE"):
        # feed body via stdin heredoc
        return S(f"cat <<'EOF' | {cmd}\n{body}\nEOF")
    return S(cmd)

try:
    print("[setup] stop systemd, write config, set admin password P1")
    S("systemctl stop qeli-server.service 2>/dev/null; sleep 1; true")
    S("mkdir -p /var/log/qeli; pkill -9 -f 'webreload-e2e.conf' 2>/dev/null; ip link del wr0 2>/dev/null; rm -f "+LOG+" "+UFILE+" "+J1+" "+J2+"; sleep 1; true")
    sc.open_sftp().putfo(io.BytesIO(CONF_TEXT.encode()), CONF)
    S(f"{BIN} set-web-password --username admin --password '{P1}' --config {CONF} >/dev/null 2>&1; true")

    Sbg(f"RUST_LOG=info setsid nohup {BIN} server -c {CONF} >/dev/null 2>&1 </dev/null & echo $! >/root/webreload-srv.pid")
    up = False
    for _ in range(20):
        time.sleep(1)
        if S(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {BASE}/login")=="200":
            up = True; break
    check("panel up", up)
    if not up:
        print(S(f"tail -20 {LOG}")); sys.exit(1)
    srv_pid = S("cat /root/webreload-srv.pid").strip()

    print("\n=== login with P1, confirm session works ===")
    login1 = curl("/api/login","POST",json.dumps({"username":"admin","password":P1}), save_jar=J1)
    check("login P1 ok", '"ok":true' in login1, login1)
    check("P1 session can read settings", curl("/api/blocked/settings", jar=J1, code_only=True)=="200")

    print("\n=== change admin password to P2 via the panel (GET config -> set hash -> PUT) ===")
    # hash P2 through the panel util endpoint
    h = curl("/api/hash-password","POST",json.dumps({"password":P2}), jar=J1)
    hash2 = json.loads(h).get("hash","") if h.strip().startswith("{") else ""
    check("hash-password returned an argon2 hash", hash2.startswith("$argon2"), h)
    # GET current config, swap web.password_hash, PUT it back
    cfg_reply = curl("/api/config", jar=J1)
    cfg = json.loads(cfg_reply)["config"]
    cfg["web"]["password_hash"] = hash2
    put = curl("/api/config","PUT",json.dumps({"config":cfg}), jar=J1)
    check("PUT /api/config accepted", '"ok":true' in put, put)
    # confirm the server did NOT restart (same pid, panel still up)
    time.sleep(1.5)
    same_pid = S("cat /root/webreload-srv.pid").strip() == srv_pid and S(f"kill -0 {srv_pid} 2>/dev/null && echo alive")== "alive"
    check("supervisor did NOT restart (same pid alive)", same_pid, f"pid={srv_pid}")
    check("panel still reachable after change", S(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {BASE}/login")=="200")

    print("\n=== verify the change applied LIVE (no restart) ===")
    # old cookie must now be rejected (password hash = HMAC salt changed)
    code_old = curl("/api/blocked/settings", jar=J1, code_only=True)
    check("old P1 session cookie now REJECTED (401)", code_old=="401", f"http={code_old}")
    # old password must fail to log in
    login_old = curl("/api/login","POST",json.dumps({"username":"admin","password":P1}))
    check("old password P1 no longer logs in", '"ok":true' not in login_old, login_old)
    # new password must work
    login_new = curl("/api/login","POST",json.dumps({"username":"admin","password":P2}), save_jar=J2)
    check("new password P2 logs in", '"ok":true' in login_new, login_new)
    check("P2 session can read settings", curl("/api/blocked/settings", jar=J2, code_only=True)=="200")
    check("server logged live web reload", "live web settings reloaded" in S(f"grep -F 'live web settings reloaded' {LOG} | tail -1"))

    print("\n================ RESULT ================")
    print(f"  {sum(PASS)}/{len(PASS)} checks passed")
    print("  Verdict: admin-password change via the panel applies LIVE, no restart." if all(PASS) else "  See failures above.")
    sys.exit(0 if all(PASS) else 1)
finally:
    print("\n=== cleanup ===")
    S("kill -9 $(cat /root/webreload-srv.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'webreload-e2e.conf' 2>/dev/null; ip link del wr0 2>/dev/null; rm -f "+J1+" "+J2+" "+CONF+" "+UFILE+" "+LOG+"; true")
    S("systemctl restart qeli-server.service >/dev/null 2>&1; sleep 1; true")
    print("[restored] systemd qeli:", S("systemctl is-active qeli-server.service"))
    sc.close()

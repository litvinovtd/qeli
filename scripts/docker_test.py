#!/usr/bin/env python3
"""Run the qeli panel/data-plane tests against a server running IN DOCKER.

Target: a Docker host (env QELI_DOCKER_HOST / QELI_DOCKER_PASS). The qeli:fix4
image must already be built there. Uses --network host so the panel (127.0.0.1:
8541) and the two VPN profiles (pa:8542 / pb:8543) live in the host netns; curl
(panel) and a client CONTAINER both hit 127.0.0.1. Verifies:
  * container runtime: image starts via the entrypoint, TUN + caps work, panel up
  * fix #1  user allowed-profiles edit applies (file-based, in-container reload)
  * fix #4  admin-password change via the panel applies live (no restart)
  * blocked-IPs lockout-policy editor persists + applies
"""
import os, sys, time, json, io
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

H = os.environ["QELI_DOCKER_HOST"]; U = "root"; P = os.environ["QELI_DOCKER_PASS"]
IMG = os.environ.get("QELI_IMAGE", "qeli:fix4")
ETC = "/root/qtest/etc"
CLI = "/root/qtest/cli"
PANEL, PA, PB = 8541, 8542, 8543
U1PW = "u1-docker-pw"
ADMIN1, ADMIN2 = "adminpw-one", "adminpw-two-new"
BASE = f"http://127.0.0.1:{PANEL}"
ORG = f"-H 'Origin: {BASE}' -H 'Referer: {BASE}/'"

SERVER_CONF = f"""[web]
enabled = true
bind = 127.0.0.1
port = {PANEL}
[auth]
users_file = /etc/qeli/dtest-users.conf
brute_force.max_attempts = 100
brute_force.window_secs = 300
brute_force.lockout_secs = 30
[logging]
level = info
[profile:pa]
identity_key = /etc/qeli/identity/shared.key
bind.address = 0.0.0.0
bind.port = {PA}
bind.transport = tcp
tun.name = dpa0
tun.address = 10.83.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.83.0.0/24
pool.exclude = 10.83.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
[profile:pb]
identity_key = /etc/qeli/identity/shared.key
bind.address = 0.0.0.0
bind.port = {PB}
bind.transport = tcp
tun.name = dpb0
tun.address = 10.82.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.82.0.0/24
pool.exclude = 10.82.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
"""

def client_conf(port, pubkey):
    return f"""[qeli]
server = 127.0.0.1:{port}
proto = tcp
user = u1
pass = {U1PW}
key = {pubkey}
mode = fake-tls
sni = www.microsoft.com
dns = off
[logging]
level = info
"""

c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(H, username=U, password=P, timeout=25, look_for_keys=False, allow_agent=False)
def S(cmd, t=120):
    i,o,e = c.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()

PASS=[]
def check(name, ok, detail=""):
    PASS.append(bool(ok)); print(f"  [{'PASS' if ok else 'FAIL'}] {name}"+(f"  ({detail[:280]})" if detail and not ok else ""))

def curl(path, method="GET", body=None, jar=None, save=None, code=False):
    p=["curl","-s","--max-time","15"]
    if code: p+=["-o","/dev/null","-w","%{http_code}"]
    p+=["-X",method]
    if jar: p+=["-b",jar]
    if save: p+=["-c",save]
    if method in ("POST","PUT","DELETE"):
        p+=[ORG,"-H 'Content-Type: application/json'"]
    cmd=" ".join(p+[f"'{BASE}{path}'"])
    if body is not None and method in ("POST","PUT","DELETE"):
        return S(f"cat <<'EOF' | " + " ".join(p+['--data','@-',f"'{BASE}{path}'"]) + f"\n{body}\nEOF")
    return S(cmd)

def logs_lc():
    return int(S("docker logs qtest 2>&1 | wc -l") or 0)

def auth_attempt(port, tag):
    n0 = logs_lc()
    S("docker rm -f qcli >/dev/null 2>&1; true")
    cf = c.open_sftp(); cf.putfo(io.BytesIO(client_conf(port, PUBKEY).encode()), CLI+"/client.conf"); cf.close()
    S(f"docker run -d --name qcli --network host --cap-add NET_ADMIN --device /dev/net/tun -v {CLI}:/etc/qeli {IMG} client >/dev/null 2>&1; true")
    line=""
    for _ in range(8):
        time.sleep(1.2)
        line = S(f"docker logs qtest 2>&1 | tail -n +{n0+1} | grep -E 'AUTH (OK|DENIED|FAIL)' | grep -F 'user=u1' | tail -1")
        if line: break
    S("docker rm -f qcli >/dev/null 2>&1; ip link del dcli0 2>/dev/null; true")
    print(f"    [{tag}] {line[:150] or '(no auth line)'}")
    return line

try:
    print(f"[setup] image={IMG}; cleaning + writing server config")
    S("docker rm -f qtest qcli >/dev/null 2>&1; rm -rf /root/qtest; mkdir -p "+ETC+" "+CLI+"; true")
    cf=c.open_sftp(); cf.putfo(io.BytesIO(SERVER_CONF.encode()), ETC+"/server.conf"); cf.close()
    # admin password via the image's own CLI (writes hash into the mounted config)
    swp = S(f"docker run --rm -v {ETC}:/etc/qeli --entrypoint /usr/local/bin/qeli {IMG} set-web-password --username admin --password '{ADMIN1}' --config /etc/qeli/server.conf 2>&1")
    check("set-web-password in container", "Web panel admin set" in swp, swp)

    print("[run] starting qeli-server container (--network host, NET_ADMIN, tun)")
    # NB: --sysctl net.ipv4.ip_forward is NOT allowed together with --network host
    # (namespaced sysctl in the host netns); the entrypoint sets it via /proc, and
    # these auth tests don't need forwarding anyway.
    S(f"docker run -d --name qtest --network host --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -v {ETC}:/etc/qeli {IMG} server >/dev/null 2>&1; true")
    up=False
    for _ in range(25):
        time.sleep(1)
        if S(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {BASE}/login")=="200" \
           and "listening on 0.0.0.0:%d"%PB in S("docker logs qtest 2>&1"):
            up=True; break
    check("container: entrypoint ran, panel up, both profiles listen", up)
    if not up:
        print(S("docker logs qtest 2>&1 | tail -30")); sys.exit(1)
    check("container still running", S("docker inspect -f '{{.State.Running}}' qtest")=="true")
    # identity pubkey the server generated (pin it on the client)
    PUBKEY = S("docker logs qtest 2>&1 | grep -oE 'public key \\(pin on client\\): [0-9a-f]{64}' | head -1 | grep -oE '[0-9a-f]{64}'")
    check("read server identity pubkey from logs", len(PUBKEY)==64, PUBKEY)

    print("\n=== login ===")
    check("panel login (admin/ADMIN1)", '"ok":true' in curl("/api/login","POST",json.dumps({"username":"admin","password":ADMIN1}), save="/root/qtest/j.txt"))

    print("\n=== FIX #1: user allowed-profiles edit applies in the container ===")
    cr = curl("/api/users","POST",json.dumps({"username":"u1","password":U1PW,"enabled":True,"profiles":[]}), jar="/root/qtest/j.txt")
    check("create u1 (all profiles)", '"ok":true' in cr, cr)
    time.sleep(1.5)
    check("u1 allowed on pb before restriction", "AUTH OK" in auth_attempt(PB, "u1->pb unrestricted"))
    up1 = curl("/api/users/u1","PUT",json.dumps({"profiles":["pa"]}), jar="/root/qtest/j.txt")
    check("edit u1 profiles=[pa]", '"ok":true' in up1, up1)
    time.sleep(1.5)
    check("u1 now DENIED on pb (edit applied in container)", "AUTH DENIED" in auth_attempt(PB, "u1->pb restricted"))
    check("u1 still allowed on pa", "AUTH OK" in auth_attempt(PA, "u1->pa"))

    print("\n=== blocked-IPs lockout-policy editor ===")
    g0 = curl("/api/blocked/settings", jar="/root/qtest/j.txt")
    check("GET settings defaults 100/300/30", '"max_attempts":100' in g0 and '"window_secs":300' in g0, g0)
    p1 = curl("/api/blocked/settings","POST",json.dumps({"max_attempts":4,"window_secs":90,"lockout_secs":150}), jar="/root/qtest/j.txt")
    check("POST settings accepted", '"ok":true' in p1, p1)
    conf_now = S(f"cat {ETC}/server.conf")
    check("config patched in container volume", "brute_force.max_attempts = 4" in conf_now and "brute_force.window_secs = 90" in conf_now, conf_now)
    check("GET reflects new settings", '"max_attempts":4' in curl("/api/blocked/settings", jar="/root/qtest/j.txt"))

    print("\n=== FIX #4: admin-password change applies live (no restart) ===")
    cid0 = S("docker inspect -f '{{.State.Pid}}' qtest")
    h = curl("/api/hash-password","POST",json.dumps({"password":ADMIN2}), jar="/root/qtest/j.txt")
    hash2 = json.loads(h).get("hash","") if h.strip().startswith("{") else ""
    check("hash-password ok", hash2.startswith("$argon2"), h)
    cfg = json.loads(curl("/api/config", jar="/root/qtest/j.txt"))["config"]
    cfg["web"]["password_hash"] = hash2
    put = curl("/api/config","PUT",json.dumps({"config":cfg}), jar="/root/qtest/j.txt")
    check("PUT config (password change) accepted", '"ok":true' in put, put)
    time.sleep(1.5)
    check("container did NOT restart (same main pid)", S("docker inspect -f '{{.State.Pid}}' qtest")==cid0 and S("docker inspect -f '{{.State.Running}}' qtest")=="true")
    check("old session cookie now rejected (401)", curl("/api/blocked/settings", jar="/root/qtest/j.txt", code=True)=="401")
    check("old password no longer logs in", '"ok":true' not in curl("/api/login","POST",json.dumps({"username":"admin","password":ADMIN1})))
    check("new password logs in", '"ok":true' in curl("/api/login","POST",json.dumps({"username":"admin","password":ADMIN2}), save="/root/qtest/j2.txt"))
    check("server logged live web reload", "live web settings reloaded" in S("docker logs qtest 2>&1 | grep -F 'live web settings reloaded' | tail -1"))

    print("\n================ RESULT ================")
    print(f"  {sum(PASS)}/{len(PASS)} checks passed")
    print(S("docker logs qtest 2>&1 | grep -E 'AUTH (OK|DENIED)|live web|Profile .* listening' | tail -8"))
    sys.exit(0 if all(PASS) else 1)
finally:
    print("\n=== cleanup ===")
    S("docker rm -f qtest qcli >/dev/null 2>&1; ip link del dcli0 2>/dev/null; ip link del dpa0 2>/dev/null; ip link del dpb0 2>/dev/null; rm -rf /root/qtest; true")
    print("[cleaned] containers:", S("docker ps -a --format '{{.Names}}' | tr '\\n' ' '") or "(none)")
    c.close()

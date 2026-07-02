#!/usr/bin/env python3
"""Verify the kick fix against a qeli server IN DOCKER.

Server + client both run as containers (--network host) on the Docker host
(env QELI_DOCKER_HOST/PASS, image QELI_IMAGE=qeli:fix4). Establishes a session,
kicks via `docker exec ... qeli kick`, and checks it leaves list-clients — for a
NORMAL client and for a STUCK one (docker pause + downstream flood so the server
stream blocks on write, the reported bug).
"""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

H=os.environ["QELI_DOCKER_HOST"]; P=os.environ["QELI_DOCKER_PASS"]; IMG=os.environ.get("QELI_IMAGE","qeli:fix4")
ETC="/root/qk/etc"; CLIDIR="/root/qk/cli"; PROF=8562; U1PW="u1-dk-pw"; CIP="10.80.0.2"
SOCK="/var/run/qeli/control.sock"

SRV_CONF=f"""[web]
enabled = false
[auth]
users_file = /etc/qeli/dk-users.conf
brute_force.max_attempts = 100
[logging]
level = info
[profile:k]
identity_key = /etc/qeli/identity/dk.key
bind.address = 0.0.0.0
bind.port = {PROF}
bind.transport = tcp
tun.name = kd0
tun.address = 10.80.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.80.0.0/24
pool.exclude = 10.80.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 16
"""
def cli_conf(pub):
    return f"""[qeli]
server = 127.0.0.1:{PROF}
proto = tcp
user = u1
pass = {U1PW}
key = {pub}
mode = fake-tls
sni = www.microsoft.com
dev = kcli0
dns = off
[logging]
level = info
"""

c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(H,username="root",password=P,timeout=25,look_for_keys=False,allow_agent=False)
def S(cmd,t=90):
    i,o,e=c.exec_command(cmd,timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()

PASS=[]
def check(n,ok,d=""):
    PASS.append(bool(ok)); print(f"  [{'PASS' if ok else 'FAIL'}] {n}"+(f"  ({d[:200]})" if d and not ok else ""))

def src():
    return S(f"docker exec qtest qeli list-clients --socket {SOCK} 2>&1 | grep -oE '127\\.0\\.0\\.1:[0-9]+' | head -1")

def start_client():
    S("docker rm -f qcli >/dev/null 2>&1; ip link del kcli0 2>/dev/null; true")
    S(f"docker run -d --name qcli --network host --cap-add NET_ADMIN --device /dev/net/tun -v {CLIDIR}:/etc/qeli {IMG} client >/dev/null 2>&1; true")
    for _ in range(14):
        time.sleep(1.3)
        s=src()
        if s: return s
    return ""

try:
    print(f"[setup] image={IMG}")
    S("docker rm -f qtest qcli >/dev/null 2>&1; rm -rf /root/qk; mkdir -p "+ETC+" "+CLIDIR+"; ip link del kcli0 2>/dev/null; ip link del kd0 2>/dev/null; true")
    c.open_sftp().putfo(io.BytesIO(SRV_CONF.encode()), ETC+"/server.conf")
    S(f"docker run --rm -v {ETC}:/etc/qeli --entrypoint /usr/local/bin/qeli {IMG} add-client u1 --password '{U1PW}' --config /etc/qeli/server.conf 2>&1 | head -1")
    S(f"docker run -d --name qtest --network host --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -v {ETC}:/etc/qeli {IMG} server >/dev/null 2>&1; true")
    up=any(f"listening on 0.0.0.0:{PROF}" in S("docker logs qtest 2>&1") for _ in [time.sleep(1) for _ in range(20)])
    check("server container up + profile listening", up)
    if not up: print(S("docker logs qtest 2>&1 | tail -20")); sys.exit(1)
    PUB=S("docker logs qtest 2>&1 | grep -oE 'public key .pin on client.: [0-9a-f]{64}' | tail -1 | grep -oE '[0-9a-f]{64}'")
    check("got server pubkey", len(PUB)==64, PUB)
    c.open_sftp().putfo(io.BytesIO(cli_conf(PUB).encode()), CLIDIR+"/client.conf")

    print("\n=== A) NORMAL client in container: kick removes + reconnect ===")
    s0=start_client()
    check("client container connected", bool(s0), s0)
    print("  before kick:", s0, "| kick:", S(f"docker exec qtest qeli kick u1 --socket {SOCK} 2>&1"))
    gone=any(src()!=s0 for _ in [time.sleep(1) for _ in range(6)])
    check("original session removed", gone, f"still {s0}")
    time.sleep(3)
    check("client reconnected", bool(src()) and src()!=s0, f"src {src()}")

    print("\n=== B) STUCK client (docker pause + flood): kick must still remove ===")
    S("docker rm -f qcli >/dev/null 2>&1; ip link del kcli0 2>/dev/null; true"); time.sleep(1)
    sb=start_client()
    check("stuck-test client connected", bool(sb), sb)
    S("docker pause qcli >/dev/null 2>&1; true")                       # freeze the client container
    S(f"nohup ping -f -s 1400 -w 6 {CIP} >/dev/null 2>&1 & true")      # fill the stuck stream's write buffer
    time.sleep(6)
    print("  stuck session before kick:", src(), "| kick:", S(f"docker exec qtest qeli kick u1 --socket {SOCK} 2>&1"))
    removed=False
    for i in range(8):
        time.sleep(1)
        if not src(): removed=True; print(f"  +{i+1}s: GONE"); break
    check("STUCK session removed by kick (the fix, in container)", removed, f"LINGERS {src()}")
    S("docker unpause qcli >/dev/null 2>&1; true")

    print("\n================ RESULT ================")
    print(f"  {sum(PASS)}/{len(PASS)} checks passed")
    print("  server kick log:"); print("   "+"\n   ".join(S("docker logs qtest 2>&1 | grep -E 'CONTROL|disconnect|AUTH OK' | tail -6").splitlines()))
    sys.exit(0 if all(PASS) else 1)
finally:
    print("\n=== cleanup ===")
    S("docker rm -f qtest qcli >/dev/null 2>&1; pkill -9 -f 'ping -f' 2>/dev/null; ip link del kcli0 2>/dev/null; ip link del kd0 2>/dev/null; rm -rf /root/qk; true")
    print("[cleaned]")
    c.close()

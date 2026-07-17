#!/usr/bin/env python3
"""Route-push test in Docker: server container pushes `route = 172.16.20.0/24`,
client container connects with route_local=false (default) and =true.
Shows the same gate applies in containers. Creds via QELI_DOCKER_HOST/PASS.
"""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

H = os.environ["QELI_DOCKER_HOST"]; P = os.environ["QELI_DOCKER_PASS"]
IMG = os.environ.get("QELI_IMG", "qeli:latest")
NET = "qrt"
BASE = "/root/qrt-test"
SETC, CETC = BASE + "/server/etc", BASE + "/client/etc"
USER, PASS = "test", "testpass123"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
TARGET = "172.16.20.0/24"

SERVER_CONF = f"""[auth]
users_file = /etc/qeli/users.conf

[logging]
level = info

[profile:tcp]
identity_key = /etc/qeli/identity/tcp.key
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.8.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.8.0.0/24
pool.exclude = 10.8.0.1
routing.nat.enabled = true
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
route = {TARGET} metric=100
"""
USERS_CONF = f"[user:{USER}]\npassword_hash = {HASH}\nenabled = true\n"

def client_conf(pub, route_local):
    return f"""[qeli]
server = qeli-server:443
proto = tcp
user = {USER}
pass = {PASS}
key = {pub}
mode = fake-tls
sni = www.microsoft.com
dns = off
route_local = {str(route_local).lower()}

[logging]
level = info
"""

c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(H, username="root", password=P, timeout=25, look_for_keys=False, allow_agent=False)
def S(cmd, t=120):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()
def put(path, text):
    sf = c.open_sftp(); sf.putfo(io.BytesIO(text.encode()), path); sf.close()

print("=== prepare ===")
S("docker rm -f qeli-server qeli-client 2>/dev/null; true")
S(f"docker network rm {NET} 2>/dev/null; true")
S(f"rm -rf {BASE}; mkdir -p {SETC}/identity {CETC}")
put(SETC + "/server.conf", SERVER_CONF); put(SETC + "/users.conf", USERS_CONF)
S(f"docker network create {NET} >/dev/null")
print("image:", S(f"docker run --rm --entrypoint /usr/local/bin/qeli {IMG} --version"))
print(f"server pushes: route = {TARGET} metric=100")

S(f"docker run -d --name qeli-server --network {NET} --cap-add NET_ADMIN --cap-add NET_RAW "
  f"--device /dev/net/tun --sysctl net.ipv4.ip_forward=1 -v {SETC}:/etc/qeli {IMG} server >/dev/null")
pub = ""
for _ in range(15):
    time.sleep(1)
    pub = S("docker logs qeli-server 2>&1 | grep -oE 'pin on client\\): [0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | head -1")
    if pub: break
print("server pubkey:", pub[:16] + "…")

for rlocal in (False, True):
    print("\n" + "=" * 70)
    print(f"### client route_local = {rlocal}")
    S("docker rm -f qeli-client 2>/dev/null; true")
    put(CETC + "/client.conf", client_conf(pub, rlocal))
    S(f"docker run -d --name qeli-client --network {NET} --cap-add NET_ADMIN "
      f"--device /dev/net/tun -v {CETC}:/etc/qeli {IMG} client >/dev/null")
    ok = False
    for _ in range(20):
        time.sleep(1.5)
        if "Auth OK" in S("docker logs qeli-client 2>&1"):
            ok = True; break
    time.sleep(2)
    tbl = S(f"docker exec qeli-client ip route show 2>/dev/null | grep '{TARGET}' || echo '(no pushed route)'")
    lg = S("docker logs qeli-client 2>&1 | grep -iE 'Pushed route applied|invalid CIDR|Routing local networks' | tail -3 || true")
    print(f"  auth: {'OK' if ok else 'FAILED'}")
    print(f"  client route table ({TARGET}): {tbl}")
    print(f"  client logs: {lg or '(none)'}")
    print(f"  => pushed route present: {'YES' if TARGET in tbl else 'NO'}")

print("\n=== cleanup ===")
S("docker rm -f qeli-server qeli-client >/dev/null 2>&1; docker network rm " + NET + " >/dev/null 2>&1; true")
print("done")
c.close()

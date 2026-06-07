"""Verify per-profile identity keys, CLI subcommands, and per-profile authz."""
import os
import sys, json, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

S = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
C = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"

def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c
def run(c, cmd, t=40):
    i,o,e = c.exec_command(cmd, timeout=t)
    try: return o.read().decode("utf-8","replace") + e.read().decode("utf-8","replace")
    except Exception as ex: return f"[timeout {ex}]"

def client_cfg(user, port, proto, net, ifn):
    return json.dumps({
        "server":{"address":S[0],"port":port,"protocol":proto,"connection_timeout_secs":12,
                  "tcp_keepalive_secs":60,"reconnect":{"enabled":False}},
        "auth":{"username":user,"password_file":"/etc/qeli/pass.txt"},
        "tun":{"name":ifn,"mtu":1400},
        "routing":{"mode":"split-tunnel","include":[f"{net}.0/24"],"bypass_private":True,"bypass_local":True},
        "dns":{"mode":"off"},
        "performance":{"tcp_nodelay":True,"tun_buffer_size":65535,"idle_timeout_secs":0},
        "obfuscation":{"padding":{"enabled":True,"min_bytes":32,"max_bytes":256,"randomize":True,"probability":0.8},
                       "heartbeat":{"enabled":True,"interval_ms":15000},"fragmentation":{"enabled":False},"quic":{"enabled":False}},
        "logging":{"level":"info"},
    })

s = conn(S); cl = conn(C)

print("="*60, "\n1) CLI show-identity (generates per-profile keys)\n", "="*60)
print(run(s, "/usr/local/bin/qeli show-identity --config /etc/qeli/server.json 2>&1"))
print("--- key files in /etc/qeli/identity/ ---")
print(run(s, "ls -la /etc/qeli/identity/ 2>&1"))

print("="*60, "\n2) CLI rotate-identity udp (key must change)\n", "="*60)
before = run(s, "/usr/local/bin/qeli show-identity --config /etc/qeli/server.json 2>&1 | grep udp")
print("before:", before.strip())
print(run(s, "/usr/local/bin/qeli rotate-identity udp --config /etc/qeli/server.json 2>&1"))
after = run(s, "/usr/local/bin/qeli show-identity --config /etc/qeli/server.json 2>&1 | grep udp")
print("after :", after.strip())
print("KEY CHANGED:", before.split()[-1] != after.split()[-1] if before.split() and after.split() else "?")

print("="*60, "\n3) Per-profile authorization\n", "="*60)
# add restricted user tcponly (profiles=["tcp"]) alongside unrestricted 'load'
users = {"users":[
    {"username":"load","password_hash":HASH,"enabled":True,"bandwidth":{"limit_mbps":0}},
    {"username":"tcponly","password_hash":HASH,"enabled":True,"bandwidth":{"limit_mbps":0},"profiles":["tcp"]},
],"groups":{}}
sf = s.open_sftp(); import io
sf.putfo(io.BytesIO(json.dumps(users,indent=2).encode()), "/etc/qeli/users.json"); sf.close()

run(s, "pkill -9 -f 'qeli server'; sleep 1; nohup /usr/local/bin/qeli server --config /etc/qeli/server.json >/tmp/qs.log 2>&1 & echo ok")
time.sleep(2)

def try_client(user, port, proto, net, ifn, tag):
    cf = client_cfg(user, port, proto, net, ifn)
    sf = cl.open_sftp(); sf.putfo(io.BytesIO(cf.encode()), "/etc/qeli/client.json"); sf.close()
    run(cl, "pkill -9 -f 'qeli client'; sleep 1; nohup /usr/local/bin/qeli client --config /etc/qeli/client.json >/tmp/qc.log 2>&1 & echo ok")
    time.sleep(4)
    log = run(cl, "grep -E 'Auth OK|auth failed|assigned IP|Connection error|UDP: Auth' /tmp/qc.log | tail -4")
    run(cl, "pkill -9 -f 'qeli client'; sleep 1")
    print(f"  [{tag}] client log: {log.strip() or '(no auth result line)'}")

print("tcponly -> tcp profile (port 443): expect SUCCESS")
try_client("tcponly", 443, "tcp", "10.9.0", "vpn0", "tcponly@tcp")
print("tcponly -> udp profile (port 4443): expect DENIED")
try_client("tcponly", 4443, "udp", "10.10.0", "vpn1", "tcponly@udp")

print("--- server AUTH lines ---")
print(run(s, "grep -E 'AUTH OK|AUTH DENIED' /tmp/qs.log | tail -6"))
run(s, "pkill -9 -f 'qeli server'")
s.close(); cl.close()

"""Verify require_client_key_proof + new log format.

Server: auth.require_client_key_proof = true.
  A) client with the CORRECT pinned server key  -> ACCEPT
  B) client with NO server key                  -> DENY
  C) client with WRONG server key               -> DENY
"""
import sys, json, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import loadtest as lt

def out(c, cmd, t=40):
    rc, o, e = lt.run(c, cmd, t); return (o + e).strip()

s = lt.conn(lt.SERVER); cl = lt.conn(lt.CLIENT)
out(s, "pkill -9 -x qeli; sleep 1; true"); out(cl, "pkill -9 -x qeli; sleep 1; true")

scfg = {
    "profiles": [{
        "name": "tcp", "bind": {"address": "0.0.0.0", "port": 443, "transport": "tcp"},
        "tun": {"name": "vpn0", "address": "10.9.0.1", "netmask": "255.255.255.0", "mtu": 1400, "device_type": "tun"},
        "pool": {"cidr": "10.9.0.0/24", "exclude": ["10.9.0.1"]},
        "routing": {"nat": {"enabled": False}, "forward_private": True}, "dns": {"enabled": False},
        "obfuscation": {"padding": {"enabled": False}, "heartbeat": {"enabled": True, "interval_ms": 15000}, "fragmentation": {"enabled": False}},
        "performance": {"tcp": {"nodelay": True, "keepalive_secs": 60, "send_buffer_size": 262144, "recv_buffer_size": 262144},
                        "tun": {"read_buffer_size": 65535, "write_buffer_size": 65535, "read_timeout_ms": 10, "max_pending_packets": 256},
                        "connection": {"max_clients": 128, "handshake_timeout_secs": 10, "idle_timeout_secs": 0, "rate_limit_packets_per_sec": 1000000}},
    }],
    "auth": {"require_client_key_proof": True,
             "users": [{"username": "load", "password_hash": lt.ARGON2_HASH, "enabled": True}]},
    "logging": {"level": "info", "file": "/var/log/qeli/server.log"}, "web": {"enabled": False},
}
sf = s.open_sftp(); sf.putfo(io.BytesIO(json.dumps(scfg).encode()), "/etc/qeli/server.json"); sf.close()
# fetch the tcp profile public key
ident = out(s, "/usr/local/bin/qeli show-identity --config /etc/qeli/server.json 2>&1")
print("=== show-identity ===\n" + ident)
key = None
for line in ident.splitlines():
    if line.startswith("tcp "):
        key = line.split()[-1]
print("tcp profile key:", key)

out(s, "rm -f /var/log/qeli/server.log; nohup /usr/local/bin/qeli server --config /etc/qeli/server.json >/tmp/qs.log 2>&1 & echo ok")
time.sleep(3)

def client(server_key):
    c = {"server": {"address": lt.SERVER[0], "port": 443, "protocol": "tcp", "connection_timeout_secs": 8,
                    "tcp_keepalive_secs": 60, "reconnect": {"enabled": False}},
         "auth": {"username": "load", "password": "testpass123"},
         "tun": {"name": "vpn0", "mtu": 1400},
         "routing": {"mode": "split-tunnel", "include": ["10.9.0.0/24"]},
         "dns": {"mode": "off"},
         "performance": {"tcp_nodelay": True, "tun_buffer_size": 65535, "idle_timeout_secs": 0},
         "obfuscation": {"padding": {"enabled": False}, "heartbeat": {"enabled": True, "interval_ms": 15000}, "fragmentation": {"enabled": False}},
         "logging": {"level": "info"}}
    if server_key is not None:
        c["auth"]["server_public_key"] = server_key
    return c

def run_case(tag, server_key):
    cf = client(server_key)
    sf = cl.open_sftp(); sf.putfo(io.BytesIO(json.dumps(cf).encode()), "/etc/qeli/client.json"); sf.close()
    out(cl, "pkill -9 -x qeli; sleep 1; rm -f /tmp/qc.log; nohup /usr/local/bin/qeli client --config /etc/qeli/client.json >/tmp/qc.log 2>&1 & echo ok")
    time.sleep(4)
    res = out(cl, "grep -E 'Auth OK|auth failed|Connection error' /tmp/qc.log | tail -2")
    out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null")
    print(f"  [{tag}] {res or '(no result)'}")

print("\n=== A) correct pinned key -> expect ACCEPT ===");  run_case("correct-key", key)
print("=== B) no key -> expect DENY ===");                 run_case("no-key", None)
print("=== C) wrong key -> expect DENY ===");              run_case("wrong-key", "00"*32)

print("\n=== SERVER log (new format + AUTH/DENIED) ===")
print(out(s, "grep -E 'AUTH OK|AUTH DENIED' /var/log/qeli/server.log | tail -6"))
print("=== raw log line sample (format check, no T/Z) ===")
print(out(s, "tail -1 /var/log/qeli/server.log"))

out(s, "pkill -9 -x qeli")
s.close(); cl.close()

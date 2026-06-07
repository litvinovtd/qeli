"""Verify: inline credentials (client+server in JSON) and server route push."""
import sys, json, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import loadtest as lt

HASH = lt.ARGON2_HASH

# Server config: INLINE users (no users_file), profile tcp pushes a route.
server_cfg = {
    "profiles": [{
        "name": "tcp",
        "bind": {"address": "0.0.0.0", "port": 443, "transport": "tcp"},
        "tun": {"name": "vpn0", "address": "10.9.0.1", "netmask": "255.255.255.0", "mtu": 1400, "device_type": "tun"},
        "pool": {"cidr": "10.9.0.0/24", "exclude": ["10.9.0.1"]},
        "routing": {"nat": {"enabled": False}, "forward_private": True,
                    "advertised_routes": [{"cidr": "192.168.77.0/24", "metric": 50}]},
        "dns": {"enabled": False},
        "obfuscation": {"padding": {"enabled": True, "min_bytes": 16, "max_bytes": 128, "randomize": True, "probability": 0.8},
                        "heartbeat": {"enabled": True, "interval_ms": 15000}, "fragmentation": {"enabled": False}},
        "performance": {
            "tcp": {"nodelay": True, "keepalive_secs": 60, "send_buffer_size": 262144, "recv_buffer_size": 262144},
            "tun": {"read_buffer_size": 65535, "write_buffer_size": 65535, "read_timeout_ms": 10, "max_pending_packets": 256},
            "connection": {"max_clients": 128, "handshake_timeout_secs": 10, "idle_timeout_secs": 0, "rate_limit_packets_per_sec": 1000000}},
    }],
    "auth": {
        "users_file": "/nonexistent/should-not-be-used.json",  # proves inline wins
        "users": [{"username": "load", "password_hash": HASH, "enabled": True, "bandwidth": {"limit_mbps": 0}}],
    },
    "logging": {"level": "info", "file": "/var/log/qeli/server.log"},
    "web": {"enabled": False},
}

# Client config: INLINE password (no password_file), explicit add_default_gateway=false.
client_cfg = {
    "server": {"address": lt.SERVER[0], "port": 443, "protocol": "tcp",
               "connection_timeout_secs": 12, "tcp_keepalive_secs": 60, "reconnect": {"enabled": False}},
    "auth": {"username": "load", "password": "testpass123"},
    "tun": {"name": "vpn0", "mtu": 1400},
    "routing": {"mode": "split-tunnel", "add_default_gateway": False,
                "include": ["10.9.0.0/24"], "bypass_private": True, "bypass_local": True},
    "dns": {"mode": "off"},
    "performance": {"tcp_nodelay": True, "tun_buffer_size": 65535, "idle_timeout_secs": 0},
    "obfuscation": {"padding": {"enabled": True, "min_bytes": 16, "max_bytes": 128, "randomize": True, "probability": 0.8},
                    "heartbeat": {"enabled": True, "interval_ms": 15000}, "fragmentation": {"enabled": False}},
    "logging": {"level": "info"},
}

def out(c, cmd, t=40):
    rc, o, e = lt.run(c, cmd, t)
    return (o + e).strip()

s = lt.conn(lt.SERVER); cl = lt.conn(lt.CLIENT)
# stop any prior instances (exact process name 'qeli' — won't match the shell)
out(s, "pkill -9 -x qeli; sleep 1; true")
out(cl, "pkill -9 -x qeli; sleep 1; true")
sf = s.open_sftp(); sf.putfo(io.BytesIO(json.dumps(server_cfg, indent=2).encode()), "/etc/qeli/server.json"); sf.close()
out(s, "rm -f /var/log/qeli/server.log /etc/qeli/users.json")  # prove inline users used
sf = cl.open_sftp(); sf.putfo(io.BytesIO(json.dumps(client_cfg, indent=2).encode()), "/etc/qeli/client.json"); sf.close()
out(cl, "rm -f /etc/qeli/pass.txt")  # prove inline password used

out(s, "nohup /usr/local/bin/qeli server --config /etc/qeli/server.json >/tmp/qs.log 2>&1 & echo ok")
time.sleep(3)
print("=== server startup (stderr/tmp) ===")
print(out(s, "tail -3 /tmp/qs.log; echo '---'; tail -4 /var/log/qeli/server.log 2>/dev/null || echo 'no logfile'"))
out(cl, "nohup /usr/local/bin/qeli client --config /etc/qeli/client.json >/tmp/qc.log 2>&1 & echo ok")
time.sleep(5)

print("=== CLIENT log (auth + pushed routes) ===")
print(out(cl, "grep -E 'Auth OK|pushed|route|Connection error|auth failed' /tmp/qc.log | tail -6"))
print("=== CLIENT routing table (tun routes) ===")
print(out(cl, "ip route show | grep -E 'vpn0|192.168.77' || echo '(none)'"))
print("=== SERVER log (inline users + auth) ===")
print(out(s, "grep -E 'inline user|AUTH OK|advertis' /var/log/qeli/server.log | tail -6"))

out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; printf 'nameserver 1.1.1.1\\n' > /etc/resolv.conf")
out(s, "pkill -9 -x qeli")
s.close(); cl.close()

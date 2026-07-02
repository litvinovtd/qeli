#!/usr/bin/env python3
"""Diagnose why the 0.7.5 benchmark tunnel passed no traffic. Brings up ONE clean
fake-tls tunnel (server .10 / client .11) with a pinned key (H-1) and dumps the
actual interface addresses, routes, verbose ping, and iperf — to tell a real
0.7.5 data-plane regression from a lab/harness glitch."""
import os, sys, io, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
SH, CH = "10.66.116.10", "10.66.116.11"
BIN = "/usr/local/bin/qeli"
SRC_BIN = "/opt/qeli-src/target/release/qeli"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"


def conn(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    return c


def out(c, cmd, t=60):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


SERVER_CONF = f"""[auth]
[logging]
level = info
file = /var/log/qeli/server.log
[profile:bench]
identity_key = /etc/qeli/identity/bench.key
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.9.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.exclude = 10.9.0.1
routing.forward_private = true
routing.nat.enabled = false
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.cloudflare.com
obf.padding.enabled = false
obf.heartbeat.enabled = true
perf.connection.max_clients = 16
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0
[user:bench]
password_hash = {HASH}
enabled = true
"""


def client_conf(key):
    return f"""[qeli]
server = {SH}:443
proto = tcp
user = bench
pass = testpass123
mode = fake-tls
key = {key}
[logging]
level = info
"""


def main():
    s = conn(SH); cl = conn(CH)
    print("[bin]", out(s, f"{BIN} --version"), "| src", out(s, f"{SRC_BIN} --version"))
    print("\n=== pre-state interfaces ===")
    print(" .10 vpn*:", out(s, "ip -br addr show | grep -E 'vpn|tun' || echo none"))
    print(" .11 vpn*:", out(cl, "ip -br addr show | grep -E 'vpn|tun' || echo none"))

    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; ip link del vpn0 2>/dev/null; sleep 1; true")
    out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    out(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    sf = s.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), "/etc/qeli/diag-server.conf"); sf.close()
    key = re.search(r"[0-9a-f]{64}", out(s, f"{BIN} show-identity --config /etc/qeli/diag-server.conf 2>&1")).group(0)
    print("\n[server key]", key[:16], "…")
    out(s, f"rm -f /var/log/qeli/server.log; nohup {BIN} server --config /etc/qeli/diag-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    print("[.10 :443]", out(s, "ss -ltn | grep :443 || echo NOT-LISTENING"))
    print("[.10 vpn0 after server start]", out(s, "ip -br addr show vpn0 2>/dev/null || echo NO-VPN0"))

    sf = cl.open_sftp(); sf.putfo(io.BytesIO(client_conf(key).encode()), "/etc/qeli/diag-client.conf"); sf.close()
    out(cl, f"rm -f /tmp/qc.log; nohup {BIN} client --config /etc/qeli/diag-client.conf >/tmp/qc.log 2>&1 & echo ok")
    ok = False
    for _ in range(12):
        time.sleep(1.5)
        if "Auth OK" in out(cl, "grep -F 'Auth OK' /tmp/qc.log || true"):
            ok = True; break
    print("\n[client Auth OK]", ok)
    print("[client log tail]\n", out(cl, "tail -n 12 /tmp/qc.log"))
    print("\n=== post-connect state ===")
    print(" .10 vpn0:", out(s, "ip -br addr show vpn0 2>/dev/null || echo NO-VPN0"))
    print(" .11 vpn0:", out(cl, "ip -br addr show vpn0 2>/dev/null || echo NO-VPN0"))
    print(" .11 route to 10.9.0.1:", out(cl, "ip route get 10.9.0.1 2>&1 | head -1"))
    print(" .10 clients:", out(s, f"{BIN} list-clients 2>&1 | head -6"))
    print("\n=== ping .11 -> 10.9.0.1 (server tun gw) ===")
    print(out(cl, "ping -c 4 -i 0.3 -W 2 10.9.0.1 2>&1"))
    print("=== iperf .11 -> 10.9.0.1 ===")
    out(s, "pkill -9 iperf3 2>/dev/null; nohup iperf3 -s -B 10.9.0.1 >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)
    print("[.10 iperf3 -s bind]", out(s, "ss -ltn | grep 10.9.0.1 || echo BIND-FAILED"), "| log:", out(s, "tail -n 3 /tmp/is.log"))
    print(out(cl, "timeout 12 iperf3 -c 10.9.0.1 -t 4 2>&1 | tail -8"))
    print("\n=== server log tail ===\n", out(s, "tail -n 15 /var/log/qeli/server.log /tmp/qs.log"))

    out(s, "pkill -9 iperf3; pkill -9 -x qeli; ip link del vpn0 2>/dev/null; systemctl start qeli-server.service 2>/dev/null; true")
    out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; true")
    s.close(); cl.close()


if __name__ == "__main__":
    main()

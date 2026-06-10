#!/usr/bin/env python3
"""Reconfigure server to reality-tls mode."""
import os
import sys
import io
import time
import secrets
import paramiko

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

SERVER_IP = "138.124.78.35"
SERVER_USER = "root"
SERVER_PASS = os.environ.get("QELI_DEPLOY_PASS", "")  # never hardcode creds

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(SERVER_IP, username=SERVER_USER, password=SERVER_PASS, timeout=15)
print("[OK] Connected")

def run(cmd, timeout=120):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='ignore')
    err = stderr.read().decode('utf-8', errors='ignore')
    return (out + err).strip()

# Generate short_id (16 hex chars = 8 bytes)
short_id = secrets.token_hex(8)
print(f"[INFO] Generated short_id: {short_id}")

# 1. Write new server.conf with reality-tls
print("\n[1] Writing reality-tls server.conf...")
server_conf = f"""[auth]
users_file = /etc/qeli/users.conf
require_client_key_proof = false
brute_force.max_attempts = 5
brute_force.window_secs = 60
brute_force.lockout_secs = 300

[web]
enabled = false
bind = 0.0.0.0
port = 8080
username = admin

[logging]
level = info
file = /var/log/qeli/server.log

[profile:reality-tls]
enabled = true
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.10.10.1
tun.netmask = 255.255.255.0
tun.mtu = 1280
tun.queues = 0
pool.cidr = 10.10.10.0/24
pool.exclude = 10.10.10.1
routing.nat.enabled = true
dns.enabled = true
dns.listen = 10.10.10.1
dns.upstream = 1.1.1.1
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
obf.tls.reality_proxy.enabled = true
obf.tls.reality_proxy.target = www.microsoft.com
obf.tls.reality_proxy.target_port = 443
obf.tls.reality_proxy.short_ids = {short_id}
obf.tls.reality_proxy.real_tls = true
obf.tls.reality_proxy.handrolled = true
obf.padding.enabled = false
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 10000
obf.heartbeat.jitter_ms = 1000
obf.quic.enabled = false
obf.multipath.enabled = false
perf.tcp.nodelay = true
perf.tcp.keepalive_secs = 30
perf.connection.max_clients = 64
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 120
"""

sftp = ssh.open_sftp()
with sftp.open("/etc/qeli/server.conf", "w") as f:
    f.write(server_conf)
sftp.close()
print("  [OK] server.conf written")

# 2. MSS-clamping (critical for reality-tls)
print("\n[2] Setting up MSS-clamping...")
run("iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -o vpn+ -j TCPMSS --set-mss 1240 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o vpn+ -j TCPMSS --set-mss 1240")
run("iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -i vpn+ -j TCPMSS --set-mss 1240 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i vpn+ -j TCPMSS --set-mss 1240")
print("  [OK] MSS-clamp 1240 applied")

# 3. Delete old identity key (force new one for reality-tls profile)
print("\n[3] Resetting identity key...")
run("rm -f /etc/qeli/identity/tcp.key")
print("  [OK] Old key removed")

# 4. Restart server
print("\n[4] Restarting server...")
run("systemctl stop qeli")
time.sleep(2)
run("systemctl start qeli")
time.sleep(4)

status = run("systemctl is-active qeli")
print(f"  Status: {status}")

if status != "active":
    logs = run("journalctl -u qeli --no-pager -n 30 2>&1")
    print(f"  Logs:\n{logs}")
    sys.exit(1)

# 5. Get new server identity
print("\n[5] Server identity (reality-tls profile):")
identity = run("source $HOME/.cargo/env 2>/dev/null; qeli show-identity --config /etc/qeli/server.conf 2>&1")
print(f"  {identity}")

# Extract public key
server_pubkey = ""
for line in identity.split("\n"):
    parts = line.split()
    if len(parts) >= 3 and parts[0] == "reality-tls":
        server_pubkey = parts[2]
        break

if not server_pubkey:
    # Try any profile
    for line in identity.split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[2].startswith("http") == False and len(parts[2]) == 64:
            server_pubkey = parts[2]
            break

# 6. Verify TUN and logs
print("\n[6] Verifying...")
print(f"  TUN: {run('ip addr show vpn0 2>/dev/null | head -3')}")
print(f"  Logs: {run('journalctl -u qeli --no-pager -n 10 2>&1')}")

# 7. Summary
print("\n" + "=" * 60)
print("  REALITY-TLS DEPLOYMENT COMPLETE")
print("=" * 60)
print(f"  Server:       {SERVER_IP}:443")
print(f"  Mode:         reality-tls (真正的 TLS 1.3)")
print(f"  Target:       www.microsoft.com (cert-borrowing)")
print(f"  TUN:          10.10.10.0/24 (MTU 1280)")
print(f"  short_id:     {short_id}")
print(f"  Server Key:   {server_pubkey}")
print(f"  MSS-clamp:    1240")
print(f"")
print(f"  Client config [qeli] section:")
print(f"    server = {SERVER_IP}:443")
print(f"    proto = tcp")
print(f"    user = testuser")
print(f"    pass = TestPass123!")
print(f"    mode = reality-tls")
print(f"    key = {server_pubkey}")
print(f"    reality_sid = {short_id}")
print(f"    sni = www.microsoft.com")
print("=" * 60)

ssh.close()

#!/usr/bin/env python3
"""Finish deployment: systemd, user, NAT, start."""
import os
import sys
import io
import time
import paramiko

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

SERVER_IP = "138.124.78.35"
SERVER_USER = "root"
SERVER_PASS = os.environ.get("QELI_DEPLOY_PASS", "")  # never hardcode creds
VPN_USER = "testuser"
VPN_PASS = "TestPass123!"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(SERVER_IP, username=SERVER_USER, password=SERVER_PASS, timeout=15)
print("[OK] Connected")

def run(cmd, timeout=120):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='ignore')
    err = stderr.read().decode('utf-8', errors='ignore')
    return (out + err).strip()

# 1. Systemd service
print("\n[1] Setting up systemd...")
service_unit = """[Unit]
Description=Qeli VPN Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/qeli server --config /etc/qeli/server.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitNPROC=1024

[Install]
WantedBy=multi-user.target
"""

sftp = ssh.open_sftp()
with sftp.open("/etc/systemd/system/qeli.service", "w") as f:
    f.write(service_unit)
sftp.close()

run("systemctl daemon-reload")
run("systemctl enable qeli")
print("  [OK] Systemd service enabled")

# 2. IP forwarding + kernel tuning
print("\n[2] Configuring kernel...")
run("sysctl -w net.ipv4.ip_forward=1")
run("""cat >> /etc/sysctl.conf << 'EOF'
net.ipv4.ip_forward=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl -p 2>/dev/null
""")
print("  [OK] Kernel tuned (BBR, buffers)")

# 3. NAT
print("\n[3] Setting up NAT...")
run("iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -j MASQUERADE")
run("iptables -C FORWARD -s 10.10.10.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD -s 10.10.10.0/24 -j ACCEPT")
run("iptables -C FORWARD -d 10.10.10.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD -d 10.10.10.0/24 -j ACCEPT")
print("  [OK] NAT configured")

# 4. Create user
print("\n[4] Creating VPN user...")
result = run(f"source $HOME/.cargo/env 2>/dev/null; qeli add-client {VPN_USER} --password {VPN_PASS} --config /etc/qeli/server.conf 2>&1")
print(f"  {result}")

# 5. Show identity
print("\n[5] Server identity (public key):")
identity = run("source $HOME/.cargo/env 2>/dev/null; qeli show-identity --config /etc/qeli/server.conf 2>&1")
print(f"  {identity}")

# Extract public key
server_pubkey = ""
for line in identity.split("\n"):
    parts = line.split()
    if len(parts) >= 3 and parts[0] == "tcp":
        server_pubkey = parts[2]
        break

# 6. Start server
print("\n[6] Starting server...")
run("systemctl stop qeli 2>/dev/null")
time.sleep(1)
run("systemctl start qeli")
time.sleep(3)

status = run("systemctl is-active qeli")
print(f"  Status: {status}")

if status != "active":
    logs = run("journalctl -u qeli --no-pager -n 30 2>&1")
    print(f"  Logs:\n{logs}")

# 7. Verify config
print("\n[7] Verifying config...")
config_check = run("cat /etc/qeli/server.conf | head -20")
print(f"  Config head:\n{config_check}")

users_check = run("cat /etc/qeli/users.conf")
print(f"  Users:\n{users_check}")

print("\n" + "=" * 60)
print("  DEPLOYMENT COMPLETE")
print("=" * 60)
print(f"  Server:     {SERVER_IP}:443")
print(f"  Protocol:   TCP fake-tls")
print(f"  TUN:        10.10.10.0/24 (MTU 1280)")
print(f"  User:       {VPN_USER}")
print(f"  Password:   {VPN_PASS}")
print(f"  Server Key: {server_pubkey}")
print(f"")
print(f"  Client config [qeli] section:")
print(f"    server = {SERVER_IP}:443")
print(f"    proto = tcp")
print(f"    user = {VPN_USER}")
print(f"    pass = {VPN_PASS}")
print(f"    mode = fake-tls")
print(f"    sni = www.microsoft.com")
print(f"    key = {server_pubkey}")
print("=" * 60)

ssh.close()

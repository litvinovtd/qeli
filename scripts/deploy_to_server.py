#!/usr/bin/env python3
"""
Deploy Qeli VPN to a remote server.
- Uploads source code
- Builds on server (Linux-only binary)
- Installs binary + configs + systemd service
- Creates a test user
"""
import os
import sys
import time
import paramiko
import getpass

SERVER_IP = "YOUR_DEPLOY_HOST"
SERVER_USER = "root"
SERVER_PASS = os.environ.get("QELI_DEPLOY_PASS", "")  # never hardcode creds
LOCAL_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REMOTE_SRC = "/opt/qeli-src"
VPN_USER = "testuser"
VPN_PASS = "TestPass123!"

def connect():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(SERVER_IP, username=SERVER_USER, password=SERVER_PASS, timeout=15)
    print(f"[OK] Connected to {SERVER_IP}")
    return ssh

def run(ssh, cmd, timeout=300, label=""):
    if label:
        print(f"  {label}...")
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    combined = out + err
    if combined.strip():
        for line in combined.strip().split("\n")[-5:]:
            print(f"    {line}")
    return combined

def upload_source(ssh):
    print("\n[1/7] Uploading source code...")
    sftp = ssh.open_sftp()
    run(ssh, f"mkdir -p {REMOTE_SRC}")

    for root, dirs, files in os.walk(LOCAL_SRC):
        # Skip .git, target, native-libs, release, qeli-android, qeli-win, qeli-mac, site, test
        rel = os.path.relpath(root, LOCAL_SRC)
        skip_dirs = {'.git', 'target', 'native-libs', 'release', 'qeli-android',
                     'qeli-win', 'qeli-mac', 'site', 'test', '__pycache__', '.github',
                     'docs', 'scripts'}
        parts = rel.split(os.sep)
        if any(p in skip_dirs for p in parts):
            continue
        if any(p.startswith('.') for p in parts):
            continue

        remote_dir = os.path.join(REMOTE_SRC, rel).replace("\\", "/")
        run(ssh, f"mkdir -p {remote_dir}")

        for f in files:
            if f.endswith(('.pyc', '.class', '.o', '.so', '.dll', '.dylib')):
                continue
            local_path = os.path.join(root, f)
            remote_path = os.path.join(remote_dir, f).replace("\\", "/")
            try:
                sftp.put(local_path, remote_path)
            except Exception as e:
                print(f"    WARN: {f}: {e}")

    sftp.close()
    print("  [OK] Source uploaded")

def install_deps(ssh):
    print("\n[2/7] Installing dependencies...")
    run(ssh, "apt-get update -qq", timeout=120)
    run(ssh, "apt-get install -y -qq build-essential pkg-config libssl-dev iptables iproute2 curl", timeout=180)
    run(ssh, """
        if ! command -v cargo >/dev/null 2>&1; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        fi
    """, timeout=180)
    print("  [OK] Dependencies installed")

def build(ssh):
    print("\n[3/7] Building binary (this may take a few minutes)...")
    run(ssh, f"""
        cd {REMOTE_SRC}/qeli && \
        source $HOME/.cargo/env && \
        cargo build --release 2>&1
    """, timeout=600)
    # Check if binary exists
    result = run(ssh, f"ls -la {REMOTE_SRC}/qeli/target/release/qeli 2>&1")
    if "No such file" in result:
        print("  [FAIL] Build failed!")
        sys.exit(1)
    print("  [OK] Build successful")

def install_binary(ssh):
    print("\n[4/7] Installing binary and configs...")
    run(ssh, f"cp {REMOTE_SRC}/qeli/target/release/qeli /usr/bin/qeli")
    run(ssh, "chmod +x /usr/bin/qeli")
    run(ssh, "setcap cap_net_admin+ep /usr/bin/qeli || true")
    print("  [OK] Binary installed")

def setup_configs(ssh):
    print("\n[5/7] Setting up configurations...")
    run(ssh, "mkdir -p /etc/qeli /var/log/qeli /var/lib/qeli /etc/qeli/identity")

    # Server config
    server_conf = """[auth]
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

[profile:tcp]
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
obf.padding.enabled = true
obf.padding.min_bytes = 0
obf.padding.max_bytes = 128
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 10000
obf.heartbeat.jitter_ms = 1000
obf.quic.enabled = false
obf.multipath.enabled = false
perf.connection.max_clients = 64
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 120
"""
    # Write server config via heredoc
    run(ssh, f"cat > /etc/qeli/server.conf << 'SERVEREOF'\n{server_conf}\nSERVEREOF")

    # Users config (empty - we'll add user via CLI)
    users_conf = """# Users database - managed by qeli add-client
"""
    run(ssh, f"cat > /etc/qeli/users.conf << 'USERSEOF'\n{users_conf}\nUSERSEOF")

    print("  [OK] Configs created")

def setup_systemd(ssh):
    print("\n[6/7] Setting up systemd service...")
    service = """[Unit]
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
    run(ssh, f"cat > /etc/systemd/system/qeli.service << 'SVCEOF'\n{service}\nSVCEOF")
    run(ssh, "systemctl daemon-reload")
    run(ssh, "systemctl enable qeli")
    print("  [OK] Systemd service created")

def create_user_and_start(ssh):
    print("\n[7/7] Creating test user and starting server...")

    # Enable IP forwarding
    run(ssh, "sysctl -w net.ipv4.ip_forward=1")
    run(ssh, "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf")

    # Optimize kernel for VPN
    run(ssh, """
        cat >> /etc/sysctl.conf << 'SYSCTLEOF'
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYSCTLEOF
        sysctl -p
    """)

    # Create test user via qeli CLI
    result = run(ssh, f"""
        source $HOME/.cargo/env && \
        qeli add-client {VPN_USER} --password {VPN_PASS} --config /etc/qeli/server.conf 2>&1
    """)
    print(f"    User creation: {result.strip().split(chr(10))[-1]}")

    # Show server identity (public key for client pinning)
    result = run(ssh, """
        source $HOME/.cargo/env && \
        qeli show-identity --config /etc/qeli/server.conf 2>&1
    """)
    print(f"    Server identity:\n{result.strip()}")

    # Get the public key
    lines = result.strip().split("\n")
    server_pubkey = ""
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "tcp":
            server_pubkey = parts[2]
            break

    # Start the server
    run(ssh, "systemctl start qeli")
    time.sleep(3)

    # Check status
    result = run(ssh, "systemctl is-active qeli")
    status = result.strip()
    if status == "active":
        print("  [OK] Server is running!")
    else:
        print(f"  [WARN] Server status: {status}")
        result = run(ssh, "journalctl -u qeli --no-pager -n 20")
        print(f"    Logs:\n{result}")

    # Setup NAT
    run(ssh, "iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -j MASQUERADE")

    return server_pubkey

def main():
    print("=" * 60)
    print("  Qeli VPN Deployment")
    print(f"  Server: {SERVER_IP}")
    print("=" * 60)

    ssh = connect()

    try:
        upload_source(ssh)
        install_deps(ssh)
        build(ssh)
        install_binary(ssh)
        setup_configs(ssh)
        setup_systemd(ssh)
        pubkey = create_user_and_start(ssh)

        print("\n" + "=" * 60)
        print("  DEPLOYMENT COMPLETE")
        print("=" * 60)
        print(f"\n  Server:    {SERVER_IP}:443")
        print(f"  Protocol:  TCP fake-tls")
        print(f"  TUN:       10.10.10.0/24")
        print(f"  User:      {VPN_USER}")
        print(f"  Password:  {VPN_PASS}")
        print(f"  Server Key: {pubkey}")
        print(f"\n  Client config (client.conf):")
        print(f"    server = {SERVER_IP}:443")
        print(f"    proto = tcp")
        print(f"    user = {VPN_USER}")
        print(f"    pass = {VPN_PASS}")
        print(f"    mode = fake-tls")
        print(f"    sni = www.microsoft.com")
        print(f"    key = {pubkey}")
        print(f"\n  Management:")
        print(f"    systemctl status qeli")
        print(f"    journalctl -u qeli -f")
        print(f"    qeli list-clients")
        print("=" * 60)

    finally:
        ssh.close()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import paramiko
import time
import sys
import os
import io
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

SERVER_IP = "10.66.116.10"
CLIENT_IP = "10.66.116.11"
PASSWORD = os.environ.get("QELI_LAB_PASS", "")
USERNAME = "root"

LOCAL_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vpn-obfuscated")
REMOTE_DIR = "/opt/qeli-project"
BINARY = "qeli"

EXCLUDE_DIRS = {"target", ".git", "debian", "__pycache__"}

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

def connect(ip):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=USERNAME, password=PASSWORD, timeout=10)
    return ssh

def run(ssh, cmd, timeout=60, quiet=False):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    full = (out + err).strip()
    if not quiet and full:
        for line in full.split("\n"):
            log(f"  {line}")
    return exit_code, full

def upload_dir(sftp, local, remote):
    try:
        sftp.stat(remote)
    except FileNotFoundError:
        sftp.mkdir(remote)
    for item in os.listdir(local):
        if item in EXCLUDE_DIRS:
            continue
        lp = os.path.join(local, item)
        rp = f"{remote}/{item}"
        if os.path.isdir(lp):
            upload_dir(sftp, lp, rp)
        else:
            sftp.put(lp, rp)

def deploy(ip, role):
    log(f"{'='*50}")
    log(f"Deploying to {ip} ({role})")
    log(f"{'='*50}")

    ssh = connect(ip)
    sftp = ssh.open_sftp()

    # 1. Install Rust if needed
    log("[1/6] Checking Rust installation...")
    rc, _ = run(ssh, "command -v cargo", quiet=True)
    if rc != 0:
        log("  Installing Rust...")
        run(ssh, "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y", timeout=120)
        run(ssh, 'echo \'export PATH="$HOME/.cargo/bin:$PATH"\' >> /root/.bashrc')
    log("  Rust OK")

    # 2. Install build dependencies
    log("[2/6] Installing build dependencies...")
    run(ssh, "apt-get update -qq && apt-get install -y -qq build-essential pkg-config libssl-dev iperf3", timeout=120)
    log("  Dependencies OK")

    # 3. Upload source
    log(f"[3/6] Uploading source to {REMOTE_DIR}...")
    run(ssh, f"mkdir -p {REMOTE_DIR}")
    upload_dir(sftp, LOCAL_SRC, REMOTE_DIR)
    log("  Upload OK")

    # 4. Build
    log("[4/6] Building (cargo build --release)...")
    log("  This may take 5-10 minutes...")
    rc, out = run(ssh, f"cd {REMOTE_DIR} && source $HOME/.cargo/env && cargo build --release 2>&1 | tail -30", timeout=900)
    if "Finished" in out:
        log("  Build OK")
    else:
        log("  BUILD FAILED")
        log(out)
        ssh.close()
        return False

    # 5. Install binary
    log("[5/6] Installing binary...")
    run(ssh, f"cp {REMOTE_DIR}/target/release/{BINARY} /usr/local/bin/{BINARY}")
    run(ssh, f"chmod +x /usr/local/bin/{BINARY}")
    run(ssh, f"mkdir -p /etc/qeli")
    log(f"  Binary installed: /usr/local/bin/{BINARY}")

    # 6. Create config
    log("[6/6] Creating config...")
    if role == "server":
        config = {
            "bind": {"address": "0.0.0.0", "port": 443, "transport": "tcp"},
            "tun": {"name": "vpn0", "address": "10.8.0.1", "netmask": "255.255.255.0", "mtu": 1500, "tx_queue_len": 1000},
            "auth": {"users_file": "/etc/qeli/users.json", "password_hash": "argon2id", "token_ttl_secs": 86400},
            "pool": {"cidr": "10.8.0.0/24", "exclude": ["10.8.0.1"], "lease_time_secs": 3600, "static_reservations": {"admin": "10.8.0.10"}},
            "dns": {"enabled": True, "listen": "10.8.0.1", "port": 53, "upstream": ["1.1.1.1", "8.8.8.8"]},
            "obfuscation": {
                "cipher": "chacha20-poly1305",
                "tls": {"server_name": "www.cloudflare.com", "session_id": True,
                        "supported_groups": ["x25519", "secp256r1"], "key_share_entropy_bytes": 32,
                        "reality_proxy": {"enabled": False, "target": "www.cloudflare.com", "target_port": 443}},
                "padding": {"enabled": True, "min_bytes": 32, "max_bytes": 512, "randomize": True, "probability": 0.8},
                "fragmentation": {"enabled": True, "min_chunk_size": 64, "max_chunk_size": 512, "max_fragments_per_packet": 16},
                "heartbeat": {"enabled": True, "interval_ms": 50, "data_size_bytes": 16, "jitter_ms": 20},
                "traffic_normalization": {"enabled": False},
                "anti_fingerprinting": {"enabled": True, "rotate_ciphers_every": 300, "add_jitter_to_handshake": True}
            },
            "performance": {
                "tcp": {"nodelay": True, "keepalive_secs": 60, "send_buffer_size": 262144, "recv_buffer_size": 262144},
                "tun": {"read_buffer_size": 65535, "write_buffer_size": 65535, "read_timeout_ms": 10, "max_pending_packets": 256},
                "connection": {"max_clients": 128, "handshake_timeout_secs": 10, "idle_timeout_secs": 300, "rate_limit_packets_per_sec": 10000}
            },
            "logging": {"level": "info", "file": "/var/log/qeli/server.log"}
        }
        users = {
            "users": [{"username": "admin", "password_hash": "$argon2id$v=19$m=16384,t=2,p=1$dnBuLXNhbHQtMjAyNg$HKitPHloJ24C7g6Vx5nsArVhRBNzSczeYQm8Ij3vFW0", "enabled": True, "static_ip": "10.8.0.10"}],
            "groups": {"admin": {"bandwidth_limit_mbps": 100, "max_sessions": 3}}
        }
        import json
        with sftp.open("/etc/qeli/server.json", "w") as f:
            f.write(json.dumps(config, indent=2))
        with sftp.open("/etc/qeli/users.json", "w") as f:
            f.write(json.dumps(users, indent=2))
        log("  Server config created at /etc/qeli/server.json")
    else:
        config = {
            "server": {"address": SERVER_IP, "port": 443, "protocol": "tcp", "connection_timeout_secs": 30, "tcp_keepalive_secs": 60,
                       "reconnect": {"enabled": True, "max_retries": -1, "base_delay_secs": 1, "max_delay_secs": 60}},
            "auth": {"username": "admin", "password_file": "/etc/qeli/password.txt"},
            "tun": {"name": "vpn0", "mtu": 1500},
            "routing": {"mode": "full-tunnel", "include": ["10.8.0.0/24"], "bypass_local": True},
            "dns": {"mode": "tunnel", "servers": ["10.8.0.1", "1.1.1.1"]},
            "obfuscation": {"cipher": "chacha20-poly1305", "padding": {"enabled": True}, "heartbeat": {"enabled": True}},
            "performance": {"tcp_nodelay": True, "tun_buffer_size": 65535, "idle_timeout_secs": 300},
            "logging": {"level": "info"}
        }
        with sftp.open("/etc/qeli/password.txt", "w") as f:
            f.write("testpass123")
        with sftp.open("/etc/qeli/client.json", "w") as f:
            f.write(json.dumps(config, indent=2))
        log("  Client config created at /etc/qeli/client.json")

    # Verify
    log("\n  Verifying installation...")
    rc, out = run(ssh, f"/usr/local/bin/{BINARY} --help 2>&1 | head -3")
    log(f"  {out}")

    sftp.close()
    ssh.close()
    log(f"✓ {ip} ({role}) deployment complete")
    return True

def main():
    log("=" * 50)
    log("QELI VPN DEPLOYMENT v2")
    log(f"Server: {SERVER_IP}")
    log(f"Client: {CLIENT_IP}")
    log(f"Source: {LOCAL_SRC}")
    log("=" * 50)

    ok_server = deploy(SERVER_IP, "server")
    ok_client = deploy(CLIENT_IP, "client")

    log("=" * 50)
    log("SUMMARY")
    log(f"  Server ({SERVER_IP}): {'OK' if ok_server else 'FAILED'}")
    log(f"  Client ({CLIENT_IP}): {'OK' if ok_client else 'FAILED'}")
    if ok_server and ok_client:
        log("\nNext steps:")
        log(f"  SSH to {SERVER_IP} and run:")
        log(f"    /usr/local/bin/qeli server -c /etc/qeli/server.json &")
        log(f"  SSH to {CLIENT_IP} and run:")
        log(f"    echo testpass123 > /etc/qeli/password.txt")
        log(f"    /usr/local/bin/qeli client -c /etc/qeli/client.json &")
    log("=" * 50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nInterrupted")
    except Exception as e:
        log(f"Error: {e}")
        import traceback
        traceback.print_exc()

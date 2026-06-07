import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import json

print("=== Configuring 10.66.116.11 as VPN CLIENT ===\n")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# 1. Stop VPN service
print("1. Stopping VPN service...")
stdin, stdout, stderr = ssh.exec_command("systemctl stop vpn-obfuscated")
stdout.channel.recv_exit_status()

# 2. Create client config
print("2. Creating client config...")
client_config = {
    "server": {
        "address": "10.66.116.10",
        "port": 443,
        "connection_timeout_secs": 30,
        "reconnect": {
            "enabled": True,
            "max_retries": -1,
            "base_delay_secs": 1,
            "max_delay_secs": 60
        }
    },
    "auth": {
        "username": "admin",
        "password_file": "/etc/vpn-obfuscated/password.txt",
        "password_command": None
    },
    "tun": {
        "name": "vpn0",
        "mtu": 1500
    },
    "routing": {
        "mode": "full-tunnel",
        "include": ["10.8.0.0/24"],
        "exclude": [],
        "bypass_private": False,
        "bypass_local": True,
        "custom_routes": []
    },
    "dns": {
        "mode": "tunnel",
        "servers": ["10.8.0.1"],
        "redirect_all": False,
        "fallback_servers": ["1.1.1.1", "8.8.8.8"],
        "search_domains": [],
        "timeout_secs": 5
    },
    "obfuscation": {
        "cipher": "chacha20-poly1305",
        "padding": {
            "enabled": True,
            "min_bytes": 32,
            "max_bytes": 512,
            "randomize": True,
            "probability": 0.8
        },
        "heartbeat": {
            "enabled": True,
            "interval_ms": 50,
            "data_size_bytes": 16,
            "jitter_ms": 20
        },
        "fragmentation": {
            "enabled": True,
            "min_chunk_size": 64,
            "max_chunk_size": 512,
            "max_fragments_per_packet": 16
        }
    },
    "performance": {
        "tcp_nodelay": True,
        "send_buffer_size": 262144,
        "recv_buffer_size": 262144,
        "tun_buffer_size": 65535
    },
    "logging": {
        "level": "debug",
        "file": "/var/log/vpn-obfuscated/client.log",
        "format": "plain"
    }
}

# Create password file
print("3. Creating password file...")
stdin, stdout, stderr = ssh.exec_command("echo 'admin' > /etc/vpn-obfuscated/password.txt && chmod 600 /etc/vpn-obfuscated/password.txt")
stdout.channel.recv_exit_status()

# Write client config
config_json = json.dumps(client_config, indent=2)
stdin, stdout, stderr = ssh.exec_command("cat > /etc/vpn-obfuscated/client.json")
stdin.write(config_json)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()

# 4. Update systemd service to run as client
print("4. Updating systemd service...")
service_content = """[Unit]
Description=Obfuscated VPN Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/vpn-obfuscated client --config /etc/vpn-obfuscated/client.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"""

stdin, stdout, stderr = ssh.exec_command("cat > /etc/systemd/system/vpn-obfuscated.service")
stdin.write(service_content)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()

# Reload and start
print("5. Starting VPN client...")
stdin, stdout, stderr = ssh.exec_command("systemctl daemon-reload && systemctl start vpn-obfuscated")
stdout.channel.recv_exit_status()

# Wait a bit
import time
time.sleep(3)

# Check status
print("\n6. Checking status...")
stdin, stdout, stderr = ssh.exec_command("systemctl status vpn-obfuscated --no-pager")
print(stdout.read().decode(errors='replace'))

# Check logs
print("\n7. Recent logs:")
stdin, stdout, stderr = ssh.exec_command("journalctl -u vpn-obfuscated --no-pager -n 30")
print(stdout.read().decode(errors='replace'))

# Check interface
print("\n8. Network interfaces:")
stdin, stdout, stderr = ssh.exec_command("ip addr show vpn0 2>/dev/null || echo 'vpn0 not found'")
print(stdout.read().decode(errors='replace'))

ssh.close()
print("\nDone!")

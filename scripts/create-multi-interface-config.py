import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Create new multi-interface config structure
print("=== Creating multi-interface config system ===")

# 1. Create main config that lists all interfaces
main_config = """{
  "interfaces": [
    {
      "name": "office",
      "config_file": "/etc/vpn-obfuscated/interfaces/office.json"
    }
  ],
  "global": {
    "bind_address": "0.0.0.0",
    "bind_port": 443,
    "log_level": "info",
    "log_file": "/var/log/vpn-obfuscated/server.log"
  }
}
"""

# Create directory
stdin, stdout, stderr = ssh.exec_command("mkdir -p /etc/vpn-obfuscated/interfaces")
stdout.channel.recv_exit_status()

# Write main config
stdin, stdout, stderr = ssh.exec_command("cat > /etc/vpn-obfuscated/main.json")
stdin.write(main_config)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()
print("Created main.json")

# 2. Create per-interface config
office_config = """{
  "tun": {
    "name": "vpn0",
    "address": "10.8.0.1",
    "netmask": "255.255.255.0",
    "mtu": 1500,
    "tx_queue_len": 1000
  },
  "pool": {
    "cidr": "10.8.0.0/24",
    "exclude": ["10.8.0.1"],
    "lease_time_secs": 3600,
    "static_reservations": {
      "admin": "10.8.0.10"
    }
  },
  "auth": {
    "users_file": "/etc/vpn-obfuscated/users.json"
  },
  "routing": {
    "client_to_client": true,
    "nat": {
      "enabled": false
    },
    "forward_private": true,
    "push_routes": []
  },
  "dns": {
    "enabled": true,
    "listen": "10.8.0.1",
    "port": 53,
    "upstream": ["1.1.1.1", "8.8.8.8"],
    "upstream_protocol": "udp",
    "cache_size": 1000,
    "timeout_secs": 5,
    "blocklist": []
  },
  "obfuscation": {
    "cipher": "chacha20-poly1305",
    "tls": {
      "server_name": "www.cloudflare.com",
      "session_id": true,
      "supported_groups": ["x25519", "secp256r1"],
      "key_share_entropy_bytes": 32
    },
    "padding": {
      "enabled": true,
      "min_bytes": 32,
      "max_bytes": 512,
      "randomize": true,
      "probability": 0.8
    },
    "fragmentation": {
      "enabled": false,
      "min_chunk_size": 64,
      "max_chunk_size": 512,
      "max_fragments_per_packet": 16
    }
  },
  "dpd": {
    "enabled": true,
    "interval_secs": 30,
    "max_retries": 3
  },
  "performance": {
    "tcp": {
      "nodelay": true,
      "keepalive_secs": 60,
      "send_buffer_size": 262144,
      "recv_buffer_size": 262144
    },
    "tun": {
      "read_buffer_size": 65535,
      "write_buffer_size": 65535,
      "read_timeout_ms": 10,
      "max_pending_packets": 256
    },
    "connection": {
      "max_clients": 128,
      "handshake_timeout_secs": 10,
      "idle_timeout_secs": 300,
      "rate_limit_packets_per_sec": 10000
    }
  }
}
"""

stdin, stdout, stderr = ssh.exec_command("cat > /etc/vpn-obfuscated/interfaces/office.json")
stdin.write(office_config)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()
print("Created office.json")

# 3. Create example client config template
client_template = """{
  "server": {
    "address": "SERVER_IP",
    "port": 443,
    "connection_timeout_secs": 30,
    "tcp_keepalive_secs": 60,
    "reconnect": {
      "enabled": true,
      "max_retries": -1,
      "base_delay_secs": 1,
      "max_delay_secs": 60
    }
  },
  "auth": {
    "username": "USERNAME",
    "password_file": "/etc/vpn-obfuscated/password.txt",
    "password_command": null
  },
  "tun": {
    "name": "vpn0",
    "mtu": 1500
  },
  "routing": {
    "mode": "split-tunnel",
    "include": ["10.8.0.0/24"],
    "exclude": [],
    "bypass_private": false,
    "bypass_local": true,
    "custom_routes": []
  },
  "dns": {
    "mode": "tunnel",
    "servers": ["10.8.0.1"],
    "redirect_all": false,
    "fallback_servers": ["1.1.1.1", "8.8.8.8"],
    "search_domains": [],
    "timeout_secs": 5
  },
  "obfuscation": {
    "cipher": "chacha20-poly1305",
    "padding": {
      "enabled": true,
      "min_bytes": 32,
      "max_bytes": 512,
      "randomize": true,
      "probability": 0.8
    },
    "fragmentation": {
      "enabled": false,
      "min_chunk_size": 64,
      "max_chunk_size": 512,
      "max_fragments_per_packet": 16
    }
  },
  "dpd": {
    "enabled": true,
    "interval_secs": 30,
    "max_retries": 3
  },
  "performance": {
    "tcp_nodelay": true,
    "send_buffer_size": 262144,
    "recv_buffer_size": 262144,
    "tun_buffer_size": 65535,
    "idle_timeout_secs": 300
  },
  "logging": {
    "level": "info",
    "file": "/var/log/vpn-obfuscated/client.log",
    "format": "plain"
  }
}
"""

stdin, stdout, stderr = ssh.exec_command("cat > /etc/vpn-obfuscated/client-template.json")
stdin.write(client_template)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()
print("Created client-template.json")

# 4. Create systemd service for multi-interface
service_content = """[Unit]
Description=Obfuscated VPN Server (Multi-Interface)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/vpn-obfuscated server --config /etc/vpn-obfuscated/main.json
Restart=on-failure
RestartSec=5
StateDirectory=vpn-obfuscated
RuntimeDirectory=vpn-obfuscated

# Security hardening
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/etc/vpn-obfuscated /var/log/vpn-obfuscated /var/lib/vpn-obfuscated

[Install]
WantedBy=multi-user.target
"""

stdin, stdout, stderr = ssh.exec_command("cat > /etc/systemd/system/vpn-obfuscated.service")
stdin.write(service_content)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()
print("Created systemd service")

# Reload systemd
stdin, stdout, stderr = ssh.exec_command("systemctl daemon-reload")
stdout.channel.recv_exit_status()

print("\n=== Multi-interface config system created ===")
print("Structure:")
print("  /etc/vpn-obfuscated/main.json          - Main config (lists interfaces)")
print("  /etc/vpn-obfuscated/interfaces/*.json   - Per-interface configs")
print("  /etc/vpn-obfuscated/client-template.json - Client config template")
print("  /etc/vpn-obfuscated/users.json          - User database")
print("  /etc/vpn-obfuscated/password.txt        - Client password")

ssh.close()

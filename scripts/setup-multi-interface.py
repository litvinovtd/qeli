import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Simpler approach: keep current architecture, make config fully dynamic
# Each interface = separate server instance with its own config

print("=== Simplified multi-interface approach ===")
print("Each interface runs as a separate server instance")

# 1. Create interface-specific systemd service template
service_template = """[Unit]
Description=Obfuscated VPN Server - {INTERFACE_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/vpn-obfuscated server --config /etc/vpn-obfuscated/interfaces/{INTERFACE_NAME}.json
Restart=on-failure
RestartSec=5
StateDirectory=vpn-obfuscated
RuntimeDirectory=vpn-obfuscated

NoNewPrivileges=false
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/etc/vpn-obfuscated /var/log/vpn-obfuscated /var/lib/vpn-obfuscated

[Install]
WantedBy=multi-user.target
"""

# Create service for office interface
office_service = service_template.replace("{INTERFACE_NAME}", "office")
stdin, stdout, stderr = ssh.exec_command("cat > /etc/systemd/system/vpn-obfuscated-office.service")
stdin.write(office_service)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()
print("Created vpn-obfuscated-office.service")

# 2. Create a management script
mgmt_script = """#!/bin/bash
# VPN Interface Manager
# Usage: vpn-manager.sh <command> [interface] [options]

CONFIG_DIR="/etc/vpn-obfuscated/interfaces"
TEMPLATE="/etc/vpn-obfuscated/client-template.json"

case "$1" in
    add-interface)
        NAME="$2"
        TUN_NAME="${3:-vpn0}"
        SUBNET="${4:-10.8.0.0/24}"
        SERVER_IP="${5:-10.8.0.1}"
        
        if [ -z "$NAME" ]; then
            echo "Usage: $0 add-interface <name> [tun_name] [subnet] [server_ip]"
            exit 1
        fi
        
        # Create interface config
        cat > "$CONFIG_DIR/$NAME.json" << EOF
{
  "tun": {
    "name": "$TUN_NAME",
    "address": "$SERVER_IP",
    "netmask": "255.255.255.0",
    "mtu": 1500,
    "tx_queue_len": 1000
  },
  "pool": {
    "cidr": "$SUBNET",
    "exclude": ["$SERVER_IP"],
    "lease_time_secs": 3600,
    "static_reservations": {}
  },
  "auth": {
    "users_file": "/etc/vpn-obfuscated/users.json"
  },
  "routing": {
    "client_to_client": true,
    "nat": {
      "enabled": false,
      "interface": "eth0"
    },
    "forward_private": true,
    "push_routes": []
  },
  "dns": {
    "enabled": true,
    "listen": "$SERVER_IP",
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
EOF
        
        # Create systemd service
        cat > "/etc/systemd/system/vpn-obfuscated-$NAME.service" << EOF
[Unit]
Description=Obfuscated VPN Server - $NAME
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/vpn-obfuscated server --config $CONFIG_DIR/$NAME.json
Restart=on-failure
RestartSec=5
StateDirectory=vpn-obfuscated
RuntimeDirectory=vpn-obfuscated

NoNewPrivileges=false
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/etc/vpn-obfuscated /var/log/vpn-obfuscated /var/lib/vpn-obfuscated

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        echo "Interface '$NAME' created. Start with: systemctl enable --now vpn-obfuscated-$NAME.service"
        ;;
    
    add-client)
        INTERFACE="$2"
        USERNAME="$3"
        PASSWORD="$4"
        CLIENT_IP="${5:-auto}"
        
        if [ -z "$INTERFACE" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
            echo "Usage: $0 add-client <interface> <username> <password> [client_ip]"
            exit 1
        fi
        
        # Generate argon2 hash
        HASH=$(/usr/bin/vpn-obfuscated gen-hash --password "$PASSWORD")
        
        # Add to users.json
        python3 -c "
import json, sys
with open('/etc/vpn-obfuscated/users.json', 'r') as f:
    data = json.load(f)

# Check if user exists
for user in data['users']:
    if user['username'] == '$USERNAME':
        print(f'User $USERNAME already exists')
        sys.exit(1)

# Add new user
user_entry = {
    'username': '$USERNAME',
    'password_hash': '$HASH',
    'static_ip': '$CLIENT_IP' if '$CLIENT_IP' != 'auto' else None,
    'enabled': True,
    'bandwidth': {
        'limit_mbps': 100,
        'burst_mbps': 150
    },
    'allowed_networks': ['0.0.0.0/0'],
    'group': 'premium',
    'metadata': {
        'email': '',
        'notes': 'Added via vpn-manager'
    }
}
data['users'].append(user_entry)

with open('/etc/vpn-obfuscated/users.json', 'w') as f:
    json.dump(data, f, indent=2)
print(f'User $USERNAME added')
"
        
        # Create client config
        SERVER_IP=$(grep -o '"address": *"[^"]*"' "$CONFIG_DIR/$INTERFACE.json" | head -1 | cut -d'"' -f4)
        SERVER_PORT=$(grep -o '"port": *[0-9]*' "$CONFIG_DIR/$INTERFACE.json" | head -1 | grep -o '[0-9]*')
        TUN_SUBNET=$(grep -o '"cidr": *"[^"]*"' "$CONFIG_DIR/$INTERFACE.json" | head -1 | cut -d'"' -f4)
        DNS_IP=$(grep -o '"listen": *"[^"]*"' "$CONFIG_DIR/$INTERFACE.json" | head -1 | cut -d'"' -f4)
        
        mkdir -p /etc/vpn-obfuscated/clients/$INTERFACE
        cat > "/etc/vpn-obfuscated/clients/$INTERFACE/$USERNAME.json" << EOF
{
  "server": {
    "address": "$SERVER_IP",
    "port": $SERVER_PORT,
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
    "username": "$USERNAME",
    "password_file": "/etc/vpn-obfuscated/clients/$INTERFACE/$USERNAME.pass",
    "password_command": null
  },
  "tun": {
    "name": "vpn0",
    "mtu": 1500
  },
  "routing": {
    "mode": "split-tunnel",
    "include": ["$TUN_SUBNET"],
    "exclude": [],
    "bypass_private": false,
    "bypass_local": true,
    "custom_routes": []
  },
  "dns": {
    "mode": "tunnel",
    "servers": ["$DNS_IP"],
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
    "file": "/var/log/vpn-obfuscated/client-$USERNAME.log",
    "format": "plain"
  }
}
EOF
        
        echo -n "$PASSWORD" > "/etc/vpn-obfuscated/clients/$INTERFACE/$USERNAME.pass"
        chmod 600 "/etc/vpn-obfuscated/clients/$INTERFACE/$USERNAME.pass"
        
        echo "Client '$USERNAME' created for interface '$INTERFACE'"
        echo "Config: /etc/vpn-obfuscated/clients/$INTERFACE/$USERNAME.json"
        ;;
    
    list-interfaces)
        echo "Configured interfaces:"
        for f in "$CONFIG_DIR"/*.json; do
            if [ -f "$f" ]; then
                NAME=$(basename "$f" .json)
                TUN=$(grep -o '"name": *"[^"]*"' "$f" | head -1 | cut -d'"' -f4)
                ADDR=$(grep -o '"address": *"[^"]*"' "$f" | head -1 | cut -d'"' -f4)
                CIDR=$(grep -o '"cidr": *"[^"]*"' "$f" | head -1 | cut -d'"' -f4)
                echo "  $NAME: TUN=$TUN, Server=$ADDR, Pool=$CIDR"
            fi
        done
        ;;
    
    list-clients)
        INTERFACE="$2"
        if [ -n "$INTERFACE" ]; then
            echo "Clients for interface '$INTERFACE':"
            for f in "/etc/vpn-obfuscated/clients/$INTERFACE"/*.json; do
                if [ -f "$f" ]; then
                    NAME=$(basename "$f" .json)
                    echo "  $NAME"
                fi
            done
        else
            echo "All clients:"
            for dir in /etc/vpn-obfuscated/clients/*/; do
                if [ -d "$dir" ]; then
                    INT=$(basename "$dir")
                    echo "  Interface: $INT"
                    for f in "$dir"*.json; do
                        if [ -f "$f" ]; then
                            NAME=$(basename "$f" .json)
                            echo "    - $NAME"
                        fi
                    done
                fi
            done
        fi
        ;;
    
    status)
        echo "VPN Services:"
        systemctl list-units --type=service --state=running 'vpn-obfuscated*' --no-pager
        echo ""
        echo "TUN Interfaces:"
        ip addr show | grep -A 2 'vpn'
        ;;
    
    *)
        echo "VPN Interface Manager"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  add-interface <name> [tun] [subnet] [server_ip]  - Create new VPN interface"
        echo "  add-client <interface> <user> <pass> [ip]        - Add client to interface"
        echo "  list-interfaces                                  - List all interfaces"
        echo "  list-clients [interface]                         - List clients"
        echo "  status                                           - Show running services"
        echo "  help                                             - Show this help"
        ;;
esac
"""

stdin, stdout, stderr = ssh.exec_command("cat > /usr/local/bin/vpn-manager.sh")
stdin.write(mgmt_script)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()

stdin, stdout, stderr = ssh.exec_command("chmod +x /usr/local/bin/vpn-manager.sh")
stdout.channel.recv_exit_status()

print("Created vpn-manager.sh")

# 3. Restore the original server mod.rs (single interface)
print("\n=== Restoring original server mod.rs ===")
# We need to get the original working version
# Let me read the current one and fix it

# Read current handler.rs to make sure it's working
stdin, stdout, stderr = ssh.exec_command("grep -c 'dpd' /root/vpn_project/src/server/handler.rs")
handler_dpd_count = int(stdout.read().decode(errors='replace').strip())
print(f"handler.rs has {handler_dpd_count} DPD references")

# The server mod.rs was overwritten with incomplete multi-interface code
# Let me restore it from the working version
# First, let me check what we have
stdin, stdout, stderr = ssh.exec_command("wc -l /root/vpn_project/src/server/mod.rs")
print(f"Current mod.rs: {stdout.read().decode(errors='replace').strip()} lines")

ssh.close()

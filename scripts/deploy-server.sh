#!/bin/bash
# OBSOLETE — targets the removed `vpn-obfuscated` binary + JSON config (pre flat-INI);
# superseded by install-reality-server.sh. Kept for reference only.
echo "OBSOLETE: deploy-server.sh targets the removed vpn-obfuscated/JSON layout; use install-reality-server.sh." >&2
exit 1

set -euo pipefail

# Qeli VPN Server Deployment Script
# Usage: sudo bash deploy-server.sh [interface_name] [server_ip] [port]

INTERFACE_NAME="${1:-office}"
SERVER_ADDRESS="${2:-0.0.0.0}"
SERVER_PORT="${3:-443}"
TUN_ADDRESS="${4:-10.8.0.1}"
TUN_NETMASK="${5:-255.255.255.0}"
POOL_CIDR="${6:-10.8.0.0/24}"

echo "=== Qeli VPN Server Deployment ==="
echo "Interface: $INTERFACE_NAME"
echo "Bind: $SERVER_ADDRESS:$SERVER_PORT"
echo "TUN: $TUN_ADDRESS/$TUN_NETMASK"
echo "Pool: $POOL_CIDR"

# 1. Install dependencies
echo ""
echo "[1/7] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq iptables iproute2 iperf3 2>/dev/null || true

# 2. Create directories
echo "[2/7] Creating directories..."
mkdir -p /etc/qeli/interfaces
mkdir -p /etc/qeli/clients
mkdir -p /var/log/qeli
mkdir -p /var/lib/qeli

# 3. Install binary
echo "[3/7] Installing qeli binary..."
if [ -f "./target/release/qeli" ]; then
    cp target/release/qeli /usr/bin/qeli
elif [ -f "./qeli" ]; then
    cp qeli /usr/bin/qeli
else
    echo "ERROR: qeli binary not found. Build with 'cargo build --release' first."
    exit 1
fi
chmod +x /usr/bin/qeli
setcap cap_net_admin+ep /usr/bin/qeli

# 4. Generate server identity key if not exists
echo "[4/7] Checking server identity key..."
if [ ! -f /var/lib/qeli/server_identity.key ]; then
    dd if=/dev/urandom of=/var/lib/qeli/server_identity.key bs=32 count=1 2>/dev/null
    chmod 600 /var/lib/qeli/server_identity.key
    echo "  Generated new server identity key"
else
    echo "  Server identity key already exists"
fi

# 5. Create users database
echo "[5/7] Creating users database..."
if [ ! -f /etc/qeli/users.json ]; then
    # Generate argon2id hash for default password "changeme"
    # Install argon2 command-line tool if available
    if command -v argon2 &> /dev/null; then
        SALT=$(openssl rand -hex 16)
        HASH=$(echo -n "changeme" | argon2 "$SALT" -id -t 3 -m 65536 -p 4 -l 32 -e)
        cat > /etc/qeli/users.json << EOF
[
  {
    "username": "admin",
    "password_hash": "\$argon2id\$v=19\$m=65536,t=3,p=4\$${SALT}\$${HASH}",
    "enabled": true
  }
]
EOF
    else
        echo '  argon2 not found, creating placeholder. Run: apt install argon2'
        cat > /etc/qeli/users.json << 'EOF'
[
  {
    "username": "admin",
    "password_hash": "REPLACE_WITH_ARGON2ID_HASH",
    "enabled": true
  }
]
EOF
    fi
    echo "  Created /etc/qeli/users.json (default user: admin)"
else
    echo "  users.json already exists"
fi

# 6. Create server config
echo "[6/7] Creating server configuration..."
cat > "/etc/qeli/interfaces/${INTERFACE_NAME}.json" << EOF
{
  "bind": {
    "address": "${SERVER_ADDRESS}",
    "port": ${SERVER_PORT},
    "transport": "tcp"
  },
  "tun": {
    "name": "vpn0",
    "address": "${TUN_ADDRESS}",
    "netmask": "${TUN_NETMASK}",
    "mtu": 1500,
    "tx_queue_len": 1000
  },
  "auth": {
    "users_file": "/etc/qeli/users.json",
    "password_hash": "argon2id"
  },
  "pool": {
    "cidr": "${POOL_CIDR}",
    "exclude": ["${TUN_ADDRESS}"],
    "lease_time_secs": 3600
  },
  "dns": {
    "enabled": true,
    "listen": "${TUN_ADDRESS}",
    "port": 53,
    "upstream": ["1.1.1.1", "8.8.8.8"],
    "upstream_protocol": "udp",
    "cache_size": 1000,
    "timeout_secs": 5
  },
  "obfuscation": {
    "cipher": "chacha20-poly1305",
    "tls": {
      "server_name": "www.cloudflare.com"
    },
    "padding": {
      "enabled": true,
      "min_bytes": 32,
      "max_bytes": 512,
      "randomize": true,
      "probability": 0.8
    },
    "heartbeat": {
      "enabled": true,
      "interval_ms": 50,
      "data_size_bytes": 16,
      "jitter_ms": 20
    },
    "traffic_normalization": {
      "enabled": false,
      "round_sizes": [64, 128, 256, 512, 1024, 1500]
    }
  },
  "performance": {
    "tcp": {
      "nodelay": true,
      "keepalive_secs": 60
    },
    "tun": {
      "read_buffer_size": 65535,
      "write_buffer_size": 65535
    },
    "connection": {
      "max_clients": 128,
      "handshake_timeout_secs": 10,
      "idle_timeout_secs": 300
    }
  },
  "logging": {
    "level": "info",
    "file": "/var/log/qeli/server.log"
  }
}
EOF
echo "  Created /etc/qeli/interfaces/${INTERFACE_NAME}.json"

# 7. Create systemd service
echo "[7/7] Creating systemd service..."
cat > /etc/systemd/system/qeli-${INTERFACE_NAME}.service << EOF
[Unit]
Description=Qeli VPN Server (${INTERFACE_NAME})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/qeli server --config /etc/qeli/interfaces/${INTERFACE_NAME}.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitNPROC=1024

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "qeli-${INTERFACE_NAME}"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Configuration: /etc/qeli/interfaces/${INTERFACE_NAME}.json"
echo "Users:          /etc/qeli/users.json"
echo "Service:        qeli-${INTERFACE_NAME}.service"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/qeli/users.json - set proper argon2id password hashes"
echo "  2. Edit /etc/qeli/interfaces/${INTERFACE_NAME}.json - adjust settings"
echo "  3. Enable IP forwarding: sysctl -w net.ipv4.ip_forward=1"
echo "  4. Setup NAT: iptables -t nat -A POSTROUTING -s ${POOL_CIDR} -o eth0 -j MASQUERADE"
echo "  5. Start: systemctl start qeli-${INTERFACE_NAME}"
echo "  6. Check:  systemctl status qeli-${INTERFACE_NAME}"
echo "  7. Logs:    journalctl -u qeli-${INTERFACE_NAME} -f"
echo ""
echo "  Default user: admin"
echo "  To generate password hash: echo -n 'YOUR_PASSWORD' | argon2 SALT -id -t 3 -m 65536 -p 4 -l 32 -e"
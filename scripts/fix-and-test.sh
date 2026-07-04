#!/bin/bash
# OBSOLETE — targets the removed `vpn-obfuscated` binary + JSON config (pre flat-INI);
# superseded by install-reality-server.sh. Kept for reference only.
echo "OBSOLETE: fix-and-test.sh targets the removed vpn-obfuscated/JSON layout; use install-reality-server.sh." >&2
exit 1

# Auto-fix VPN and Run Tests
# Запуск на обоих серверах: ./fix-and-test.sh [server|client]

set -e

ROLE=${1:-server}
SERVER_IP="10.66.116.10"
CLIENT_IP="10.66.116.11"

echo "=========================================="
echo "VPN Auto-Fix and Test Script"
echo "Role: $ROLE"
echo "Date: $(date)"
echo "=========================================="
echo ""

# Функция для логирования
log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# 1. Диагностика
log "[1/10] Running diagnostics..."
echo ""

# Проверка процесса
if pgrep -f vpn-obfuscated > /dev/null; then
    log "✓ VPN process is running"
    ps aux | grep vpn-obfuscated | grep -v grep | head -1
else
    log "✗ VPN process NOT running"
fi
echo ""

# Проверка TUN интерфейса
if ip link show | grep -q "vpn0"; then
    log "✓ TUN interface vpn0 exists"
    ip addr show vpn0 2>/dev/null | grep inet || echo "  No IP assigned"
else
    log "✗ TUN interface vpn0 NOT found"
fi
echo ""

# Проверка портов
log "Checking listening ports..."
ss -tlnp | grep -E "443|vpn" || echo "  No VPN ports listening"
echo ""

# Проверка маршрутов
log "Checking routes..."
ip route show | grep -E "10.8.0|vpn0" || echo "  No VPN routes found"
echo ""

# 2. Остановка старых процессов
log "[2/10] Stopping old VPN processes..."
systemctl stop vpn-obfuscated 2>/dev/null || true
pkill -9 vpn-obfuscated 2>/dev/null || true
sleep 2
log "✓ Old processes stopped"
echo ""

# 3. Проверка конфигурации
log "[3/10] Checking configuration..."
CONFIG_DIR="/etc/vpn-obfuscated"
mkdir -p $CONFIG_DIR

if [ "$ROLE" = "server" ]; then
    if [ ! -f "$CONFIG_DIR/server.json" ]; then
        log "Creating server configuration..."
        cat > $CONFIG_DIR/server.json <<'EOF'
{
  "bind": {
    "address": "0.0.0.0",
    "port": 443
  },
  "tun": {
    "name": "vpn0",
    "address": "10.8.0.1",
    "netmask": "255.255.255.0",
    "mtu": 1500,
    "tx_queue_len": 1000
  },
  "auth": {
    "users_file": "/etc/vpn-obfuscated/users.json",
    "password_hash": "argon2id",
    "token_ttl_secs": 86400
  },
  "pool": {
    "cidr": "10.8.0.0/24",
    "exclude": ["10.8.0.1"],
    "lease_time_secs": 3600,
    "static_reservations": {
      "admin": "10.8.0.10"
    }
  },
  "routing": {
    "client_to_client": true,
    "nat": {
      "enabled": true,
      "interface": "eth0"
    },
    "forward_private": true
  },
  "dns": {
    "enabled": false,
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
      "enabled": false,
      "min_bytes": 0,
      "max_bytes": 0,
      "randomize": false,
      "probability": 0.0
    },
    "fragmentation": {
      "enabled": false,
      "min_chunk_size": 64,
      "max_chunk_size": 512,
      "max_fragments_per_packet": 16
    },
    "heartbeat": {
      "enabled": true,
      "interval_ms": 1000,
      "data_size_bytes": 16,
      "jitter_ms": 100
    },
    "http2_masking": {
      "enabled": false,
      "ratio": 0.1
    },
    "traffic_normalization": {
      "enabled": false,
      "round_sizes": [64, 128, 256, 512, 1024, 1500],
      "randomize_sequence": false
    },
    "anti_fingerprinting": {
      "enabled": false,
      "rotate_ciphers_every": 300,
      "add_jitter_to_handshake": true
    }
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
  },
  "logging": {
    "level": "info",
    "file": "/var/log/vpn-obfuscated/server.log",
    "format": "plain",
    "rotation": {
      "max_size_mb": 100,
      "max_files": 7,
      "compress": true
    }
  }
}
EOF
        log "✓ Server config created"
    else
        log "✓ Server config exists"
    fi
    
    # Создание users.json
    if [ ! -f "$CONFIG_DIR/users.json" ]; then
        log "Creating users configuration..."
        cat > $CONFIG_DIR/users.json <<'EOF'
{
  "users": [
    {
      "username": "admin",
      "password_hash": "$argon2id$v=19$m=16384,t=2,p=1$dnBuLXNhbHQtMjAyNg$HKitPHloJ24C7g6Vx5nsArVhRBNzSczeYQm8Ij3vFW0",
      "static_ip": "10.8.0.10",
      "enabled": true,
      "bandwidth": {
        "limit_mbps": 100,
        "burst_mbps": 150
      },
      "allowed_networks": ["0.0.0.0/0"],
      "group": "premium",
      "metadata": {
        "email": "admin@example.com",
        "notes": "Full access"
      }
    }
  ],
  "groups": {
    "premium": {
      "bandwidth_limit_mbps": 100,
      "max_sessions": 3,
      "allowed_networks": ["0.0.0.0/0"]
    }
  }
}
EOF
        log "✓ Users config created"
    fi
else
    if [ ! -f "$CONFIG_DIR/client.json" ]; then
        log "Creating client configuration..."
        cat > $CONFIG_DIR/client.json <<EOF
{
  "server": {
    "address": "$SERVER_IP",
    "port": 443,
    "connection_timeout_secs": 30,
    "reconnect": {
      "enabled": true,
      "max_retries": -1,
      "base_delay_secs": 1,
      "max_delay_secs": 60
    }
  },
  "auth": {
    "username": "admin",
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
    "bypass_private": true,
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
      "enabled": false,
      "min_bytes": 0,
      "max_bytes": 0,
      "randomize": false,
      "probability": 0.0
    },
    "heartbeat": {
      "enabled": true,
      "interval_ms": 1000,
      "data_size_bytes": 16,
      "jitter_ms": 100
    },
    "fragmentation": {
      "enabled": false,
      "min_chunk_size": 64,
      "max_chunk_size": 512,
      "max_fragments_per_packet": 16
    }
  },
  "performance": {
    "tcp_nodelay": true,
    "send_buffer_size": 262144,
    "recv_buffer_size": 262144,
    "tun_buffer_size": 65535
  },
  "logging": {
    "level": "info",
    "file": "/var/log/vpn-obfuscated/client.log",
    "format": "plain"
  }
}
EOF
        log "✓ Client config created"
    else
        log "✓ Client config exists"
    fi
    
    # Создание password.txt
    if [ ! -f "$CONFIG_DIR/password.txt" ]; then
        echo "testpass123" > $CONFIG_DIR/password.txt
        chmod 600 $CONFIG_DIR/password.txt
        log "✓ Password file created"
    fi
fi
echo ""

# 4. Проверка бинарника
log "[4/10] Checking VPN binary..."
if [ ! -f /usr/local/bin/vpn-obfuscated ]; then
    log "✗ VPN binary not found at /usr/local/bin/vpn-obfuscated"
    log "Please build and install VPN binary first:"
    log "  cargo build --release"
    log "  cp target/release/vpn-obfuscated /usr/local/bin/"
    exit 1
else
    log "✓ VPN binary found"
    /usr/local/bin/vpn-obfuscated --version 2>&1 || echo "  Version info not available"
fi
echo ""

# 5. Создание лог директории
log "[5/10] Setting up logging..."
mkdir -p /var/log/vpn-obfuscated
mkdir -p /var/lib/vpn-obfuscated
log "✓ Log directories ready"
echo ""

# 6. Запуск VPN
log "[6/10] Starting VPN..."
if [ "$ROLE" = "server" ]; then
    nohup /usr/local/bin/vpn-obfuscated server -c /etc/vpn-obfuscated/server.json > /var/log/vpn-obfuscated/server.log 2>&1 &
else
    nohup /usr/local/bin/vpn-obfuscated client -c /etc/vpn-obfuscated/client.json > /var/log/vpn-obfuscated/client.log 2>&1 &
fi
sleep 3

# Проверка что процесс запустился
if pgrep -f vpn-obfuscated > /dev/null; then
    log "✓ VPN started successfully"
    ps aux | grep vpn-obfuscated | grep -v grep | head -1
else
    log "✗ VPN failed to start"
    log "Checking logs..."
    tail -20 /var/log/vpn-obfuscated/*.log 2>/dev/null || echo "  No logs available"
    exit 1
fi
echo ""

# 7. Ожидание инициализации
log "[7/10] Waiting for VPN initialization..."
sleep 5

# Проверка TUN интерфейса
if ip link show | grep -q "vpn0"; then
    log "✓ TUN interface created"
    ip addr show vpn0 2>/dev/null | grep inet || echo "  Waiting for IP..."
else
    log "✗ TUN interface not created"
    log "Checking logs..."
    tail -20 /var/log/vpn-obfuscated/*.log 2>/dev/null || echo "  No logs available"
fi
echo ""

# 8. Проверка соединения (только на клиенте)
if [ "$ROLE" = "client" ]; then
    log "[8/10] Testing VPN connection..."
    sleep 3
    
    # Пинг VPN gateway
    if ping -c 3 -W 2 10.8.0.1 > /dev/null 2>&1; then
        log "✓ VPN gateway (10.8.0.1) is reachable"
    else
        log "✗ VPN gateway (10.8.0.1) NOT reachable"
    fi
    
    # Пинг VPN client IP
    if ping -c 3 -W 2 10.8.0.10 > /dev/null 2>&1; then
        log "✓ VPN client (10.8.0.10) is reachable"
    else
        log "✗ VPN client (10.8.0.10) NOT reachable"
    fi
else
    log "[8/10] Skipping connection test (server mode)"
fi
echo ""

# 9. Установка инструментов для тестов
log "[9/10] Installing benchmark tools..."
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq iperf3 sysstat bc jq > /dev/null 2>&1
log "✓ Tools installed"
echo ""

# 10. Запуск тестов (только на клиенте)
if [ "$ROLE" = "client" ]; then
    log "[10/10] Running performance tests..."
    echo ""
    
    # Запуск iperf3 сервера на server
    log "Starting iperf3 server on $SERVER_IP..."
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$SERVER_IP "pkill -9 iperf3 || true; nohup iperf3 -s > /dev/null 2>&1 &" 2>/dev/null || true
    sleep 2
    
    # Тест 1: Direct connection
    log "Test 1: Direct connection ($SERVER_IP)..."
    iperf3 -c $SERVER_IP -t 10 -P 4 -J > /tmp/test_direct.json 2>&1 || true
    if [ -f /tmp/test_direct.json ]; then
        DIRECT_BW=$(cat /tmp/test_direct.json | jq -r '.end.sum_received.bits_per_second // 0' 2>/dev/null || echo "0")
        DIRECT_MBPS=$(echo "scale=2; $DIRECT_BW/1000000" | bc 2>/dev/null || echo "0")
        log "  Direct: ${DIRECT_MBPS} Mbps"
    fi
    echo ""
    
    # Тест 2: VPN connection
    log "Test 2: VPN connection (10.8.0.1)..."
    iperf3 -c 10.8.0.1 -t 10 -P 4 -J > /tmp/test_vpn.json 2>&1 || true
    if [ -f /tmp/test_vpn.json ]; then
        VPN_BW=$(cat /tmp/test_vpn.json | jq -r '.end.sum_received.bits_per_second // 0' 2>/dev/null || echo "0")
        VPN_MBPS=$(echo "scale=2; $VPN_BW/1000000" | bc 2>/dev/null || echo "0")
        log "  VPN: ${VPN_MBPS} Mbps"
    fi
    echo ""
    
    # Тест 3: Latency
    log "Test 3: Latency..."
    DIRECT_LAT=$(ping -c 100 -i 0.01 $SERVER_IP 2>/dev/null | tail -1 | awk -F'/' '{print $5}' || echo "0")
    VPN_LAT=$(ping -c 100 -i 0.01 10.8.0.1 2>/dev/null | tail -1 | awk -F'/' '{print $5}' || echo "0")
    log "  Direct latency: ${DIRECT_LAT} ms"
    log "  VPN latency: ${VPN_LAT} ms"
    echo ""
    
    # Тест 4: CPU usage
    log "Test 4: CPU usage..."
    CPU_IDLE=$(mpstat 1 5 | tail -1 | awk '{print $NF}' || echo "0")
    CPU_USAGE=$(echo "100 - $CPU_IDLE" | bc 2>/dev/null || echo "0")
    log "  CPU usage: ${CPU_USAGE}%"
    echo ""
    
    # Сохранение результатов
    cat > /tmp/vpn_test_results.txt <<EOF
VPN Performance Test Results
============================
Date: $(date)
Role: $ROLE

Direct Connection:
  Bandwidth: ${DIRECT_MBPS:-N/A} Mbps
  Latency: ${DIRECT_LAT:-N/A} ms

VPN Connection:
  Bandwidth: ${VPN_MBPS:-N/A} Mbps
  Latency: ${VPN_LAT:-N/A} ms

System:
  CPU Usage: ${CPU_USAGE:-N/A}%

Comparison:
  Throughput: $(echo "scale=1; ${VPN_MBPS:-0} / ${DIRECT_MBPS:-1} * 100" | bc 2>/dev/null || echo "N/A")% of direct
  Latency overhead: $(echo "${VPN_LAT:-0} - ${DIRECT_LAT:-0}" | bc 2>/dev/null || echo "N/A") ms
EOF
    
    log "✓ Tests complete"
    log "Results saved to: /tmp/vpn_test_results.txt"
    echo ""
    cat /tmp/vpn_test_results.txt
else
    log "[10/10] Skipping tests (server mode)"
fi
echo ""

echo "=========================================="
echo "Script Complete"
echo "=========================================="
echo ""
log "VPN Status: $(pgrep -f vpn-obfuscated > /dev/null && echo 'RUNNING' || echo 'STOPPED')"
log "TUN Interface: $(ip link show | grep -q vpn0 && echo 'UP' || echo 'DOWN')"
echo ""
log "Logs: tail -f /var/log/vpn-obfuscated/*.log"
log "To stop VPN: pkill -9 vpn-obfuscated"
echo ""

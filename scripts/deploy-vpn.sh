#!/bin/bash
# Deploy Optimized VPN to Server
# Запуск на обоих серверах: ./deploy-vpn.sh [server|client]

set -e

ROLE=${1:-server}
echo "=== Deploying Optimized VPN ($ROLE) ==="

# Установка зависимостей
echo "[1/8] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential pkg-config libssl-dev curl git

# Установка Rust если не установлен
if ! command -v cargo &> /dev/null; then
    echo "[2/8] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "[2/8] Rust already installed"
fi

# Клонирование/обновление репозитория
echo "[3/8] Setting up VPN code..."
VPN_DIR="/opt/vpn-obfuscated"
mkdir -p $VPN_DIR

# Копирование оптимизированных файлов
echo "[4/8] Applying optimizations..."
cd $VPN_DIR

# Создание структуры
mkdir -p src/{server,client,crypto,protocol,config,tun}
mkdir -p config

# Копирование оптимизированных файлов (предполагается что они в текущей директории)
if [ -f "mod_optimized.rs" ]; then
    cp src/server/mod_optimized.rs src/server/mod.rs
    cp src/client/mod_optimized.rs src/client/mod.rs
    cp src/crypto/cipher_optimized.rs src/crypto/cipher.rs
    echo "Applied optimized code"
fi

# Копирование оптимизированных конфигов
if [ "$ROLE" = "server" ]; then
    cp config/server_optimized.json /etc/vpn-obfuscated/server.json 2>/dev/null || \
    cp config/server_optimized.json config/server.json
else
    cp config/client_optimized.json /etc/vpn-obfuscated/client.json 2>/dev/null || \
    cp config/client_optimized.json config/client.json
fi

# Сборка
echo "[5/8] Building optimized version..."
cargo build --release

# Установка бинарника
echo "[6/8] Installing binary..."
cp target/release/vpn-obfuscated /usr/local/bin/
chmod +x /usr/local/bin/vpn-obfuscated

# Создание systemd service
echo "[7/8] Setting up systemd service..."
cat > /etc/systemd/system/vpn-obfuscated.service <<EOF
[Unit]
Description=Obfuscated VPN Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/vpn-obfuscated $ROLE -c /etc/vpn-obfuscated/$ROLE.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Создание директорий
mkdir -p /etc/vpn-obfuscated
mkdir -p /var/log/vpn-obfuscated
mkdir -p /var/lib/vpn-obfuscated

# Настройка MTU для TUN
echo "[8/8] Configuring system..."
cat >> /etc/sysctl.conf <<EOF
# VPN optimizations
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl -p

# Перезапуск service
systemctl daemon-reload
systemctl enable vpn-obfuscated
systemctl restart vpn-obfuscated

echo ""
echo "=== Deployment Complete ==="
echo "Status: $(systemctl is-active vpn-obfuscated)"
echo "Logs: journalctl -u vpn-obfuscated -f"
echo ""

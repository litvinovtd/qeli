#!/bin/bash
# Install WireGuard for Comparison
# Запуск на обоих серверах: ./install-wireguard.sh [server|client]

set -e

ROLE=${1:-server}
SERVER_IP="10.66.116.10"
CLIENT_IP="10.66.116.11"
WG_SERVER_IP="10.9.0.1"
WG_CLIENT_IP="10.9.0.2"

echo "=== Installing WireGuard ($ROLE) ==="

# Установка
echo "[1/5] Installing WireGuard..."
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools qrencode

# Генерация ключей
echo "[2/5] Generating keys..."
mkdir -p /etc/wireguard
cd /etc/wireguard
umask 077

if [ ! -f privatekey ]; then
    wg genkey | tee privatekey | wg pubkey > publickey
    echo "Generated new keys"
else
    echo "Keys already exist"
fi

PRIVATE_KEY=$(cat privatekey)
PUBLIC_KEY=$(cat publickey)

echo "Public key: $PUBLIC_KEY"
echo ""

# Конфигурация сервера
if [ "$ROLE" = "server" ]; then
    echo "[3/5] Configuring WireGuard server..."
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $WG_SERVER_IP/24
ListenPort = 51820
MTU = 1420

# SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Client
PublicKey = CLIENT_PUBLIC_KEY_HERE
AllowedIPs = $WG_CLIENT_IP/32
EOF

    echo "IMPORTANT: Replace CLIENT_PUBLIC_KEY_HERE with client's public key"
    echo "Client public key should be obtained from client server"
fi

# Конфигурация клиента
if [ "$ROLE" = "client" ]; then
    echo "[3/5] Configuring WireGuard client..."
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $WG_CLIENT_IP/24
MTU = 1420

[Peer]
# Server
PublicKey = SERVER_PUBLIC_KEY_HERE
Endpoint = $SERVER_IP:51820
AllowedIPs = $WG_SERVER_IP/32, 10.8.0.0/24
PersistentKeepalive = 25
EOF

    echo "IMPORTANT: Replace SERVER_PUBLIC_KEY_HERE with server's public key"
    echo "Server public key should be obtained from server (10.66.116.10)"
fi

# Включение IP forwarding
echo "[4/5] Enabling IP forwarding..."
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

# Запуск
echo "[5/5] Starting WireGuard..."
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo ""
echo "=== WireGuard Installation Complete ==="
echo ""
echo "Status: $(systemctl is-active wg-quick@wg0)"
echo "Interface:"
ip addr show wg0 || echo "Interface not up yet"
echo ""
echo "Public key: $PUBLIC_KEY"
echo ""
echo "Next steps:"
if [ "$ROLE" = "server" ]; then
    echo "1. Get client's public key from 10.66.116.11"
    echo "2. Edit /etc/wireguard/wg0.conf and replace CLIENT_PUBLIC_KEY_HERE"
    echo "3. Restart: systemctl restart wg-quick@wg0"
else
    echo "1. Get server's public key from 10.66.116.10"
    echo "2. Edit /etc/wireguard/wg0.conf and replace SERVER_PUBLIC_KEY_HERE"
    echo "3. Restart: systemctl restart wg-quick@wg0"
fi
echo ""
echo "Test connection:"
echo "  ping $WG_SERVER_IP  # from client"
echo "  ping $WG_CLIENT_IP  # from server"
echo ""

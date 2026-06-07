#!/bin/bash
# Install OpenVPN for Comparison
# Запуск на обоих серверах: ./install-openvpn.sh [server|client]

set -e

ROLE=${1:-server}
SERVER_IP="10.66.116.10"

echo "=== Installing OpenVPN ($ROLE) ==="

# Установка
echo "[1/6] Installing OpenVPN..."
apt-get update -qq
apt-get install -y -qq openvpn easy-rsa

if [ "$ROLE" = "server" ]; then
    echo "[2/6] Setting up CA and certificates..."
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa
    
    # Инициализация PKI
    ./easyrsa init-pki
    
    # Создание CA (без пароля для автоматизации)
    echo -e "\n\n\n\n\n\n\n" | ./easyrsa build-ca nopass
    
    # Генерация сертификата сервера
    ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server
    
    # Генерация DH параметров
    ./easyrsa gen-dh
    
    # Генерация TLS auth key
    openvpn --genkey --secret pki/ta.key
    
    echo "[3/6] Configuring OpenVPN server..."
    cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun

ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/easy-rsa/pki/ta.key 0

server 10.10.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

push "route 10.8.0.0 255.255.255.0"
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"

keepalive 10 120
cipher AES-256-GCM
compress lz4-v2
push "compress lz4-v2"

max-clients 100
user nobody
group nogroup

persist-key
persist-tun

status openvpn-status.log
verb 3
explicit-exit-notify 1

mtu-disc yes
tun-mtu 1500
fragment 1400
mssfix
EOF

    echo "[4/6] Enabling IP forwarding..."
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p
    
    echo "[5/6] Setting up NAT..."
    iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
    apt-get install -y -qq iptables-persistent
    
    echo "[6/6] Starting OpenVPN server..."
    systemctl enable openvpn-server@server
    systemctl start openvpn-server@server
    
    echo ""
    echo "=== OpenVPN Server Installation Complete ==="
    echo ""
    echo "Generate client certificate:"
    echo "  cd /etc/openvpn/easy-rsa"
    echo "  ./easyrsa gen-req client1 nopass"
    echo "  ./easyrsa sign-req client client1"
    echo ""
    echo "Copy these files to client:"
    echo "  /etc/openvpn/easy-rsa/pki/ca.crt"
    echo "  /etc/openvpn/easy-rsa/pki/issued/client1.crt"
    echo "  /etc/openvpn/easy-rsa/pki/private/client1.key"
    echo "  /etc/openvpn/easy-rsa/pki/ta.key"
    echo ""
    
else
    echo "[2/6] OpenVPN client setup..."
    echo ""
    echo "IMPORTANT: You need to copy certificate files from server first!"
    echo ""
    echo "Required files from server (10.66.116.10):"
    echo "  - /etc/openvpn/easy-rsa/pki/ca.crt"
    echo "  - /etc/openvpn/easy-rsa/pki/issued/client1.crt"
    echo "  - /etc/openvpn/easy-rsa/pki/private/client1.key"
    echo "  - /etc/openvpn/easy-rsa/pki/ta.key"
    echo ""
    echo "Copy them to /etc/openvpn/ on this server"
    echo ""
    
    read -p "Have you copied the certificate files? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Please copy the files and run this script again"
        exit 1
    fi
    
    echo "[3/6] Configuring OpenVPN client..."
    cat > /etc/openvpn/client.conf <<EOF
client
dev tun
proto udp
remote $SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun

ca /etc/openvpn/ca.crt
cert /etc/openvpn/client1.crt
key /etc/openvpn/client1.key
tls-auth /etc/openvpn/ta.key 1

cipher AES-256-GCM
compress lz4-v2

verb 3

mtu-disc yes
tun-mtu 1500
fragment 1400
mssfix
EOF

    echo "[4/6] Starting OpenVPN client..."
    systemctl enable openvpn-client@client
    systemctl start openvpn-client@client
    
    echo ""
    echo "=== OpenVPN Client Installation Complete ==="
    echo ""
fi

echo "Status: $(systemctl is-active openvpn-*@* 2>/dev/null || echo 'unknown')"
echo ""
echo "Test connection:"
if [ "$ROLE" = "server" ]; then
    echo "  Server IP: 10.10.0.1"
else
    echo "  ping 10.10.0.1  # ping server"
fi
echo ""

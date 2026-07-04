#!/bin/bash
# OBSOLETE — targets the removed `vpn-obfuscated` binary + JSON config (pre flat-INI);
# superseded by install-reality-server.sh. Kept for reference only.
echo "OBSOLETE: diagnose.sh targets the removed vpn-obfuscated/JSON layout; use install-reality-server.sh." >&2
exit 1

# VPN Connection Diagnostics
# Запуск: ./diagnose.sh

set -e

echo "=== VPN Connection Diagnostics ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo ""

# 1. Проверка VPN процесса
echo "[1/10] Checking VPN process..."
if pgrep -f vpn-obfuscated > /dev/null; then
    echo "✓ VPN process running"
    ps aux | grep vpn-obfuscated | grep -v grep
else
    echo "✗ VPN process NOT running"
    systemctl status vpn-obfuscated || true
fi
echo ""

# 2. Проверка TUN интерфейса
echo "[2/10] Checking TUN interface..."
if ip link show | grep -q "vpn0"; then
    echo "✓ TUN interface vpn0 exists"
    ip addr show vpn0
    ip link show vpn0
else
    echo "✗ TUN interface vpn0 NOT found"
    ip link show | grep -E "tun|vpn" || echo "No TUN/VPN interfaces found"
fi
echo ""

# 3. Проверка маршрутов
echo "[3/10] Checking routes..."
ip route show | grep -E "10.8.0|vpn0" || echo "No VPN routes found"
echo ""

# 4. Проверка портов
echo "[4/10] Checking listening ports..."
ss -tlnp | grep -E "443|vpn" || echo "No VPN ports listening"
echo ""

# 5. Проверка логов
echo "[5/10] Recent VPN logs..."
journalctl -u vpn-obfuscated --no-pager -n 20 || tail -20 /var/log/vpn-obfuscated/*.log 2>/dev/null || echo "No logs found"
echo ""

# 6. Проверка конфигурации
echo "[6/10] Checking configuration..."
if [ -f /etc/vpn-obfuscated/server.json ]; then
    echo "Server config:"
    cat /etc/vpn-obfuscated/server.json | head -20
elif [ -f /etc/vpn-obfuscated/client.json ]; then
    echo "Client config:"
    cat /etc/vpn-obfuscated/client.json | head -20
else
    echo "✗ No config files found"
fi
echo ""

# 7. Проверка connectivity
echo "[7/10] Testing connectivity..."
echo "Ping to 10.66.116.10:"
ping -c 3 -W 2 10.66.116.10 2>&1 || echo "Failed"
echo ""
echo "Ping to 10.66.116.11:"
ping -c 3 -W 2 10.66.116.11 2>&1 || echo "Failed"
echo ""
echo "Ping to 10.8.0.1 (VPN gateway):"
ping -c 3 -W 2 10.8.0.1 2>&1 || echo "Failed"
echo ""
echo "Ping to 10.8.0.10 (VPN client):"
ping -c 3 -W 2 10.8.0.10 2>&1 || echo "Failed"
echo ""

# 8. Проверка firewall
echo "[8/10] Checking firewall..."
iptables -L -n | head -20 || echo "iptables not available"
echo ""

# 9. Проверка сетевых интерфейсов
echo "[9/10] Network interfaces..."
ip addr show | grep -E "^[0-9]+:|inet " | head -30
echo ""

# 10. Проверка системных ресурсов
echo "[10/10] System resources..."
echo "CPU:"
mpstat 1 1 | tail -1 || top -bn1 | head -5
echo ""
echo "Memory:"
free -h
echo ""
echo "Disk:"
df -h / | tail -1
echo ""

echo "=== Diagnostics Complete ==="
echo ""
echo "Common issues:"
echo "1. VPN process not running: systemctl restart vpn-obfuscated"
echo "2. TUN interface missing: Check /dev/net/tun exists"
echo "3. No routes: Check config file routing section"
echo "4. Firewall blocking: Check iptables rules"
echo "5. Wrong config: Verify /etc/vpn-obfuscated/*.json"
echo ""

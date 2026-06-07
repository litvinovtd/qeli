#!/bin/bash
# Collect Test Results from Both Servers
# Запуск на клиенте (10.66.116.11): ./collect-results.sh

set -e

SERVER_IP="10.66.116.10"
CLIENT_IP="10.66.116.11"

echo "=========================================="
echo "Collecting VPN Test Results"
echo "Date: $(date)"
echo "=========================================="
echo ""

# Локальные результаты
echo "[1/3] Local test results (Client - $CLIENT_IP):"
echo "----------------------------------------"
if [ -f /tmp/vpn_test_results.txt ]; then
    cat /tmp/vpn_test_results.txt
else
    echo "No local test results found"
    echo "Run ./fix-and-test.sh client first"
fi
echo ""

# Результаты с сервера
echo "[2/3] Remote test results (Server - $SERVER_IP):"
echo "----------------------------------------"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$SERVER_IP "cat /tmp/vpn_test_results.txt 2>/dev/null || echo 'No test results on server'" 2>/dev/null || echo "Cannot connect to server"
echo ""

# Статус VPN на обоих серверах
echo "[3/3] VPN Status Check:"
echo "----------------------------------------"

echo "Server ($SERVER_IP):"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$SERVER_IP "
    echo '  Process:' \$(pgrep -f vpn-obfuscated > /dev/null && echo 'RUNNING' || echo 'STOPPED')
    echo '  TUN:' \$(ip link show | grep -q vpn0 && echo 'UP' || echo 'DOWN')
    echo '  IP:' \$(ip addr show vpn0 2>/dev/null | grep inet | awk '{print \$2}' || echo 'N/A')
" 2>/dev/null || echo "  Cannot connect"
echo ""

echo "Client ($CLIENT_IP):"
echo "  Process: $(pgrep -f vpn-obfuscated > /dev/null && echo 'RUNNING' || echo 'STOPPED')"
echo "  TUN: $(ip link show | grep -q vpn0 && echo 'UP' || echo 'DOWN')"
echo "  IP: $(ip addr show vpn0 2>/dev/null | grep inet | awk '{print $2}' || echo 'N/A')"
echo ""

# Проверка соединения
echo "Connection Tests:"
echo "  Ping to server (10.66.116.10): $(ping -c 1 -W 2 $SERVER_IP > /dev/null 2>&1 && echo 'OK' || echo 'FAIL')"
echo "  Ping to VPN gateway (10.8.0.1): $(ping -c 1 -W 2 10.8.0.1 > /dev/null 2>&1 && echo 'OK' || echo 'FAIL')"
echo "  Ping to VPN client (10.8.0.10): $(ping -c 1 -W 2 10.8.0.10 > /dev/null 2>&1 && echo 'OK' || echo 'FAIL')"
echo ""

# Создание итогового отчета
cat > /tmp/final_report.txt <<EOF
========================================
VPN PERFORMANCE TEST REPORT
========================================
Date: $(date)

INFRASTRUCTURE:
  Server: $SERVER_IP
  Client: $CLIENT_IP
  VPN Network: 10.8.0.0/24

STATUS:
  Server VPN: $(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$SERVER_IP "pgrep -f vpn-obfuscated > /dev/null && echo 'RUNNING' || echo 'STOPPED'" 2>/dev/null || echo 'UNKNOWN')
  Client VPN: $(pgrep -f vpn-obfuscated > /dev/null && echo 'RUNNING' || echo 'STOPPED')
  VPN Tunnel: $(ping -c 1 -W 2 10.8.0.1 > /dev/null 2>&1 && echo 'UP' || echo 'DOWN')

PERFORMANCE:
$(cat /tmp/vpn_test_results.txt 2>/dev/null || echo "  No data available")

RECOMMENDATIONS:
  - If VPN is down: Run ./fix-and-test.sh on both servers
  - If performance is low: Check OPTIMIZATION_GUIDE.md
  - For comparison: Install WireGuard with ./install-wireguard.sh

LOGS:
  Server: ssh root@$SERVER_IP "tail -f /var/log/vpn-obfuscated/server.log"
  Client: tail -f /var/log/vpn-obfuscated/client.log

========================================
EOF

echo "=========================================="
echo "Final Report"
echo "=========================================="
cat /tmp/final_report.txt
echo ""
echo "Report saved to: /tmp/final_report.txt"
echo ""

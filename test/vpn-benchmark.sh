#!/bin/bash
# VPN Performance Benchmark Script
# Запуск: ./vpn-benchmark.sh

set -e

SERVER1="10.66.116.10"
SERVER2="10.66.116.11"
PASS="${QELI_LAB_PASS}"
VPN_IP="10.8.0.10"  # IP VPN интерфейса на server1

echo "=== VPN Performance Benchmark ==="
echo ""

# Функция для выполнения команд на удаленном сервере
remote_exec() {
    local server=$1
    local cmd=$2
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no root@$server "$cmd"
}

# Проверка доступности серверов
echo "[1/6] Checking server connectivity..."
remote_exec $SERVER1 "echo 'Server 1: OK'" || { echo "ERROR: Cannot connect to $SERVER1"; exit 1; }
remote_exec $SERVER2 "echo 'Server 2: OK'" || { echo "ERROR: Cannot connect to $SERVER2"; exit 1; }

# Установка необходимых инструментов
echo ""
echo "[2/6] Installing benchmark tools..."
for server in $SERVER1 $SERVER2; do
    remote_exec $server "apt-get update -qq && apt-get install -y -qq iperf3 sysstat htop" > /dev/null 2>&1
done
echo "Tools installed"

# Проверка VPN соединения
echo ""
echo "[3/6] Checking VPN tunnel..."
remote_exec $SERVER1 "ip addr show | grep '10.8.0' || echo 'VPN interface not found on server1'"
remote_exec $SERVER2 "ip addr show | grep '10.8.0' || echo 'VPN interface not found on server2'"

# Запуск iperf3 сервера
echo ""
echo "[4/6] Starting iperf3 server on $SERVER2..."
remote_exec $SERVER2 "pkill -9 iperf3 || true"
remote_exec $SERVER2 "nohup iperf3 -s > /tmp/iperf3.log 2>&1 &"
sleep 2

# Тест 1: Базовая пропускная способность (без VPN)
echo ""
echo "[5/6] Running bandwidth tests..."
echo ""
echo "--- Test 1: Direct connection (no VPN) ---"
remote_exec $SERVER1 "iperf3 -c $SERVER2 -t 10 -i 2 -J" > /tmp/iperf3_direct.json 2>&1
DIRECT_BW=$(cat /tmp/iperf3_direct.json | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
echo "Direct bandwidth: $(echo "scale=2; $DIRECT_BW/1000000" | bc) Mbps"

# Тест 2: Через VPN
echo ""
echo "--- Test 2: Through VPN tunnel ---"
remote_exec $SERVER1 "iperf3 -c $VPN_IP -t 10 -i 2 -J" > /tmp/iperf3_vpn.json 2>&1 || echo "VPN test failed"
if [ -f /tmp/iperf3_vpn.json ]; then
    VPN_BW=$(cat /tmp/iperf3_vpn.json | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
    echo "VPN bandwidth: $(echo "scale=2; $VPN_BW/1000000" | bc) Mbps"
fi

# Тест 3: CPU usage во время нагрузки
echo ""
echo "[6/6] Measuring CPU usage under load..."
echo ""
echo "--- CPU usage during VPN transfer ---"

# Запускаем нагрузку в фоне
remote_exec $SERVER1 "nohup iperf3 -c $VPN_IP -t 30 -P 4 > /dev/null 2>&1 &"
sleep 3

# Измеряем CPU
echo "Server 1 (VPN client) CPU:"
remote_exec $SERVER1 "mpstat 1 5 | tail -1"
echo ""
echo "Server 2 (VPN server) CPU:"
remote_exec $SERVER2 "mpstat 1 5 | tail -1"

# Остановка iperf3
remote_exec $SERVER1 "pkill -9 iperf3 || true"
remote_exec $SERVER2 "pkill -9 iperf3 || true"

# Дополнительная диагностика
echo ""
echo "=== Additional Diagnostics ==="
echo ""
echo "--- VPN Process Info ---"
remote_exec $SERVER1 "ps aux | grep vpn-obfuscated | grep -v grep || echo 'VPN process not found'"
remote_exec $SERVER2 "ps aux | grep vpn-obfuscated | grep -v grep || echo 'VPN process not found'"

echo ""
echo "--- Network Interface Stats ---"
remote_exec $SERVER1 "ip -s link show | grep -A 5 'vpn0\|tun0' || echo 'VPN interface not found'"

echo ""
echo "--- MTU Settings ---"
remote_exec $SERVER1 "ip link show | grep mtu"
remote_exec $SERVER2 "ip link show | grep mtu"

echo ""
echo "=== Benchmark Complete ==="
echo ""
echo "Results saved to:"
echo "  - /tmp/iperf3_direct.json"
echo "  - /tmp/iperf3_vpn.json"

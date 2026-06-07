#!/bin/bash
# Comprehensive VPN Benchmark
# Запуск на клиенте (10.66.116.11): ./benchmark-all.sh

set -e

SERVER_IP="10.66.116.10"
VPN_OBFUSCATED_IP="10.8.0.10"
WIREGUARD_IP="10.9.0.1"
OPENVPN_IP="10.10.0.1"

TEST_DURATION=30
PARALLEL_STREAMS=4

echo "=== Comprehensive VPN Benchmark ==="
echo "Date: $(date)"
echo "Test duration: ${TEST_DURATION}s per test"
echo "Parallel streams: $PARALLEL_STREAMS"
echo ""

# Установка инструментов
echo "[0/5] Installing benchmark tools..."
apt-get update -qq
apt-get install -y -qq iperf3 sysstat mtr curl wget bc jq
echo ""

# Функция для запуска теста
run_test() {
    local name=$1
    local target_ip=$2
    local output_file=$3
    
    echo "Testing $name ($target_ip)..."
    
    # Проверка доступности
    if ! ping -c 1 -W 2 $target_ip > /dev/null 2>&1; then
        echo "  ✗ $target_ip not reachable"
        echo "N/A" > $output_file
        return
    fi
    
    # Запуск iperf3 сервера на target (если еще не запущен)
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$SERVER_IP "pkill -9 iperf3 || true; nohup iperf3 -s > /dev/null 2>&1 &" 2>/dev/null || true
    sleep 2
    
    # Throughput test
    echo "  Running throughput test..."
    iperf3 -c $target_ip -t $TEST_DURATION -P $PARALLEL_STREAMS -J > /tmp/iperf3_${name}.json 2>&1 || true
    
    # Извлечение результатов
    if [ -f /tmp/iperf3_${name}.json ]; then
        BANDWIDTH=$(cat /tmp/iperf3_${name}.json | jq -r '.end.sum_received.bits_per_second // 0' 2>/dev/null || echo "0")
        BANDWIDTH_MBPS=$(echo "scale=2; $BANDWIDTH/1000000" | bc 2>/dev/null || echo "0")
        RETRANSMITS=$(cat /tmp/iperf3_${name}.json | jq -r '.end.sum_sent.retransmits // 0' 2>/dev/null || echo "0")
    else
        BANDWIDTH_MBPS="0"
        RETRANSMITS="0"
    fi
    
    # Latency test
    echo "  Running latency test..."
    LATENCY=$(ping -c 100 -i 0.01 $target_ip 2>/dev/null | tail -1 | awk -F'/' '{print $5}' || echo "0")
    
    # Packet loss test
    echo "  Running packet loss test..."
    LOSS=$(ping -c 1000 -i 0.001 $target_ip 2>/dev/null | grep "packet loss" | awk -F',' '{print $3}' | awk '{print $1}' || echo "0")
    
    # CPU usage (на локальной машине)
    echo "  Measuring CPU usage..."
    CPU_IDLE=$(mpstat 1 5 | tail -1 | awk '{print $NF}' || echo "0")
    CPU_USAGE=$(echo "100 - $CPU_IDLE" | bc 2>/dev/null || echo "0")
    
    # Сохранение результатов
    cat > $output_file <<EOF
Name: $name
Target: $target_ip
Bandwidth: ${BANDWIDTH_MBPS} Mbps
Retransmits: $RETRANSMITS
Latency: ${LATENCY} ms
Packet Loss: ${LOSS}%
CPU Usage: ${CPU_USAGE}%
EOF
    
    echo "  ✓ Complete: ${BANDWIDTH_MBPS} Mbps, ${LATENCY}ms latency"
    echo ""
}

# Тест 1: Direct connection (без VPN)
echo "[1/5] Testing direct connection..."
run_test "Direct" "$SERVER_IP" "/tmp/benchmark_direct.txt"

# Тест 2: VPN Obfuscated
echo "[2/5] Testing VPN Obfuscated..."
run_test "VPN_Obfuscated" "$VPN_OBFUSCATED_IP" "/tmp/benchmark_vpn_obfuscated.txt"

# Тест 3: WireGuard
echo "[3/5] Testing WireGuard..."
run_test "WireGuard" "$WIREGUARD_IP" "/tmp/benchmark_wireguard.txt"

# Тест 4: OpenVPN
echo "[4/5] Testing OpenVPN..."
run_test "OpenVPN" "$OPENVPN_IP" "/tmp/benchmark_openvpn.txt"

# Тест 5: Реальная нагрузка (scp)
echo "[5/5] Testing real-world performance..."
echo "  Creating 100MB test file..."
dd if=/dev/urandom of=/tmp/testfile bs=1M count=100 2>/dev/null

for target in "$SERVER_IP" "$VPN_OBFUSCATED_IP" "$WIREGUARD_IP" "$OPENVPN_IP"; do
    name=$(echo $target | tr '.' '_')
    echo "  Testing SCP to $target..."
    if ping -c 1 -W 2 $target > /dev/null 2>&1; then
        START_TIME=$(date +%s.%N)
        scp -o StrictHostKeyChecking=no /tmp/testfile root@$target:/tmp/ 2>/dev/null || true
        END_TIME=$(date +%s.%N)
        DURATION=$(echo "$END_TIME - $START_TIME" | bc)
        SPEED=$(echo "scale=2; 100 / $DURATION" | bc 2>/dev/null || echo "0")
        echo "    Speed: ${SPEED} MB/s"
        echo "SCP_Speed: ${SPEED} MB/s" >> /tmp/benchmark_${name}.txt
    else
        echo "    ✗ Not reachable"
    fi
done

rm -f /tmp/testfile

echo ""
echo "=== Benchmark Results ==="
echo ""

# Создание сравнительной таблицы
echo "VPN Solution | Bandwidth (Mbps) | Latency (ms) | Packet Loss | CPU Usage | SCP Speed (MB/s)"
echo "-------------|------------------|--------------|-------------|-----------|------------------"

for file in /tmp/benchmark_*.txt; do
    if [ -f "$file" ] && [ "$(cat $file)" != "N/A" ]; then
        NAME=$(grep "Name:" $file | cut -d: -f2 | xargs)
        BW=$(grep "Bandwidth:" $file | cut -d: -f2 | xargs | awk '{print $1}')
        LAT=$(grep "Latency:" $file | cut -d: -f2 | xargs | awk '{print $1}')
        LOSS=$(grep "Packet Loss:" $file | cut -d: -f2 | xargs | awk '{print $1}')
        CPU=$(grep "CPU Usage:" $file | cut -d: -f2 | xargs | awk '{print $1}')
        SCP=$(grep "SCP_Speed:" $file | cut -d: -f2 | xargs | awk '{print $1}')
        
        printf "%-12s | %-16s | %-12s | %-11s | %-9s | %s\n" \
            "$NAME" "$BW" "$LAT" "$LOSS" "$CPU" "${SCP:-N/A}"
    fi
done

echo ""
echo "Detailed results saved to /tmp/benchmark_*.txt"
echo ""

# Создание JSON отчета
cat > /tmp/benchmark_summary.json <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "test_duration": $TEST_DURATION,
  "parallel_streams": $PARALLEL_STREAMS,
  "results": {
EOF

first=true
for file in /tmp/benchmark_*.txt; do
    if [ -f "$file" ] && [ "$(cat $file)" != "N/A" ]; then
        NAME=$(grep "Name:" $file | cut -d: -f2 | xargs)
        BW=$(grep "Bandwidth:" $file | cut -d: -f2 | xargs | awk '{print $1}')
        LAT=$(grep "Latency:" $file | cut -d: -f2 | xargs | awk '{print $1}')
        LOSS=$(grep "Packet Loss:" $file | cut -d: -f2 | xargs | awk '{print $1}' | tr -d '%')
        CPU=$(grep "CPU Usage:" $file | cut -d: -f2 | xargs | awk '{print $1}' | tr -d '%')
        
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> /tmp/benchmark_summary.json
        fi
        
        cat >> /tmp/benchmark_summary.json <<EOF
    "$NAME": {
      "bandwidth_mbps": $BW,
      "latency_ms": $LAT,
      "packet_loss_percent": ${LOSS:-0},
      "cpu_usage_percent": ${CPU:-0}
    }
EOF
    fi
done

cat >> /tmp/benchmark_summary.json <<EOF
  }
}
EOF

echo ""
echo "JSON report: /tmp/benchmark_summary.json"
echo ""
echo "=== Benchmark Complete ==="
echo ""

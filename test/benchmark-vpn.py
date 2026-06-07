import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import time

# Install iperf3 on both servers
print("=== Installing iperf3 ===")
for host, name in [('10.66.116.10', 'Server'), ('10.66.116.11', 'Client')]:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
    print(f"\n--- {name} ---")
    stdin, stdout, stderr = ssh.exec_command("apt-get install -y iperf3 2>&1 | tail -3")
    print(stdout.read().decode(errors='replace'))
    ssh.close()

# Start iperf3 server on VPN server (10.8.0.1)
print("\n=== Starting iperf3 server on 10.8.0.1 ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin, stdout, stderr = ssh.exec_command("pkill iperf3 2>/dev/null; sleep 0.5; iperf3 -s -B 10.8.0.1 -D")
stdout.channel.recv_exit_status()
time.sleep(1)
ssh.close()

# Test 1: TCP download (Client -> Server)
print("\n=== Test 1: TCP Download (Client -> Server via VPN) ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin2, stdout2, stderr2 = ssh2.exec_command("iperf3 -c 10.8.0.1 -B 10.8.0.10 -t 15 -P 4 --json 2>&1")
result = stdout2.read().decode(errors='replace')
import json
try:
    data = json.loads(result)
    print(f"  Sender:   {data['end']['sum_sent']['bits_per_second']/1e6:.2f} Mbps")
    print(f"  Receiver: {data['end']['sum_received']['bits_per_second']/1e6:.2f} Mbps")
except:
    print(f"  Raw: {result[:500]}")
ssh2.close()

# Test 2: TCP upload (Server -> Client)
print("\n=== Test 2: TCP Upload (Server -> Client via VPN) ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin2, stdout2, stderr2 = ssh2.exec_command("iperf3 -c 10.8.0.1 -B 10.8.0.10 -t 15 -P 4 -R --json 2>&1")
result = stdout2.read().decode(errors='replace')
try:
    data = json.loads(result)
    print(f"  Sender:   {data['end']['sum_sent']['bits_per_second']/1e6:.2f} Mbps")
    print(f"  Receiver: {data['end']['sum_received']['bits_per_second']/1e6:.2f} Mbps")
except:
    print(f"  Raw: {result[:500]}")
ssh2.close()

# Test 3: UDP
print("\n=== Test 3: UDP (Client -> Server via VPN) ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin2, stdout2, stderr2 = ssh2.exec_command("iperf3 -c 10.8.0.1 -B 10.8.0.10 -t 10 -u -b 100M --json 2>&1")
result = stdout2.read().decode(errors='replace')
try:
    data = json.loads(result)
    print(f"  Bits/sec: {data['end']['sum']['bits_per_second']/1e6:.2f} Mbps")
    print(f"  Jitter:   {data['end']['sum']['jitter_ms']:.2f} ms")
    print(f"  Lost:     {data['end']['sum']['lost_packets']}/{data['end']['sum']['packets']} ({data['end']['sum']['lost_percent']:.2f}%)")
except:
    print(f"  Raw: {result[:500]}")
ssh2.close()

# Test 4: Baseline (direct LAN, no VPN)
print("\n=== Test 4: Baseline TCP (Direct LAN 10.66.116.11 -> 10.66.116.10) ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin, stdout, stderr = ssh.exec_command("pkill iperf3 2>/dev/null; sleep 0.5; iperf3 -s -B 10.66.116.10 -D")
stdout.channel.recv_exit_status()
time.sleep(1)
ssh.close()

ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin2, stdout2, stderr2 = ssh2.exec_command("iperf3 -c 10.66.116.10 -B 10.66.116.11 -t 10 -P 4 --json 2>&1")
result = stdout2.read().decode(errors='replace')
try:
    data = json.loads(result)
    print(f"  Sender:   {data['end']['sum_sent']['bits_per_second']/1e6:.2f} Mbps")
    print(f"  Receiver: {data['end']['sum_received']['bits_per_second']/1e6:.2f} Mbps")
except:
    print(f"  Raw: {result[:500]}")
ssh2.close()

# Test 5: Ping latency comparison
print("\n=== Test 5: Latency Comparison ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

print("\n  Direct LAN ping:")
stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 20 10.66.116.10 2>&1 | tail -3")
print(f"  {stdout2.read().decode(errors='replace').strip()}")

print("\n  VPN ping:")
stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 20 10.8.0.1 2>&1 | tail -3")
print(f"  {stdout2.read().decode(errors='replace').strip()}")
ssh2.close()

# Test 6: CPU usage during VPN traffic
print("\n=== Test 6: CPU Usage During VPN Traffic ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Start iperf3 on VPN
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin, stdout, stderr = ssh.exec_command("pkill iperf3 2>/dev/null; sleep 0.5; iperf3 -s -B 10.8.0.1 -D")
stdout.channel.recv_exit_status()
time.sleep(1)
ssh.close()

ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin2, stdout2, stderr2 = ssh2.exec_command("iperf3 -c 10.8.0.1 -B 10.8.0.10 -t 10 -P 4 > /dev/null 2>&1 &")
stdout2.channel.recv_exit_status()

time.sleep(3)

# Measure CPU
print("\n  Server CPU during VPN traffic:")
for i in range(3):
    stdin, stdout, stderr = ssh.exec_command("top -bn1 | grep 'vpn-obfuscated' | head -3")
    output = stdout.read().decode(errors='replace').strip()
    if output:
        print(f"  {output}")
    stdin, stdout, stderr = ssh.exec_command("ps aux | grep 'vpn-obfuscated' | grep -v grep | awk '{printf \"CPU: %s%%  MEM: %s%%  PID: %s\\n\", $3, $4, $2}'")
    print(f"  {stdout.read().decode(errors='replace').strip()}")
    time.sleep(2)

# Cleanup
print("\n=== Cleanup ===")
ssh.exec_command("pkill iperf3 2>/dev/null")
ssh2.exec_command("pkill iperf3 2>/dev/null")
ssh.close()
ssh2.close()

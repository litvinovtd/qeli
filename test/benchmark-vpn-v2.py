import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import time
import json

results = {}

# Test 1: TCP Download
print("=== Test 1: TCP Download (Client -> Server via VPN) ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin, stdout, stderr = ssh.exec_command("pkill iperf3 2>/dev/null; sleep 0.5; iperf3 -s -B 10.8.0.1 -D")
stdout.channel.recv_exit_status()
time.sleep(1)
ssh.close()

ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin2, stdout2, stderr2 = ssh2.exec_command("iperf3 -c 10.8.0.1 -B 10.8.0.10 -t 15 -P 4 --json 2>&1")
result = stdout2.read().decode(errors='replace')
try:
    data = json.loads(result)
    sender = data['end']['sum_sent']['bits_per_second']/1e6
    receiver = data['end']['sum_received']['bits_per_second']/1e6
    print(f"  Sender:   {sender:.2f} Mbps")
    print(f"  Receiver: {receiver:.2f} Mbps")
    results['tcp_download'] = {'sender': sender, 'receiver': receiver}
except:
    print(f"  Raw: {result[:300]}")
    results['tcp_download'] = {'error': result[:300]}
ssh2.close()

# Test 2: TCP Upload
print("\n=== Test 2: TCP Upload (Server -> Client via VPN) ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin2, stdout2, stderr2 = ssh2.exec_command("iperf3 -c 10.8.0.1 -B 10.8.0.10 -t 15 -P 4 -R --json 2>&1")
result = stdout2.read().decode(errors='replace')
try:
    data = json.loads(result)
    sender = data['end']['sum_sent']['bits_per_second']/1e6
    receiver = data['end']['sum_received']['bits_per_second']/1e6
    print(f"  Sender:   {sender:.2f} Mbps")
    print(f"  Receiver: {receiver:.2f} Mbps")
    results['tcp_upload'] = {'sender': sender, 'receiver': receiver}
except:
    print(f"  Raw: {result[:300]}")
    results['tcp_upload'] = {'error': result[:300]}
ssh2.close()

# Test 3: UDP
print("\n=== Test 3: UDP (Client -> Server via VPN) ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin2, stdout2, stderr2 = ssh2.exec_command("iperf3 -c 10.8.0.1 -B 10.8.0.10 -t 10 -u -b 500M --json 2>&1")
result = stdout2.read().decode(errors='replace')
try:
    data = json.loads(result)
    bits = data['end']['sum']['bits_per_second']/1e6
    jitter = data['end']['sum']['jitter_ms']
    lost_pct = data['end']['sum']['lost_percent']
    print(f"  Bits/sec: {bits:.2f} Mbps")
    print(f"  Jitter:   {jitter:.2f} ms")
    print(f"  Lost:     {lost_pct:.2f}%")
    results['udp'] = {'bits': bits, 'jitter': jitter, 'lost_pct': lost_pct}
except:
    print(f"  Raw: {result[:300]}")
    results['udp'] = {'error': result[:300]}
ssh2.close()

# Test 4: Baseline
print("\n=== Test 4: Baseline TCP (Direct LAN) ===")
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
    sender = data['end']['sum_sent']['bits_per_second']/1e6
    receiver = data['end']['sum_received']['bits_per_second']/1e6
    print(f"  Sender:   {sender:.2f} Mbps")
    print(f"  Receiver: {receiver:.2f} Mbps")
    results['baseline'] = {'sender': sender, 'receiver': receiver}
except:
    print(f"  Raw: {result[:300]}")
    results['baseline'] = {'error': result[:300]}
ssh2.close()

# Test 5: Latency
print("\n=== Test 5: Latency ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 50 10.66.116.10 2>&1 | grep 'rtt'")
lan_ping = stdout2.read().decode(errors='replace').strip()
print(f"  LAN:  {lan_ping}")

stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 50 10.8.0.1 2>&1 | grep 'rtt'")
vpn_ping = stdout2.read().decode(errors='replace').strip()
print(f"  VPN:  {vpn_ping}")

results['latency'] = {'lan': lan_ping, 'vpn': vpn_ping}
ssh2.close()

# Test 6: CPU usage
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
for i in range(5):
    stdin, stdout, stderr = ssh.exec_command("ps aux | grep 'vpn-obfuscated' | grep -v grep | awk '{printf \"CPU: %s%%  MEM: %s%%  RSS: %sKB\\n\", $3, $4, $6}'")
    cpu_info = stdout.read().decode(errors='replace').strip()
    if cpu_info:
        print(f"  Server: {cpu_info}")
    time.sleep(1)

# Cleanup
print("\n=== Cleanup ===")
ssh.exec_command("pkill iperf3 2>/dev/null")
ssh2.exec_command("pkill iperf3 2>/dev/null")
ssh.close()
ssh2.close()

# Summary
print("\n" + "="*60)
print("SUMMARY")
print("="*60)
for k, v in results.items():
    print(f"\n{k}:")
    for kk, vv in v.items():
        print(f"  {kk}: {vv}")

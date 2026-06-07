import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import time
import json

results = {}

# Start iperf3 server on VPN
print("=== Starting iperf3 on VPN ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
stdin, stdout, stderr = ssh.exec_command("pkill iperf3 2>/dev/null; sleep 0.5; iperf3 -s -B 10.8.0.1 -D")
stdout.channel.recv_exit_status()
time.sleep(1)
ssh.close()

# Test 1: TCP Download
print("\n=== Test 1: TCP Download (Client -> Server via VPN) ===")
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
except Exception as e:
    print(f"  Error: {e}")
    print(f"  Raw: {result[:300]}")
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
except Exception as e:
    print(f"  Error: {e}")
    print(f"  Raw: {result[:300]}")
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
except Exception as e:
    print(f"  Error: {e}")
    print(f"  Raw: {result[:300]}")
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
except Exception as e:
    print(f"  Error: {e}")
    print(f"  Raw: {result[:300]}")
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

# Summary
print("\n" + "="*60)
print("PERFORMANCE SUMMARY")
print("="*60)
print(f"\n{'Metric':<25} {'VPN':>15} {'Baseline':>15} {'Overhead':>10}")
print("-"*65)

if 'tcp_download' in results and 'baseline' in results:
    vpn_down = results['tcp_download'].get('receiver', 0)
    baseline = results['baseline'].get('receiver', 1)
    overhead = ((baseline - vpn_down) / baseline * 100) if baseline > 0 else 0
    print(f"{'TCP Download (Mbps)':<25} {vpn_down:>15.2f} {baseline:>15.2f} {overhead:>9.1f}%")

if 'tcp_upload' in results and 'baseline' in results:
    vpn_up = results['tcp_upload'].get('receiver', 0)
    baseline = results['baseline'].get('receiver', 1)
    overhead = ((baseline - vpn_up) / baseline * 100) if baseline > 0 else 0
    print(f"{'TCP Upload (Mbps)':<25} {vpn_up:>15.2f} {baseline:>15.2f} {overhead:>9.1f}%")

if 'udp' in results:
    print(f"{'UDP (Mbps)':<25} {results['udp'].get('bits', 0):>15.2f}")
    print(f"{'UDP Jitter (ms)':<25} {results['udp'].get('jitter', 0):>15.2f}")
    print(f"{'UDP Loss (%)':<25} {results['udp'].get('lost_pct', 0):>15.2f}")

if 'latency' in results:
    print(f"\n{'Latency LAN':<25} {results['latency'].get('lan', 'N/A')}")
    print(f"{'Latency VPN':<25} {results['latency'].get('vpn', 'N/A')}")

import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import time

ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Kill any existing client
print("=== Killing existing client ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("pkill -f 'vpn-obfuscated client' 2>/dev/null; sleep 1")
stdout2.channel.recv_exit_status()

# Start client in background
print("=== Starting client in background ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("nohup /usr/bin/vpn-obfuscated client --config /etc/vpn-obfuscated/client.json > /tmp/vpn-client.log 2>&1 &")
stdout2.channel.recv_exit_status()

time.sleep(5)

# Check if client is running
print("=== Client process ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("ps aux | grep vpn-obfuscated | grep -v grep")
print(stdout2.read().decode(errors='replace'))

# Check TUN interface
print("\n=== Client TUN interface ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("ip addr show vpn0 2>&1")
print(stdout2.read().decode(errors='replace'))

# Check client log
print("\n=== Client log ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("tail -20 /tmp/vpn-client.log")
print(stdout2.read().decode(errors='replace'))

# Test ping
print("\n=== Ping from client to server ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 3 10.8.0.1 2>&1")
print(stdout2.read().decode(errors='replace'))

# Check server side
print("\n=== Server TUN interface ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin, stdout, stderr = ssh.exec_command("ip addr show vpn0 2>&1")
print(stdout.read().decode(errors='replace'))

# Server logs
print("\n=== Server logs ===")
stdin, stdout, stderr = ssh.exec_command("journalctl -u vpn-obfuscated --no-pager -n 15 --since '20:19:00'")
print(stdout.read().decode(errors='replace'))

ssh.close()
ssh2.close()

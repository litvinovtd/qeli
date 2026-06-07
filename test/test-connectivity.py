import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import time

# Check server TUN interface
print("=== Server TUN interface ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin, stdout, stderr = ssh.exec_command("ip addr show vpn0 2>&1")
print(stdout.read().decode(errors='replace'))

# Check client TUN interface
print("\n=== Client TUN interface ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin2, stdout2, stderr2 = ssh2.exec_command("ip addr show vpn0 2>&1")
print(stdout2.read().decode(errors='replace'))

# Test ping from client to server
print("\n=== Ping from client to server (10.8.0.1) ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 5 -I vpn0 10.8.0.1 2>&1")
print(stdout2.read().decode(errors='replace'))

# Check server logs
print("\n=== Server logs ===")
stdin, stdout, stderr = ssh.exec_command("journalctl -u vpn-obfuscated --no-pager -n 20 --since '20:18:00'")
print(stdout.read().decode(errors='replace'))

ssh.close()
ssh2.close()

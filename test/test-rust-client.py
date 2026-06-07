import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import time

# Test with Rust client
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# Stop service
print("Stopping client service...")
stdin, stdout, stderr = ssh.exec_command("systemctl stop vpn-obfuscated; sleep 1")
stdout.channel.recv_exit_status()

# Run client manually
print("Running Rust client...")
cmd = "timeout 15 /usr/bin/vpn-obfuscated client --config /etc/vpn-obfuscated/client.json 2>&1"
stdin, stdout, stderr = ssh.exec_command(cmd)

output = ""
start_time = time.time()
while time.time() - start_time < 20:
    if stdout.channel.recv_ready():
        chunk = stdout.channel.recv(4096).decode(errors='replace')
        output += chunk
        print(chunk, end='')
    if stderr.channel.recv_ready():
        chunk = stderr.channel.recv(4096).decode(errors='replace')
        output += chunk
        print(chunk, end='')
    if stdout.channel.exit_status_ready():
        break
    time.sleep(0.5)

# Check server logs
print("\n=== Server logs ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

stdin2, stdout2, stderr2 = ssh2.exec_command("journalctl -u vpn-obfuscated --no-pager -n 20 --since '22:33:00'")
print(stdout2.read().decode(errors='replace'))

ssh.close()
ssh2.close()

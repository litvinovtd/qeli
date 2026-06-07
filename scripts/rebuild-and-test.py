import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# Check binary hash
print("=== Current binary hash ===")
stdin, stdout, stderr = ssh.exec_command("md5sum /usr/bin/vpn-obfuscated; ls -la /usr/bin/vpn-obfuscated")
print(stdout.read().decode(errors='replace'))

# Check source hash
print("\n=== Source file hash ===")
stdin, stdout, stderr = ssh.exec_command("md5sum /root/vpn_project/src/server/handler.rs")
print(stdout.read().decode(errors='replace'))

# Rebuild to be sure
print("\n=== Rebuilding server ===")
stdin, stdout, stderr = ssh.exec_command("cd /root/vpn_project && cargo build --release 2>&1 | tail -10")
print(stdout.read().decode(errors='replace'))

# Install
print("\n=== Installing ===")
stdin, stdout, stderr = ssh.exec_command("cp /root/vpn_project/target/release/vpn-obfuscated /usr/bin/vpn-obfuscated")
stdout.channel.recv_exit_status()

# Restart
print("\n=== Restarting server ===")
stdin, stdout, stderr = ssh.exec_command("systemctl restart vpn-obfuscated")
stdout.channel.recv_exit_status()

time.sleep(3)

# Check status
print("\n=== Server status ===")
stdin, stdout, stderr = ssh.exec_command("systemctl status vpn-obfuscated --no-pager -n 5")
print(stdout.read().decode(errors='replace'))

# Test connection
print("\n=== Testing connection ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# Stop client
stdin2, stdout2, stderr2 = ssh2.exec_command("systemctl stop vpn-obfuscated; sleep 1")
stdout2.channel.recv_exit_status()

# Run client
print("Running client...")
stdin2, stdout2, stderr2 = ssh2.exec_command("timeout 20 /usr/bin/vpn-obfuscated client --config /etc/vpn-obfuscated/client.json 2>&1")
output = ""
start_time = time.time()
while time.time() - start_time < 25:
    if stdout2.channel.recv_ready():
        chunk = stdout2.channel.recv(4096).decode(errors='replace')
        output += chunk
        print(chunk, end='')
    if stderr2.channel.recv_ready():
        chunk = stderr2.channel.recv(4096).decode(errors='replace')
        output += chunk
        print(chunk, end='')
    if stdout2.channel.exit_status_ready():
        break
    time.sleep(0.5)

# Check server logs
print("\n=== Server logs ===")
stdin, stdout, stderr = ssh.exec_command("journalctl -u vpn-obfuscated --no-pager -n 30 --since '22:36:00'")
print(stdout.read().decode(errors='replace'))

ssh.close()
ssh2.close()

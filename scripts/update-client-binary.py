import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import time

# Copy new binary from server 10 to server 11
print("=== Copying binary from server 10 to server 11 ===")

# First, get binary from server 10
ssh10 = paramiko.SSHClient()
ssh10.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh10.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# Read binary
stdin, stdout, stderr = ssh10.exec_command("cat /root/vpn_project/target/release/vpn-obfuscated")
binary_data = stdout.read()
print(f"Binary size: {len(binary_data)} bytes")

# Copy to server 11
ssh11 = paramiko.SSHClient()
ssh11.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh11.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# Stop client
print("\n=== Stopping client ===")
stdin, stdout, stderr = ssh11.exec_command("systemctl stop vpn-obfuscated; sleep 1")
stdout.channel.recv_exit_status()

# Write binary
print("\n=== Writing new binary ===")
stdin, stdout, stderr = ssh11.exec_command("cat > /usr/bin/vpn-obfuscated.new")
stdin.write(binary_data)
stdin.channel.shutdown_write()
exit_code = stdout.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

# Replace
print("\n=== Replacing binary ===")
stdin, stdout, stderr = ssh11.exec_command("""
mv /usr/bin/vpn-obfuscated /usr/bin/vpn-obfuscated.old
mv /usr/bin/vpn-obfuscated.new /usr/bin/vpn-obfuscated
chmod +x /usr/bin/vpn-obfuscated
md5sum /usr/bin/vpn-obfuscated
ls -la /usr/bin/vpn-obfuscated
""")
print(stdout.read().decode(errors='replace'))

# Restart client
print("\n=== Restarting client ===")
stdin, stdout, stderr = ssh11.exec_command("systemctl start vpn-obfuscated")
stdout.channel.recv_exit_status()

time.sleep(5)

# Check status
print("\n=== Client status ===")
stdin, stdout, stderr = ssh11.exec_command("systemctl status vpn-obfuscated --no-pager -n 10")
print(stdout.read().decode(errors='replace'))

# Check server logs
print("\n=== Server logs ===")
stdin, stdout, stderr = ssh10.exec_command("journalctl -u vpn-obfuscated --no-pager -n 30 --since '22:42:00'")
print(stdout.read().decode(errors='replace'))

ssh10.close()
ssh11.close()

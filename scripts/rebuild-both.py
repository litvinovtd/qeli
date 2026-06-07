import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

# Rebuild server first (config/mod.rs is shared)
print("=== Rebuilding server ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin, stdout, stderr = ssh.exec_command("cd /root/vpn_project && cargo build --release 2>&1 | grep -E 'Compiling|Finished|error'")
print(stdout.read().decode(errors='replace'))

# Install
print("\n=== Installing server ===")
stdin, stdout, stderr = ssh.exec_command("""
rm -f /usr/bin/vpn-obfuscated
cp /root/vpn_project/target/release/vpn-obfuscated /usr/bin/vpn-obfuscated
chmod +x /usr/bin/vpn-obfuscated
systemctl restart vpn-obfuscated
""")
stdout.channel.recv_exit_status()

import time
time.sleep(3)

# Rebuild client
print("\n=== Rebuilding client ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin2, stdout2, stderr2 = ssh2.exec_command("cd /root/vpn_project && cargo build --release 2>&1 | grep -E 'Compiling|Finished|error'")
print(stdout2.read().decode(errors='replace'))

# Install
print("\n=== Installing client ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("""
rm -f /usr/bin/vpn-obfuscated
cp /root/vpn_project/target/release/vpn-obfuscated /usr/bin/vpn-obfuscated
chmod +x /usr/bin/vpn-obfuscated
""")
stdout2.channel.recv_exit_status()

# Restart client
print("\n=== Restarting client ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("pkill -f 'vpn-obfuscated client'; sleep 2")
stdout2.channel.recv_exit_status()

stdin2, stdout2, stderr2 = ssh2.exec_command("nohup /usr/bin/vpn-obfuscated client --config /etc/vpn-obfuscated/client.json > /tmp/vpn-client.log 2>&1 &")
stdout2.channel.recv_exit_status()

time.sleep(5)

# Test
print("\n=== Test ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 5 10.8.0.1 2>&1 | tail -3")
print(stdout2.read().decode(errors='replace'))

ssh.close()
ssh2.close()

import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

# Copy config/mod.rs from server to client
print("=== Copying config/mod.rs from server to client ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Read server config/mod.rs
stdin, stdout, stderr = ssh.exec_command("cat /root/vpn_project/src/config/mod.rs")
server_mod = stdout.read().decode(errors='replace')

ssh.close()

# Write to client
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin2, stdout2, stderr2 = ssh2.exec_command("cat > /root/vpn_project/src/config/mod.rs")
stdin2.write(server_mod)
stdin2.channel.shutdown_write()
exit_code = stdout2.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

# Verify
print("\n=== Verify on client ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("grep -n 'DpdConfig' /root/vpn_project/src/config/mod.rs")
print(stdout2.read().decode(errors='replace'))

# Rebuild
print("\n=== Rebuilding client ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("cd /root/vpn_project && cargo build --release 2>&1 | grep -E 'Compiling|Finished|error'")
print(stdout2.read().decode(errors='replace'))

# Install
print("\n=== Installing ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("""
rm -f /usr/bin/vpn-obfuscated
cp /root/vpn_project/target/release/vpn-obfuscated /usr/bin/vpn-obfuscated
chmod +x /usr/bin/vpn-obfuscated
""")
stdout2.channel.recv_exit_status()

# Update client config with DPD
print("\n=== Updating client config ===")
import json
stdin2, stdout2, stderr2 = ssh2.exec_command("cat /etc/vpn-obfuscated/client.json")
client_config = json.loads(stdout2.read().decode(errors='replace'))

# Add DPD config
client_config['dpd'] = {
    'enabled': True,
    'interval_secs': 30,
    'max_retries': 3
}

# Remove heartbeat from obfuscation
if 'heartbeat' in client_config.get('obfuscation', {}):
    client_config['obfuscation']['heartbeat']['enabled'] = False

stdin2, stdout2, stderr2 = ssh2.exec_command("cat > /etc/vpn-obfuscated/client.json")
stdin2.write(json.dumps(client_config, indent=2))
stdin2.channel.shutdown_write()
stdout2.channel.recv_exit_status()

print("Client config updated")

# Restart client
print("\n=== Restarting client ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("pkill -f 'vpn-obfuscated client'; sleep 2")
stdout2.channel.recv_exit_status()

stdin2, stdout2, stderr2 = ssh2.exec_command("nohup /usr/bin/vpn-obfuscated client --config /etc/vpn-obfuscated/client.json > /tmp/vpn-client.log 2>&1 &")
stdout2.channel.recv_exit_status()

import time
time.sleep(5)

# Test
print("\n=== Test ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 5 10.8.0.1 2>&1 | tail -3")
print(stdout2.read().decode(errors='replace'))

ssh2.close()

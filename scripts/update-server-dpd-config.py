import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import json

# Update server config with DPD
print("=== Updating server config ===")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin, stdout, stderr = ssh.exec_command("cat /etc/vpn-obfuscated/server.json")
server_config = json.loads(stdout.read().decode(errors='replace'))

# Add DPD config
server_config['dpd'] = {
    'enabled': True,
    'interval_secs': 30,
    'max_retries': 3
}

# Disable heartbeat
if 'heartbeat' in server_config.get('obfuscation', {}):
    server_config['obfuscation']['heartbeat']['enabled'] = False

stdin, stdout, stderr = ssh.exec_command("cat > /etc/vpn-obfuscated/server.json")
stdin.write(json.dumps(server_config, indent=2))
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()

print("Server config updated")

# Restart server
print("\n=== Restarting server ===")
stdin, stdout, stderr = ssh.exec_command("systemctl restart vpn-obfuscated")
stdout.channel.recv_exit_status()

import time
time.sleep(3)

# Restart client
print("\n=== Restarting client ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin2, stdout2, stderr2 = ssh2.exec_command("pkill -f 'vpn-obfuscated client'; sleep 2")
stdout2.channel.recv_exit_status()

stdin2, stdout2, stderr2 = ssh2.exec_command("nohup /usr/bin/vpn-obfuscated client --config /etc/vpn-obfuscated/client.json > /tmp/vpn-client.log 2>&1 &")
stdout2.channel.recv_exit_status()

time.sleep(5)

# Test
print("\n=== Test ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("ping -c 10 10.8.0.1 2>&1 | tail -3")
print(stdout2.read().decode(errors='replace'))

# Check logs
print("\n=== Server logs ===")
stdin, stdout, stderr = ssh.exec_command("journalctl -u vpn-obfuscated --no-pager -n 15 --since '20:40:00'")
print(stdout.read().decode(errors='replace'))

ssh.close()
ssh2.close()

import os
import paramiko
import time

# Add packet capture to see what's being sent
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# Stop current client on 11
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

print("Stopping client...")
stdin, stdout, stderr = ssh2.exec_command("systemctl stop vpn-obfuscated")
stdout.channel.recv_exit_status()

# Start tcpdump on server
print("Starting tcpdump on server...")
stdin, stdout, stderr = ssh.exec_command("tcpdump -i any -nn -X 'port 443 and host 10.66.116.11' -c 50 > /tmp/capture.txt 2>&1 &")
tcpdump_pid = stdout.read().decode().strip()
print(f"tcpdump PID: {tcpdump_pid}")

time.sleep(2)

# Start client
print("Starting client...")
stdin2, stdout2, stderr2 = ssh2.exec_command("systemctl start vpn-obfuscated")
stdout2.channel.recv_exit_status()

time.sleep(10)

# Stop tcpdump
print("Stopping tcpdump...")
stdin, stdout, stderr = ssh.exec_command("pkill tcpdump; sleep 1; cat /tmp/capture.txt")
capture = stdout.read().decode(errors='replace')
print("\n=== TCPDUMP CAPTURE ===")
print(capture[:3000])

# Get server logs
print("\n=== SERVER LOGS ===")
stdin, stdout, stderr = ssh.exec_command("journalctl -u vpn-obfuscated --no-pager -n 20 --since '22:26:00'")
print(stdout.read().decode(errors='replace'))

ssh.close()
ssh2.close()

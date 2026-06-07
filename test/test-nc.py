import os
import paramiko
import time

# Test manual connection from 11 to 10
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

print("=== Testing manual TCP connection ===")

# Use nc to test connection
cmd = "timeout 5 bash -c 'echo test | nc -w 3 10.66.116.10 443' 2>&1 || echo 'Connection failed or timed out'"
stdin, stdout, stderr = ssh.exec_command(cmd)
output = stdout.read().decode(errors='replace')
print(f"nc output: {output}")

# Check if we can see the connection on server side
print("\n=== Server side connections ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

stdin2, stdout2, stderr2 = ssh2.exec_command("ss -tnp | grep 443")
print(stdout2.read().decode(errors='replace'))

# Check server logs for any connection attempts
print("\n=== Server logs ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("journalctl -u vpn-obfuscated --no-pager -n 20 --since '22:28:00'")
print(stdout2.read().decode(errors='replace'))

ssh.close()
ssh2.close()

import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Install argon2-cffi
print("=== Install argon2-cffi ===")
stdin, stdout, stderr = ssh.exec_command("pip3 install --break-system-packages argon2-cffi 2>&1")
output = stdout.read().decode(errors='replace')
print(output[-200:] if len(output) > 200 else output)

ssh.close()

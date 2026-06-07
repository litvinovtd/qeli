import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Check if DpdConfig is actually in the file
print("=== Grep DpdConfig ===")
stdin, stdout, stderr = ssh.exec_command("grep -n 'DpdConfig' /root/vpn_project/src/config/mod.rs")
print(stdout.read().decode(errors='replace'))

# Check file structure
print("\n=== File structure around DpdConfig ===")
stdin, stdout, stderr = ssh.exec_command("sed -n '120,135p' /root/vpn_project/src/config/mod.rs")
print(stdout.read().decode(errors='replace'))

# Check if there's a syntax issue
print("\n=== Full config/mod.rs ===")
stdin, stdout, stderr = ssh.exec_command("wc -l /root/vpn_project/src/config/mod.rs")
print(stdout.read().decode(errors='replace'))

ssh.close()

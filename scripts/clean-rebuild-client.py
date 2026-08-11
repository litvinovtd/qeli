import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko
import ssh_hostkey

ssh2 = paramiko.SSHClient()
ssh_hostkey.harden(ssh2)
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Clean rebuild
print("=== Clean rebuild ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("cd /root/vpn_project && cargo clean && cargo build --release 2>&1 | tail -20")
print(stdout2.read().decode(errors='replace'))

ssh2.close()

#!/usr/bin/env python3
"""Generate qeli:// share link for reality-tls."""
import os
import sys
import io
import paramiko

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("138.124.78.35", username="root", password=os.environ.get("QELI_DEPLOY_PASS", ""), timeout=15)

def run(cmd, timeout=30):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    return (stdout.read().decode('utf-8', errors='ignore') + stderr.read().decode('utf-8', errors='ignore')).strip()

# Generate share link with a new user
result = run("""source $HOME/.cargo/env 2>/dev/null; qeli add-client testuser3 --password TestPass123! --config /etc/qeli/server.conf --link --host 138.124.78.35 2>&1""")
print(result)

ssh.close()

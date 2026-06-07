import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# Install argon2-cffi with --break-system-packages
print("=== Install argon2-cffi ===")
stdin, stdout, stderr = ssh.exec_command("pip3 install --break-system-packages argon2-cffi 2>&1 | tail -5")
print(stdout.read().decode(errors='replace'))

# Generate hash
print("\n=== Generate hash ===")
stdin, stdout, stderr = ssh.exec_command("""
python3 -c "
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=16384, parallelism=1, hash_len=32, salt_len=16)
h = ph.hash('admin')
print(h)
" 2>&1
""")
new_hash = stdout.read().decode(errors='replace').strip()
print(new_hash)

# Update users.json
print("\n=== Updating users.json ===")
if new_hash and '$argon2id' in new_hash:
    # Read current users.json
    stdin, stdout, stderr = ssh.exec_command("cat /etc/vpn-obfuscated/users.json")
    content = stdout.read().decode(errors='replace')
    
    # Replace both password hashes
    import re
    content = re.sub(r'"password_hash":\s*"[^"]+"', f'"password_hash": "{new_hash}"', content)
    
    # Write back
    stdin, stdout, stderr = ssh.exec_command("cat > /etc/vpn-obfuscated/users.json")
    stdin.write(content)
    stdin.channel.shutdown_write()
    exit_code = stdout.channel.recv_exit_status()
    print(f"Write exit code: {exit_code}")
    
    # Verify
    stdin, stdout, stderr = ssh.exec_command("grep password_hash /etc/vpn-obfuscated/users.json")
    print(stdout.read().decode(errors='replace'))
else:
    print("ERROR: Could not generate hash")

ssh.close()

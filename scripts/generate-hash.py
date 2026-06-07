import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# Generate new argon2id hash for admin:admin
print("=== Generating new hash ===")
stdin, stdout, stderr = ssh.exec_command("""
python3 -c "
import hashlib
import base64

# Try to use argon2-cffi if available
try:
    from argon2 import PasswordHasher
    ph = PasswordHasher(time_cost=2, memory_cost=16384, parallelism=1, hash_len=32, salt_len=16)
    hash = ph.hash('admin')
    print('argon2-cffi:', hash)
except ImportError:
    print('argon2-cffi not available')

# Fallback: use the same parameters as users.json
# Salt: vpn-salt-2026 (base64: dnBuLXNhbHQtMjAyNg)
print('Need to generate hash with: time=2, memory=16384, parallelism=1, salt=vpn-salt-2026')
" 2>&1
""")
print(stdout.read().decode(errors='replace'))

# Check if argon2 is available
print("\n=== Check argon2 availability ===")
stdin, stdout, stderr = ssh.exec_command("pip3 list 2>/dev/null | grep -i argon || echo 'argon2 not installed via pip'")
print(stdout.read().decode(errors='replace'))

# Install argon2-cffi and generate hash
print("\n=== Install argon2-cffi ===")
stdin, stdout, stderr = ssh.exec_command("pip3 install argon2-cffi 2>&1 | tail -3")
print(stdout.read().decode(errors='replace'))

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
    # Escape for sed
    escaped_hash = new_hash.replace('/', '\\/').replace('$', '\\$').replace('&', '\\&')
    stdin, stdout, stderr = ssh.exec_command(f"""
sed -i 's/"password_hash": ".*"/"password_hash": "{new_hash}"/g' /etc/vpn-obfuscated/users.json
cat /etc/vpn-obfuscated/users.json | grep password_hash
""")
    print(stdout.read().decode(errors='replace'))
else:
    print("ERROR: Could not generate hash")

ssh.close()

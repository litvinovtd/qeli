import os
import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

FILE = '/root/android-project/app/src/main/kotlin/com/vpn/obfuscated/VpnServiceImpl.kt'

# Патч 1: Увеличить лимит TLS record
print("=== Patch 1: TLS record limit ===")
stdin, stdout, stderr = ssh.exec_command(
    f"sed -i 's/payloadLen > 16384 + 2048/payloadLen > 65535/g' {FILE}"
)
print("stderr:", stderr.read().decode())

# Проверка
stdin2, stdout2, stderr2 = ssh.exec_command(f"grep -n 'payloadLen > 65535' {FILE}")
print("Result:", stdout2.read().decode())

# Патч 2: IPv6 filter — используем Python на сервере
print("\n=== Patch 2: IPv6 filter ===")
python_script = """
import re
path = '/root/android-project/app/src/main/kotlin/com/vpn/obfuscated/VpnServiceImpl.kt'
with open(path, 'r') as f:
    content = f.read()

old = '                    tunRxCount++\\n                    if (tunRxCount <= 10'
new = '                    val ver = (buf[0].toInt() and 0xFF) shr 4\\n                    if (ver != 4) { continue }\\n                    tunRxCount++\\n                    if (tunRxCount <= 10'

if old in content:
    content = content.replace(old, new)
    with open(path, 'w') as f:
        f.write(content)
    print('SUCCESS: IPv6 filter applied')
else:
    print('WARNING: pattern not found, trying alternative')
    # Попробуем найти tunRxCount++
    for i, line in enumerate(content.split('\\n')):
        if 'tunRxCount++' in line and 'ver' not in content.split('\\n')[max(0,i-2):i+1]:
            print(f'  Found tunRxCount++ at line {i+1}: {line.strip()}')
"""

stdin3, stdout3, stderr3 = ssh.exec_command(f'python3 -c "{python_script}"')
out3 = stdout3.read().decode()
err3 = stderr3.read().decode()
print("stdout:", out3)
print("stderr:", err3)

# Проверка
stdin4, stdout4, stderr4 = ssh.exec_command(f"grep -n 'ver != 4\\|tunRxCount' {FILE}")
print("\nVerification:", stdout4.read().decode())

ssh.close()
print("\nDone!")

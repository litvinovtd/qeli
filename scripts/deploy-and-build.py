import os
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

# 1. Увеличить лимит TLS record с 18432 до 65535
stdin, stdout, stderr = ssh.exec_command(
    "sed -i 's/payloadLen > 16384 + 2048/payloadLen > 65535/g' "
    "/root/vpn-obfuscated-android/app/src/main/kotlin/com/vpn/obfuscated/VpnServiceImpl.kt"
)
print("sed stdout:", stdout.read().decode())
print("sed stderr:", stderr.read().decode())

# 2. Добавить фильтрацию IPv6 — вставить проверку ver != 4 перед tunRxCount++
stdin2, stdout2, stderr2 = ssh.exec_command(
    r"""python3 -c "
import re
path = '/root/vpn-obfuscated-android/app/src/main/kotlin/com/vpn/obfuscated/VpnServiceImpl.kt'
with open(path, 'r') as f:
    content = f.read()

old = '''                    tunRxCount++
                    if (tunRxCount <= 10'''

new = '''                    val ver = (buf[0].toInt() and 0xFF) shr 4
                    if (ver != 4) { continue }
                    tunRxCount++
                    if (tunRxCount <= 10'''

content = content.replace(old, new)
with open(path, 'w') as f:
    f.write(content)
print('IPv6 filter applied')
"
"""
)
print("filter stdout:", stdout2.read().decode())
print("filter stderr:", stderr2.read().decode())

# 3. Проверка изменений
stdin3, stdout3, stderr3 = ssh.exec_command(
    "grep -n 'payloadLen > 65535\\|ver != 4' /root/vpn-obfuscated-android/app/src/main/kotlin/com/vpn/obfuscated/VpnServiceImpl.kt"
)
print("Verification:", stdout3.read().decode())

# 4. Сборка APK
print("\n--- Building APK ---")
stdin4, stdout4, stderr4 = ssh.exec_command(
    "cd /root/vpn-obfuscated-android && ./gradlew assembleRelease --offline 2>&1 | tail -20",
    get_pty=True
)
# Ждём завершения сборки
exit_code = stdout4.channel.recv_exit_status()
output = stdout4.read().decode() + stderr4.read().decode()
print(output)

ssh.close()
print("\nDone!")

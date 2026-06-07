import os
import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

PROJECT = '/root/android-project'
GRADLE = '/root/gradle-8.11.1/bin/gradle'
FILE = f'{PROJECT}/app/src/main/kotlin/com/vpn/obfuscated/VpnServiceImpl.kt'

print("=== Step 1: Read current file ===")
stdin, stdout, stderr = ssh.exec_command(f"cat {FILE}")
content = stdout.read().decode()
print(f"File size: {len(content)} bytes")

# Патч 1: Увеличить лимит TLS record
old1 = "payloadLen > 16384 + 2048"
new1 = "payloadLen > 65535"
content = content.replace(old1, new1)
print(f"Patch 1 applied: {old1} -> {new1}")

# Патч 2: Добавить фильтрацию IPv6
old2 = """                    tunRxCount++
                    if (tunRxCount <= 10"""
new2 = """                    val ver = (buf[0].toInt() and 0xFF) shr 4
                    if (ver != 4) { continue }
                    tunRxCount++
                    if (tunRxCount <= 10"""
content = content.replace(old2, new2)
print(f"Patch 2 applied: IPv6 filter added")

# Записываем обратно
print("\n=== Step 2: Write patched file ===")
stdin_w, stdout_w, stderr_w = ssh.exec_command(f"cat > {FILE}", get_pty=True)
stdin_w.write(content)
stdin_w.channel.shutdown_write()
exit_code = stdout_w.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

# Проверяем
print("\n=== Step 3: Verify patches ===")
stdin3, stdout3, stderr3 = ssh.exec_command(f"grep -n 'payloadLen > 65535\\|ver != 4' {FILE}")
print(stdout3.read().decode())

# Собираем
print("\n=== Step 4: Building release APK ===")
cmd = f"cd {PROJECT} && {GRADLE} assembleRelease --offline --no-daemon 2>&1"
transport = ssh.get_transport()
channel = transport.open_session()
channel.get_pty()
channel.exec_command(cmd)

output = b""
while True:
    if channel.recv_ready():
        chunk = channel.recv(4096)
        if chunk:
            output += chunk
            print(chunk.decode(errors='replace'), end='')
    if channel.exit_status_ready():
        break
    time.sleep(0.5)

# Ждём завершения
channel.close()
exit_status = channel.recv_exit_status()

print(f"\n\n=== Build exit code: {exit_status} ===")

# Ищем APK
stdin5, stdout5, stderr5 = ssh.exec_command(f"find {PROJECT}/app/build -name '*.apk' -newer {FILE} 2>/dev/null")
apk_path = stdout5.read().decode().strip()
if apk_path:
    print(f"APK built: {apk_path}")
else:
    print("APK not found, checking for errors...")
    stdin6, stdout6, stderr6 = ssh.exec_command(f"tail -50 /root/gradle_build.log 2>/dev/null || echo 'No log'")
    print(stdout6.read().decode())

ssh.close()
print("\nDone!")

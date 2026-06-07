import os
import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

PROJECT = '/root/android-project'
GRADLE = '/root/gradle-8.11.1/bin/gradle'

print("=== Clean build ===")
cmd = f"cd {PROJECT} && {GRADLE} clean assembleDebug --offline --no-daemon 2>&1"

transport = ssh.get_transport()
channel = transport.open_session()
channel.get_pty()
channel.exec_command(cmd)

while not channel.exit_status_ready():
    if channel.recv_ready():
        chunk = channel.recv(4096).decode(errors='replace')
        print(chunk, end='')
    time.sleep(0.5)

while channel.recv_ready():
    chunk = channel.recv(4096).decode(errors='replace')
    print(chunk, end='')

exit_status = channel.recv_exit_status()
print(f"\n\n=== Build exit code: {exit_status} ===")

stdin, stdout, stderr = ssh.exec_command(f"ls -lh {PROJECT}/app/build/outputs/apk/debug/app-debug.apk")
print(stdout.read().decode())

ssh.close()

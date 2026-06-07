"""Generate an Argon2id PHC hash for 'qelibench' on the server."""
import os
import paramiko, sys
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("10.66.116.10", username="root", password=os.environ.get("QELI_LAB_PASS", ""),
          timeout=15, allow_agent=False, look_for_keys=False)
for cmd in [
    "which argon2 || apt-get install -y argon2 >/dev/null 2>&1; which argon2",
    "echo -n 'qelibench' | argon2 'vpn-salt-2026' -id -t 2 -m 14 -p 1 -e",
]:
    _, o, _ = c.exec_command(cmd); o.channel.set_combine_stderr(True)
    print(f"$ {cmd}")
    sys.stdout.write(o.read().decode(errors='replace'))
c.close()

"""Stop qeli, install the fresh binary on both hosts, restart."""
from __future__ import annotations
import os
import paramiko, sys
from pathlib import Path

LOCAL = Path(r"C:\Users\Administrator\Documents\project\vpn\release\qeli-linux-amd64")
HOSTS = ["10.66.116.10", "10.66.116.11"]
USER, PASS = "root", os.environ.get("QELI_LAB_PASS", "")


def run(c, cmd):
    print(f"  $ {cmd}")
    _, o, _ = c.exec_command(cmd)
    o.channel.set_combine_stderr(True)
    data = o.read().decode(errors="replace").strip()
    if data:
        for line in data.splitlines():
            print(f"    {line}")
    return o.channel.recv_exit_status()


for host in HOSTS:
    print(f"\n=== {host} ===")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=USER, password=PASS, timeout=15,
              allow_agent=False, look_for_keys=False)
    try:
        run(c, "systemctl stop qeli")
        sftp = c.open_sftp()
        sftp.put(str(LOCAL), "/usr/bin/qeli.new")
        sftp.chmod("/usr/bin/qeli.new", 0o755)
        sftp.close()
        run(c, "mv /usr/bin/qeli /usr/bin/qeli.prev || true")
        run(c, "mv /usr/bin/qeli.new /usr/bin/qeli")
        run(c, "sha256sum /usr/bin/qeli")
        run(c, "stat -c '%s bytes, %y' /usr/bin/qeli")
        # do NOT start qeli here — benchmark script controls lifecycle
    finally:
        c.close()
print("\nBinary installed on both hosts (services left stopped).")

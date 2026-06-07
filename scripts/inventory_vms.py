#!/usr/bin/env python3
"""Read-only inventory of both lab VMs before any cleanup."""
import os
import paramiko

HOSTS = {"server .10": "10.66.116.10", "client .11": "10.66.116.11"}
USER, PWD = "root", os.environ.get("QELI_LAB_PASS", "")


def sh(ip, cmd, t=60):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username=USER, password=PWD, timeout=20, look_for_keys=False, allow_agent=False)
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    c.close(); return out.rstrip()


CMDS = [
    ("running qeli/java/emulator procs",
     "ps -eo pid,etimes,comm,args --sort=-etimes | grep -iE 'qeli|java|emulator|qemu|adb|gradle' | grep -v grep | head -20"),
    ("/root top-level (size, mtime)",
     "cd /root && du -sh */ 2>/dev/null | sort -h | tail -40"),
    ("/root files (non-dir)",
     "find /root -maxdepth 1 -type f -printf '%TY-%Tm-%Td %10s  %p\\n' 2>/dev/null | sort"),
    ("/root total",
     "du -sh /root 2>/dev/null"),
    ("/etc/qeli",
     "ls -la /etc/qeli 2>/dev/null; echo '--- *.json/*.conf in /etc/qeli ---'; ls /etc/qeli/*.json /etc/qeli/*.conf 2>/dev/null"),
    ("qeli source trees",
     "for d in /root/qeli /opt/qeli-src /root/android-project; do echo \"== $d ==\"; ls -d $d 2>/dev/null && du -sh $d 2>/dev/null; done"),
    ("log dirs",
     "du -sh /var/log/qeli 2>/dev/null; ls -la /var/log/qeli 2>/dev/null | head"),
    ("disk usage",
     "df -h / | tail -1"),
]

for name, ip in HOSTS.items():
    print("\n" + "=" * 70 + f"\n{name} ({ip})\n" + "=" * 70)
    for title, cmd in CMDS:
        print(f"\n### {title}")
        try:
            print(sh(ip, cmd))
        except Exception as ex:
            print("[err]", ex)

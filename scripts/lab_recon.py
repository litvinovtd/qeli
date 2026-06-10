#!/usr/bin/env python3
"""One-shot lab recon before a benchmark run: reachability, uptime, CPU,
release-binary freshness vs source, listening qeli, iperf3 presence."""
import os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
HOSTS = {"server .10": "10.66.116.10", "client .11": "10.66.116.11"}
SRC_BIN = "/opt/qeli-src/target/release/qeli"


def conn(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=60):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


for label, ip in HOSTS.items():
    print(f"\n===== {label} ({ip}) =====")
    try:
        c = conn(ip)
    except Exception as ex:
        print("  UNREACHABLE:", ex); continue
    print("  uptime    :", run(c, "uptime -p; echo 'since '$(uptime -s)"))
    print("  kernel    :", run(c, "uname -r"))
    print("  nproc     :", run(c, "nproc"), "| load:", run(c, "cat /proc/loadavg"))
    print("  mem       :", run(c, "free -m | awk '/Mem:/{print $3\"/\"$2\" MB used\"}'"))
    print("  iperf3    :", run(c, "iperf3 --version 2>&1 | head -1 || echo MISSING"))
    if "10" in label:
        print("  src HEAD  :", run(c, "cd /opt/qeli-src 2>/dev/null && git log -1 --format='%h %ci %s' 2>/dev/null || echo 'no git'"))
        print("  rel bin   :", run(c, f"ls -la {SRC_BIN} 2>/dev/null || echo MISSING"))
        print("  rel sha16 :", run(c, f"sha256sum {SRC_BIN} 2>/dev/null | cut -c1-16 || echo -"))
        print("  rel ver   :", run(c, f"{SRC_BIN} --version 2>&1 || echo -"))
        print("  newest src:", run(c, "cd /opt/qeli-src && find qeli/src -name '*.rs' -newer target/release/qeli 2>/dev/null | head -5; echo '(files newer than release binary ^)'"))
        print("  systemd   :", run(c, "systemctl is-active qeli-server.service 2>/dev/null"))
        print("  listening :", run(c, "ss -ltnp 2>/dev/null | grep -oE ':[0-9]+ ' | sort -u | tr '\\n' ' '"))
    c.close()
print("\n[recon done]")

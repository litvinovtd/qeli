"""Clean lab state: kill all iperf3 / orphan qeli / restart services / verify."""
import os
import paramiko, time, sys

for ip, role in [("10.66.116.10", "server"), ("10.66.116.11", "client")]:
    print(f"\n=== {ip} ({role}) ===")
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=os.environ.get("QELI_LAB_PASS", ""), timeout=15,
              allow_agent=False, look_for_keys=False)
    for cmd in [
        "systemctl stop qeli; sleep 1",
        "pkill -9 -f iperf3 2>/dev/null; pkill -9 -f 'top -b' 2>/dev/null; pkill -9 -f pidstat 2>/dev/null; sleep 1",
        "pgrep -fa 'qeli|iperf3' || echo nothing-running",
        "ss -tlnp | grep -E ':(443|4443|5201)' || echo no-listeners",
        "ls /var/run/qeli/ 2>/dev/null || true",
        "rm -f /var/run/qeli/control.sock 2>/dev/null || true",
        "ip link show vpn0 2>/dev/null && ip link del vpn0 || echo no-vpn0",
        "free -m | head -2",
        "uptime",
    ]:
        _, o, _ = c.exec_command(cmd, timeout=15); o.channel.set_combine_stderr(True)
        out = o.read().decode(errors='replace').strip()
        print(f"  $ {cmd[:60]}")
        for line in out.splitlines()[:5]:
            print(f"    {line}")
    c.close()
print("\ndone")

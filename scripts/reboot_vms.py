"""Reboot both lab VMs, wait for them to come back, verify baseline TCP works."""
import time
import sys

from lab_common import connect, LAB_SRV, LAB_CLI

VMS = (LAB_SRV, LAB_CLI)

for host in VMS:
    ip = host[0]
    print(f"--- reboot {ip}")
    try:
        c = connect(host, timeout=5)
        c.exec_command("(sleep 1; reboot) >/dev/null 2>&1 &")
        c.close()
    except Exception as e:
        print(f"  warning: {e}")

print("\nWaiting for both VMs to come back online...")
# Poll until both accept SSH again
for host in VMS:
    ip = host[0]
    for attempt in range(60):
        time.sleep(2)
        try:
            c = connect(host, timeout=3)
            _, o, _ = c.exec_command("uptime")
            o.channel.set_combine_stderr(True)
            print(f"  {ip} up: {o.read().decode().strip()}")
            c.close()
            break
        except Exception:
            print(f"  {ip} attempt {attempt+1}/60 — not yet")
    else:
        print(f"  {ip} did NOT come back within 2 min — aborting")
        sys.exit(1)

print("\nBoth VMs back. Sleeping 5 s for services to settle.")
time.sleep(5)
print("Done. State:")
for host in VMS:
    ip = host[0]
    c = connect(host, timeout=10)
    for cmd in [
        "uptime",
        "systemctl is-active qeli",
        "pgrep -fa qeli || echo not-running",
        "ip -br a show vpn0 2>/dev/null || echo no-vpn0",
        "ss -tlnp | grep -E ':(443|4443)' || echo no-vpn-listeners",
    ]:
        _, o, _ = c.exec_command(cmd); o.channel.set_combine_stderr(True)
        print(f"  [{ip}] $ {cmd}  →  {o.read().decode().strip()}")
    c.close()

"""Reboot both lab VMs, wait for them to come back, verify baseline TCP works."""
import os
import paramiko, time, sys

def ssh(ip, timeout=10):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=os.environ.get("QELI_LAB_PASS", ""), timeout=timeout,
              allow_agent=False, look_for_keys=False)
    return c

for ip in ("10.66.116.10", "10.66.116.11"):
    print(f"--- reboot {ip}")
    try:
        c = ssh(ip, timeout=5)
        c.exec_command("(sleep 1; reboot) >/dev/null 2>&1 &")
        c.close()
    except Exception as e:
        print(f"  warning: {e}")

print("\nWaiting for both VMs to come back online...")
# Poll until both accept SSH again
for ip in ("10.66.116.10", "10.66.116.11"):
    for attempt in range(60):
        time.sleep(2)
        try:
            c = ssh(ip, timeout=3)
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
for ip in ("10.66.116.10", "10.66.116.11"):
    c = ssh(ip, timeout=10)
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

"""Full lab reboot: clean -> guest `reboot` on both VMs -> wait -> clean again -> verify.

Deliberately a GUEST reboot (not a hypervisor power-cycle): it resets everything
the lab owns — TUN devices, orphan processes, page cache, routing — and the one
thing it cannot fix (throughput noise from neighbouring VMs on the hypervisor) a
power-cycle would not fix either. Use scripts/stability_gate.py to decide whether
the host is quiet enough to measure on.

The cleanup runs TWICE on purpose:
  * before, so a running emulator/benchmark cannot dirty the shutdown;
  * after, because `qeli.service` is Restart=always and the emulator may be
    started by whatever left it running — a fresh boot is not automatically a
    quiet one.
"""
import time
import sys

from lab_common import connect, run, LAB_SRV, LAB_CLI
import lab_hygiene as hy

VMS = ((LAB_SRV, ".10 server"), (LAB_CLI, ".11 client"))

print("=== pre-reboot cleanup ===")
for host, name in VMS:
    try:
        c = connect(host, timeout=10)
        hy.full_clean(c, run, label=name)
        c.close()
    except Exception as e:
        print(f"  [{name}] warning: {e}")

print("\n=== rebooting both VMs ===")
for host, name in VMS:
    ip = host[0]
    print(f"--- reboot {ip}")
    try:
        c = connect(host, timeout=5)
        # `sync` first: an immediate reboot has silently lost a freshly uploaded
        # binary (page cache never hit the disk), which then failed the next run.
        c.exec_command("sync; (sleep 1; reboot) >/dev/null 2>&1 &")
        c.close()
    except Exception as e:
        print(f"  warning: {e}")

print("\nWaiting for both VMs to come back online...")
for host, name in VMS:
    ip = host[0]
    for attempt in range(60):
        time.sleep(2)
        try:
            c = connect(host, timeout=3)
            up = run(c, "uptime -p").strip()
            print(f"  {ip} up: {up}")
            c.close()
            break
        except Exception:
            pass
    else:
        print(f"  {ip} did NOT come back within 2 min — aborting")
        sys.exit(1)

print("\nSettling 10 s, then post-boot cleanup (autostarted units / emulator)...")
time.sleep(10)

ok = True
print("\n=== post-reboot cleanup ===")
for host, name in VMS:
    c = connect(host, timeout=10)
    st = hy.full_clean(c, run, label=name)
    ok &= hy.assert_quiet(st, name)
    c.close()

print("\n=== state ===")
for host, name in VMS:
    ip = host[0]
    c = connect(host, timeout=10)
    for cmd in [
        "uptime -p",
        "cat /proc/loadavg",
        "vmstat 1 2 | tail -1 | awk '{print \"cpu steal: \"$NF\"%\"}'",
        "ss -tlnp | grep -E ':(443|4443)' || echo no-vpn-listeners",
    ]:
        print(f"  [{ip}] {run(c, cmd).strip()}")
    c.close()

print("\nDone." if ok else "\nDone, but the lab is NOT clean — see warnings above.")
sys.exit(0 if ok else 1)

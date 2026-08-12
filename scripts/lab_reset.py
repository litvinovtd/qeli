"""Clean lab state without rebooting: stop qeli units, kill the Android emulator
and measurers, drop orphan TUNs and leftover tc/netem qdiscs, then report.

Previously this killed only iperf3 / orphan qeli / vpn0 — it left the Android
emulator running (which wrecked a whole benchmark sweep) and left tc qdiscs in
place (which would silently cap throughput and read as a regression). All of
that now lives in lab_hygiene.full_clean so reboot_vms.py, the benchmark and
this script cannot drift apart again.
"""
import sys

from lab_common import connect, run, LAB_SRV, LAB_CLI
import lab_hygiene as hy

ok = True
for host, role in ((LAB_SRV, "server"), (LAB_CLI, "client")):
    ip = host[0]
    print(f"\n=== {ip} ({role}) ===")
    c = connect(host, timeout=15)
    st = hy.full_clean(c, run, label=f"{ip} {role}")
    ok &= hy.assert_quiet(st, f"{ip} ({role})")
    # Control socket of a killed server would otherwise refuse the next start.
    run(c, "rm -f /var/run/qeli/control.sock 2>/dev/null; true")
    for cmd in [
        "pgrep -fa 'qeli|iperf3' || echo nothing-running",
        "ss -tlnp | grep -E ':(443|4443|5201)' || echo no-listeners",
        "ip -br link | grep -ivE 'lo |ens18' || echo 'no leftover ifaces'",
        "ip route get 192.168.50.50 2>/dev/null | head -1",
        "free -m | head -2 | tail -1",
        "uptime -p",
    ]:
        out = run(c, cmd).strip()
        for line in out.splitlines()[:4]:
            print(f"    {line}")
    c.close()

print("\ndone" if ok else "\ndone — but the lab is NOT clean (see warnings)")
sys.exit(0 if ok else 1)

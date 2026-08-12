#!/usr/bin/env python3
"""Shared lab-hygiene helpers: everything that must be OFF before a measurement.

One place, because the same cleanup was previously copy-pasted (and each copy
forgot something different). What bit us in practice:

  * the Android emulator (qemu-system-x86_64) kept running through a benchmark
    and wrecked six of ten iperf3 runs — neither reboot_vms.py nor benchmark.py
    touched it;
  * `qeli.service` / `qeli-server.service` are Restart=always, so `pkill qeli`
    alone resurrects them (and they grab vpn0), which once made an ACL case
    "pass" against the wrong server;
  * leftover tc/netem qdiscs from a shaping test silently cap throughput;
  * orphan TUN devices keep pushed routes alive — twice they blackholed the SSH
    return path to .11.

NB: match the emulator as `qemu-system-x86_64`, never the loose `qemu` — the
VMs themselves run `/usr/sbin/qemu-ga` (guest agent) and killing that is both
wrong and misleading (it made me report a "respawning emulator" that was not).
The `[q]` bracket trick keeps pgrep/pkill from matching their own command line.
"""
import sys

EMU_PAT = "[q]emu-system-x86_64"
ADB = "/root/android-sdk/platform-tools/adb"


def kill_emulator(c, run):
    """Stop the Android emulator + adb. No-op when neither is present."""
    run(c, f"pkill -9 -f '{EMU_PAT}' 2>/dev/null; "
           f"{ADB} kill-server 2>/dev/null; sleep 1; true")
    return run(c, f"pgrep -f '{EMU_PAT}' | wc -l").strip().splitlines()[-1]


def stop_qeli(c, run):
    """Stop the units FIRST (Restart=always), then any stragglers."""
    run(c, "systemctl stop qeli.service qeli-server.service 2>/dev/null; sleep 1; "
           "pkill -9 -x qeli 2>/dev/null; sleep 1; true")
    return run(c, "pgrep -x qeli | wc -l").strip().splitlines()[-1]


# Qdiscs the kernel installs by itself (net.core.default_qdisc differs per VM:
# .10 uses fq_codel, .11 uses fq). Removing these is NOT cleanup — it changes the
# host's networking behaviour and would itself perturb the measurement, so only
# artificial shapers left over from a test are removed.
# NB: do NOT put bare "codel" here — it substring-matches `fq_codel`, the system
# default on .10, so the "cleanup" deleted the very qdisc it was meant to keep
# (the kernel silently reinstalled it, which is why it looked harmless).
SHAPERS = ("netem", "tbf", "htb", "cake", "hfsc")


def clear_netem(c, run):
    """Remove leftover ARTIFICIAL shapers (netem/tbf/htb/…), keep system defaults.

    A forgotten `tc qdisc add … netem rate/delay` silently caps throughput and
    reads as a regression. But `fq`/`fq_codel`/`pfifo_fast`/`mq`/`noqueue` are
    what the kernel puts there on its own — deleting those swaps the scheduler
    mid-benchmark, which is exactly the kind of self-inflicted noise this module
    exists to prevent.
    """
    pat = "|".join(SHAPERS)
    run(c, "for d in $(ip -br link | awk '{print $1}' | cut -d@ -f1 | grep -vE '^lo$'); do "
           f"if tc qdisc show dev $d | head -1 | grep -qE '{pat}'; then "
           "tc qdisc del dev $d root 2>/dev/null; fi; done; true")
    left = run(c, f"tc qdisc show 2>/dev/null | grep -E '{pat}' | head -3 || true").strip()
    return left


def clear_tuns(c, run, keep=("lo", "ens18")):
    """Delete every interface that is not the loopback or the uplink."""
    pat = "|".join(f"^{k}$" for k in keep)
    run(c, f"for i in $(ip -br link | awk '{{print $1}}' | cut -d@ -f1 | grep -vE '{pat}'); do "
           f"ip link del $i 2>/dev/null; done; "
           f"ip tuntap del dev vpn0 mode tun 2>/dev/null; true")
    return run(c, f"ip -br link | awk '{{print $1}}' | cut -d@ -f1 | grep -vE '{pat}' "
                  f"| tr '\\n' ' ' || true").strip()


def kill_measurers(c, run):
    """iperf3 servers/clients and sampling helpers from an aborted run."""
    run(c, "pkill -9 -x iperf3 2>/dev/null; pkill -9 -f '[t]op -b' 2>/dev/null; "
           "pkill -9 -f '[p]idstat' 2>/dev/null; pkill -9 -x nc 2>/dev/null; sleep 1; true")


def restore_dns(c, run):
    run(c, "printf 'nameserver 1.1.1.1\\n' > /etc/resolv.conf 2>/dev/null; true")


def full_clean(c, run, label=""):
    """Everything that must be off before measuring. Returns a status dict."""
    emu = kill_emulator(c, run)
    qeli = stop_qeli(c, run)
    kill_measurers(c, run)
    tuns = clear_tuns(c, run)
    qdisc = clear_netem(c, run)
    restore_dns(c, run)
    st = {"emulator": emu, "qeli_procs": qeli,
          "leftover_ifaces": tuns or "(none)", "odd_qdisc": qdisc or "(none)"}
    if label:
        print(f"  [{label}] emulator={st['emulator']} qeli={st['qeli_procs']} "
              f"ifaces={st['leftover_ifaces']} qdisc={st['odd_qdisc']}")
    return st


def assert_quiet(st, where):
    """Fail loudly rather than measure a dirty host."""
    bad = []
    if st["emulator"] != "0":
        bad.append(f"emulator still running ({st['emulator']})")
    if st["qeli_procs"] != "0":
        bad.append(f"qeli still running ({st['qeli_procs']})")
    if st["leftover_ifaces"] != "(none)":
        bad.append(f"leftover interfaces: {st['leftover_ifaces']}")
    if bad:
        print(f"!! {where} is NOT clean: {'; '.join(bad)}", file=sys.stderr)
        return False
    return True


def versioned_result_path(version, stem):
    """Build `release/<stem>_v<version>_<date>.json`, never overwriting.

    Result files used to carry a HARD-CODED version in their name (e.g.
    `download_bonding_0.7.12.json`), so every later run silently relabelled its
    data as that old version — a 0.7.15 sweep landed in a file named 0.7.12, and
    the real 0.7.12 reference was overwritten. Pass the version of the binary that
    actually ran; a repeat run gets a `_runN` suffix instead of clobbering.

    `version` is the raw `qeli --version` line ("qeli 0.7.15") or any label.
    """
    import os as _os
    import time as _time
    ver = (version or "unknown").replace("qeli ", "v").strip() or "unknown"
    rel = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "release")
    base = _os.path.join(rel, f"{stem}_{ver}_{_time.strftime('%Y-%m-%d')}")
    path, n = base + ".json", 1
    while _os.path.exists(path):
        n += 1
        path = f"{base}_run{n}.json"
    return _os.path.normpath(path)

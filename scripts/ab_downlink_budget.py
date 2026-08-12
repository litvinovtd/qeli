#!/usr/bin/env python3
"""A/B the downlink buffer budget: 4 MiB (0.7.15 as shipped) vs 16 MiB.

Question under test: the 0.7.15 Linux client lost ~13% of DOWNLOAD throughput
versus 0.7.14, and the suspected cause is `MAX_DOWNLINK_BUFFER_BYTES` in
transport_core/linux_tun.rs — the TUN-write queue went from an effectively
~32 MiB channel (2048 x Vec<u8>) to a hard 4 MiB pool with backpressure.

Both binaries are built from the SAME tree with the SAME flags, differing only in
that constant, so any delta is attributable to it and not to build differences.

Runs are INTERLEAVED (A,B,A,B,…) rather than grouped: on this lab the second half
of a grouped run is systematically slower (host drift + measurement order bias),
which previously produced a fake 20-30% "regression". Interleaving cancels it.

Reports per mode: median download of each variant plus the delta.
"""
import os, sys, io, time, json, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm
import lab_hygiene as hy
from lab_common import run

ROUNDS = int(os.environ.get("AB_ROUNDS", "4"))
VARIANTS = [("4MiB", "/opt/qeli-exp/qeli-4mb"), ("16MiB", "/opt/qeli-exp/qeli-16mb")]
# The modes where the regression was largest, plus reality-tls as the sensitive one.
MODE_NAMES = ["tcp-plain-raw", "tcp-faketls", "tcp-obfs", "tcp-reality-tls"]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                   "release", "ab_downlink_budget.json")


def install(s, cl, path):
    """Put the chosen binary on BOTH ends (client is what writes to its TUN)."""
    bm.out(s, f"install -m755 {path} {bm.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(path, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, bm.BIN); cf.close()
    bm.out(cl, f"chmod 755 {bm.BIN}")
    return bm.out(s, f"sha256sum {bm.BIN} | cut -c1-16").strip().splitlines()[-1]


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    hy.full_clean(s, run, label=".10"); hy.full_clean(cl, run, label=".11")
    modes = [m for m in bm.MODES if m["name"] in MODE_NAMES]
    data = {v: {m["name"]: [] for m in modes} for v, _ in VARIANTS}
    shas = {}

    print(f"interleaved A/B, {ROUNDS} rounds x {len(modes)} modes x 2 variants\n")
    for r in range(ROUNDS):
        # Alternate which variant goes first each round, so neither variant
        # always occupies the (slightly slower) second slot.
        order = VARIANTS if r % 2 == 0 else VARIANTS[::-1]
        for label, path in order:
            shas[label] = install(s, cl, path)
            for m in modes:
                try:
                    res = bm.run_mode(s, cl, m)
                    down = res.get("tcp_down", {}).get("mbps")
                    up = res.get("tcp_up", {}).get("mbps")
                except Exception as ex:
                    print(f"  round{r+1} {label:<6} {m['name']:<16} raised: {ex}")
                    continue
                if down:
                    data[label][m["name"]].append(down)
                print(f"  round{r+1} {label:<6} {m['name']:<16} down={down} up={up}")
        print()

    bm.out(cl, "ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; true")
    bm.out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    print("=" * 66)
    print(f"{'режим':<18}{'4MiB down':>12}{'16MiB down':>12}{'Δ':>10}")
    print("-" * 66)
    summary = {}
    for m in modes:
        n = m["name"]
        a = data["4MiB"][n]; b = data["16MiB"][n]
        if not a or not b:
            print(f"{n:<18}{'нет данных':>34}"); continue
        ma, mb = statistics.median(a), statistics.median(b)
        d = (mb - ma) / ma * 100
        print(f"{n:<18}{ma:>12.1f}{mb:>12.1f}{d:>+9.1f}%")
        summary[n] = {"median_4mib": round(ma, 1), "median_16mib": round(mb, 1),
                      "delta_pct": round(d, 1), "raw_4mib": a, "raw_16mib": b}
    with open(os.path.normpath(OUT), "w", encoding="utf-8") as f:
        json.dump({"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "rounds": ROUNDS, "sha": shas, "modes": summary}, f, indent=2, ensure_ascii=False)
    print(f"\nsaved -> {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Localise the 0.7.15 download regression: is it the SERVER or the CLIENT?

`benchmark.py` always installs one binary on both ends, so a version delta there
cannot tell which side lost the throughput. This script crosses them:

    S14/C14   baseline (0.7.14 both ends)
    S14/C15   new client against old server
    S15/C14   old client against new server
    S15/C15   shipped 0.7.15

download = server -> client, so:
  * if S14/C15 is slow and S15/C14 is fast  -> the CLIENT receive path regressed
  * if S15/C14 is slow and S14/C15 is fast  -> the SERVER send path regressed
  * if both crosses are slow                -> both sides contribute
  * if both crosses are fast                -> it is an interaction of the two

Combinations are interleaved across rounds so host drift cannot masquerade as a
version effect (grouping previously produced a fake 20-30% "regression" here).
Cross-version pairs are expected to interoperate; a handshake failure is reported
rather than silently recorded as zero.
"""
import os, sys, io, time, json, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm
import lab_hygiene as hy
from lab_common import run

ROUNDS = int(os.environ.get("XV_ROUNDS", "3"))
BIN14 = "/opt/qeli-exp/qeli-0.7.14"
BIN15 = "/opt/qeli-exp/qeli-0.7.15"
COMBOS = [("S14/C14", BIN14, BIN14), ("S14/C15", BIN14, BIN15),
          ("S15/C14", BIN15, BIN14), ("S15/C15", BIN15, BIN15)]
MODE_NAMES = ["tcp-plain-raw", "tcp-faketls"]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                   "release", "ab_crossver_downlink.json")


def install_pair(s, cl, server_bin, client_bin):
    bm.out(s, f"install -m755 {server_bin} {bm.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(client_bin, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, bm.BIN); cf.close()
    bm.out(cl, f"chmod 755 {bm.BIN}")
    return (bm.out(s, f"{bm.BIN} --version 2>&1 | tail -1").strip().splitlines()[-1],
            bm.out(cl, f"{bm.BIN} --version 2>&1 | tail -1").strip().splitlines()[-1])


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    hy.full_clean(s, run, label=".10"); hy.full_clean(cl, run, label=".11")
    modes = [m for m in bm.MODES if m["name"] in MODE_NAMES]
    data = {c[0]: {m["name"]: [] for m in modes} for c in COMBOS}

    print(f"cross-version A/B, {ROUNDS} rounds x {len(modes)} modes x {len(COMBOS)} combos\n")
    for r in range(ROUNDS):
        order = COMBOS if r % 2 == 0 else COMBOS[::-1]
        for label, sbin, cbin in order:
            sv, cv = install_pair(s, cl, sbin, cbin)
            for m in modes:
                try:
                    res = bm.run_mode(s, cl, m)
                    down = res.get("tcp_down", {}).get("mbps")
                except Exception as ex:
                    print(f"  r{r+1} {label:<8} {m['name']:<15} FAILED: {ex}")
                    continue
                if down:
                    data[label][m["name"]].append(down)
                print(f"  r{r+1} {label:<8} {m['name']:<15} down={down}   [srv {sv} / cli {cv}]")
        print()

    bm.out(cl, "ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; true")
    bm.out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    print("=" * 72)
    print(f"{'режим':<16}" + "".join(f"{c[0]:>13}" for c in COMBOS))
    print("-" * 72)
    summary = {}
    for m in modes:
        n = m["name"]
        meds = {}
        line = f"{n:<16}"
        for label, _, _ in COMBOS:
            vals = data[label][n]
            med = statistics.median(vals) if vals else None
            meds[label] = round(med, 1) if med else None
            line += f"{(f'{med:.1f}' if med else '—'):>13}"
        print(line)
        summary[n] = meds
    print("\nчтение: download = сервер->клиент; медленная комбинация показывает виновную сторону")
    with open(os.path.normpath(OUT), "w", encoding="utf-8") as f:
        json.dump({"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "rounds": ROUNDS, "modes": summary,
                   "raw": {k: v for k, v in data.items()}}, f, indent=2, ensure_ascii=False)
    print(f"saved -> {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()

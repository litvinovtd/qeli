#!/usr/bin/env python3
"""Decide whether the lab host is quiet enough to trust a benchmark.

Why this exists: the v0.7.13 sweep had to be thrown away. Two runs of the SAME
binary disagreed by up to 40%, and the raw no-VPN baseline drifted 18.9 -> 14.7
Gbps mid-session — i.e. the noise came from the hypervisor (neighbouring VMs),
invisible from inside the guest (`steal` stayed at 0%). Any per-mode number
taken in that window is fiction, so the gate must run BEFORE the sweep, not as
a post-mortem.

Method: N raw iperf3 runs with NO tunnel involved, in BOTH directions (upload
and `-R` download). Both, because the noise can be asymmetric and `down` is the
most sensitive figure we report (reality-tls). Verdict per direction:

    spread = (max - min) / max  <=  MAX_SPREAD

Defaults: 5 runs, 8% — a clean reality-tls x5 sat around sigma ~1.5%, while the
noisy host showed 22%, so 8% separates them without tripping on ordinary jitter.

Exit code 0 = quiet (go), 1 = noisy (do not measure). Env overrides:
QELI_GATE_RUNS, QELI_GATE_MAX_SPREAD (percent).
"""
import os, sys, time, json, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm
import lab_hygiene as hy
from lab_common import run

RUNS = int(os.environ.get("QELI_GATE_RUNS", "5"))
MAX_SPREAD = float(os.environ.get("QELI_GATE_MAX_SPREAD", "8"))
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                   "release", "stability_gate_last.json")


def stats(vals):
    good = [v for v in vals if v]
    if len(good) < 2:
        return None
    spread = (max(good) - min(good)) / max(good) * 100
    return {"n": len(good), "min": min(good), "max": max(good),
            "median": round(statistics.median(good), 1),
            "stdev": round(statistics.pstdev(good), 1),
            "spread_pct": round(spread, 1)}


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    # A dirty host fails the gate for the wrong reason — clean first, and say so.
    print("=== hygiene ===")
    st_s = hy.full_clean(s, run, label=".10 server")
    st_c = hy.full_clean(cl, run, label=".11 client")
    clean = hy.assert_quiet(st_s, ".10") & hy.assert_quiet(st_c, ".11")

    bm.out(s, "pkill -9 -x iperf3 2>/dev/null; sleep 1; iperf3 -s -D; sleep 1; true")
    steal = bm.out(s, "vmstat 1 3 | tail -1 | awk '{print $NF}'").strip().splitlines()[-1]
    print(f"\n=== raw iperf3, NO tunnel — {RUNS} runs per direction ===")
    print(f"    (cpu steal on .10: {steal}%)")

    res = {}
    for direction, reverse in (("up", False), ("down", True)):
        vals = []
        for i in range(RUNS):
            r = bm.iperf_tcp(cl, bm.SERVER[0], reverse=reverse)
            v = r.get("mbps")
            vals.append(v)
            print(f"  {direction:<4} run{i+1}: {v} Mbps" + ("" if v else f"  ERROR: {r.get('error')}"))
            time.sleep(2)
        res[direction] = stats(vals)

    bm.out(s, "pkill -9 -x iperf3 2>/dev/null; true")
    s.close(); cl.close()

    print("\n" + "=" * 60)
    verdict = clean
    for d, st in res.items():
        if not st:
            print(f"  {d:<5} NO DATA — iperf3 failed"); verdict = False; continue
        ok = st["spread_pct"] <= MAX_SPREAD
        verdict &= ok
        print(f"  {d:<5} median={st['median']} min={st['min']} max={st['max']} "
              f"spread={st['spread_pct']}%  -> {'OK' if ok else 'TOO NOISY'}")
    print(f"\n  threshold: spread <= {MAX_SPREAD}% in BOTH directions")
    print(f"  VERDICT: {'HOST QUIET — safe to benchmark' if verdict else 'HOST NOISY — numbers would be unreliable, do NOT measure'}")

    payload = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "runs": RUNS, "max_spread_pct": MAX_SPREAD, "cpu_steal_pct": steal,
               "host_clean": clean, "directions": res, "verdict_quiet": bool(verdict)}
    with open(os.path.normpath(OUT), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"  saved -> {os.path.normpath(OUT)}")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())

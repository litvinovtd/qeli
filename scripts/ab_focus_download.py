#!/usr/bin/env python3
"""High-repetition, order-alternating A/B of ONE mode's DOWNLOAD throughput.

Answers "is the download delta real or noise?" when the full sweep is inconclusive
on a contended host. Both binaries must be built the SAME way (jemalloc) — an
allocator mismatch alone shifts throughput ~20%.

  MODE=tcp-plain-raw N=8 python scripts/ab_focus_download.py
"""
import os, sys, io, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm

A_SRC = os.environ.get("A_SRC", "/opt/qeli-0711/target/release/qeli")   # tag build
B_SRC = os.environ.get("B_SRC", "/opt/qeli-src/target/release/qeli")    # current
A_LAB = os.environ.get("A_LAB", "0.7.11")
B_LAB = os.environ.get("B_LAB", "0.7.12")
MODE_NAME = os.environ.get("MODE", "tcp-plain-raw")
N = int(os.environ.get("N", "8"))

s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
print("tag build:", bm.out(s, f"test -x {A_SRC} && echo present || echo MISSING"))
print("allocator check (both must say jemalloc):")
for lab, src in ((A_LAB, A_SRC), (B_LAB, B_SRC)):
    has = bm.out(s, f"strings {src} 2>/dev/null | grep -c jemalloc || echo 0")
    print(f"  {lab}: jemalloc symbols = {has}")
bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true")


def install(src):
    bm.out(s, f"install -m755 {src} {bm.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(src, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, bm.BIN); cf.close()
    bm.out(cl, f"chmod 755 {bm.BIN}")


MODE = next(m for m in bm.MODES if m["name"] == MODE_NAME)
res = {A_LAB: [], B_LAB: []}
pos = {"first": [], "second": []}
for r in range(N):
    # Alternate who runs first: within a round the SECOND run is systematically
    # slower (the host has not recovered), so a fixed order biases one version.
    seq = [(A_LAB, A_SRC), (B_LAB, B_SRC)] if r % 2 == 0 else [(B_LAB, B_SRC), (A_LAB, A_SRC)]
    for i, (lab, src) in enumerate(seq):
        install(src)
        out = bm.run_mode(s, cl, MODE)
        d = out.get("tcp_down", {}).get("mbps")
        if d:
            res[lab].append(d)
            pos["first" if i == 0 else "second"].append(d)
    print(f"  round {r+1}/{N}: {A_LAB}={res[A_LAB][-1:]}  {B_LAB}={res[B_LAB][-1:]}", flush=True)

bm.out(cl, "ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; true")
bm.out(s, "systemctl start qeli-server.service 2>/dev/null; true")
s.close(); cl.close()

med = statistics.median
a, b = res[A_LAB], res[B_LAB]
print(f"\n=== {MODE_NAME} DOWNLOAD — {N} rounds each, order alternated, matched builds ===")
for lab, v in ((A_LAB, a), (B_LAB, b)):
    print(f"  {lab}: median {med(v):7.1f} | mean {statistics.mean(v):7.1f} | sd {statistics.pstdev(v):6.1f} "
          f"| raw {sorted(round(x) for x in v)}")
print(f"  delta (median): {(med(b)-med(a))/med(a)*100:+.1f}%")
print(f"  positional control: first {med(pos['first']):.1f} vs second {med(pos['second']):.1f} "
      f"({(med(pos['second'])-med(pos['first']))/med(pos['first'])*100:+.1f}% — should be ~0 if order is neutralised)")
lo, hi = max(min(a), min(b)), min(max(a), max(b))
print(f"  range overlap: {hi-lo:+.0f} Mbps -> "
      f"{'INDISTINGUISHABLE — the delta is noise' if hi > lo else 'SEPARATED — a real difference'}")

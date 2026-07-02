#!/usr/bin/env python3
"""Clean same-lab A/B for the P3/B1 perf change, using the GitHub v0.7.5 release
binary as the pristine "before" (no P3/B1) vs the freshly-built "after"
(0.7.5 + P3 in-place AEAD + B1 reality-tls rx pipeline). Both binaries run the
reality-tls tunnel 5× back-to-back on the SAME reboot — so the only difference is
the code. reality-tls DOWNLOAD is B1's target.

Run on a freshly-rebooted lab with the .11 rogue qeli.service DISABLED.
"""
import os, sys, io, time, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm

BEFORE_LOCAL = r"C:\Users\litvi\AppData\Local\Temp\claude\C--Users-litvi-Documents-api-dev-autocash-ru\f0a9a9ed-a799-4cc9-beaa-51baa0d8cfce\scratchpad\qeli-linux-amd64"
AFTER_SRC = bm.SRC_BIN  # /opt/qeli-src/target/release/qeli (current 0.7.5+P3/B1)
RTLS = next(m for m in bm.MODES if m["name"] == "tcp-reality-tls")
N = 5


def put_both_local(s, cl, local):
    data = open(local, "rb").read()
    for c in (s, cl):
        sf = c.open_sftp(); sf.putfo(io.BytesIO(data), bm.BIN); sf.close()
        bm.out(c, f"chmod 755 {bm.BIN}")


def put_both_src(s, cl):
    bm.out(s, f"install -m755 {AFTER_SRC} {bm.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(AFTER_SRC, buf); sf.close()
    sf = cl.open_sftp(); buf.seek(0); sf.putfo(buf, bm.BIN); sf.close()
    bm.out(cl, f"chmod 755 {bm.BIN}")


def rtls5(s, cl, label):
    ups, downs, cpus = [], [], []
    for i in range(N):
        r = bm.run_mode(s, cl, RTLS)
        if r.get("error") or "tcp_up" not in r:
            print(f"  [{label} {i+1}/{N}] FAIL: {r.get('error')}"); continue
        u, d = r["tcp_up"]["mbps"], r["tcp_down"]["mbps"]
        ups.append(u); downs.append(d)
        if r["tcp_up"].get("qeli_cpu_max_pct"): cpus.append(r["tcp_up"]["qeli_cpu_max_pct"])
        print(f"  [{label} {i+1}/{N}] up={u} down={d}")
        time.sleep(1)
    med = lambda xs: round(statistics.median(xs), 1) if xs else None
    sd = lambda xs: round(statistics.pstdev(xs), 1) if len(xs) > 1 else 0
    return {"up_med": med(ups), "down_med": med(downs), "down_sd": sd(downs),
            "up_sd": sd(ups), "downs": downs, "ups": ups, "cpu_max": max(cpus) if cpus else None}


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; true")
    bm.out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; true")

    print("\n========== BEFORE: GitHub v0.7.5 release (no P3/B1) ==========")
    put_both_local(s, cl, BEFORE_LOCAL)
    print("[before bin]", bm.out(s, f"{bm.BIN} --version"), bm.out(s, f"sha256sum {bm.BIN} | cut -c1-16"))
    before = rtls5(s, cl, "before")

    print("\n========== AFTER: current 0.7.5 + P3/B1 ==========")
    put_both_src(s, cl)
    print("[after bin]", bm.out(s, f"{bm.BIN} --version"), bm.out(s, f"sha256sum {bm.BIN} | cut -c1-16"))
    after = rtls5(s, cl, "after")

    bm.out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; true")
    bm.out(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    def pct(a, b):
        return f"{(b - a) / a * 100:+.1f}%" if a else "n/a"

    print("\n" + "=" * 64)
    print("reality-tls A/B — GitHub v0.7.5 (before) vs 0.7.5+P3/B1 (after)")
    print("=" * 64)
    print(f"  before  down={before['down_med']} (σ{before['down_sd']}) up={before['up_med']} (σ{before['up_sd']})  raw down={before['downs']}")
    print(f"  after   down={after['down_med']} (σ{after['down_sd']}) up={after['up_med']} (σ{after['up_sd']})  raw down={after['downs']}")
    print(f"\n  DOWNLOAD (B1 target): {before['down_med']} -> {after['down_med']} Mbps  ({pct(before['down_med'], after['down_med'])})")
    print(f"  UPLOAD              : {before['up_med']} -> {after['up_med']} Mbps  ({pct(before['up_med'], after['up_med'])})")
    print(f"  qeli CPU max (ps)   : before {before['cpu_max']}%  after {after['cpu_max']}%")


if __name__ == "__main__":
    main()

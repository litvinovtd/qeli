#!/usr/bin/env python3
"""Repeat the tcp-reality-tls mode N times on the clean lab and report
mean/median/min/max/stdev for up & down. Reuses benchmark.py's config builders
and run_mode so the tunnel is byte-identical to the canonical sweep."""
import os, sys, io, json, time, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm

N = int(os.environ.get("RTLS_RUNS", "5"))
MODE = next(m for m in bm.MODES if m["name"] == "tcp-reality-tls")
OUT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\reality_tls_5x_v0.7.2_2026-06-20.json"


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    # free the port + install the freshly-built release binary on both VMs
    bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true")
    bm.out(s, f"install -m755 {bm.SRC_BIN} {bm.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(bm.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, bm.BIN); cf.close()
    bm.out(cl, f"chmod 755 {bm.BIN}; mkdir -p /etc/qeli")
    bm.out(s, "mkdir -p /etc/qeli /etc/qeli/identity /var/log/qeli")
    ver = bm.out(s, f"{bm.BIN} --version 2>&1"); sha = bm.out(s, f"sha256sum {bm.BIN} | cut -c1-16")
    print("binary:", ver, sha, "| runs:", N)
    print("server load:", bm.out(s, "cat /proc/loadavg"), "| client load:", bm.out(cl, "cat /proc/loadavg"))

    runs = []
    for i in range(N):
        print(f"\n===== reality-tls run {i+1}/{N} =====")
        try:
            r = bm.run_mode(s, cl, MODE)
        except Exception as ex:
            print("  raised:", ex); r = {"error": str(ex)}
        if r.get("error") or "tcp_up" not in r:
            print("  RUN FAILED:", r.get("error"))
            runs.append({"run": i + 1, "error": r.get("error", "no tcp data")})
            continue
        u = r["tcp_up"]["mbps"]; d = r["tcp_down"]["mbps"]
        cpu = r["tcp_up"].get("qeli_cpu_max_pct"); rss = r["tcp_up"].get("qeli_rss_mb")
        runs.append({"run": i + 1, "up": u, "down": d, "qeli_cpu_max": cpu, "rss_mb": rss,
                     "retr_up": r["tcp_up"].get("retransmits"), "retr_down": r["tcp_down"].get("retransmits")})
        print(f"  up={u} down={d} Mbps | qeliCPUmax={cpu}% rss={rss}MB")
        time.sleep(2)

    # restore lab
    bm.out(cl, "ip link del vpn0 2>/dev/null; printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf")
    bm.out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    ups = [x["up"] for x in runs if "up" in x]
    downs = [x["down"] for x in runs if "down" in x]

    def st(xs):
        if not xs: return None
        return {"n": len(xs), "mean": round(statistics.mean(xs), 1),
                "median": round(statistics.median(xs), 1), "min": min(xs), "max": max(xs),
                "stdev": round(statistics.pstdev(xs), 1)}

    summary = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "version": ver, "sha256_16": sha, "mode": "tcp-reality-tls",
               "runs": runs, "up_stats": st(ups), "down_stats": st(downs)}
    open(OUT, "w", encoding="utf-8").write(json.dumps(summary, indent=2, ensure_ascii=False))

    print("\n" + "=" * 60)
    print(f"reality-tls × {N}  (Mbps)")
    print("  raw up  :", ups)
    print("  raw down:", downs)
    print("  UP  ", st(ups))
    print("  DOWN", st(downs))
    print("saved ->", OUT)


if __name__ == "__main__":
    main()

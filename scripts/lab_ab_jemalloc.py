#!/usr/bin/env python3
"""Same-session A/B: glibc vs jemalloc server binary, throughput + data-plane RSS.
Reuses benchmark.py's harness (run_mode: setup tunnel, iperf up/down, sample the
worker's CPU/RSS). Runs obfs + reality-tls back-to-back per binary so lab conditions
are equal. Memory NOTE: the prod ~180 MB arena plateau comes from CONCURRENT multi-
thread churn — a 2-VM sequential lab won't reproduce it; this run proves throughput
parity. The real RSS win is measured on prod under real load.
"""
import os, sys, io, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import benchmark as B

GLIBC = "/opt/qeli-src/qeli-glibc"
JEMALLOC = "/opt/qeli-src/qeli-jemalloc"
MODES = [
    {"name": "tcp-obfs", "transport": "tcp", "port": 443, "client_mode": "obfs",
     "server_mode": "obfs", "obfs_key": "benchkey", "padding": True},
    {"name": "tcp-reality-tls", "transport": "tcp", "port": 443, "client_mode": "reality-tls",
     "server_mode": "fake-tls", "reality": True, "real_tls": True,
     "short_id": "0123456789abcdef", "require_proof": True},
]


def main():
    s = B.conn(B.SERVER); cl = B.conn(B.CLIENT)
    B.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; true")
    B.out(s, "mkdir -p /etc/qeli /etc/qeli/identity /var/log/qeli"); B.out(cl, "mkdir -p /etc/qeli")

    # jemalloc binary = current target/release build; copy it aside, then build glibc.
    B.out(s, f"cp -f /opt/qeli-src/target/release/qeli {JEMALLOC}", t=30)
    print("jemalloc-bin jemalloc strings:", B.out(s, f"strings {JEMALLOC} | grep -ic jemalloc"))
    print("building glibc (default) ...")
    print(B.out(s, "cd /opt/qeli-src && cargo build --release 2>&1 | tail -2", t=600))
    B.out(s, f"cp -f /opt/qeli-src/target/release/qeli {GLIBC}", t=30)
    print("glibc-bin jemalloc strings (want 0):", B.out(s, f"strings {GLIBC} | grep -ic jemalloc"))

    results = {}
    for variant, src in [("glibc", GLIBC), ("jemalloc", JEMALLOC)]:
        B.out(s, f"install -m755 {src} {B.BIN}")
        sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(src, buf); sf.close()
        cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, B.BIN); cf.close(); B.out(cl, f"chmod 755 {B.BIN}")
        print(f"\n===== VARIANT {variant}: {B.out(s, f'{B.BIN} --version')} =====")
        results[variant] = {}
        for m in MODES:
            results[variant][m["name"]] = B.run_mode(s, cl, m)

    B.out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    out = os.path.join(os.path.dirname(__file__), "..", "release", "ab_jemalloc.json")
    try:
        with open(out, "w", encoding="utf-8") as f: json.dump(results, f, indent=2, ensure_ascii=False)
        print("\nsaved", out)
    except Exception as ex:
        print("save fail", ex)

    print("\n\n===== A/B: glibc vs jemalloc =====")
    def g(r, k, sub):
        v = r.get(k) if isinstance(r, dict) else None
        return v.get(sub) if isinstance(v, dict) else None
    for m in [x["name"] for x in MODES]:
        gg, jj = results["glibc"].get(m, {}), results["jemalloc"].get(m, {})
        print(f"\n[{m}]")
        for label, key, sub in [("up Mbps", "tcp_up", "mbps"), ("down Mbps", "tcp_down", "mbps"),
                                ("srv CPU% (up)", "tcp_up", "cpu_server"),
                                ("worker RSS MB (up)", "tcp_up", "qeli_rss_mb")]:
            a, b = g(gg, key, sub), g(jj, key, sub)
            print(f"  {label:22} glibc={a}  jemalloc={b}")
        if gg.get("error") or jj.get("error"):
            print("  ERR glibc:", gg.get("error"), "| jemalloc:", jj.get("error"))


if __name__ == "__main__":
    main()

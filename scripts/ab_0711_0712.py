#!/usr/bin/env python3
"""Host-neutral A/B: 0.7.11 (git tag v0.7.11) vs 0.7.12 (current /opt/qeli-src),
measured BACK-TO-BACK in the same lab session so both binaries see the identical
hypervisor conditions (CPU steal cancels out). Answers "did 0.7.12 regress?"
independent of noisy-neighbor host drift.

Builds 0.7.11 in an ISOLATED tree (/opt/qeli-0711) from `git archive v0.7.11` —
the 0.7.12 working tree (/opt/qeli-src) is untouched. For each wire mode we run
0.7.11 then 0.7.12 back-to-back (interleaved per mode); reality-tls is repeated
RTLS_RUNS times each and the median reported.
"""
import os, sys, io, json, time, tarfile, tempfile, subprocess, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import lab_sync_build as lsb   # conn/run/sync_tree
import benchmark as bm         # run_mode + MODES + config builders

REMOTE_071 = "/opt/qeli-0711"
SRC_079 = "/opt/qeli-src/target/release/qeli"
SRC_071 = f"{REMOTE_071}/target/release/qeli"
RTLS_RUNS = int(os.environ.get("AB_RTLS_RUNS", "3"))
OUT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\ab_0711_vs_0712_2026-07-18.json"


def build_071():
    tmp = tempfile.mkdtemp(prefix="qeli071_")
    tar = os.path.join(tmp, "q.tar")
    subprocess.run(["git", "archive", "v0.7.11", "-o", tar, "--", "qeli"], cwd=REPO, check=True)
    with tarfile.open(tar) as t:
        t.extractall(tmp)
    lsb.LOCAL_ROOT = os.path.join(tmp, "qeli")
    lsb.REMOTE_ROOT = REMOTE_071
    c = lsb.conn(lsb.SERVER)
    lsb.run(c, f"systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; mkdir -p {REMOTE_071}; true", t=30)
    n = lsb.sync_tree(c)
    print(f"synced {n} files -> {REMOTE_071}")
    # MUST match how the CURRENT build is produced (lab_sync_build.py uses
    # `--features jemalloc`, like the shipped Linux binary/.deb). Building the tag with a
    # plain `--release` left it on glibc malloc while the current side ran jemalloc, so the
    # A/B silently compared ALLOCATORS as well as versions — which showed up as a
    # systematic ~+20-28% "gain" for whichever side had jemalloc (measured 2026-07-18).
    rc, ob = lsb.run(
        c, f"cd {REMOTE_071} && cargo build --release --features jemalloc 2>&1", t=1200
    )
    print("0.7.11 build:", "\n".join(ob.splitlines()[-3:]), "| rc", rc)
    ver = lsb.run(c, f"{SRC_071} --version")[1]
    sha = lsb.run(c, f"sha256sum {SRC_071} | cut -c1-16")[1]
    c.close()
    if rc != 0:
        sys.exit("0.7.11 build FAILED")
    print("0.7.11 binary:", ver, sha)
    return ver, sha


def install_both(s, cl, src):
    bm.out(s, f"install -m755 {src} {bm.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(src, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, bm.BIN); cf.close()
    bm.out(cl, f"chmod 755 {bm.BIN}")


def pair_throughput(r):
    if r.get("error"):
        return None
    return r["tcp_up"]["mbps"], r["tcp_down"]["mbps"]


def main():
    ver071, sha071 = build_071()
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true")
    bm.out(s, "mkdir -p /etc/qeli /etc/qeli/identity /var/log/qeli")
    bm.out(cl, "mkdir -p /etc/qeli")
    sha072 = bm.out(s, f"sha256sum {SRC_079} | cut -c1-16")
    v072 = bm.out(s, f"{SRC_079} --version 2>&1")
    print("A/B:", ver071, sha071, "  VS  ", v072, sha072, "| reality-tls runs:", RTLS_RUNS)

    VARIANTS = [("0.7.11", SRC_071), ("0.7.12", SRC_079)]
    rows = {}
    # ORDER BIAS (measured 2026-07-18, cost a false "UDP regression"): inside one round the
    # SECOND run is systematically worse — the UDP sweep hammers the client's open-loop
    # receiver and the host has not recovered when the next run starts. With a fixed
    # tag-first/current-second order that penalty always lands on the CURRENT build: an
    # order-reversal test moved the "2x worse" label onto whichever version ran second,
    # not onto a version. So alternate who goes first per mode/rep and the bias cancels.
    order_flip = 0
    for m in bm.MODES:
        name = m["name"]
        # Repeat every mode, not just reality-tls: on a contended host a single sample per
        # version is dominated by noise (a 2026-07-18 run produced frag +60% / padding -31%
        # in ONE pass). UDP is the twitchiest, so it gets the most reps; the median over
        # alternating-order reps is what the delta is read from.
        reps = RTLS_RUNS if name == "tcp-reality-tls" else (3 if m["transport"] == "udp" else 2)
        acc = {"0.7.11": {"up": [], "down": []}, "0.7.12": {"up": [], "down": []}}
        for _ in range(reps):
            seq = VARIANTS if order_flip % 2 == 0 else list(reversed(VARIANTS))
            order_flip += 1
            for vlabel, src in seq:
                install_both(s, cl, src)
                try:
                    r = bm.run_mode(s, cl, m)
                except Exception as ex:
                    print(f"  !! {name}/{vlabel} raised: {ex}"); r = {"error": str(ex)}
                if m["transport"] == "udp":
                    # record 400M/500M loss for udp
                    sw = r.get("udp_sweep", {})
                    acc[vlabel].setdefault("loss400", []).append(sw.get("400M", {}).get("loss_pct"))
                    acc[vlabel].setdefault("loss500", []).append(sw.get("500M", {}).get("loss_pct"))
                else:
                    pt = pair_throughput(r)
                    if pt:
                        acc[vlabel]["up"].append(pt[0]); acc[vlabel]["down"].append(pt[1])
                time.sleep(1)
        rows[name] = acc
        # live print
        if m["transport"] == "udp":
            print(f"== {name}: 0.7.11 loss400/500={acc['0.7.11'].get('loss400')}/{acc['0.7.11'].get('loss500')} "
                  f"| 0.7.12={acc['0.7.12'].get('loss400')}/{acc['0.7.12'].get('loss500')}")
        else:
            def med(xs):
                return round(statistics.median(xs), 1) if xs else None
            u1, d1 = med(acc["0.7.11"]["up"]), med(acc["0.7.11"]["down"])
            u2, d2 = med(acc["0.7.12"]["up"]), med(acc["0.7.12"]["down"])
            du = f"{(u2-u1)/u1*100:+.1f}%" if (u1 and u2) else "?"
            dd = f"{(d2-d1)/d1*100:+.1f}%" if (d1 and d2) else "?"
            print(f"== {name}: 0.7.11 {u1}/{d1}  ->  0.7.12 {u2}/{d2}   (up {du}, down {dd})")

    bm.out(cl, "ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf")
    bm.out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    summary = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "v071": {"version": ver071, "sha": sha071},
               "v072": {"version": v072, "sha": sha072},
               "rtls_runs": RTLS_RUNS, "rows": rows}
    open(OUT, "w", encoding="utf-8").write(json.dumps(summary, indent=2, ensure_ascii=False))
    print("\nsaved ->", OUT)


if __name__ == "__main__":
    main()

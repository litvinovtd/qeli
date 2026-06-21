#!/usr/bin/env python3
"""Host-neutral A/B: 0.7.1 (git tag v0.7.1) vs 0.7.2 (current /opt/qeli-src),
measured BACK-TO-BACK in the same lab session so both binaries see the identical
hypervisor conditions (CPU steal cancels out). Answers "did 0.7.2 regress?"
independent of noisy-neighbor host drift.

Builds 0.7.1 in an ISOLATED tree (/opt/qeli-071) from `git archive v0.7.1` —
the 0.7.2 working tree (/opt/qeli-src) is untouched. For each wire mode we run
0.7.1 then 0.7.2 back-to-back (interleaved per mode); reality-tls is repeated
RTLS_RUNS times each and the median reported.
"""
import os, sys, io, json, time, tarfile, tempfile, subprocess, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import lab_sync_build as lsb   # conn/run/sync_tree
import benchmark as bm         # run_mode + MODES + config builders

REMOTE_071 = "/opt/qeli-071"
SRC_072 = "/opt/qeli-src/target/release/qeli"
SRC_071 = f"{REMOTE_071}/target/release/qeli"
RTLS_RUNS = int(os.environ.get("AB_RTLS_RUNS", "3"))
OUT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\ab_071_vs_072_2026-06-20.json"


def build_071():
    tmp = tempfile.mkdtemp(prefix="qeli071_")
    tar = os.path.join(tmp, "q.tar")
    subprocess.run(["git", "archive", "v0.7.1", "-o", tar, "--", "qeli"], cwd=REPO, check=True)
    with tarfile.open(tar) as t:
        t.extractall(tmp)
    lsb.LOCAL_ROOT = os.path.join(tmp, "qeli")
    lsb.REMOTE_ROOT = REMOTE_071
    c = lsb.conn(lsb.SERVER)
    lsb.run(c, f"systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; mkdir -p {REMOTE_071}; true", t=30)
    n = lsb.sync_tree(c)
    print(f"synced {n} files -> {REMOTE_071}")
    rc, ob = lsb.run(c, f"cd {REMOTE_071} && cargo build --release 2>&1", t=1200)
    print("0.7.1 build:", "\n".join(ob.splitlines()[-3:]), "| rc", rc)
    ver = lsb.run(c, f"{SRC_071} --version")[1]
    sha = lsb.run(c, f"sha256sum {SRC_071} | cut -c1-16")[1]
    c.close()
    if rc != 0:
        sys.exit("0.7.1 build FAILED")
    print("0.7.1 binary:", ver, sha)
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
    sha072 = bm.out(s, f"sha256sum {SRC_072} | cut -c1-16")
    v072 = bm.out(s, f"{SRC_072} --version 2>&1")
    print("A/B:", ver071, sha071, "  VS  ", v072, sha072, "| reality-tls runs:", RTLS_RUNS)

    VARIANTS = [("0.7.1", SRC_071), ("0.7.2", SRC_072)]
    rows = {}
    for m in bm.MODES:
        name = m["name"]
        reps = RTLS_RUNS if name == "tcp-reality-tls" else 1
        acc = {"0.7.1": {"up": [], "down": []}, "0.7.2": {"up": [], "down": []}}
        for _ in range(reps):
            for vlabel, src in VARIANTS:
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
            print(f"== {name}: 0.7.1 loss400/500={acc['0.7.1'].get('loss400')}/{acc['0.7.1'].get('loss500')} "
                  f"| 0.7.2={acc['0.7.2'].get('loss400')}/{acc['0.7.2'].get('loss500')}")
        else:
            def med(xs):
                return round(statistics.median(xs), 1) if xs else None
            u1, d1 = med(acc["0.7.1"]["up"]), med(acc["0.7.1"]["down"])
            u2, d2 = med(acc["0.7.2"]["up"]), med(acc["0.7.2"]["down"])
            du = f"{(u2-u1)/u1*100:+.1f}%" if (u1 and u2) else "?"
            dd = f"{(d2-d1)/d1*100:+.1f}%" if (d1 and d2) else "?"
            print(f"== {name}: 0.7.1 {u1}/{d1}  ->  0.7.2 {u2}/{d2}   (up {du}, down {dd})")

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

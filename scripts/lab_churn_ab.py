#!/usr/bin/env python3
"""Concurrent-churn A/B in the lab: does glibc balloon its arenas (the prod ~180 MB
plateau) while jemalloc stays bounded + returns memory? K parallel clients cycle
connect/auth/hold/drop against the .10 server (obfs, split-tunnel, unique dev per
client) → many simultaneous handshakes across the worker's threads. Sample worker
RSS: PEAK during churn, SETTLED after 60 s idle. Compare glibc vs jemalloc.
"""
import os, sys, io, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import benchmark as B

GLIBC = "/opt/qeli-src/qeli-glibc"
JEMALLOC = "/opt/qeli-src/qeli-jemalloc"
K = 16                 # concurrent clients
CHURN_SECS = 80        # churn duration
MODE = {"name": "obfs", "transport": "tcp", "port": 443, "client_mode": "obfs",
        "server_mode": "obfs", "obfs_key": "benchkey"}


def client_conf(server_key, n):
    return (f"[qeli]\nserver = {B.SERVER[0]}:443\nproto = tcp\nuser = bench\n"
            f"pass = {B.PASS}\nmode = obfs\nkey = {server_key}\nobfs_key = benchkey\n"
            f"dev = vpn{n}\ngateway = false\n\n[logging]\nlevel = error\n")


def worker_rss(s):
    w = B.out(s, "pgrep -f 'qeli _worker' | head -1")
    if not w.isdigit():
        return None
    r = B.out(s, f"awk '/VmRSS/{{print $2}}' /proc/{w}/status")
    return round(int(r) / 1024, 1) if r.isdigit() else None


def arenas(s):
    w = B.out(s, "pgrep -f 'qeli _worker' | head -1")
    if not w.isdigit():
        return ""
    return B.out(s, f"grep 'Rss:' /proc/{w}/smaps | awk '{{print $2}}' | sort -rn | head -8 | tr '\\n' ' '")


def run_variant(s, cl, variant, src):
    B.out(s, f"install -m755 {src} {B.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(src, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, B.BIN); cf.close(); B.out(cl, f"chmod 755 {B.BIN}")
    print(f"\n===== {variant}: {B.out(s, f'{B.BIN} --version')} =====")

    # server up
    B.out(s, "pkill -9 -x qeli; sleep 1; true")
    B.out(cl, "pkill -9 -x qeli; for i in $(seq 0 %d); do ip link del vpn$i 2>/dev/null; done; rm -f /var/lib/qeli/known_hosts; true" % K)
    B.put(s, "/etc/qeli/bench-server.conf", B.server_ini(MODE))
    key = B.identity_pubkey(s)
    B.out(s, f"rm -f /var/log/qeli/server.log; nohup {B.BIN} server --config /etc/qeli/bench-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    base = worker_rss(s)
    print(f"  baseline worker RSS: {base} MB")

    # write K client configs + a detached churn script (background loops inheriting
    # the SSH channel's fds would keep exec_command from returning → detach fully).
    for n in range(K):
        B.put(cl, f"/tmp/c{n}.conf", client_conf(key, n))
    churn_sh = ("#!/bin/bash\nfor n in $(seq 0 %d); do ( while [ -f /tmp/churn.on ]; do "
                "timeout 6 /usr/local/bin/qeli client --config /tmp/c$n.conf >/dev/null 2>&1; "
                "done ) & done\nwait\n") % (K - 1)
    B.put(cl, "/tmp/churn.sh", churn_sh)
    B.out(cl, "touch /tmp/churn.on; setsid nohup bash /tmp/churn.sh >/dev/null 2>&1 </dev/null & echo launched")

    # sample worker RSS during churn → peak
    peak, t0, samples = base or 0, time.time(), []
    while time.time() - t0 < CHURN_SECS:
        time.sleep(4)
        rss = worker_rss(s)
        if rss:
            samples.append(rss); peak = max(peak, rss)
    # count how many auth'd (churn actually happened)
    auth = B.out(s, "grep -c 'connected on profile' /var/log/qeli/server.log")
    print(f"  churn: {len(samples)} samples, sessions={auth}, PEAK={peak} MB")
    print(f"  arenas@peak: {arenas(s)}")

    # stop churn, idle, settled RSS
    B.out(cl, "rm -f /tmp/churn.on; pkill -9 -x qeli; true")
    time.sleep(60)
    settled = worker_rss(s)
    print(f"  SETTLED after 60s idle: {settled} MB")
    B.out(cl, "for i in $(seq 0 %d); do ip link del vpn$i 2>/dev/null; done; true" % K)
    B.out(s, "pkill -9 -x qeli; true")
    return {"baseline": base, "peak": peak, "settled": settled, "sessions": auth}


def main():
    s = B.conn(B.SERVER); cl = B.conn(B.CLIENT)
    B.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; true")
    B.out(s, "mkdir -p /etc/qeli /etc/qeli/identity /var/log/qeli"); B.out(cl, "mkdir -p /etc/qeli")
    res = {}
    for variant, src in [("glibc", GLIBC), ("jemalloc", JEMALLOC)]:
        res[variant] = run_variant(s, cl, variant, src)
    B.out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()
    print("\n\n===== CONCURRENT-CHURN A/B (K=%d clients, %ds) =====" % (K, CHURN_SECS))
    print(f"{'':10} {'baseline':>9} {'PEAK':>8} {'settled':>9} {'sessions':>9}")
    for v in ("glibc", "jemalloc"):
        r = res[v]
        print(f"{v:10} {str(r['baseline'])+' MB':>9} {str(r['peak'])+' MB':>8} {str(r['settled'])+' MB':>9} {r['sessions']:>9}")


if __name__ == "__main__":
    main()

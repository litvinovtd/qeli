"""Phase-2 measurement harness for traffic-flow shaping (Ось 2B).

Characterizes the server->client on-wire flow under a BULK download (the
"looks like a download" case DPI flags): captures packet sizes + inter-packet
times and prints size/IPT histograms + summary stats. Run with shaping OFF and
ON to see whether a shaping model moves the distribution — and to PROVE it does
not add a new tell. Measure before you shape.

Usage:  python shaping_profile.py            # shaping OFF (baseline)
        python shaping_profile.py shaped     # shaping ON
"""
import sys, time, re, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import benchmark as B

SHAPED = len(sys.argv) > 1 and sys.argv[1] == "shaped"
MODE = {"name": "tcp-faketls", "transport": "tcp", "port": 443,
        "client_mode": "fake-tls", "server_mode": "fake-tls"}
SIP = "10.9.0.1"
ANCHOR = "obf.heartbeat.interval_ms = 15000\n"
SHAPING = "\n".join([
    "obf.traffic_shaping.enabled = true",
    "obf.traffic_shaping.idle_gap_mean_ms = 60",
    "obf.traffic_shaping.idle_gap_min_ms = 10",
    "obf.traffic_shaping.budget_bytes_per_sec = 262144",
    "obf.traffic_shaping.min_size = 80",
    "obf.traffic_shaping.max_size = 700",
    # STEALTH: rate-cap + cover-under-load — the Phase 2 case under test.
    "obf.traffic_shaping.stealth = true",
    "obf.traffic_shaping.stealth_rate_mbps = 2",
]) + "\n"


def server_conf():
    base = B.server_ini(MODE)
    return base.replace(ANCHOR, ANCHOR + SHAPING) if SHAPED else base


def bring_up(s, cl):
    B.out(s, "pkill -9 -x qeli; sleep 1; true")
    B.out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    B.put(s, "/etc/qeli/bench-server.conf", server_conf())
    key = B.identity_pubkey(s)
    B.put(cl, "/etc/qeli/bench-client.conf", B.client_ini(MODE, key))
    B.out(s, f"rm -f /var/log/qeli/server.log; nohup {B.BIN} server --config /etc/qeli/bench-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    B.out(cl, f"rm -f /tmp/qc.log; nohup {B.BIN} client --config /etc/qeli/bench-client.conf >/tmp/qc.log 2>&1 & echo ok")
    for _ in range(10):
        time.sleep(1.5)
        if "Auth OK" in B.out(cl, "grep -E 'Auth OK' /tmp/qc.log || true"):
            return True
    print("CONNECT FAILED:", B.out(cl, "tail -n 4 /tmp/qc.log"))
    return False


def hist(values, edges, label):
    """Bucketed histogram as text bars."""
    counts = [0] * (len(edges) + 1)
    for v in values:
        placed = False
        for i, e in enumerate(edges):
            if v <= e:
                counts[i] += 1; placed = True; break
        if not placed:
            counts[-1] += 1
    total = max(1, len(values))
    print(f"  {label} (n={len(values)}):")
    lbls = [f"<={edges[0]}"] + [f"{edges[i-1]+1}-{edges[i]}" for i in range(1, len(edges))] + [f">{edges[-1]}"]
    for lbl, c in zip(lbls, counts):
        pct = 100.0 * c / total
        print(f"    {lbl:>10}: {'#' * int(pct/2):<50} {pct:5.1f}%  ({c})")


def main():
    s, cl = B.conn(B.SERVER), B.conn(B.CLIENT)
    B.out(s, "systemctl stop qeli-server.service 2>&1; sleep 1; true")
    B.out(s, f"install -m755 {B.SRC_BIN} {B.BIN}")
    import io
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(B.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, B.BIN); cf.close()
    B.out(cl, f"chmod 755 {B.BIN}; mkdir -p /etc/qeli /var/log/qeli"); B.out(s, "mkdir -p /etc/qeli /var/log/qeli")
    print(f"=== shaping {'ON' if SHAPED else 'OFF'} — server->client flow profile under bulk download ===")
    print("binary:", B.out(s, f"{B.BIN} --version 2>&1"))
    if not bring_up(s, cl):
        return

    # Start an iperf server on the tunnel IP, then run a ~6s download (-R) from the
    # client while tcpdumping server->client on :443. Bulk transfer = the "download
    # shape" the DPI flags: we expect ~all full-MTU packets at a ~constant rate.
    B.out(s, f"pkill -9 iperf3; sleep 1; rm -f /tmp/is.log; nohup iperf3 -s -B {SIP} >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)
    # iperf client in the BACKGROUND so we can capture synchronously during it —
    # a backgrounded tcpdump redirected to a file loses its buffer on the timeout
    # SIGTERM, so grab tcpdump's stdout over SSH instead (mirrors validate_shaping).
    print("[iperf client launch]:", B.out(cl, f"rm -f /tmp/ic.log; (setsid timeout 14 iperf3 -c {SIP} -t 8 -R -i 0 >/tmp/ic.log 2>&1 &) ; echo launched"))
    time.sleep(2)  # let iperf3 control-handshake + data start before capturing
    # Cap packet count + snaplen: at ~600 Mbps the full tcpdump text would flood
    # the SSH channel. 4000 header-only packets is plenty to characterize the
    # size/IPT distribution of the bulk shape.
    raw = B.out(s, "timeout 7 tcpdump -i any -nn -tt -c 4000 -s 96 'tcp port 443' 2>/dev/null || true", t=14)
    print(f"[debug] captured {len(raw.splitlines())} tcpdump lines; iperf client tail:")
    print("   ", B.out(cl, "tail -n 3 /tmp/ic.log 2>/dev/null || echo none").replace(chr(10), " | "))
    B.out(s, "pkill -9 iperf3; pkill -9 -x qeli; true")
    B.out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; true")
    B.out(s, "systemctl start qeli-server.service 2>&1; true")

    srv = B.SERVER[0]
    sizes, ts = [], []
    for line in raw.splitlines():
        if f"{srv}.443 > " not in line:
            continue
        tm = re.match(r"^(\d+\.\d+)", line)
        lm = re.search(r"length (\d+)", line)
        if tm and lm and int(lm.group(1)) > 0:
            sizes.append(int(lm.group(1))); ts.append(float(tm.group(1)))
    ipts = [round((b - a) * 1000, 2) for a, b in zip(ts, ts[1:])]

    if not sizes:
        print("no server->client payload packets captured"); return
    print(f"\npackets={len(sizes)}  duration={ts[-1]-ts[0]:.1f}s  bytes={sum(sizes)}")
    fullmtu = sum(1 for s_ in sizes if s_ >= 1300)
    print(f"size: min={min(sizes)} median={int(statistics.median(sizes))} max={max(sizes)} "
          f"mean={int(statistics.mean(sizes))}  full-MTU(>=1300)={100.0*fullmtu/len(sizes):.1f}%")
    hist(sizes, [80, 200, 400, 700, 1000, 1300, 1500], "packet size (bytes)")
    if ipts:
        cv = (statistics.pstdev(ipts) / statistics.mean(ipts)) if statistics.mean(ipts) > 0 else 0
        print(f"\nIPT ms: min={min(ipts)} median={statistics.median(ipts)} mean={statistics.mean(ipts):.2f} "
              f"max={max(ipts)}  CV(burstiness)={cv:.2f}")
        hist(ipts, [0.1, 0.5, 1, 2, 5, 20, 100], "inter-packet time (ms)")
    print("\nNB: a 'download' tell = size histogram dominated by full-MTU + low-CV (regular) IPT.")
    print("    'browsing' = broad size mix + high-CV (bursty) IPT. Phase 2 targets this under load.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""0.7.12: adaptive bonding must ramp on DOWNLOAD-only load.

The historic defect (fixed in Rust earlier, in C#/Kotlin in 0.7.12) was that the
ramp decision read the upload counter only, so the archetypal case -- a big
download with an almost empty uplink, exactly what bonding exists for -- never
grew past one stream.

Cases:
  A  download-only load   -> must ramp to >1 stream   (the regression guard)
  B  upload-only load     -> must ramp to >1 stream   (control: never was broken)
  C  idle                 -> must NOT ramp            (the >2 Mbps under_load gate)

Bonding is server-pushed: max_streams/adaptive arrive in AuthOk, the client has
no opt-in key. TCP only.
"""
import os, sys, re, time, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm

MODE = {"name": "bond", "port": 8443, "transport": "tcp",
        "server_mode": "fake-tls", "client_mode": "fake-tls"}
NET = "10.9.0"
MAXS = 4
LOG = "/tmp/bond-client.log"


def server_conf():
    ini = bm.server_ini(MODE)
    return ini.replace(
        "perf.tcp.nodelay = true",
        "obf.multipath.enabled = true\n"
        f"obf.multipath.max_streams = {MAXS}\n"
        "obf.multipath.adaptive = true\n"
        "perf.tcp.nodelay = true")


def conns(cl):
    """Live TCP connections client -> server:port = bonded stream count."""
    o = bm.out(cl, f"ss -tan 'dst {bm.SERVER[0]}:{MODE['port']}' | grep -c ESTAB")
    try:
        return int(o.strip().splitlines()[-1])
    except Exception:
        return -1


def ramp_events(cl):
    o = bm.out(cl, f"grep -aE 'Multipath' {LOG} || true")
    ramped = [int(m) for m in re.findall(r"ramped to (\d+) stream", o)]
    plateau = [int(m) for m in re.findall(r"plateau at (\d+) stream", o)]
    allows = re.search(r"server allows up to (\d+) bonded streams \(adaptive=(\w+)\)", o)
    return {"ramped": ramped, "plateau": plateau,
            "allows": (int(allows.group(1)), allows.group(2)) if allows else None,
            "raw": o.strip().splitlines()[-8:]}


def start_client(cl, key):
    bm.put(cl, "/etc/qeli/bond-client.conf", bm.client_ini(MODE, key))
    bm.out(cl, f"pkill -9 -x qeli 2>/dev/null; sleep 1; ip link del vpn0 2>/dev/null; rm -f {LOG}; true")
    bm.out(cl, f"setsid {bm.BIN} client --config /etc/qeli/bond-client.conf "
               f">{LOG} 2>&1 < /dev/null & sleep 6")
    ip = bm.out(cl, "ip -4 -br addr show vpn0 2>/dev/null || echo DOWN")
    return ip


def case(cl, name, load_cmd, secs, expect_ramp):
    print(f"\n--- case {name} ({secs}s) ---")
    if load_cmd:
        bm.out(cl, load_cmd, t=secs + 25)
    else:
        time.sleep(secs)
    ev = ramp_events(cl)
    n = conns(cl)
    peak = max(ev["ramped"]) if ev["ramped"] else 1
    ok = (peak > 1) == expect_ramp
    print(f"  ramp events   : {ev['ramped'] or 'none'}")
    print(f"  plateau       : {ev['plateau'] or 'none'}")
    print(f"  live TCP conns: {n}")
    print(f"  peak streams  : {peak}  (expected {'>1' if expect_ramp else '==1'})")
    print(f"  -> {'PASS' if ok else 'FAIL'}")
    for l in ev["raw"]:
        print("     |", l)
    return {"case": name, "peak_streams": peak, "live_conns": n,
            "ramped": ev["ramped"], "plateau": ev["plateau"],
            "expect_ramp": expect_ramp, "pass": ok}


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    print("emulator on .11:", bm.out(cl, "pgrep -f '[q]emu-system-x86_64' | wc -l"), "(0 = clean)")

    bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; true")
    bm.out(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    bm.put(s, "/etc/qeli/bench-server.conf", server_conf())
    bm.out(s, f"setsid {bm.BIN} server --config /etc/qeli/bench-server.conf "
              ">/tmp/bond-server.log 2>&1 < /dev/null & sleep 4")
    key = bm.identity_pubkey(s)
    print("server key:", key[:16], "| up:", bm.out(s, "ip -4 -br addr show vpn0 | head -1"))
    bm.out(s, "pkill -x iperf3; sleep 1; iperf3 -s -D; sleep 1; true")

    tun = start_client(cl, key)
    print("client tun:", tun)
    if "DOWN" in tun:
        print("CLIENT FAILED TO CONNECT:\n", bm.out(cl, f"tail -25 {LOG}"))
        return

    sip = f"{NET}.1"
    res = []
    # C first: idle must not ramp (and it seeds best_rate at 0 honestly)
    res.append(case(cl, "C idle (no load)", None, 12, expect_ramp=False))
    # A: the regression guard -- reverse = server sends, client downloads
    res.append(case(cl, "A download-only (iperf3 -R)",
                    f"timeout 60 iperf3 -c {sip} -t 45 -i 0 -R --json >/tmp/dl.json 2>&1 || true",
                    45, expect_ramp=True))
    # restart client so B starts from a clean ramp state
    start_client(cl, key)
    time.sleep(2)
    res.append(case(cl, "B upload-only (iperf3)",
                    f"timeout 60 iperf3 -c {sip} -t 45 -i 0 --json >/tmp/ul.json 2>&1 || true",
                    45, expect_ramp=True))

    # throughput actually achieved on the download case
    try:
        dl = json.loads(bm.out(cl, "cat /tmp/dl.json"))
        print("\ndownload throughput:",
              round(dl["end"]["sum_received"]["bits_per_second"] / 1e6, 1), "Mbps")
    except Exception:
        pass

    bm.out(cl, f"pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; "
               f"printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf; true")
    bm.out(s, "pkill -9 -x qeli; pkill -x iperf3; sleep 1; "
              "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    print("\n" + "=" * 62)
    npass = sum(1 for r in res if r["pass"])
    for r in res:
        print(f"  {'PASS' if r['pass'] else 'FAIL'}  {r['case']:<30} peak={r['peak_streams']} conns={r['live_conns']}")
    print(f"  {npass}/{len(res)} cases passed")
    open(r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\download_bonding_0.7.12.json",
         "w", encoding="utf-8").write(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

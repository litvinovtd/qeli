#!/usr/bin/env python3
"""L3 behavioral -- user-limit / allocation keys with a visible data-plane effect
that this round's other suites don't already exercise:

  bandwidth.limit_mbps  -> throughput is actually capped near the limit
  static_ip             -> the user is handed exactly that tunnel IP
  pool.reservation.<u>  -> profile-level reservation hands that IP (pool.rs fix)
  max_sessions = 1      -> a 2nd concurrent session for the user is refused

(obf.* modes, routes, dns, multipath, allowed_networks, mtu, nat, dev_attach and
QELI_TRACE are covered by the benchmark / push-matrix / route-push / features /
bonding suites already run this round -- see the L3 coverage table in the report.)
"""
import os, sys, io, re, json, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm

MODE = {"name": "l3", "port": 8443, "transport": "tcp",
        "server_mode": "fake-tls", "client_mode": "fake-tls"}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NET = "10.9.0"
LOG = "/tmp/l3-client.log"


def server_conf(user_extra="", profile_extra=""):
    ini = bm.server_ini(MODE)
    if profile_extra:
        ini = ini.replace("perf.tcp.nodelay = true", profile_extra + "\nperf.tcp.nodelay = true")
    if user_extra:
        ini = ini.replace("[user:bench]", f"[user:bench]\n{user_extra}")
    return ini


def start_server(s, ini):
    bm.put(s, "/etc/qeli/l3-server.conf", ini)
    bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 2; ip link del vpn0 2>/dev/null; true")
    if bm.out(s, "pgrep -x qeli | wc -l").strip().splitlines()[-1] != "0":
        raise RuntimeError("prev server alive")
    bm.out(s, "rm -f /tmp/l3-srv.log; setsid " + bm.BIN +
           " server --config /etc/qeli/l3-server.conf >/dev/null 2>&1 </dev/null & sleep 5")
    return bm.identity_pubkey(s)


def start_client(cl, key, tag="a"):
    log = f"/tmp/l3-client-{tag}.log"
    bm.put(cl, f"/etc/qeli/l3-client-{tag}.conf", bm.client_ini(MODE, key))
    bm.out(cl, f"rm -f {log}; setsid {bm.BIN} client --config /etc/qeli/l3-client-{tag}.conf "
               f">{log} 2>&1 < /dev/null & sleep 7")
    return log


def client_ip(cl, log):
    o = bm.out(cl, f"ip -4 -br addr show vpn0 2>/dev/null | grep -oE '{NET}\\.[0-9]+' | head -1")
    return o.strip().splitlines()[-1] if o.strip() else None


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    res = []
    try:
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; true")

        # ---- bandwidth.limit_mbps ----
        print("===== bandwidth.limit_mbps = 50 =====")
        key = start_server(s, server_conf(user_extra="bandwidth.limit_mbps = 50"))
        log = start_client(cl, key)
        bm.out(s, "pkill -x iperf3; sleep 1; iperf3 -s -D; sleep 1; true")
        r = bm.iperf_tcp(cl, f"{NET}.1", reverse=True)  # download = server->client
        mbps = r.get("mbps", 0)
        ok = 30 <= mbps <= 75  # ~50 with slack for burst/measurement
        print(f"  download through 50 Mbps cap: {mbps} Mbps -> {'PASS' if ok else 'FAIL'} (want ~50)")
        res.append({"case": "bandwidth.limit_mbps=50", "pass": ok, "measured_mbps": mbps})
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; true")

        # ---- static_ip ----
        print("\n===== static_ip = 10.9.0.77 =====")
        key = start_server(s, server_conf(user_extra="static_ip = 10.9.0.77"))
        log = start_client(cl, key)
        ip = client_ip(cl, log)
        ok = ip == "10.9.0.77"
        print(f"  assigned tunnel IP: {ip} -> {'PASS' if ok else 'FAIL'} (want 10.9.0.77)")
        res.append({"case": "static_ip", "pass": ok, "ip": ip})
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; true")

        # ---- pool.reservation.<user> (profile-level; the pool.rs fix) ----
        print("\n===== pool.reservation.bench = 10.9.0.88 =====")
        key = start_server(s, server_conf(profile_extra="pool.reservation.bench = 10.9.0.88"))
        log = start_client(cl, key)
        ip = client_ip(cl, log)
        ok = ip == "10.9.0.88"
        print(f"  assigned tunnel IP: {ip} -> {'PASS' if ok else 'FAIL'} (want 10.9.0.88)")
        res.append({"case": "pool.reservation", "pass": ok, "ip": ip})
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; true")

        # ---- max_sessions = 1 ----
        print("\n===== max_sessions = 1 (2nd concurrent session refused) =====")
        key = start_server(s, server_conf(user_extra="max_sessions = 1"))
        log_a = start_client(cl, key, tag="a")
        ip_a = client_ip(cl, log_a)
        # second client, same user, different local process/dev
        bm.put(cl, "/etc/qeli/l3-client-b.conf",
               bm.client_ini(MODE, key).replace("[logging]", "dev = vpn1\n[logging]"))
        bm.out(cl, "rm -f /tmp/l3-client-b.log; setsid " + bm.BIN +
               " client --config /etc/qeli/l3-client-b.conf >/tmp/l3-client-b.log 2>&1 </dev/null & sleep 7")
        up_b = "10.9.0." in bm.out(cl, "ip -4 -br addr show vpn1 2>/dev/null || echo none")
        srv_refused = bm.out(s, "grep -aciE 'max.session|session limit|too many' /tmp/l3-srv.log 2>/dev/null || echo 0").strip().splitlines()[-1]
        # first stays up, second does NOT get a tunnel
        ok = (ip_a is not None) and (not up_b)
        print(f"  1st session IP: {ip_a} | 2nd session got tunnel: {up_b} "
              f"(refused markers: {srv_refused}) -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("  2nd client log:", bm.out(cl, "tail -4 /tmp/l3-client-b.log"))
        res.append({"case": "max_sessions=1", "pass": ok, "first_ip": ip_a, "second_up": up_b})
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; true")

    finally:
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; "
                   "printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf; true")
        bm.out(s, "pkill -9 -x qeli; pkill -x iperf3; sleep 1; systemctl start qeli-server.service 2>/dev/null; true")
        s.close(); cl.close()

    print("\n" + "=" * 60)
    for r in res:
        print(f"  {'PASS' if r['pass'] else 'FAIL'}  {r['case']}")
    print(f"  {sum(1 for r in res if r['pass'])}/{len(res)} passed")
    open(os.path.join(ROOT, "release", "l3_user_limits_0.7.13.json"),
         "w", encoding="utf-8").write(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

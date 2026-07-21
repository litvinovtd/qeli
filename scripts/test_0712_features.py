#!/usr/bin/env python3
"""0.7.12 feature surface: allowed_networks ACL, QELI_TRACE, dev_attach.

allowed_networks -- per-user destination ACL, enforced server-side. The lab
gives the server a second subnet (dummy55 = 10.55.55.1/24) reachable only
through the tunnel, so "allowed" vs "denied" is a real forwarding decision and
not just a routing-table artifact.

QELI_TRACE -- opt-in packet timeline. It claims to record packet *shapes* only;
the test checks the file fills AND that no plaintext payload leaks into it.

dev_attach -- attach to an externally-owned interface instead of refusing it
(the refusal path is covered by test_tun_reclaim.py case 2).
"""
import os, sys, re, time, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm

MODE = {"name": "feat", "port": 8443, "transport": "tcp",
        "server_mode": "fake-tls", "client_mode": "fake-tls"}
NET = "10.9.0"
FAR = "10.55.55.1"
LOG = "/tmp/feat-client.log"
CANARY = "QELICANARYPAYLOAD1234567890"


def server_conf(acl=None, route=True):
    ini = bm.server_ini(MODE)
    if route:
        ini = ini.replace("routing.forward_private = true",
                          "routing.forward_private = true\nroute = 10.55.55.0/24")
    if acl is not None:
        ini = ini.replace("[user:bench]", f"[user:bench]\nallowed_networks = {acl}")
    return ini


SRVLOG = "/tmp/feat-server.log"


def start_server(s, ini, env=""):
    """Start a server and PROVE it is the one now serving.

    The server logs to the file named in `[logging] file`, not to stdout, so the
    log has to be redirected there for the markers to be readable at all -- and
    the previous instance has to be provably gone before the new one binds. A
    lingering old instance kept serving once and quietly invalidated an ACL case
    (it answered without the ACL, so the test 'passed' the wrong server).
    """
    ini = ini.replace("file = /var/log/qeli/server.log", f"file = {SRVLOG}")
    bm.put(s, "/etc/qeli/feat-server.conf", ini)
    # `pkill -9 qeli` alone is not enough: qeli-server.service is Restart=always,
    # so systemd immediately resurrects it, it takes vpn0 (10.0.0.1/24) and OUR
    # profile then cannot bind its own address. That is exactly how an ACL case
    # once "passed" against the wrong server. Stop the unit, don't just kill it.
    bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; sleep 1; "
              "pkill -9 -x qeli; sleep 3; ip link del vpn0 2>/dev/null; sleep 1; true")
    left = bm.out(s, "pgrep -x qeli | wc -l").strip().splitlines()[-1]
    if left != "0":
        raise RuntimeError(f"previous server still alive ({left} procs) — aborting")
    bm.out(s, f"rm -f {SRVLOG}; {env} setsid {bm.BIN} server "
              f"--config /etc/qeli/feat-server.conf >/dev/null 2>&1 < /dev/null & sleep 5")
    bad = bm.out(s, f"grep -acE 'respawning|already assigned' {SRVLOG} || echo 0"
                 ).strip().splitlines()[-1]
    if bad != "0":
        raise RuntimeError(f"server did not come up cleanly:\n{bm.out(s, f'tail -6 {SRVLOG}')}")
    # And prove the listener on our port is the process we just started.
    own = bm.out(s, f"ss -tlnp | grep ':{MODE['port']} ' || echo none")
    if "qeli" not in own:
        raise RuntimeError(f"nothing of ours is listening on {MODE['port']}: {own}")
    return bm.identity_pubkey(s)


def start_client(cl, key, extra=""):
    ini = bm.client_ini(MODE, key)
    if extra:
        ini = ini.replace("[logging]", extra + "\n[logging]")
    bm.put(cl, "/etc/qeli/feat-client.conf", ini)
    bm.out(cl, f"pkill -9 -x qeli; sleep 2; ip link del vpn0 2>/dev/null; rm -f {LOG}; true")
    bm.out(cl, f"setsid {bm.BIN} client --config /etc/qeli/feat-client.conf "
               f">{LOG} 2>&1 < /dev/null & sleep 7")


def reach(cl, ip):
    """True only if replies actually came back.

    NB: do not substring-match "0% packet loss" -- "100% packet loss" contains
    it, so a fully blocked destination reads as reachable and an ACL denial
    silently inverts into a pass. Count received packets instead.
    """
    o = bm.out(cl, f"ping -c3 -W2 {ip} 2>&1 | tail -2", t=25)
    m = re.search(r"(\d+)\s+received", o)
    return bool(m) and int(m.group(1)) > 0


MGMT = os.environ.get("QELI_MGMT_NET", "192.168.50.0/24")
# Lab management gateway/interface used to keep the SSH path alive while the tunnel is up.
# Overridable via env for a different lab; the defaults match the current bench VMs.
MGMT_GW = os.environ.get("QELI_MGMT_GW", "10.66.116.1")
MGMT_IF = os.environ.get("QELI_MGMT_IF", "ens18")


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    res = []
    try:
        bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; true")
        # The allowed_networks cases run the client with `route_local = true`,
        # which installs the whole RFC1918 blanket -- 192.168.0.0/16 swallows the
        # management subnet this test is driven from and kills the SSH return path
        # mid-run (it bit us here once). Pin the mgmt /24 to the uplink first: it
        # is more specific than the pushed /16, so route_local is still exercised.
        bm.out(cl, f"ip route replace {MGMT} via {MGMT_GW} dev {MGMT_IF} metric 50; true")
        bm.out(s, "modprobe dummy 2>/dev/null; ip link del dummy55 2>/dev/null; "
                  "ip link add dummy55 type dummy; ip addr add 10.55.55.1/24 dev dummy55; "
                  "ip link set dummy55 up; sysctl -qw net.ipv4.ip_forward=1; true")
        print("far target on server:", bm.out(s, "ip -4 -br addr show dummy55"))

        # ---------- allowed_networks ----------
        print("\n===== allowed_networks (per-user destination ACL) =====")
        for label, acl, want_tun, want_far in [
            ("unset (default = allow all)", None, True, True),
            ("tunnel subnet only", f"{NET}.0/24", True, False),
            ("tunnel + far subnet", f"{NET}.0/24,10.55.55.0/24", True, True),
        ]:
            key = start_server(s, server_conf(acl=acl).replace("level = info", "level = debug"))
            start_client(cl, key, extra="route_local = true")
            tun_ok = reach(cl, f"{NET}.1")
            far_ok = reach(cl, FAR)
            # The server states its own view: absent marker on a restricted user
            # means the ACL never loaded, which must not read as a pass.
            marker = "restricted to" in bm.out(s, f"grep -ai 'restricted to' {SRVLOG} || true")
            drops = bm.out(s, f"grep -ac 'ACL: dropped' {SRVLOG} || echo 0").strip().splitlines()[-1]
            ok = (tun_ok == want_tun) and (far_ok == want_far) and (marker == (acl is not None))
            print(f"  allowed_networks = {str(acl):<32} tun={tun_ok} far={far_ok} "
                  f"(want {want_tun}/{want_far}) marker={marker} drops={drops} "
                  f"-> {'PASS' if ok else 'FAIL'}")
            if not ok:
                print("    client log:", bm.out(cl, f"tail -4 {LOG}"))
            res.append({"case": f"allowed_networks={acl}", "pass": ok, "marker": marker,
                        "acl_drops": drops, "tun": tun_ok, "far": far_ok})
            bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; true")

        # ---------- QELI_TRACE ----------
        print("\n===== QELI_TRACE (opt-in packet timeline) =====")
        # The trace is an in-memory ring: it reaches disk on SIGUSR1 or a clean
        # shutdown, never continuously. Killing with -9 leaves no file at all.
        TR = "/tmp/qeli-trace.csv"
        bm.out(s, f"rm -f {TR}; true")
        key = start_server(s, server_conf(), env=f"QELI_TRACE={TR}")
        armed = "packet trace armed" in bm.out(s, f"grep -ai 'packet trace' {SRVLOG} || true")
        start_client(cl, key)
        # Push a canary through the tunnel and confirm it really arrived, so
        # "not in the trace" means "not recorded", not "never sent".
        bm.out(s, f"pkill -x nc; rm -f /tmp/got.txt; (timeout 12 nc -l -p 9999 >/tmp/got.txt 2>&1 &); sleep 1; true")
        bm.out(cl, f"for i in 1 2 3 4 5; do echo {CANARY} | timeout 3 nc {NET}.1 9999; done; true", t=40)
        reach(cl, f"{NET}.1")
        arrived = bm.out(s, f"grep -c {CANARY} /tmp/got.txt 2>/dev/null || echo 0").strip().splitlines()[-1]
        bm.out(s, "pkill -USR1 -x qeli; sleep 2; true")
        size = bm.out(s, f"stat -c %s {TR} 2>/dev/null || echo 0").strip().splitlines()[-1]
        lines = bm.out(s, f"wc -l < {TR} 2>/dev/null || echo 0").strip().splitlines()[-1]
        leak = bm.out(s, f"grep -c {CANARY} {TR} 2>/dev/null || echo 0").strip().splitlines()[-1]
        blobs = bm.out(s, f"grep -cE '[A-Za-z0-9+/]{{40,}}' {TR} 2>/dev/null || echo 0").strip().splitlines()[-1]
        sample = bm.out(s, f"head -4 {TR} 2>/dev/null")
        ok = (armed and int(size) > 0 and int(lines) > 0
              and leak == "0" and blobs == "0" and arrived != "0")
        print(f"  armed: {armed} | canary reached the far side: {arrived} | bytes: {size} | records: {lines}")
        print(f"  canary in trace: {leak} | long opaque blobs: {blobs}  (both MUST be 0 -- shapes only)")
        print("  sample:\n    " + "\n    ".join(sample.splitlines()[:4]))
        print(f"  -> {'PASS' if ok else 'FAIL'}")
        res.append({"case": "QELI_TRACE", "pass": ok, "bytes": size, "records": lines,
                    "payload_leak": leak, "canary_arrived": arrived})
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; true")

        # ---------- dev_attach ----------
        print("\n===== dev_attach (attach to an externally-owned interface) =====")
        key = start_server(s, server_conf())
        bm.out(cl, "ip tuntap del dev ext0 mode tun 2>/dev/null; ip tuntap add dev ext0 mode tun; "
                   "ip link set ext0 up; sleep 1; true")
        pre = bm.out(cl, "ip -br link show ext0 | head -1")
        start_client(cl, key, extra="dev = ext0\ndev_attach = true")
        # dev_attach deliberately does NOT address the interface -- L3 stays with
        # whoever owns it ("Attached ext0; L3 (address X) left to its owner"), so
        # asserting a tunnel IP on the device would be asserting the opposite of
        # the contract. Attachment + no refusal is what "it worked" means here;
        # the owner supplies the addressing, which is what the lab does next.
        attached = "Attached ext0" in bm.out(cl, f"grep -ai 'Attached ext0' {LOG} || true")
        refused = "refusing" in bm.out(cl, f"grep -ai refusing {LOG} || true")
        ip_line = bm.out(cl, f"grep -aoE 'address [0-9.]+' {LOG} | head -1").strip()
        addr = ip_line.split()[-1] if ip_line else ""
        if attached and addr:
            bm.out(cl, f"ip addr add {addr}/24 dev ext0 2>/dev/null; ip link set ext0 up; sleep 2; true")
        ping_ok = reach(cl, f"{NET}.1") if attached and addr else False
        ok = attached and ping_ok and not refused
        print(f"  pre-created: {pre.strip()}")
        print(f"  attached: {attached} | L3 left to owner: {addr or 'n/a'} | "
              f"traffic once owner addresses it: {ping_ok} | refused: {refused}")
        print(f"  -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("  client log:", bm.out(cl, f"tail -8 {LOG}"))
        res.append({"case": "dev_attach", "pass": ok, "attached": attached, "ping": ping_ok})

    finally:
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; "
                   "ip tuntap del dev ext0 mode tun 2>/dev/null; "
                   "printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf; true")
        bm.out(s, "pkill -9 -x qeli; pkill -x nc; sleep 1; ip link del dummy55 2>/dev/null; "
                  "systemctl start qeli-server.service 2>/dev/null; true")
        print("\ncleanup client:", bm.out(cl, f"ip -br link | grep -ivE 'lo |{MGMT_IF}' || echo clean").strip())
        s.close(); cl.close()

    print("\n" + "=" * 62)
    for r in res:
        print(f"  {'PASS' if r['pass'] else 'FAIL'}  {r['case']}")
    print(f"  {sum(1 for r in res if r['pass'])}/{len(res)} passed")
    open(r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\features_0.7.12.json",
         "w", encoding="utf-8").write(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

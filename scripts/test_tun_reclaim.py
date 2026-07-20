#!/usr/bin/env python3
"""0.7.12: `interface 'vpn0' already exists` after an uplink drop.

Before the fix, a data plane that exited on an error path leaked its reader
thread; the tun then still existed on the next reconnect and EVERY later attempt
failed identically, forever, until the process was killed by hand.

Cases:
  1  uplink drop -> reconnect   -> must recover (the actual fix path)
  2  foreign persistent tun     -> must REFUSE (never delete someone else's)
  3  same name, not a TUN       -> must REFUSE
  4  kill -9 -> restart         -> clean start (kernel reaps non-persistent dev)

Safety: the outage is simulated with an nft rule in a DEDICATED table scoped to
the qeli server port only, torn down in a finally block. SSH is never touched.
"""
import os, sys, re, time, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm

MODE = {"name": "reclaim", "port": 8443, "transport": "tcp",
        "server_mode": "fake-tls", "client_mode": "fake-tls"}
NET = "10.9.0"
LOG = "/tmp/reclaim-client.log"
TABLE = "qeli_outage_test"


def outage(cl, on):
    """Drop client->server:8443 in an isolated table. SSH is untouched."""
    if on:
        bm.out(cl, f"nft add table ip {TABLE} 2>/dev/null; "
                   f"nft add chain ip {TABLE} out '{{ type filter hook output priority 0; }}' 2>/dev/null; "
                   f"nft add rule ip {TABLE} out ip daddr {bm.SERVER[0]} tcp dport {MODE['port']} drop; true")
    else:
        bm.out(cl, f"nft delete table ip {TABLE} 2>/dev/null; true")


def tun_up(cl, name="vpn0"):
    return "10.9.0." in bm.out(cl, f"ip -4 -br addr show {name} 2>/dev/null || echo none")


def start_client(cl, key, extra=""):
    ini = bm.client_ini(MODE, key)
    if extra:
        ini = ini.replace("[logging]", extra + "\n[logging]")
    bm.put(cl, "/etc/qeli/reclaim-client.conf", ini)
    bm.out(cl, f"rm -f {LOG}; setsid {bm.BIN} client --config /etc/qeli/reclaim-client.conf "
               f">{LOG} 2>&1 < /dev/null & sleep 6")


def log(cl, n=6):
    return bm.out(cl, f"tail -{n} {LOG} 2>/dev/null || true")


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    res = []
    try:
        bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; true")
        bm.out(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
        bm.put(s, "/etc/qeli/bench-server.conf", bm.server_ini(MODE))
        bm.out(s, f"setsid {bm.BIN} server --config /etc/qeli/bench-server.conf "
                  ">/tmp/reclaim-server.log 2>&1 < /dev/null & sleep 4")
        key = bm.identity_pubkey(s)
        print("server key:", key[:16])
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; true")

        # ---- case 1: uplink drop -> reconnect ------------------------------
        print("\n--- case 1: uplink drop -> reconnect (the fix path) ---")
        start_client(cl, key)
        before = tun_up(cl)
        print("  connected:", before)
        outage(cl, True)
        print("  outage ON (dropping ->:%d), waiting 40s for the tunnel to die..." % MODE["port"])
        time.sleep(40)
        outage(cl, False)
        print("  outage OFF, waiting 45s for reconnect...")
        time.sleep(45)
        after = tun_up(cl)
        lg = bm.out(cl, f"grep -acE \"already exists\" {LOG} || echo 0").strip().splitlines()[-1]
        alive = bm.out(cl, "pgrep -x qeli | wc -l").strip().splitlines()[-1]
        ping = bm.out(cl, f"ping -c3 -W2 {NET}.1 2>&1 | tail -2", t=25)
        # "100% packet loss" contains "0% packet loss" -- count replies instead.
        m = re.search(r"(\d+)\s+received", ping)
        ping_ok = bool(m) and int(m.group(1)) > 0
        ok = before and after and lg == "0" and ping_ok
        print(f"  reconnected  : {after}   qeli alive: {alive}")
        print(f"  'already exists' occurrences: {lg}  (must be 0)")
        print(f"  ping through tunnel: {'OK' if ping_ok else 'FAIL'}")
        print(f"  -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("  log tail:\n", log(cl, 15))
        res.append({"case": "1 uplink drop -> reconnect", "pass": bool(ok),
                    "already_exists_hits": lg, "reconnected": after})
        bm.out(cl, "pkill -9 -x qeli; sleep 2; ip link del vpn0 2>/dev/null; true")

        # ---- case 2: foreign PERSISTENT tun must be refused ----------------
        print("\n--- case 2: foreign persistent tun -> must refuse ---")
        bm.out(cl, "ip tuntap add dev vpn0 mode tun; ip link set vpn0 up; sleep 1; true")
        start_client(cl, key)
        lg = log(cl, 12)
        refused = "persistent device" in lg or "refusing to delete" in lg
        still = "vpn0" in bm.out(cl, "ip -br link show vpn0 2>/dev/null || echo gone")
        ok = refused and still
        print(f"  refused with the right reason: {refused}")
        print(f"  foreign device left intact   : {still}")
        print(f"  -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("  log tail:\n", lg)
        res.append({"case": "2 foreign persistent tun refused", "pass": bool(ok)})
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip tuntap del dev vpn0 mode tun 2>/dev/null; true")

        # ---- case 3: name taken by a NON-tun device -----------------------
        print("\n--- case 3: name taken by a dummy (non-TUN) device -> must refuse ---")
        bm.out(cl, "modprobe dummy 2>/dev/null; ip link add vpn0 type dummy 2>/dev/null; "
                   "ip link set vpn0 up; sleep 1; true")
        start_client(cl, key)
        lg = log(cl, 12)
        ok = "not a TUN/TAP device" in lg
        print(f"  refused with 'not a TUN/TAP device': {ok}")
        print(f"  -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("  log tail:\n", lg)
        res.append({"case": "3 non-tun name collision refused", "pass": bool(ok)})
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; true")

        # ---- case 4: kill -9 then restart ---------------------------------
        print("\n--- case 4: kill -9 -> restart must be clean ---")
        start_client(cl, key)
        up1 = tun_up(cl)
        bm.out(cl, "pkill -9 -x qeli; sleep 3; true")
        gone = "none" in bm.out(cl, "ip -4 -br addr show vpn0 2>/dev/null || echo none")
        start_client(cl, key)
        up2 = tun_up(cl)
        ok = up1 and gone and up2
        print(f"  first connect: {up1} | device reaped by kernel after kill -9: {gone} | reconnect: {up2}")
        print(f"  -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("  log tail:\n", log(cl, 12))
        res.append({"case": "4 kill -9 -> clean restart", "pass": bool(ok)})

    finally:
        outage(cl, False)
        bm.out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; "
                   "ip tuntap del dev vpn0 mode tun 2>/dev/null; "
                   "printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf; true")
        bm.out(s, "pkill -9 -x qeli; sleep 1; systemctl start qeli-server.service 2>/dev/null; true")
        left = bm.out(cl, "ip -br link | grep -ivE 'lo |ens18' || echo 'no leftover ifaces'")
        rt = bm.out(cl, "ip route get 192.168.50.50 | head -1")
        print("\ncleanup:", left.strip(), "|", rt.strip())
        s.close(); cl.close()

    print("\n" + "=" * 62)
    for r in res:
        print(f"  {'PASS' if r['pass'] else 'FAIL'}  {r['case']}")
    print(f"  {sum(1 for r in res if r['pass'])}/{len(res)} cases passed")
    open(r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\tun_reclaim_0.7.12.json",
         "w", encoding="utf-8").write(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

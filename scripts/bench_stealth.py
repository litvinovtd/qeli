"""Throughput sweep across wire modes with STEALTH off vs on.

Reuses benchmark.py's bring-up + iperf. For the stealth pass, monkeypatches
server_ini to inject obf.traffic_shaping.{enabled,stealth,...} into each profile.
Stops the systemd qeli-server.service first (it holds :443; bench pkill loses to
its restart) and restores it after.

Quantifies the speed cost of stealth per mode.
"""
import sys, io
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import benchmark as B

_orig_server_ini = B.server_ini
_STEALTH = {"on": False}
STEALTH_RATE = 10  # Mbps cap under stealth for this bench (default ships at 2)
STEALTH_KEYS = (
    "obf.traffic_shaping.enabled = true\n"
    "obf.traffic_shaping.idle_gap_mean_ms = 60\n"
    "obf.traffic_shaping.idle_gap_min_ms = 10\n"
    "obf.traffic_shaping.budget_bytes_per_sec = 262144\n"
    "obf.traffic_shaping.min_size = 80\n"
    "obf.traffic_shaping.max_size = 700\n"
    "obf.traffic_shaping.stealth = true\n"
    f"obf.traffic_shaping.stealth_rate_mbps = {STEALTH_RATE}\n"
)


def _patched(m):
    s = _orig_server_ini(m)
    if _STEALTH["on"]:
        # Inject into the [profile:bench] section (just before [user:bench]).
        s = s.replace("\n[user:bench]", "\n" + STEALTH_KEYS + "\n[user:bench]")
    return s


B.server_ini = _patched

WANT = ("tcp-plain-raw", "tcp-faketls", "tcp-obfs", "tcp-reality-tls", "udp-faketls")
MODES = [m for m in B.MODES if m["name"] in WANT]


def speed(r):
    if not r or "error" in r:
        return f"ERR {r.get('error', '?') if r else 'none'}"
    if "udp_sweep" in r:
        best = 0.0
        for v in r["udp_sweep"].values():
            if isinstance(v, dict) and v.get("loss_pct", 100) < 2:
                best = max(best, v.get("mbps", 0))
        return f"{best:.0f} Mbps (UDP <2% loss)"
    up = r.get("tcp_up", {}).get("mbps")
    dn = r.get("tcp_down", {}).get("mbps")
    return f"up {up} / down {dn} Mbps"


def fresh():
    return B.conn(B.SERVER), B.conn(B.CLIENT)


def main():
    # One-time setup: stop the service, KILL any leftover qeli (a prior aborted run
    # can leave one holding /usr/local/bin/qeli busy → install fails), install binary.
    s, cl = fresh()
    B.out(s, "systemctl stop qeli-server.service 2>&1; pkill -9 -x qeli; sleep 1; true")
    B.out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; sleep 1; true")
    B.out(s, f"install -m755 {B.SRC_BIN} {B.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(B.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, B.BIN); cf.close()
    B.out(cl, f"chmod 755 {B.BIN}; mkdir -p /etc/qeli /var/log/qeli")
    B.out(s, "mkdir -p /etc/qeli /var/log/qeli")
    print("binary:", B.out(s, f"{B.BIN} --version 2>&1"), "| stealth cap:", STEALTH_RATE, "Mbps")
    try:
        s.close(); cl.close()
    except Exception:
        pass

    # Reconnect PER MODE (short sessions) so a transient SSH reset only costs one
    # mode, not the whole sweep; retry once, else record ERR and continue.
    results = {}
    for stealth in (False, True):
        _STEALTH["on"] = stealth
        for m in MODES:
            for attempt in range(2):
                s = cl = None
                try:
                    s, cl = fresh()
                    B.out(s, "systemctl stop qeli-server.service 2>&1; true")
                    results[(m["name"], stealth)] = B.run_mode(s, cl, m)
                    break
                except Exception as ex:
                    if attempt == 1:
                        results[(m["name"], stealth)] = {"error": str(ex)[:60]}
                    import time as _t; _t.sleep(3)
                finally:
                    for c in (s, cl):
                        try:
                            if c:
                                c.close()
                        except Exception:
                            pass

    try:
        s, _ = fresh()
        B.out(s, "systemctl start qeli-server.service 2>&1; true")
        s.close()
    except Exception:
        pass

    print("\n===== THROUGHPUT: stealth OFF vs ON =====")
    print(f"{'mode':<18} {'OFF':<30} {'ON (stealth ' + str(STEALTH_RATE) + ' Mbps)':<30}")
    print("-" * 78)
    for m in MODES:
        off = results.get((m["name"], False), {})
        on = results.get((m["name"], True), {})
        print(f"{m['name']:<18} {speed(off):<30} {speed(on):<30}")
    print(f"\nNB: stealth caps the data plane to ~{STEALTH_RATE} Mbps (configurable via "
          "obf.traffic_shaping.stealth_rate_mbps; ships at 2). OFF = native per-mode speed.")


if __name__ == "__main__":
    main()

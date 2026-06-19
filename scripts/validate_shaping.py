"""Live-capture validation for traffic-shaping Phase 1 (Ось 2B).

Brings up a tcp fake-tls tunnel with obf.traffic_shaping ON, confirms the tunnel
survives cover (ping 0% loss), then tcpdumps a ~6s IDLE window on the server and
measures server->client payload packets and their inter-packet gaps. Compares to
a shaping-OFF control (fixed 15s heartbeat → ~0 packets in a 6s idle window).

PASS = shaping-ON shows many cover packets with VARYING (non-constant) gaps,
shaping-OFF shows ~none. Proves cover is emitted and is non-periodic (not a beacon).
"""
import sys, time, re, statistics
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import benchmark as B

# `python validate_shaping.py udp` tests the UDP path; default is TCP.
_UDP = len(sys.argv) > 1 and sys.argv[1] == "udp"
MODE = ({"name": "udp-faketls", "transport": "udp", "port": 4443,
         "client_mode": "fake-tls", "server_mode": "fake-tls"} if _UDP else
        {"name": "tcp-faketls", "transport": "tcp", "port": 443,
         "client_mode": "fake-tls", "server_mode": "fake-tls"})
_PROTO = "udp" if _UDP else "tcp"
_SIP = "10.10.0.1" if _UDP else "10.9.0.1"

SHAPING = "\n".join([
    "obf.traffic_shaping.enabled = true",
    "obf.traffic_shaping.idle_gap_mean_ms = 200",
    "obf.traffic_shaping.idle_gap_min_ms = 30",
    "obf.traffic_shaping.idle_gap_max_ms = 1500",
    "obf.traffic_shaping.budget_bytes_per_sec = 65536",
    "obf.traffic_shaping.min_size = 80",
    "obf.traffic_shaping.max_size = 600",
]) + "\n"

ANCHOR = "obf.heartbeat.interval_ms = 15000\n"


def server_conf(shaping_on):
    base = B.server_ini(MODE)
    if shaping_on:
        return base.replace(ANCHOR, ANCHOR + SHAPING)
    return base


def bring_up(s, cl, shaping_on):
    B.out(s, "pkill -9 -x qeli; sleep 1; true")
    B.out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; "
              "rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    B.put(s, "/etc/qeli/bench-server.conf", server_conf(shaping_on))
    key = B.identity_pubkey(s)
    B.put(cl, "/etc/qeli/bench-client.conf", B.client_ini(MODE, key))
    B.out(s, f"rm -f /var/log/qeli/server.log; nohup {B.BIN} server "
             f"--config /etc/qeli/bench-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    B.out(cl, f"rm -f /tmp/qc.log; nohup {B.BIN} client "
              f"--config /etc/qeli/bench-client.conf >/tmp/qc.log 2>&1 & echo ok")
    for _ in range(10):
        time.sleep(1.5)
        if "Auth OK" in B.out(cl, "grep -E 'Auth OK' /tmp/qc.log || true"):
            return True
    print("  CONNECT FAILED:", B.out(cl, "tail -n 4 /tmp/qc.log"))
    return False


def capture(s, secs=6):
    """Capture BOTH directions' TCP payload packets during idle. `-i any` inserts
    an iface + direction token between the ts and `IP`, so parse robustly: ts at
    line start, server `:443` on the src (S2C) or dst (C2S) side, trailing length."""
    port = MODE["port"]
    raw = B.out(s, f"timeout {secs} tcpdump -i any -nn -tt '{_PROTO} port {port}' "
                   f"2>/dev/null || true", t=secs + 8)
    srv = B.SERVER[0]
    s2c, c2s, samples = [], [], []
    for line in raw.splitlines():
        tm = re.match(r"^(\d+\.\d+)", line)
        lm = re.search(r"length (\d+)", line)
        if not (tm and lm and int(lm.group(1)) > 0):
            continue
        t = float(tm.group(1))
        if f"{srv}.{port} > " in line:        # server -> client
            s2c.append(t)
            if len(samples) < 4:
                samples.append("S2C " + line[:108])
        elif f"> {srv}.{port}:" in line:      # client -> server
            c2s.append(t)
            if len(samples) < 8:
                samples.append("C2S " + line[:108])
    return s2c, c2s, samples


def _gaps(ts):
    return [round((b - a) * 1000) for a, b in zip(ts, ts[1:])]  # ms


def measure(s, cl, shaping_on):
    label = "ON " if shaping_on else "OFF"
    if not bring_up(s, cl, shaping_on):
        return {"shaping": label, "error": "connect failed"}
    sip = _SIP
    ping = B.out(cl, f"ping -c 10 -i 0.2 -q {sip}")
    loss = next((l for l in ping.splitlines() if "packet loss" in l), "")
    # Let the link go fully idle, then capture.
    time.sleep(2)
    s2c, c2s, samples = capture(s, 6)
    print(f"  [{label}] raw samples:")
    for ln in samples:
        print("     ", ln)
    B.out(s, "pkill -9 -x qeli; true")
    B.out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; true")
    g_s, g_c = _gaps(s2c), _gaps(c2s)
    r = {
        "shaping": label,
        "ping_loss": loss.split(",")[2].strip() if "," in loss else loss.strip(),
        "s2c_pkts": len(s2c), "s2c_gaps": len(set(g_s)),
        "s2c_mean": round(statistics.mean(g_s)) if g_s else None,
        "c2s_pkts": len(c2s), "c2s_gaps": len(set(g_c)),
        "c2s_mean": round(statistics.mean(g_c)) if g_c else None,
    }
    print("  ", r)
    return r


def main():
    s, cl = B.conn(B.SERVER), B.conn(B.CLIENT)
    # The systemd qeli-server.service holds 0.0.0.0:443 and auto-restarts, so a
    # plain pkill loses the race and the bench server can't bind (→ client hits a
    # stale server → "decryption failed"). Stop it for the test, restore at the end.
    B.out(s, "systemctl stop qeli-server.service 2>&1; sleep 1; true")
    B.out(s, f"install -m755 {B.SRC_BIN} {B.BIN}")
    import io
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(B.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, B.BIN); cf.close()
    B.out(cl, f"chmod 755 {B.BIN}; mkdir -p /etc/qeli /var/log/qeli")
    B.out(s, "mkdir -p /etc/qeli /var/log/qeli")
    print("binary:", B.out(s, f"{B.BIN} --version 2>&1"))

    print("\n=== shaping OFF (control: fixed 15s heartbeat) ===")
    off = measure(s, cl, False)
    print("\n=== shaping ON (Poisson cover, mean 200ms) ===")
    on = measure(s, cl, True)

    print("\n===== VERDICT =====")
    ok_tunnel = on.get("ping_loss", "").startswith("0%")
    ok_s2c = on.get("s2c_pkts", 0) >= 5 and on.get("s2c_gaps", 0) >= 4
    ok_c2s = on.get("c2s_pkts", 0) >= 5 and on.get("c2s_gaps", 0) >= 4
    ok_control = (off.get("s2c_pkts", 99) < on.get("s2c_pkts", 0)
                  and off.get("c2s_pkts", 99) < on.get("c2s_pkts", 0))
    print(f"tunnel survives cover (ON ping 0% loss):       {ok_tunnel}")
    print(f"server->client cover (ON >=5 pkts, >=4 gaps):  {ok_s2c}  ({on.get('s2c_pkts')} pkts, {on.get('s2c_gaps')} gaps, mean {on.get('s2c_mean')}ms)")
    print(f"client->server cover (ON >=5 pkts, >=4 gaps):  {ok_c2s}  ({on.get('c2s_pkts')} pkts, {on.get('c2s_gaps')} gaps, mean {on.get('c2s_mean')}ms)")
    print(f"OFF control quieter (both dirs):               {ok_control}  (OFF s2c {off.get('s2c_pkts')}/c2s {off.get('c2s_pkts')} vs ON s2c {on.get('s2c_pkts')}/c2s {on.get('c2s_pkts')})")
    print("RESULT:", "PASS" if (ok_tunnel and ok_s2c and ok_c2s and ok_control) else "REVIEW")

    # Restore the lab to as-found (systemd service back up).
    B.out(s, "systemctl start qeli-server.service 2>&1; true")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Functional + overhead test of the new AmneziaWG-style junk masking on obfs (F2).
Brings up an obfs tunnel WITHOUT junk (baseline) and WITH junk (awg.jc>0) on the
lab, proves both connect + pass traffic, and reports the throughput cost of the
pre-handshake junk (which should be ~0 on steady-state, being handshake-only).

  SERVER 10.66.116.10   CLIENT 10.66.116.11   (run after the pristine reboot)
"""
import os, sys, io, re, time, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
SH, CH = "10.66.116.10", "10.66.116.11"
BIN = "/usr/local/bin/qeli"
SRC_BIN = "/opt/qeli-src/target/release/qeli"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
PSK = "awgbenchkey"


def conn(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    return c


def out(c, cmd, t=60):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def put(c, path, text):
    sf = c.open_sftp(); sf.putfo(io.BytesIO(text.encode()), path); sf.close()


def server_conf(awg_jc):
    awg = f"obf.awg.enabled = {'true' if awg_jc else 'false'}\nobf.awg.jc = {awg_jc}\nobf.awg.jmin = 40\nobf.awg.jmax = 300"
    return f"""[auth]
[logging]
level = info
file = /var/log/qeli/server.log
[profile:awgobfs]
identity_key = /etc/qeli/identity/awgobfs.key
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.9.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.exclude = 10.9.0.1
routing.forward_private = true
routing.nat.enabled = false
dns.enabled = false
obf.mode = obfs
obf.obfs_key = {PSK}
obf.obfs_fronting = websocket
{awg}
obf.padding.enabled = false
obf.heartbeat.enabled = true
perf.connection.max_clients = 16
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0
[user:bench]
password_hash = {HASH}
enabled = true
"""


def client_conf(key, awg_jc):
    awg = f"awg = {'true' if awg_jc else 'false'}\njc = {awg_jc}\njmin = 40\njmax = 300" if awg_jc else "awg = false"
    return f"""[qeli]
server = {SH}:443
proto = tcp
user = bench
pass = testpass123
mode = obfs
obfs_key = {PSK}
front = websocket
key = {key}
{awg}
[logging]
level = info
"""


def run_variant(s, cl, label, awg_jc):
    print(f"\n=== {label} (awg.jc={awg_jc}) ===")
    out(s, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; sleep 1; true")
    out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    put(s, "/etc/qeli/awg-server.conf", server_conf(awg_jc))
    key = re.search(r"[0-9a-f]{64}", out(s, f"{BIN} show-identity --config /etc/qeli/awg-server.conf 2>&1")).group(0)
    out(s, f"rm -f /var/log/qeli/server.log; nohup {BIN} server --config /etc/qeli/awg-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    put(cl, "/etc/qeli/awg-client.conf", client_conf(key, awg_jc))
    out(cl, f"rm -f /tmp/qc.log; nohup {BIN} client --config /etc/qeli/awg-client.conf >/tmp/qc.log 2>&1 & echo ok")
    ok = False
    for _ in range(12):
        time.sleep(1.5)
        if "Auth OK" in out(cl, "grep -F 'Auth OK' /tmp/qc.log || true"):
            ok = True; break
    if not ok:
        print("  FAIL: no Auth OK\n   CLI:", out(cl, "tail -n 6 /tmp/qc.log"),
              "\n   SRV:", out(s, "tail -n 6 /tmp/qs.log /var/log/qeli/server.log"))
        out(s, "pkill -9 -x qeli"); out(cl, "pkill -9 -x qeli")
        return {"ok": False}
    time.sleep(3)  # let the tunnel settle before measuring (avoid setup-churn artifacts)
    ping = out(cl, "ping -c 4 -i 0.3 -W 2 10.9.0.1 2>&1 | tail -2")
    pong = "0% packet loss" in ping or bool(re.search(r"[1-4] received", ping))
    out(s, "pkill -9 iperf3 2>/dev/null; nohup iperf3 -s -B 10.9.0.1 >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)
    def mbps(j):
        try: return round(json.loads(j)["end"]["sum_received"]["bits_per_second"] / 1e6, 1)
        except Exception: return None
    import statistics as _st
    # 3 download + 3 upload samples on the SAME stable tunnel → median (isolates
    # steady-state from per-tunnel setup variance; junk is one-time pre-handshake).
    dns, ups = [], []
    for _ in range(3):
        d = mbps(out(cl, "timeout 16 iperf3 -c 10.9.0.1 -t 8 -O 2 -R --json 2>/dev/null", t=25))
        if d: dns.append(d)
        time.sleep(0.5)
    for _ in range(3):
        u = mbps(out(cl, "timeout 16 iperf3 -c 10.9.0.1 -t 8 -O 2 --json 2>/dev/null", t=25))
        if u: ups.append(u)
        time.sleep(0.5)
    u = round(_st.median(ups), 1) if ups else None
    d = round(_st.median(dns), 1) if dns else None
    print(f"  Auth OK | ping {'OK' if pong else 'FAIL'} | up={u} down={d}  (down raw {dns})")
    out(s, "pkill -9 iperf3; pkill -9 -x qeli"); out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null")
    return {"ok": True, "up": u, "down": d, "ping": pong}


def main():
    s = conn(SH); cl = conn(CH)
    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; mkdir -p /etc/qeli/identity /var/log/qeli; true")
    out(s, f"install -m755 {SRC_BIN} {BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close()
    out(cl, f"chmod 755 {BIN}; mkdir -p /etc/qeli")
    print("binary:", out(s, f"{BIN} --version"), out(s, f"sha256sum {BIN} | cut -c1-16"))

    import statistics
    N = int(os.environ.get("AWG_RUNS", "5"))
    b_up, b_dn, a_up, a_dn = [], [], [], []
    conn_ok = True
    # interleave baseline/junk each round so any drift cancels
    for i in range(N):
        print(f"\n########## ROUND {i + 1}/{N} ##########")
        b = run_variant(s, cl, "obfs baseline (no junk)", 0)
        a = run_variant(s, cl, "obfs + AmneziaWG junk", 8)
        conn_ok = conn_ok and b.get("ok") and a.get("ok")
        if b.get("down"): b_up.append(b["up"]); b_dn.append(b["down"])
        if a.get("down"): a_up.append(a["up"]); a_dn.append(a["down"])

    out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    med = lambda xs: round(statistics.median(xs), 1) if xs else None
    sd = lambda xs: round(statistics.pstdev(xs), 1) if len(xs) > 1 else 0
    print("\n" + "=" * 60)
    print(f"AmneziaWG obfs masking (F2) — functional + overhead ({N}× medians)")
    print("=" * 60)
    print(f"  connect (all rounds): {'OK' if conn_ok else 'SOME FAILED'}")
    print(f"  obfs baseline : up {med(b_up)} (σ{sd(b_up)})  down {med(b_dn)} (σ{sd(b_dn)})  raw down={b_dn}")
    print(f"  obfs + junk×8 : up {med(a_up)} (σ{sd(a_up)})  down {med(a_dn)} (σ{sd(a_dn)})  raw down={a_dn}")
    if b_dn and a_dn:
        du = (med(a_up) - med(b_up)) / med(b_up) * 100
        dd = (med(a_dn) - med(b_dn)) / med(b_dn) * 100
        print(f"\n  junk overhead (median): up {du:+.1f}%  down {dd:+.1f}%")


if __name__ == "__main__":
    main()

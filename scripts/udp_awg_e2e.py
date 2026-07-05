#!/usr/bin/env python3
"""E2E: AWG junk preamble on UDP. Rust client (.11) -> Rust server (.10).
Verifies the UDP handshake completes WITH awg jc>0 (server drops the junk
datagrams cheaply before its rate limiter) across obfs + QUIC masking, plus a
baseline (jc=0) to confirm nothing broke.  SERVER .10  CLIENT .11
"""
import os, sys, io, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
SH, CH = "10.66.116.10", "10.66.116.11"
BIN = "/usr/local/bin/qeli"
SRC_BIN = "/opt/qeli-src/target/release/qeli"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
PSK = "awgudpkey"


def conn(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    return c


def out(c, cmd, t=90):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def put(c, path, text):
    sf = c.open_sftp(); sf.putfo(io.BytesIO(text.encode()), path); sf.close()


def server_conf(port, mode, quic, awg_jc):
    obf = [f"obf.mode = {mode}"]
    if mode == "obfs":
        obf.append(f"obf.obfs_key = {PSK}")
    obf.append(f"obf.quic.enabled = {'true' if quic else 'false'}")
    obf.append(f"obf.awg.enabled = {'true' if awg_jc else 'false'}")
    obf.append(f"obf.awg.jc = {awg_jc}\nobf.awg.jmin = 40\nobf.awg.jmax = 300")
    return f"""[auth]
[logging]
level = info
file = /var/log/qeli/server.log
[profile:awgudp]
identity_key = /etc/qeli/identity/awgudp.key
bind.address = 0.0.0.0
bind.port = {port}
bind.transport = udp
tun.name = vpn0
tun.address = 10.9.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.exclude = 10.9.0.1
routing.forward_private = true
routing.nat.enabled = false
dns.enabled = false
{chr(10).join(obf)}
obf.padding.enabled = false
obf.heartbeat.enabled = true
perf.connection.max_clients = 16
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 0
[user:bench]
password_hash = {HASH}
enabled = true
"""


def client_conf(key, port, mode, quic, awg_jc):
    lines = [f"server = {SH}:{port}", "proto = udp", "user = bench", "pass = testpass123",
             f"mode = {mode}"]
    if mode == "obfs":
        lines.append(f"obfs_key = {PSK}")
    if quic:
        lines.append("quic = 1")
    lines.append(f"key = {key}")
    if awg_jc:
        lines.append(f"awg = true\njc = {awg_jc}\njmin = 40\njmax = 300")
    return "[qeli]\n" + "\n".join(lines) + "\n[logging]\nlevel = info\n"


def variant(s, cl, label, port, mode, quic, awg_jc):
    print(f"\n=== {label} (udp {mode}{' +quic' if quic else ''}, awg.jc={awg_jc}) ===")
    out(s, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; sleep 1; true")
    out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    put(s, "/etc/qeli/awgudp-server.conf", server_conf(port, mode, quic, awg_jc))
    key = re.search(r"[0-9a-f]{64}", out(s, f"{BIN} show-identity --config /etc/qeli/awgudp-server.conf 2>&1")).group(0)
    out(s, f"rm -f /var/log/qeli/server.log; nohup {BIN} server --config /etc/qeli/awgudp-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    put(cl, "/etc/qeli/awgudp-client.conf", client_conf(key, port, mode, quic, awg_jc))
    out(cl, f"rm -f /tmp/qc.log; nohup {BIN} client --config /etc/qeli/awgudp-client.conf >/tmp/qc.log 2>&1 & echo ok")
    ok = False
    for _ in range(12):
        time.sleep(1.5)
        if "Auth OK" in out(cl, "grep -F 'Auth OK' /tmp/qc.log || true"):
            ok = True; break
    junk = out(cl, "grep -F 'AWG junk' /tmp/qc.log || true")
    if not ok:
        print("  FAIL: no Auth OK")
        print("   CLI:", out(cl, "tail -n 8 /tmp/qc.log"))
        print("   SRV:", out(s, "tail -n 8 /var/log/qeli/server.log"))
        out(s, "pkill -9 -x qeli"); out(cl, "pkill -9 -x qeli")
        return False
    time.sleep(2)
    ping = out(cl, "ping -c 4 -i 0.3 -W 2 10.9.0.1 2>&1 | tail -2")
    pong = "0% packet loss" in ping or bool(re.search(r"[1-4] received", ping))
    srv = out(s, "grep -F 'AUTH OK' /var/log/qeli/server.log | tail -1")
    print(f"  Auth OK ✓ | ping {'✓' if pong else 'FAIL'}")
    print(f"  client junk log: {junk or '(none)'}")
    print(f"  server auth:     {srv or '(none)'}")
    out(s, "pkill -9 -x qeli"); out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null")
    return pong


def main():
    s = conn(SH); cl = conn(CH)
    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; mkdir -p /etc/qeli/identity /var/log/qeli; true")
    print("building release on .10 ...")
    b = out(s, "cd /opt/qeli-src && cargo build --release 2>&1 | tail -2", t=400)
    print(" ", b)
    out(s, f"install -m755 {SRC_BIN} {BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close()
    out(cl, f"chmod 755 {BIN}; mkdir -p /etc/qeli")
    print("binary:", out(s, f"{BIN} --version"))

    r = {}
    r["udp-obfs-baseline"] = variant(s, cl, "baseline (no junk)", 4443, "obfs", False, 0)
    r["udp-obfs-awg8"]     = variant(s, cl, "obfs + AWG junk",    4443, "obfs", False, 8)
    r["udp-quic-awg8"]     = variant(s, cl, "fake-tls+QUIC + AWG junk", 4444, "fake-tls", True, 8)

    out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()
    print("\n===== SUMMARY =====")
    for k, v in r.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    print("VERDICT:", "PASS" if all(r.values()) else "FAIL")


if __name__ == "__main__":
    main()

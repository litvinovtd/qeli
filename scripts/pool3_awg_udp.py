#!/usr/bin/env python3
"""Verify AWG on UDP fake-tls / quic (the doc says 'TCP obfs AND every UDP mode').
Builds the client INI MANUALLY with awg=true (bypassing the share-link gate) so we
test the actual server+client UDP junk path. On UDP jc is sender-only, so both awg-on
and awg-off connect; we also grep the client log for the junk emission to prove junk
is actually sent."""
import os, sys, io, re, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool2_multiprofile as p2
from pool3_awg import add_awg

# name, port, tun, client-mode, extra(awg on/off)
TARGETS = [("udp-fake-tls", 8448, 6, "fake-tls"), ("udp-quic", 8449, 7, "fake-tls"), ("obfs-ws", 8445, 3, "obfs")]


def client_ini(name, port, tun, cm, key, awg):
    L = [f"[qeli]", f"server = {p2.SRV[0]}:{port}", f"proto = {'tcp' if name=='obfs-ws' else 'udp'}",
         "user = bench", f"pass = {p2.PASS}", f"mode = {cm}", f"key = {key}", "gateway = false", f"dev = u{tun}"]
    if name == "udp-quic": L.append("quic = true")
    if name == "obfs-ws": L.append("obfs_key = wskey1234567890")
    if awg: L += ["awg = true", "jc = 4", "jmin = 40", "jmax = 200"]
    return "\n".join(L + ["", "[logging]", "level = debug"]) + "\n"


def main():
    s = p2.conn(p2.SRV); cl = p2.conn(p2.CLI)
    p2.r(s, f"install -m755 {p2.SRC_BIN} {p2.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(p2.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, p2.BIN); cf.close(); p2.r(cl, f"chmod 755 {p2.BIN}; mkdir -p /etc/qeli")

    p2.r(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; for i in $(seq 0 9); do ip link del vpn$i 2>/dev/null; done; true")
    p2.r(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    conf = add_awg(p2.build_conf(), {"udp-fake-tls", "udp-quic"})  # force awg on UDP fake-tls/quic
    s.open_sftp().putfo(io.BytesIO(conf.encode()), p2.CONF)
    p2.r(s, f"rm -f /var/log/qeli/server.log; nohup {p2.BIN} server --config {p2.CONF} >/tmp/mp.log 2>&1 & echo ok")
    time.sleep(5)
    ident = p2.r(s, f"{p2.BIN} show-identity --config {p2.CONF} 2>&1")
    keys = {m.group(1): m.group(2) for m in re.finditer(r"(\S+)\s+\w+://\S+\s+([0-9a-f]{64})", ident)}

    for name, port, tun, cm in TARGETS:
        key = keys.get(name, "")
        print(f"\n[{name} :{port}]  (server awg forced on)" if name != "obfs-ws" else f"\n[{name} :{port}] control (obfs, awg in template)")
        for awg in (True, False):
            p2.r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del u{tun} 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
            cl.open_sftp().putfo(io.BytesIO(client_ini(name, port, tun, cm, key, awg).encode()), f"/tmp/u{tun}.conf")
            p2.r(cl, f"rm -f /tmp/u{tun}.log; nohup {p2.BIN} client --config /tmp/u{tun}.conf >/tmp/u{tun}.log 2>&1 & echo ok")
            ok = False
            for _ in range(8):
                time.sleep(1.5)
                if "Auth OK" in p2.r(cl, f"grep -F 'Auth OK' /tmp/u{tun}.log || true"): ok = True; break
            junk_log = p2.r(cl, f"grep -iE 'junk|awg|jc=' /tmp/u{tun}.log | head -2")
            print(f"   awg={str(awg):5} connect={ok}" + (f"  junk-log: {junk_log.splitlines()[0][:80]}" if junk_log else "  (no junk log line)"))
            p2.r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del u{tun} 2>/dev/null; true")

    print("\n=== server: junk datagrams dropped? ===")
    print(p2.r(s, "grep -iE 'junk' /var/log/qeli/server.log | tail -3") or "(no junk mention in server log)")
    p2.r(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()


if __name__ == "__main__":
    main()

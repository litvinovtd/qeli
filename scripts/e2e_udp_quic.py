#!/usr/bin/env python3
"""Live e2e for the udp-quic profile on the lab (.10 server, .11 client).

Reproduces "udp-quic doesn't work" by testing four combinations of the QUIC
masking flag on server vs client, plus a plain udp-faketls control. QUIC wraps
from the very first datagram (the ClientHello), so it MUST match on both sides;
a mismatch breaks the handshake silently. Prints Auth OK / ping / UDP throughput
and the tail of both logs per case.

Reuses benchmark.py's SSH + config-key helpers.
"""
import os, sys, io, json, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bm

PORT = 4455
NET = "10.10.0"
SIP = f"{NET}.1"


def server_conf(quic, padding):
    lines = [
        "[auth]", "require_client_key_proof = false", "",
        "[logging]", "level = info", "file = /var/log/qeli/server.log", "",
        "[profile:udpq]",
        "identity_key = /etc/qeli/identity/bench.key",
        "bind.address = 0.0.0.0", f"bind.port = {PORT}", "bind.transport = udp",
        "tun.name = vpn1", f"tun.address = {SIP}", "tun.netmask = 255.255.255.0",
        "tun.mtu = 1400", "tun.device_type = tun",
        f"pool.cidr = {NET}.0/24", f"pool.exclude = {SIP}",
        "routing.forward_private = true", "routing.nat.enabled = false", "dns.enabled = false",
        "obf.mode = fake-tls", "obf.tls.server_name = www.microsoft.com",
        f"obf.quic.enabled = {str(quic).lower()}",
        "obf.quic.cid_length = 4", "obf.quic.version = 1",
        f"obf.padding.enabled = {str(padding).lower()}",
        "obf.padding.min_bytes = 40", "obf.padding.max_bytes = 400", "obf.padding.randomize = true",
        "obf.heartbeat.enabled = true", "obf.heartbeat.interval_ms = 15000",
        "perf.tun.read_buffer_size = 65535", "perf.connection.handshake_timeout_secs = 10",
        "perf.connection.idle_timeout_secs = 0", "",
        "[user:bench]",
        f"password_hash = {bm.HASH}", "enabled = true",
    ]
    return "\n".join(lines) + "\n"


def client_conf(quic, server_key):
    lines = [
        "[qeli]",
        f"server = {bm.SERVER[0]}:{PORT}", "proto = udp",
        "user = bench", f"pass = {bm.PASS}", "mode = fake-tls",
        f"key = {server_key}",
        f"quic = {str(quic).lower()}",
        # distinct TUN name so we don't collide with a pre-existing vpn0 on .11
        "dev = vpnq",
        "", "[logging]", "level = info",
    ]
    return "\n".join(lines) + "\n"


def run_case(s, cl, srv_quic, cli_quic, padding, label):
    print(f"\n########## CASE: {label}  (server quic={srv_quic}, client quic={cli_quic}, padding={padding}) ##########")
    bm.out(s, "pkill -9 -x qeli; sleep 1; true")
    bm.out(cl, "pkill -9 -x qeli; ip link del vpnq 2>/dev/null; ip link del vpn1 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    bm.put(s, "/etc/qeli/bench-server.conf", server_conf(srv_quic, padding))
    key = bm.identity_pubkey(s)
    bm.put(cl, "/etc/qeli/bench-client.conf", client_conf(cli_quic, key))
    bm.out(s, f"rm -f /var/log/qeli/server.log; nohup {bm.BIN} server --config /etc/qeli/bench-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    bm.out(cl, f"rm -f /tmp/qc.log; nohup {bm.BIN} client --config /etc/qeli/bench-client.conf >/tmp/qc.log 2>&1 & echo ok")
    ok = False
    for _ in range(10):
        time.sleep(1.5)
        if "Auth OK" in bm.out(cl, "grep -E 'Auth OK' /tmp/qc.log || true"):
            ok = True; break
    res = {"case": label, "auth_ok": ok}
    if ok:
        ping = bm.out(cl, f"ping -c 10 -i 0.2 -q {SIP} 2>&1")
        loss = next((l for l in ping.splitlines() if "packet loss" in l), "")
        res["ping_loss"] = loss.split(",")[2].strip() if "," in loss else loss.strip()
        bm.out(s, f"pkill -9 iperf3; sleep 1; nohup iperf3 -s -B {SIP} >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)
        res["udp"] = bm.iperf_udp_sweep(cl, SIP, [100, 200])
        bm.out(s, "pkill -9 iperf3; true")
    res["cli_tun"] = bm.out(cl, "ip -br a show vpnq 2>/dev/null || echo NO-vpnq")
    res["cli_log"] = bm.out(cl, "grep -E 'QUIC|Auth|error|Error|fail|Fail|handshake|timeout|refused' /tmp/qc.log | tail -n 6 || true")
    res["srv_log"] = bm.out(s, "grep -E 'error|Error|fail|Fail|handshake|reject|drop|decrypt|new session|Auth' /var/log/qeli/server.log /tmp/qs.log 2>/dev/null | tail -n 6 || true")
    bm.out(cl, "pkill -9 -x qeli; ip link del vpnq 2>/dev/null; ip link del vpn1 2>/dev/null; true")
    bm.out(s, "pkill -9 -x qeli; true")
    print("  auth_ok:", ok, "| tun:", res.get("cli_tun", "-"), "| ping:", res.get("ping_loss", "-"), "| udp:", json.dumps(res.get("udp", {}), ensure_ascii=False))
    print("  cli_log:", res["cli_log"].replace("\n", " | "))
    print("  srv_log:", res["srv_log"].replace("\n", " | "))
    return res


def main():
    s = bm.conn(bm.SERVER); cl = bm.conn(bm.CLIENT)
    bm.out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true")
    bm.out(s, f"install -m755 {bm.SRC_BIN} {bm.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(bm.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, bm.BIN); cf.close()
    bm.out(cl, f"chmod 755 {bm.BIN}; mkdir -p /etc/qeli")
    bm.out(s, "mkdir -p /etc/qeli /etc/qeli/identity /var/log/qeli")
    print("binary:", bm.out(s, f"{bm.BIN} --version"))

    cases = [
        (True,  True,  False, "quic MATCHED (both on)"),
        (True,  True,  True,  "quic MATCHED + padding (template-like)"),
        (True,  False, False, "MISMATCH: server quic ON, client OFF"),
        (False, True,  False, "MISMATCH: server quic OFF, client ON"),
        (False, False, False, "control: plain udp-faketls (no quic)"),
    ]
    results = [run_case(s, cl, sq, cq, pad, lbl) for (sq, cq, pad, lbl) in cases]

    bm.out(cl, "ip link del vpn1 2>/dev/null; printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf")
    bm.out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()
    print("\n================ SUMMARY ================")
    for r in results:
        print(f"  {'PASS' if r['auth_ok'] else 'FAIL'}  {r['case']:42} ping={r.get('ping_loss','-')} udp={r.get('udp','-')}")


if __name__ == "__main__":
    main()

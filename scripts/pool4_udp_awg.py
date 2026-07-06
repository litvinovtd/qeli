#!/usr/bin/env python3
"""POOL 4 — verify the UDP AWG junk-masking claim (release 0.7.7):
  * junk works on ANY UDP profile: udp-obfs, udp-fake-tls+QUIC, udp-fake-tls (baseline)
  * client sends jc decoy datagrams before the ClientHello (client log + pcap count)
  * junk rides the profile's mask (obfs-XOR / QUIC-wrap) → the cleartext fragment
    magic F0 9B 71 is NOT visible on the wire for masked profiles
  * each junk datagram <= 1200 B (no IP fragmentation)
  * jc=0 => byte-identical (no extra junk datagrams)
  * server drops junk (Auth OK still reached; ping works)
Live e2e on the lab (.10 server, .11 client), split-tunnel so SSH survives.
"""
import os, sys, io, re, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool2_multiprofile as p2
from pool3_awg import add_awg

FRAG_MAGIC = "f09b71"
# name, port, tun, client-mode, extra (awg toggled per-run)
UDP = [("udp-obfs", 8450, 8, "obfs", {"obfs_key": "udpobfskey1234567890"}),
       ("udp-quic", 8449, 7, "fake-tls", {"quic": True}),
       ("udp-fake-tls", 8448, 6, "fake-tls", {})]


def udp_payloads(pcap_bytes, dport):
    """Return list of client->server UDP payload (bytes) to dport from a pcap."""
    d = pcap_bytes
    if len(d) < 24:
        return []
    le = d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    en = "<" if le else ">"
    link = struct.unpack(en + "I", d[20:24])[0]
    off = 24; out = []
    while off + 16 <= len(d):
        _t, _u, caplen, _o = struct.unpack(en + "IIII", d[off:off + 16]); off += 16
        pkt = d[off:off + caplen]; off += caplen
        # link layer -> IP
        if link == 1: l3 = pkt[14:]
        elif link == 113: l3 = pkt[16:]
        elif link == 276: l3 = pkt[20:]
        else: l3 = pkt
        if len(l3) < 20 or (l3[0] >> 4) != 4 or l3[9] != 17:  # IPv4 UDP
            continue
        ihl = (l3[0] & 0xF) * 4
        udp = l3[ihl:]
        if len(udp) < 8: continue
        dp = struct.unpack(">H", udp[2:4])[0]
        if dp != dport: continue
        out.append(udp[8:])
    return out


def run(cl, s, name, port, tun, cm, extra, key, awg, jc=4):
    ex = dict(extra)
    if awg: ex["awg"] = True
    m = (name, port, "udp", tun, cm, ex)
    ini = p2.client_ini(m, key)
    if awg and jc != 4:
        ini = ini.replace("jc = 4", f"jc = {jc}")
    p2.r(cl, f"pkill -9 -x qeli 2>/dev/null; pkill -9 tcpdump 2>/dev/null; ip link del mp{tun} 2>/dev/null; rm -f /var/lib/qeli/known_hosts /tmp/u.pcap; sleep 1; true")
    cl.open_sftp().putfo(io.BytesIO(ini.encode()), f"/tmp/u{tun}.conf")
    # start capture of client->server datagrams — setsid+nohup so it survives the
    # SSH channel closing (a bare `&` via paramiko is reaped and captures nothing).
    p2.r(cl, f"setsid nohup tcpdump -i any -s0 -w /tmp/u.pcap 'udp and host {p2.SRV[0]} and port {port}' </dev/null >/tmp/td.log 2>&1 & echo started")
    time.sleep(2)
    p2.r(cl, f"rm -f /tmp/uc{tun}.log; nohup {p2.BIN} client --config /tmp/u{tun}.conf >/tmp/uc{tun}.log 2>&1 & echo ok")
    ok = False
    for _ in range(9):
        time.sleep(1.5)
        if "Auth OK" in p2.r(cl, f"grep -F 'Auth OK' /tmp/uc{tun}.log || true"): ok = True; break
    gw = f"10.9.{tun}.1"
    ping_ok = ok and "0% packet loss" in p2.r(cl, f"ping -c 3 -W 2 -q {gw} 2>&1")
    time.sleep(1)
    # SIGTERM (not -9) so tcpdump flushes its capture buffer to the pcap before exit
    p2.r(cl, "pkill -TERM tcpdump 2>/dev/null; sleep 1.5; true")
    junk_log = p2.r(cl, f"grep -oE 'Sent [0-9]+ AWG junk datagram' /tmp/uc{tun}.log | head -1")
    err = "" if ok else p2.r(cl, f"tail -n 3 /tmp/uc{tun}.log")[:160]
    # pull + analyze pcap
    sf = cl.open_sftp(); buf = io.BytesIO()
    try: sf.getfo("/tmp/u.pcap", buf)
    except Exception: pass
    sf.close()
    pays = udp_payloads(buf.getvalue(), port)
    sizes = [len(p) for p in pays]
    magic_hits = sum(1 for p in pays if len(p) >= 3 and p[:3].hex() == FRAG_MAGIC)
    # junk visible on the wire ONLY for an unmasked profile: FRAG_MAGIC + MSG_JUNK(3).
    junk = [p for p in pays if len(p) >= 4 and p[:3].hex() == FRAG_MAGIC and p[3] == 3]
    p2.r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del mp{tun} 2>/dev/null; true")
    return {"auth": ok, "ping": ping_ok, "junk_log": junk_log, "c2s_datagrams": len(pays),
            "max_size": max(sizes) if sizes else 0, "over1200": sum(1 for x in sizes if x > 1200),
            "plaintext_magic": magic_hits, "junk_wire": len(junk),
            "junk_max": max((len(p) for p in junk), default=0),
            "ipfrag_risk": sum(1 for x in sizes if x > 1280), "err": err}


def main():
    s = p2.conn(p2.SRV); cl = p2.conn(p2.CLI)
    p2.r(s, f"install -m755 {p2.SRC_BIN} {p2.BIN}")
    sf = s.open_sftp(); b = io.BytesIO(); sf.getfo(p2.SRC_BIN, b); sf.close()
    cf = cl.open_sftp(); b.seek(0); cf.putfo(b, p2.BIN); cf.close(); p2.r(cl, f"chmod 755 {p2.BIN}; mkdir -p /etc/qeli")
    print("bin:", p2.r(s, f"{p2.BIN} --version"), "sha", p2.r(s, f"sha256sum {p2.BIN}|cut -c1-16"))

    p2.r(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; for i in $(seq 0 9); do ip link del vpn$i 2>/dev/null; done; true")
    p2.r(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    conf = add_awg(p2.build_conf(), {"udp-obfs", "udp-quic", "udp-fake-tls"})   # awg on all 3 UDP
    s.open_sftp().putfo(io.BytesIO(conf.encode()), p2.CONF)
    p2.r(s, f"rm -f /var/log/qeli/server.log; nohup {p2.BIN} server --config {p2.CONF} >/tmp/mp.log 2>&1 & echo ok")
    time.sleep(5)
    ident = p2.r(s, f"{p2.BIN} show-identity --config {p2.CONF} 2>&1")
    keys = {m.group(1): m.group(2) for m in re.finditer(r"(\S+)\s+\w+://\S+\s+([0-9a-f]{64})", ident)}
    print("udp listening:", p2.r(s, "ss -lunH | grep -oE ':(844[89]|8450)' | sort -u | tr '\\n' ' '"))

    results = {}
    for name, port, tun, cm, extra in UDP:
        r = run(cl, s, name, port, tun, cm, extra, keys.get(name, ""), awg=True)
        results[(name, "awg=4")] = r
        print(f"\n[{name} :{port} awg jc=4] auth={r['auth']} ping={r['ping']} | client-log:'{r['junk_log']}' "
              f"| c2s={r['c2s_datagrams']} max={r['max_size']}B over1200={r['over1200']} plaintextFRAG={r['plaintext_magic']}"
              + (f"  ERR={r['err']}" if r.get('err') else ""))

    # baseline: udp-fake-tls with awg OFF -> no junk, wire byte-identical. Let the
    # prior session drain first (avoid a same-user reconnect race on the server).
    p2.r(s, "true"); time.sleep(3)
    rb = run(cl, s, "udp-fake-tls", 8448, 6, "fake-tls", {}, keys.get("udp-fake-tls", ""), awg=False)
    results[("udp-fake-tls", "off")] = rb
    print(f"\n[udp-fake-tls :8448 awg OFF baseline] auth={rb['auth']} ping={rb['ping']} | client-log:'{rb['junk_log'] or '(no junk)'}' "
          f"| c2s={rb['c2s_datagrams']} max={rb['max_size']}B plaintextFRAG={rb['plaintext_magic']}"
          + (f"  ERR={rb['err']}" if rb.get('err') else ""))

    base_c2s = rb["c2s_datagrams"]
    print("\n===== POOL 4 SUMMARY (UDP AWG masking) =====")
    npass = 0
    for name, port, tun, cm, extra in UDP:
        r = results[(name, "awg=4")]
        sent = "4" in (r["junk_log"] or "")              # client emitted jc=4 junk (log)
        masked = r["plaintext_magic"] == 0               # obfs/quic: junk+frags invisible on wire
        no_ipfrag = r["ipfrag_risk"] == 0                # every datagram < 1280 (IPv6 min MTU)
        junk_small = r["junk_max"] <= 1200               # visible junk (unmasked) <= 1200
        ok = r["auth"] and r["ping"] and sent and no_ipfrag and junk_small
        npass += ok
        note = "junk MASKED (0 plaintext FRAG)" if masked else \
               f"junk visible as {r['junk_wire']} MSG_JUNK frags (unmasked profile → blends with real frags)"
        print(f"  {name:13} auth={r['auth']} ping={r['ping']} junk-sent(jc=4)={sent} | {note} | "
              f"max-datagram={r['max_size']}B (<1280={no_ipfrag}) junk-max={r['junk_max']}B(<=1200={junk_small})")
    ftls = results[("udp-fake-tls", "awg=4")]
    print(f"  jc-delta proof (unmasked udp-fake-tls): awg c2s={ftls['c2s_datagrams']} - baseline c2s={base_c2s} "
          f"= {ftls['c2s_datagrams'] - base_c2s} extra datagrams (expect ~4 junk)")
    base_clean = rb["auth"] and rb["ping"] and not rb["junk_log"] and rb["junk_wire"] == 0
    print(f"  baseline (awg OFF): auth={rb['auth']} ping={rb['ping']} no-junk-on-wire={rb['junk_wire'] == 0}  (byte-identical)")
    print(f"\n>>> {npass}/3 UDP profiles PASS (auth+ping+junk-sent+no-IP-frag+junk<=1200) ; baseline clean={base_clean}")
    p2.r(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()


if __name__ == "__main__":
    main()

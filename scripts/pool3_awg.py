#!/usr/bin/env python3
"""POOL 3.3 — can AWG (AmneziaWG junk) be used on ANY profile? Enable obf.awg on
NON-obfs profiles (fake-tls, reality-tls) plus an obfs one (obfs-none, control),
regenerate the qeli:// link (must carry awg/jc/jmin/jmax), then:
  A) connect a client built from the link (awg ON)   -> should auth
  B) connect the same client with awg STRIPPED (off)  -> mismatch probe
Interpretation: obfs control => A ok / B fails (junk really exchanged). For fake-tls
/reality-tls: A ok + B ok  => awg is IGNORED (no effect); A ok + B fails => awg works;
A fails => awg breaks the mode.
"""
import os, sys, io, re, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool2_multiprofile as p2
from pool3_links import parse_uri, link_to_ini, USERS_FILE

TARGETS = [("fake-tls", 8444, 2), ("reality-tls", 443, 0), ("obfs-ws", 8445, 3)]  # name, port, tun; obfs-ws already has awg (control)


def add_awg(conf, names, jc=4):
    parts = re.split(r"(?m)(?=^\[)", conf)
    out = []
    for b in parts:
        m = re.match(r"\[profile:([^\]]+)\]", b)
        if m and m.group(1) in names and "obf.awg.enabled = true" not in b:
            b = re.sub(r"(obf\.mode = .*\n)",
                       r"\1obf.awg.enabled = true\nobf.awg.jc = %d\nobf.awg.jmin = 40\nobf.awg.jmax = 200\n" % jc,
                       b, count=1)
        out.append(b)
    return "".join(out)


def connect(cl, ini, tag):
    p2.r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del {tag} 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    cl.open_sftp().putfo(io.BytesIO(ini.encode()), f"/tmp/{tag}.conf")
    p2.r(cl, f"rm -f /tmp/{tag}.log; nohup /usr/local/bin/qeli client --config /tmp/{tag}.conf >/tmp/{tag}.log 2>&1 & echo ok")
    ok = False
    for _ in range(8):
        time.sleep(1.5)
        if "Auth OK" in p2.r(cl, f"grep -F 'Auth OK' /tmp/{tag}.log || true"): ok = True; break
    err = "" if ok else p2.r(cl, f"tail -n 2 /tmp/{tag}.log")[:130]
    p2.r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del {tag} 2>/dev/null; true")
    return ok, err


def main():
    s = p2.conn(p2.SRV); cl = p2.conn(p2.CLI)
    p2.r(s, f"install -m755 {p2.SRC_BIN} {p2.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(p2.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, p2.BIN); cf.close(); p2.r(cl, f"chmod 755 {p2.BIN}; mkdir -p /etc/qeli")

    p2.r(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; for i in $(seq 0 9); do ip link del vpn$i 2>/dev/null; done; true")
    p2.r(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    conf = p2.build_conf().replace("[auth]\n", f"[auth]\nusers_file = {USERS_FILE}\n", 1)
    conf = add_awg(conf, {t[0] for t in TARGETS})   # force awg on fake-tls, reality-tls, obfs-none
    s.open_sftp().putfo(io.BytesIO(conf.encode()), p2.CONF)
    p2.r(s, f"rm -f {USERS_FILE}; touch {USERS_FILE}")
    print("awg forced on:", [t[0] for t in TARGETS])
    print("verify awg in each profile block:",
          p2.r(s, f"awk '/^\\[profile:(fake-tls|reality-tls|obfs-none)\\]/{{p=$0}} /obf.awg.enabled = true/{{print p, \"awg=on\"}}' {p2.CONF}"))

    # generate links
    links = {}
    for i, (name, port, tun) in enumerate(TARGETS):
        out = p2.r(s, f"{p2.BIN} add-client aw{i} --password aw{i}pass --link --link-profile {name} "
                      f"--host {p2.SRV[0]}:{port} --config {p2.CONF} 2>&1")
        links[name] = next((ln.strip() for ln in out.splitlines() if ln.strip().startswith("qeli://")), "")

    p2.r(s, f"rm -f /var/log/qeli/server.log; nohup {p2.BIN} server --config {p2.CONF} >/tmp/mp.log 2>&1 & echo ok")
    time.sleep(5)

    print("\n=== AWG on any profile: link carries awg? + connect A(awg)/B(no-awg) ===")
    for name, port, tun in TARGETS:
        uri = links[name]
        p = parse_uri(uri)
        has_awg = p and p.get("awg") == "1" and p.get("jc") == "4"
        print(f"\n[{name} :{port}]  link awg={p.get('awg') if p else '?'} jc={p.get('jc') if p else '?'}  -> link-carries-awg={has_awg}")
        # A: client with awg (from link as-is)
        okA, errA = connect(cl, link_to_ini(p, f"aw{tun}"), f"awA{tun}")
        # B: client with awg stripped
        pB = dict(p); pB.pop("awg", None); pB.pop("jc", None)
        okB, errB = connect(cl, link_to_ini(pB, f"aw{tun}"), f"awB{tun}")
        verdict = ("AWG REAL (junk exchanged)" if okA and not okB else
                   "AWG IGNORED on this mode" if okA and okB else
                   "AWG BREAKS this mode" if not okA else "?")
        print(f"   A(awg on)={okA}  B(awg off)={okB}  => {verdict}")
        if errA: print("   A err:", errA)

    p2.r(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()


if __name__ == "__main__":
    main()

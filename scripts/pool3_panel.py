#!/usr/bin/env python3
"""POOL 3.2 — verify the WEB PANEL builds the same complete qeli:// share link as
the CLI, for every profile. Enables the panel on .10 (loopback, Basic-auth for the
API), generates a CLI link per profile via add-client, then POSTs /api/share and
compares the panel link's mode-critical params to the CLI link. Spot-connects the
`reality` panel link (the one the rsid fix touched)."""
import os, sys, io, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool2_multiprofile as p2
from pool3_links import parse_uri, link_to_ini, USERS_FILE

WEB = """[web]
enabled = true
bind = 127.0.0.1
port = 8080
username = admin
password_hash = {hash}
public_host = 10.66.116.10
"""
# params that must match between CLI and panel links (creds may differ on reset)
CMP = ["proto", "mode", "key", "sni", "rsid", "obfs", "front", "quic", "awg", "jc", "jmin", "jmax"]


def main():
    s = p2.conn(p2.SRV); cl = p2.conn(p2.CLI)
    p2.r(s, f"install -m755 {p2.SRC_BIN} {p2.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(p2.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, p2.BIN); cf.close(); p2.r(cl, f"chmod 755 {p2.BIN}; mkdir -p /etc/qeli")

    # config: 10 profiles + users_file + ENABLED web panel (replace the [web] block)
    p2.r(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; for i in $(seq 0 9); do ip link del vpn$i 2>/dev/null; done; true")
    p2.r(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    conf = p2.build_conf().replace("[auth]\n", f"[auth]\nusers_file = {USERS_FILE}\n", 1)
    conf = re.sub(r"\[web\].*?(?=\n\[)", WEB.format(hash=p2.HASH).strip() + "\n", conf, count=1, flags=re.S)
    s.open_sftp().putfo(io.BytesIO(conf.encode()), p2.CONF)
    p2.r(s, f"rm -f {USERS_FILE}; touch {USERS_FILE}")

    # CLI links (also creates lt<i> users)
    cli = {}
    for i, (name, port, *_ ) in enumerate(p2.MODES):
        out = p2.r(s, f"{p2.BIN} add-client lt{i} --password lp{i}pass --link --link-profile {name} "
                      f"--host {p2.SRV[0]}:{port} --config {p2.CONF} 2>&1")
        cli[name] = next((ln.strip() for ln in out.splitlines() if ln.strip().startswith("qeli://")), "")

    p2.r(s, f"rm -f /var/log/qeli/server.log; nohup {p2.BIN} server --config {p2.CONF} >/tmp/mp.log 2>&1 & echo ok")
    time.sleep(5)
    web_up = p2.r(s, "ss -ltnH | grep -c ':8080'")
    print("panel :8080 listening:", web_up, "| boot errs:", p2.r(s, "grep -iE 'web|panel|error' /var/log/qeli/server.log | grep -iE 'listen|error|panel' | tail -3") or "(none)")

    # auth probe (Basic auth for the API)
    probe = p2.r(s, "curl -sS -o /dev/null -w '%{http_code}' -u admin:testpass123 http://127.0.0.1:8080/api/status")
    print("Basic-auth /api/status:", probe)

    print("\n=== per-profile: panel link vs CLI link ===")
    results = {}
    for i, (name, port, proto, tun, cm, extra) in enumerate(p2.MODES):
        body = json.dumps({"profile": name, "host": p2.SRV[0], "user": f"lt{i}", "allow_reset": "true"})
        raw = p2.r(s, f"curl -sS -u admin:testpass123 -X POST http://127.0.0.1:8080/api/share "
                      f"-H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' -d '{body}'")
        try:
            j = json.loads(raw); puri = j.get("uri", "")
        except Exception:
            puri = ""; j = {"raw": raw[:120]}
        pp = parse_uri(puri) if puri else None
        cc = parse_uri(cli[name]) if cli.get(name) else None
        match = bool(pp and cc) and all((pp.get(k) or "") == (cc.get(k) or "") for k in CMP)
        results[name] = {"panel_uri": puri, "match": match, "ok": bool(j.get("ok", puri))}
        diffs = [] if not (pp and cc) else [f"{k}:{cc.get(k)}!={pp.get(k)}" for k in CMP if (pp.get(k) or "") != (cc.get(k) or "")]
        print(f"[{name:13}] panel={'ok' if puri else 'FAIL '+str(j)[:80]}  match-CLI={match}" + (f"  DIFF={diffs}" if diffs else ""))

    # spot-connect the reality panel link (the rsid-fix path) from link params only
    print("\n=== spot-connect: reality profile FROM PANEL LINK ===")
    rp = parse_uri(results["reality"]["panel_uri"]) if results["reality"]["panel_uri"] else None
    auth = False
    if rp:
        p2.r(cl, "pkill -9 -x qeli 2>/dev/null; ip link del ltp1 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
        cl.open_sftp().putfo(io.BytesIO(link_to_ini(rp, "ltp1").encode()), "/tmp/ltp1.conf")
        p2.r(cl, "rm -f /tmp/ltpc1.log; nohup /usr/local/bin/qeli client --config /tmp/ltp1.conf >/tmp/ltpc1.log 2>&1 & echo ok")
        for _ in range(9):
            time.sleep(1.5)
            if "Auth OK" in p2.r(cl, "grep -F 'Auth OK' /tmp/ltpc1.log || true"): auth = True; break
        if not auth: print("   err:", p2.r(cl, "tail -n 2 /tmp/ltpc1.log")[:150])
        p2.r(cl, "pkill -9 -x qeli 2>/dev/null; ip link del ltp1 2>/dev/null; true")
    print("reality connect-from-panel-link:", auth)

    print("\n===== POOL 3.2 SUMMARY =====")
    nm = sum(1 for n in results if results[n]["match"])
    for name, *_ in p2.MODES:
        print(f"  {name:14} panel-link={'ok' if results[name]['panel_uri'] else 'FAIL':>4}  matches-CLI={results[name]['match']}")
    print(f"\n>>> {nm}/10 panel links match the CLI link; reality connects from panel link = {auth}")
    p2.r(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()


if __name__ == "__main__":
    main()

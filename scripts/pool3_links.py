#!/usr/bin/env python3
"""POOL 3 — qeli:// SHARE LINK validation for all 10 profiles (release 0.7.7).

For each profile:
  1. generate the link via the CLI: `qeli add-client <u> --link --link-profile <p>`
  2. decode the qeli:// URI and check it carries EVERY param the mode needs
  3. build a client config from the LINK PARAMS ONLY (mirror ClientConfig::from_link)
     and connect — proving the link is self-sufficient (auth OK).

Reuses pool2's multiprofile deploy. Expected finding: the `reality` profile
(fake-tls + reality_proxy, real_tls=false) omits `rsid` in the link (add_client /
share.rs only set reality_sid when real_tls=true) → client can't seal the short_id.
"""
import os, sys, io, re, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool2_multiprofile as p2

USERS_FILE = "/etc/qeli/mp-users.conf"
# per profile: which link query params are REQUIRED for the mode to work
REQUIRED = {
    "reality-tls": {"mode": "reality-tls", "need": ["key", "sni", "rsid"]},
    "reality":     {"mode": "fake-tls",    "need": ["key", "sni", "rsid"]},   # rsid expected
    "fake-tls":    {"mode": "fake-tls",    "need": ["key", "sni"]},
    "obfs-ws":     {"mode": "obfs",        "need": ["key", "obfs", "awg", "jc"]},
    "obfs-none":   {"mode": "obfs",        "need": ["key", "obfs", "front"]},
    "plain":       {"mode": "plain",       "need": ["key"]},
    "udp-fake-tls":{"mode": "fake-tls",    "need": ["key", "sni"], "proto": "udp"},
    "udp-quic":    {"mode": "fake-tls",    "need": ["key", "quic"], "proto": "udp"},
    "udp-obfs":    {"mode": "obfs",        "need": ["key", "obfs"], "proto": "udp"},
    "obfs-awg":    {"mode": "obfs",        "need": ["key", "obfs", "front", "awg", "jc"]},
}


def parse_uri(uri):
    m = re.match(r"qeli://(?:([^@]*)@)?([^?#]+)(?:\?([^#]*))?(?:#(.*))?$", uri.strip())
    if not m:
        return None
    userinfo, hostport, query, frag = m.groups()
    user, pw = (userinfo.split(":", 1) + [""])[:2] if userinfo else ("", "")
    host, port = hostport.rsplit(":", 1)
    p = {"_user": user, "_pass": pw, "_host": host, "_port": port, "_label": frag or ""}
    for pair in (query or "").split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        p[k] = v
    return p


def link_to_ini(p, dev):
    """Mirror ClientConfig::from_link — build the [qeli] INI from ONLY link params."""
    L = [f"[qeli]", f"server = {p['_host']}:{p['_port']}", f"proto = {p.get('proto','tcp')}",
         f"user = {p['_user']}", f"pass = {p['_pass']}", f"mode = {p.get('mode','fake-tls')}",
         "gateway = false", f"dev = {dev}"]
    if p.get("key"):  L.append(f"key = {p['key']}")
    if p.get("sni"):  L.append(f"sni = {p['sni']}")
    if p.get("rsid"): L.append(f"reality_sid = {p['rsid']}")
    if p.get("obfs"): L.append(f"obfs_key = {p['obfs']}")
    if p.get("front"): L.append(f"front = {p['front']}")
    if p.get("quic") in ("1", "true"): L.append("quic = true")
    if p.get("awg") in ("1", "true"):
        L += ["awg = true", f"jc = {p.get('jc','0')}", f"jmin = {p.get('jmin','40')}", f"jmax = {p.get('jmax','300')}"]
    return "\n".join(L + ["", "[logging]", "level = info"]) + "\n"


def main():
    s = p2.conn(p2.SRV); cl = p2.conn(p2.CLI)
    print("bin:", p2.r(s, f"install -m755 {p2.SRC_BIN} {p2.BIN}; {p2.BIN} --version"))
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(p2.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, p2.BIN); cf.close(); p2.r(cl, f"chmod 755 {p2.BIN}; mkdir -p /etc/qeli")

    # deploy config (10 profiles) with a users_file so add-client can append users
    p2.r(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; for i in $(seq 0 9); do ip link del vpn$i 2>/dev/null; done; true")
    p2.r(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    conf = p2.build_conf().replace("[auth]\n", f"[auth]\nusers_file = {USERS_FILE}\n", 1)
    if "users_file" not in conf:  # no [auth] header in template → prepend one
        conf = f"[auth]\nusers_file = {USERS_FILE}\n\n" + conf
    s.open_sftp().putfo(io.BytesIO(conf.encode()), p2.CONF)
    p2.r(s, f"rm -f {USERS_FILE}; touch {USERS_FILE}")

    # 1) generate a link per profile via the CLI (creates lt<i> in the users_file)
    print("\n=== generating CLI qeli:// links ===")
    links = {}
    for i, (name, port, proto, tun, cm, extra) in enumerate(p2.MODES):
        out = p2.r(s, f"{p2.BIN} add-client lt{i} --password lp{i}pass --link "
                      f"--link-profile {name} --host {p2.SRV[0]}:{port} --config {p2.CONF} 2>&1")
        uri = next((ln.strip() for ln in out.splitlines() if ln.strip().startswith("qeli://")), "")
        links[name] = uri
        print(f"[{name:13}] {uri or '!! no link: ' + out[-120:]}")

    # start the server so lt0..9 are active
    p2.r(s, f"rm -f /var/log/qeli/server.log; nohup {p2.BIN} server --config {p2.CONF} >/tmp/mp.log 2>&1 & echo ok")
    time.sleep(5)
    print("\nlisten TCP:", p2.r(s, "ss -ltnH | grep -oE ':(443|844[0-9]|8451)' | sort -u | tr '\\n' ' '"),
          "| UDP:", p2.r(s, "ss -lunH | grep -oE ':(844[89]|8450)' | sort -u | tr '\\n' ' '"))

    # 2+3) completeness check + connect FROM THE LINK ONLY
    results = {}
    for i, (name, port, proto, tun, cm, extra) in enumerate(p2.MODES):
        uri = links.get(name, "")
        req = REQUIRED[name]
        p = parse_uri(uri) if uri else None
        miss = []
        if not p:
            results[name] = {"complete": False, "missing": ["<no link>"], "auth": False}; continue
        # mode correct?
        if p.get("mode") != req["mode"]: miss.append(f"mode={p.get('mode')}!={req['mode']}")
        if req.get("proto") and p.get("proto") != req["proto"]: miss.append(f"proto={p.get('proto')}")
        for k in req["need"]:
            if k == "front":
                if p.get("front") != "none": miss.append("front=none")
            elif not p.get(k):
                miss.append(k)
        complete = not miss
        # connect from link
        p2.r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del lt{tun} 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
        cl.open_sftp().putfo(io.BytesIO(link_to_ini(p, f"lt{tun}").encode()), f"/tmp/lt{tun}.conf")
        p2.r(cl, f"rm -f /tmp/ltc{tun}.log; nohup {p2.BIN} client --config /tmp/lt{tun}.conf >/tmp/ltc{tun}.log 2>&1 & echo ok")
        auth = False
        for _ in range(9):
            time.sleep(1.5)
            if "Auth OK" in p2.r(cl, f"grep -F 'Auth OK' /tmp/ltc{tun}.log || true"): auth = True; break
        err = "" if auth else p2.r(cl, f"tail -n 2 /tmp/ltc{tun}.log")[:150]
        p2.r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del lt{tun} 2>/dev/null; true")
        results[name] = {"complete": complete, "missing": miss, "auth": auth, "err": err}
        mark = "OK  " if (complete and auth) else "FAIL"
        print(f"[{name:13} {proto}:{port}] {mark} link-complete={complete} connect-from-link={auth}"
              + (f"  MISSING={miss}" if miss else "") + (f"  err={err}" if err else ""))

    print("\n===== POOL 3.1 SUMMARY (CLI links) =====")
    npass = sum(1 for n in results if results[n]["complete"] and results[n]["auth"])
    for name, _, _, _, _, _ in p2.MODES:
        rr = results[name]
        print(f"  {name:14} complete={str(rr['complete']):>5} connect={str(rr['auth']):>5} "
              + (f"missing={rr['missing']}" if rr["missing"] else ""))
    print(f"\n>>> {npass}/10 profiles: link complete AND connects from link alone")
    p2.r(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()


if __name__ == "__main__":
    main()

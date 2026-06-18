#!/usr/bin/env python3
"""Functional test of the SHIPPED default configs (qeli/config/*.conf) on 0.7.1.

- Parse-validates every server/users config via `show-identity` and every client
  config via a short `client` launch (did it get past parsing?).
- Brings up two real tunnels end-to-end on the lab and proves traffic flows:
    server.conf        (fake-tls, full default stack: NAT/DNS/padding/frag/HB, H-1)
    server-maxobf.conf (reality-tls: real_tls + hand-rolled, require_proof, H-1)
  Client side uses the real lab pin (key from show-identity) — i.e. the placeholder
  client.conf / client-maxobf.conf with their `key`/`server` filled in for the lab.

  SERVER 10.66.116.10   CLIENT 10.66.116.11
"""
import os, sys, io, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ.get("QELI_LAB_PASS", "")
SH, CH = "10.66.116.10", "10.66.116.11"
BIN = "/usr/local/bin/qeli"
SRC_BIN = "/opt/qeli-src/target/release/qeli"
CFG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "qeli", "config")
USER, PASS = "client1", "testpass123"
results = []


def conn(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    return c


def out(c, cmd, t=120):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def put_local(c, local, remote):
    sf = c.open_sftp(); sf.put(local, remote); sf.close()


def put_text(c, remote, text):
    sf = c.open_sftp(); sf.putfo(io.BytesIO(text.encode()), remote); sf.close()


def pubkey_of(s, remote_conf, profile=None):
    o = out(s, f"{BIN} show-identity --config {remote_conf} 2>&1")
    for line in o.splitlines():
        m = re.search(r"([0-9a-f]{64})", line)
        if m and (profile is None or profile in line):
            return m.group(1)
    m = re.search(r"([0-9a-f]{64})", o)
    return m.group(1) if m else None


def client_ini(server, mode, key, extra):
    L = ["[qeli]", f"server = {server}", "proto = tcp", f"user = {USER}", f"pass = {PASS}",
         f"mode = {mode}", f"key = {key}"]
    L += extra
    L += ["", "[logging]", "level = info"]
    return "\n".join(L) + "\n"


def parse_validate(s, cl):
    print("\n=== PARSE-VALIDATION of shipped config files ===")
    # server + users configs via show-identity (loads & validates the full config)
    for f in ("server.conf", "server-maxobf.conf"):
        put_local(s, os.path.join(CFG, f), f"/tmp/pv-{f}")
        o = out(s, f"{BIN} show-identity --config /tmp/pv-{f} 2>&1")
        ok = bool(re.search(r"[0-9a-f]{64}", o)) and "error" not in o.lower() and "panic" not in o.lower()
        print(f"  [{'OK ' if ok else 'FAIL'}] {f}")
        if not ok:
            print("        ", o.splitlines()[-1][:160] if o else "(no output)")
        results.append((f"parse {f}", ok))
    # client configs: launch briefly, did it get past config parsing?
    for f in ("client.conf", "client-maxobf.conf", "client-reality-tls.conf", "client-YOUR_DEPLOY_HOST.conf"):
        put_local(cl, os.path.join(CFG, f), f"/tmp/pv-{f}")
        o = out(cl, f"timeout 3 {BIN} client --config /tmp/pv-{f} 2>&1 | head -25 || true", t=20)
        low = o.lower()
        parsed = ("connecting to" in low or "wire mode" in low or "resolving" in low)
        cfg_err = any(w in low for w in ("invalid", "failed to parse", "expected", "missing field",
                                         "odd number of digits", "invalid hex", "parse error"))
        ok = parsed and not cfg_err
        note = "parsed→connect" if ok else ("config/parse error" if cfg_err else "no parse marker")
        print(f"  [{'OK ' if ok else 'FAIL'}] {f}  ({note})")
        if not ok:
            print("        ", next((l for l in o.splitlines() if l.strip()), "")[:160])
        results.append((f"parse {f}", ok))


def e2e(s, cl, name, conf_file, port, tun_gw, mode, client_extra, profile=None, extra_files=None):
    print(f"\n=== E2E: {name} ({conf_file}) ===")
    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; sleep 1; true")
    out(cl, "pkill -9 -x qeli 2>/dev/null; ip link del vpn0 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    out(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    put_local(s, os.path.join(CFG, conf_file), f"/etc/qeli/{conf_file}")
    for ef in (extra_files or []):
        put_local(s, os.path.join(CFG, ef), f"/etc/qeli/{ef}")
    key = pubkey_of(s, f"/etc/qeli/{conf_file}", profile)
    if not key:
        print("  FAIL: no server identity key from show-identity"); results.append((name, False)); return
    print(f"  server key: {key[:16]}…")
    out(s, f"rm -f /var/log/qeli/server.log; nohup {BIN} server --config /etc/qeli/{conf_file} >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    listening = out(s, f"ss -ltn | grep -q ':{port} ' && echo yes || echo no")
    if listening != "yes":
        print("  FAIL: server not listening on", port, "—", out(s, "tail -n 6 /tmp/qs.log /var/log/qeli/server.log"))
        results.append((name, False)); out(s, "pkill -9 -x qeli"); return
    ini = client_ini(f"{SH}:{port}", mode, key, client_extra)
    put_text(cl, "/etc/qeli/ft-client.conf", ini)
    out(cl, f"rm -f /tmp/qc.log; nohup {BIN} client --config /etc/qeli/ft-client.conf >/tmp/qc.log 2>&1 & echo ok")
    ok = False
    for _ in range(12):
        time.sleep(1.5)
        if "Auth OK" in out(cl, "grep -F 'Auth OK' /tmp/qc.log || true"):
            ok = True; break
    if not ok:
        print("  FAIL: no Auth OK\n  CLI:", out(cl, "tail -n 5 /tmp/qc.log"),
              "\n  SRV:", out(s, "tail -n 6 /tmp/qs.log /var/log/qeli/server.log"))
        results.append((name, False)); out(s, "pkill -9 -x qeli"); out(cl, "pkill -9 -x qeli"); return
    # traffic proof: ping the tun gateway + tiny iperf3 through the tunnel
    time.sleep(1)
    ping = out(cl, f"ping -c 4 -i 0.3 -W 2 {tun_gw} 2>&1 | tail -2")
    pong = "0% packet loss" in ping or re.search(r"[1-4] received", ping)
    out(s, f"pkill -9 iperf3 2>/dev/null; nohup iperf3 -s -B {tun_gw} >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)
    thr = out(cl, f"timeout 12 iperf3 -c {tun_gw} -t 4 -O 1 --json 2>/dev/null", t=20)
    mbps = None
    try:
        import json as _j; mbps = round(_j.loads(thr)["end"]["sum_received"]["bits_per_second"] / 1e6, 1)
    except Exception:
        pass
    cip = out(cl, "ip -4 -o addr show vpn0 2>/dev/null | awk '{print $4}'")
    good = bool(pong) and (mbps or 0) > 50
    print(f"  Auth OK | client tun IP {cip} | ping gw {'OK' if pong else 'FAIL'} | iperf {mbps} Mbps -> {'PASS' if good else 'PARTIAL'}")
    results.append((name, good))
    out(s, "pkill -9 iperf3 2>/dev/null; pkill -9 -x qeli 2>/dev/null")
    out(cl, "pkill -9 -x qeli 2>/dev/null; ip link del vpn0 2>/dev/null; true")


def main():
    s = conn(SH); cl = conn(CH)
    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; true")
    out(s, f"install -m755 {SRC_BIN} {BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close()
    out(cl, f"chmod 755 {BIN}; mkdir -p /etc/qeli")
    print("binary:", out(s, f"{BIN} --version"), out(s, f"sha256sum {BIN} | cut -c1-16"))

    parse_validate(s, cl)

    # E2e 1: server.conf — fake-tls, full default stack (H-1 default on → client pins key)
    e2e(s, cl, "server.conf fake-tls", "server.conf", 443, "10.0.0.1", "fake-tls",
        ["sni = www.cloudflare.com"], profile="tcp", extra_files=["users.conf"])

    # E2e 2: server-maxobf.conf — reality-tls (real_tls + hand-rolled), require_proof, H-1
    e2e(s, cl, "server-maxobf.conf reality-tls", "server-maxobf.conf", 443, "10.9.0.1", "reality-tls",
        ["reality_sid = 7e78a17ad41f1004", "sni = www.microsoft.com"], profile="maxobf")

    # restore
    out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    out(cl, "printf 'nameserver 1.1.1.1\\n' > /etc/resolv.conf 2>/dev/null; true")
    s.close(); cl.close()

    print("\n" + "=" * 56)
    print("CONFIG FUNCTIONALITY SUMMARY (0.7.1)")
    print("=" * 56)
    for n, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {n}")
    npass = sum(1 for _, ok in results if ok)
    print(f"\n  {npass}/{len(results)} checks passed")


if __name__ == "__main__":
    main()

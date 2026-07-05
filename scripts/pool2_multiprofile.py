#!/usr/bin/env python3
"""POOL 2 — deploy the full 10-mode multiprofile template to the LAB server (.10)
and functionally validate EVERY mode from a lab client (.11): auth + tunnel + ping
the gateway + resolve a domain THROUGH the tunnel DNS (not just ping). Confirms all
modes work and the config is complete (nothing missing).

Server: qeli/config/server-multiprofile.conf with CHANGEME obfs keys filled, a test
user appended, and per-profile identity_key added. Split-tunnel clients (gateway=off)
so .11's SSH survives; DNS tested by querying the profile's tun DNS IP directly.
"""
import os, sys, io, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

SRV = ("10.66.116.10", "root", os.environ["QELI_LAB_PASS"])
CLI = ("10.66.116.11", "root", os.environ["QELI_LAB_PASS"])
BIN = "/usr/local/bin/qeli"
SRC_BIN = "/opt/qeli-src/target/release/qeli"
TMPL = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli\config\server-multiprofile.conf"
CONF = "/etc/qeli/mp-test.conf"
# testpass123 argon2id (same as benchmark.py)
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
PASS = "testpass123"
OBFS_KEYS = {"CHANGEME-obfs-ws-psk": "wskey1234567890", "CHANGEME-obfs-none-psk": "nonekey1234567890",
             "CHANGEME-udp-obfs-psk": "udpobfskey1234567890", "CHANGEME-obfs-awg-psk": "awgkey1234567890"}
DOMAIN = "github.com"
# name, port, proto, tun-index, client-mode, extra client keys
MODES = [
    ("reality-tls", 443, "tcp", 0, "reality-tls", {"sni": "www.microsoft.com", "reality_sid": "0123456789abcdef"}),
    ("reality", 8443, "tcp", 1, "fake-tls", {"sni": "www.microsoft.com", "reality_sid": "fedcba9876543210"}),
    ("fake-tls", 8444, "tcp", 2, "fake-tls", {}),
    ("obfs-ws", 8445, "tcp", 3, "obfs", {"obfs_key": "wskey1234567890", "front": "websocket", "awg": True}),
    ("obfs-none", 8446, "tcp", 4, "obfs", {"obfs_key": "nonekey1234567890", "front": "none"}),
    ("plain", 8447, "tcp", 5, "plain", {}),
    ("udp-fake-tls", 8448, "udp", 6, "fake-tls", {}),
    ("udp-quic", 8449, "udp", 7, "fake-tls", {"quic": True}),
    ("udp-obfs", 8450, "udp", 8, "obfs", {"obfs_key": "udpobfskey1234567890"}),
    ("obfs-awg", 8451, "tcp", 9, "obfs", {"obfs_key": "awgkey1234567890", "front": "none", "awg": True}),
]


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


def r(c, cmd, t=60):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def build_conf():
    txt = open(TMPL, encoding="utf-8").read().replace("\r\n", "\n")
    for k, v in OBFS_KEYS.items():
        txt = txt.replace(k, v)
    # add identity_key right after each [profile:NAME] header
    def add_ident(m):
        name = m.group(1)
        return f"[profile:{name}]\nidentity_key = /etc/qeli/identity/{name}.key"
    txt = re.sub(r"\[profile:([^\]]+)\]", add_ident, txt)
    # append a test user
    txt += f"\n[user:bench]\npassword_hash = {HASH}\nenabled = true\n"
    return txt


def client_ini(m, key):
    name, port, proto, tun, cm, extra = m
    lines = [f"[qeli]", f"server = {SRV[0]}:{port}", f"proto = {proto}", "user = bench",
             f"pass = {PASS}", f"mode = {cm}", f"key = {key}", "gateway = false", f"dev = mp{tun}"]
    if extra.get("sni"): lines.append(f"sni = {extra['sni']}")
    if extra.get("reality_sid"): lines.append(f"reality_sid = {extra['reality_sid']}")
    if extra.get("obfs_key"): lines.append(f"obfs_key = {extra['obfs_key']}")
    if extra.get("front"): lines.append(f"front = {extra['front']}")
    if extra.get("quic"): lines.append("quic = true")
    if extra.get("awg"): lines += ["awg = true", "jc = 4", "jmin = 40", "jmax = 200"]
    lines += ["", "[logging]", "level = info"]
    return "\n".join(lines) + "\n"


def main():
    s = conn(SRV); cl = conn(CLI)
    print("server bin:", r(s, f"install -m755 {SRC_BIN} {BIN}; {BIN} --version"), "sha", r(s, f"sha256sum {BIN}|cut -c1-16"))
    # install same binary on client
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close(); r(cl, f"chmod 755 {BIN}; mkdir -p /etc/qeli")

    # deploy config + start server (all 10 profiles)
    r(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; for i in $(seq 0 9); do ip link del vpn$i 2>/dev/null; done; true")
    r(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    s.open_sftp().putfo(io.BytesIO(build_conf().encode()), CONF)
    print("\nconfig deployed. profiles:", r(s, f"grep -c '^\\[profile:' {CONF}"))
    r(s, f"rm -f /var/log/qeli/server.log; nohup {BIN} server --config {CONF} >/tmp/mp.log 2>&1 & echo ok")
    time.sleep(5)
    listening = r(s, "ss -ltnH | grep -oE ':(443|844[0-9]|8451)' | sort -u | tr '\\n' ' '")
    udp_listen = r(s, "ss -lunH | grep -oE ':(844[89]|8450)' | sort -u | tr '\\n' ' '")
    print("TCP listening:", listening, "| UDP listening:", udp_listen)
    boot_err = r(s, "grep -iE 'error|failed|panic' /tmp/mp.log /var/log/qeli/server.log 2>/dev/null | head -5")
    if boot_err: print("server boot warnings:", boot_err)

    # per-profile identity pubkeys
    ident = r(s, f"{BIN} show-identity --config {CONF} 2>&1")
    keys = {}
    for line in ident.splitlines():
        mm = re.match(r"(\S+)\s+\w+://\S+\s+([0-9a-f]{64})", line.strip())
        if mm: keys[mm.group(1)] = mm.group(2)
    print("identities parsed:", len(keys), "of 10")

    # test each mode
    results = {}
    for m in MODES:
        name, port, proto, tun, cm, extra = m
        key = keys.get(name, "")
        if not key:
            results[name] = {"auth": False, "err": "no identity pubkey"}; print(f"\n[{name}] SKIP — no pubkey"); continue
        r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del mp{tun} 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
        cl.open_sftp().putfo(io.BytesIO(client_ini(m, key).encode()), f"/tmp/mp{tun}.conf")
        r(cl, f"rm -f /tmp/mpc{tun}.log; nohup {BIN} client --config /tmp/mp{tun}.conf >/tmp/mpc{tun}.log 2>&1 & echo ok")
        ok = False
        for _ in range(10):
            time.sleep(1.5)
            if "Auth OK" in r(cl, f"grep -F 'Auth OK' /tmp/mpc{tun}.log || true"): ok = True; break
        gw = f"10.9.{tun}.1"
        res = {"auth": ok}
        if ok:
            ping = r(cl, f"ping -c 3 -W 2 -q {gw} 2>&1")
            res["ping_ok"] = "0% packet loss" in ping or " 0% packet loss" in ping
            res["ping"] = next((l for l in ping.splitlines() if "packet loss" in l), "").strip()[:40]
            dns = r(cl, f"nslookup -timeout=4 {DOMAIN} {gw} 2>&1 || true", t=15)
            res["dns_ok"] = ("Address:" in dns and DOMAIN.split('.')[0] in dns.lower()) or "answer:" in dns.lower() or bool(re.search(r"Address:\s*\d+\.\d+\.\d+\.\d+", dns.split("Server:")[-1] if "Server:" in dns else dns))
            res["dns"] = " ".join(dns.split())[:90]
        else:
            res["err"] = r(cl, f"tail -n 3 /tmp/mpc{tun}.log")[:160]
            res["srv"] = r(s, "tail -n 3 /var/log/qeli/server.log")[:160]
        results[name] = res
        mark = "OK " if (res.get("auth") and res.get("ping_ok") and res.get("dns_ok")) else "FAIL"
        print(f"\n[{name:12} {proto}:{port}] {mark} auth={res.get('auth')} ping={res.get('ping_ok')} dns={res.get('dns_ok')}")
        if mark == "FAIL": print("   ", res.get("err") or res.get("dns") or res.get("ping"))
        r(cl, f"pkill -9 -x qeli 2>/dev/null; ip link del mp{tun} 2>/dev/null; true")

    # summary
    print("\n\n===== POOL 2 SUMMARY (10 modes) =====")
    print(f"{'mode':14}{'auth':>6}{'ping':>6}{'DNS':>6}")
    npass = 0
    for name, _, _, _, _, _ in MODES:
        rr = results.get(name, {})
        allok = rr.get("auth") and rr.get("ping_ok") and rr.get("dns_ok")
        npass += 1 if allok else 0
        print(f"{name:14}{str(rr.get('auth')):>6}{str(rr.get('ping_ok')):>6}{str(rr.get('dns_ok')):>6}")
    print(f"\n>>> {npass}/10 modes fully OK (auth+ping+DNS)")
    r(s, "pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()


if __name__ == "__main__":
    main()

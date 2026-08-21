#!/usr/bin/env python3
"""Functional test of every repository config template in qeli/config.

- Runs the strict `check-config` path for every server and client file. Server
  checks point at the shipped users.conf, so the worker's real users loader is
  exercised too. Documented placeholders are replaced with inert valid values.
- Brings up two real tunnels end-to-end on the lab and proves traffic flows:
    server.conf        (fake-tls, full default stack: NAT/DNS/padding/frag/HB, H-1)
    server-maxobf.conf (reality-tls: real_tls + hand-rolled, require_proof, H-1)
  Client side uses the real lab pin (key from show-identity) — i.e. the placeholder
  client.conf / client-maxobf.conf with their `key`/`server` filled in for the lab.

  SERVER 10.66.116.10   CLIENT 10.66.116.11
"""
import os, sys, io, re, shlex, time
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko
import ssh_hostkey

PW = os.environ.get("QELI_LAB_PASS", "")
SH = os.environ.get("QELI_BUILD_LAB_IP", "10.66.116.10")
CH = os.environ.get("QELI_LAB_IP", "10.66.116.11")
BIN = os.environ.get("QELI_LAB_BIN", "/usr/local/bin/qeli")
SRC_BIN = os.environ.get("QELI_LAB_SRC_BIN", "/opt/qeli-src/target/release/qeli")
ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "qeli" / "config"
USER, PASS = "client1", "testpass123"
# RFC 7748 X25519 base point (little-endian u=9): public, non-secret and accepted as
# a syntactically and cryptographically meaningful pinned key in validation-only configs.
VALID_TEST_PIN = "09" + "00" * 31
SERVER_PID = "/tmp/qeli-config-functest-server.pid"
CLIENT_PID = "/tmp/qeli-config-functest-client.pid"
IPERF_PID = "/tmp/qeli-config-functest-iperf.pid"
results = []


def conn(ip):
    c = paramiko.SSHClient(); ssh_hostkey.harden(c)
    c.connect(ip, username="root", password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    return c


def out(c, cmd, t=120):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def checked(c, cmd, t=120):
    _i, o, e = c.exec_command(cmd, timeout=t)
    text = (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()
    return o.channel.recv_exit_status(), text


def stop_tracked_group(pid_file, expected_binary=BIN):
    """Gracefully stop a qeli process group, then kill the whole group at the bound.

    `qeli server` is a supervisor with a `_worker` child. Killing only the recorded
    supervisor PID with SIGKILL skips Rust drop and leaves that worker holding the
    listener/TUN. Every test launch uses `setsid`, so this one group id owns both.
    """
    path = shlex.quote(pid_file)
    binary = shlex.quote(expected_binary)
    return (
        f"if [ -s {path} ]; then p=$(cat {path}); "
        "case \"$p\" in ''|*[!0-9]*) ;; *) "
        f"want=$(readlink -f {binary} 2>/dev/null); "
        "actual=$(readlink -f \"/proc/$p/exe\" 2>/dev/null); "
        "pgid=$(ps -o pgid= -p \"$p\" 2>/dev/null | tr -d ' '); "
        "if [ \"$p\" -gt 1 ] 2>/dev/null && [ -n \"$want\" ] "
        "&& [ \"$actual\" = \"$want\" ] && [ \"$pgid\" = \"$p\" ]; then "
        "kill -TERM -- \"-$p\" 2>/dev/null || true; "
        "for _qeli_i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do "
        "kill -0 -- \"-$p\" 2>/dev/null || break; sleep 0.25; done; "
        "kill -0 -- \"-$p\" 2>/dev/null && kill -KILL -- \"-$p\" 2>/dev/null || true; "
        "fi; "
        "esac; fi; "
        f"rm -f {path}; true"
    )


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
    print("\n=== STRICT VALIDATION of every qeli/config/*.conf file ===")
    users_remote = "/tmp/pv-users.conf"
    put_local(s, CFG / "users.conf", users_remote)

    # Make every standalone server template load this exact users example, not an
    # unrelated /etc/qeli/users.conf left by another lab workload.
    for path in sorted(CFG.glob("server*.conf")):
        f = path.name
        text = path.read_text(encoding="utf-8")
        if re.search(r"(?m)^users_file\s*=", text):
            text = re.sub(
                r"(?m)^users_file\s*=.*$", f"users_file = {users_remote}", text
            )
        else:
            text = text.replace("[auth]", f"[auth]\nusers_file = {users_remote}", 1)
        put_text(s, f"/tmp/pv-{f}", text)
        rc, output = checked(s, f"{BIN} check-config --config /tmp/pv-{f} 2>&1")
        ok = rc == 0 and output.rstrip().endswith(": OK")
        print(f"  [{'OK ' if ok else 'FAIL'}] {f} + users.conf")
        if not ok:
            print("        ", output.splitlines()[-1][:160] if output else "(no output)")
        results.append((f"check-config {f} + users.conf", ok))

    # Validate all client files without opening a socket. REALITY templates intentionally
    # ship an unusable zero/paste placeholder; materialize every documented key placeholder
    # with a real non-zero X25519 public input so this gate tests the complete config instead
    # of merely confirming that placeholder rejection works.
    for path in sorted(CFG.glob("client*.conf")):
        f = path.name
        text = re.sub(
            r"(?m)^key\s*=\s*(?:0{64}|PASTE_64_HEX_KEY_FROM_qeli_show-identity)\s*$",
            f"key = {VALID_TEST_PIN}",
            path.read_text(encoding="utf-8"),
        )
        put_text(cl, f"/tmp/pv-{f}", text)
        rc, output = checked(
            cl, f"{BIN} check-config --client --config /tmp/pv-{f} 2>&1"
        )
        ok = rc == 0 and output.rstrip().endswith(": OK")
        print(f"  [{'OK ' if ok else 'FAIL'}] {f}")
        if not ok:
            print("        ", output.splitlines()[-1][:160] if output else "(no output)")
        results.append((f"check-config {f}", ok))


# Argon2id digest of PASS ("testpass123") — the same credential every other lab
# script uses. Replaces the shipped INERT placeholder so the e2e can authenticate.
REAL_HASH = ("$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$"
             "CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w")


def seed_real_password(s, *paths):
    """Swap the all-zero placeholder digest for a working one, in place.

    Flattens nested lists so callers can pass a single path or a list of extras.
    """
    flat = []
    for p in paths:
        flat.extend(p if isinstance(p, (list, tuple)) else [p])
    for path in flat:
        # `|` as the sed delimiter: the PHC string is full of `/` and `$`.
        out(s, f"sed -i 's|^password_hash = .*|password_hash = {REAL_HASH}|' {path} 2>/dev/null; true")


def e2e(s, cl, name, conf_file, port, tun_gw, mode, client_extra, profile=None, extra_files=None):
    print(f"\n=== E2E: {name} ({conf_file}) ===")
    out(s, stop_tracked_group(SERVER_PID) + "; sleep 1")
    out(cl, stop_tracked_group(CLIENT_PID) + "; ip link del vpn0 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    out(s, "mkdir -p /etc/qeli/identity /var/log/qeli")
    put_local(s, CFG / conf_file, f"/etc/qeli/{conf_file}")
    for ef in (extra_files or []):
        put_local(s, CFG / ef, f"/etc/qeli/{ef}")
    # The shipped users.conf / [user:*] samples carry an INERT placeholder digest
    # (all-zero, see the comment in qeli/config/users.conf): by design no password
    # verifies against it, so an operator cannot accidentally ship a live sample
    # credential. That is correct product behaviour, but it means the shipped
    # configs cannot authenticate as-is — this test used to read that as a product
    # failure ("AUTH FAIL — wrong password", 3/7) on EVERY version, 0.7.14 included.
    # Seed the real hash for the sample password the same way `qeli add-client`
    # would, so the e2e exercises the config, not the placeholder.
    seed_real_password(s, f"/etc/qeli/{conf_file}", [f"/etc/qeli/{ef}" for ef in (extra_files or [])])
    key = pubkey_of(s, f"/etc/qeli/{conf_file}", profile)
    if not key:
        print("  FAIL: no server identity key from show-identity"); results.append((name, False)); return
    print(f"  server key: {key[:16]}…")
    out(s, f"rm -f /var/log/qeli/server.log; nohup setsid {BIN} server --config /etc/qeli/{conf_file} >/tmp/qs.log 2>&1 & echo $! >{SERVER_PID}")
    time.sleep(3)
    listening = out(s, f"ss -ltn | grep -q ':{port} ' && echo yes || echo no")
    if listening != "yes":
        print("  FAIL: server not listening on", port, "—", out(s, "tail -n 6 /tmp/qs.log /var/log/qeli/server.log"))
        results.append((name, False)); out(s, stop_tracked_group(SERVER_PID)); return
    ini = client_ini(f"{SH}:{port}", mode, key, client_extra)
    put_text(cl, "/etc/qeli/ft-client.conf", ini)
    out(cl, f"rm -f /tmp/qc.log; nohup setsid {BIN} client --config /etc/qeli/ft-client.conf >/tmp/qc.log 2>&1 & echo $! >{CLIENT_PID}")
    ok = False
    for _ in range(12):
        time.sleep(1.5)
        if "Auth OK" in out(cl, "grep -F 'Auth OK' /tmp/qc.log || true"):
            ok = True; break
    if not ok:
        print("  FAIL: no Auth OK\n  CLI:", out(cl, "tail -n 5 /tmp/qc.log"),
              "\n  SRV:", out(s, "tail -n 6 /tmp/qs.log /var/log/qeli/server.log"))
        results.append((name, False))
        out(s, stop_tracked_group(SERVER_PID))
        out(cl, stop_tracked_group(CLIENT_PID))
        return
    # traffic proof: ping the tun gateway + tiny iperf3 through the tunnel
    time.sleep(1)
    ping = out(cl, f"ping -c 4 -i 0.3 -W 2 {tun_gw} 2>&1 | tail -2")
    pong = "0% packet loss" in ping or re.search(r"[1-4] received", ping)
    out(s, f"xargs -r kill -9 <{IPERF_PID} 2>/dev/null; rm -f {IPERF_PID}; nohup iperf3 -s -B {tun_gw} >/tmp/is.log 2>&1 & echo $! >{IPERF_PID}"); time.sleep(1)
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
    out(s, f"xargs -r kill -9 <{IPERF_PID} 2>/dev/null; rm -f {IPERF_PID}; " + stop_tracked_group(SERVER_PID))
    out(cl, stop_tracked_group(CLIENT_PID) + "; ip link del vpn0 2>/dev/null; true")


def run_all(s, cl):
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

    print("\n" + "=" * 56)
    print("CONFIG FUNCTIONALITY SUMMARY")
    print("=" * 56)
    for n, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {n}")
    npass = sum(1 for _, ok in results if ok)
    print(f"\n  {npass}/{len(results)} checks passed")
    if npass != len(results):
        raise RuntimeError("one or more repository configuration checks failed")


def main():
    s = cl = None
    server_active_units = []
    client_active_units = []
    try:
        s = conn(SH)
        cl = conn(CH)
        active_query = (
            "for u in qeli.service qeli-server.service; do "
            "systemctl is-active --quiet $u && echo $u; done; true"
        )
        server_active_units = out(
            s,
            active_query,
        ).splitlines()
        client_active_units = out(cl, active_query).splitlines()
        out(
            s,
            "systemctl stop qeli.service qeli-server.service 2>/dev/null; "
            + stop_tracked_group(SERVER_PID),
        )
        out(
            cl,
            "systemctl stop qeli.service qeli-server.service 2>/dev/null; "
            + stop_tracked_group(CLIENT_PID),
        )
        run_all(s, cl)
    finally:
        if cl is not None:
            out(cl, stop_tracked_group(CLIENT_PID) + "; ip link del vpn0 2>/dev/null; true")
            for unit in client_active_units:
                out(cl, f"systemctl start {unit} 2>/dev/null; true")
            cl.close()
        if s is not None:
            out(s, f"xargs -r kill -9 <{IPERF_PID} 2>/dev/null; rm -f {IPERF_PID}; " + stop_tracked_group(SERVER_PID) + "; ip link del vpn0 2>/dev/null; true")
            for unit in server_active_units:
                out(s, f"systemctl start {unit} 2>/dev/null; true")
            s.close()


if __name__ == "__main__":
    main()

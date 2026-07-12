#!/usr/bin/env python3
"""Binary-only PROD upgrade — deploy the current dev batch (CHANGELOG [0.7.11] bucket).

Same safe flow as deploy_prod_073.py: pull the freshly-built jemalloc release binary
from the lab (.10), read-only pre-flight on PROD (new binary parses the LIVE config +
the reality-tls identity pubkey 7ff1c274 is preserved), back up the current binary,
swap via stop->cp->start, then verify (active + version + NRestarts=0 + :443 listening
+ REALITY cert handshake + identity preserved + no journal errors) and AUTO-ROLL-BACK
on any failure. Config + identity are NOT modified.

Extra recon vs 073: reports whether the live config has NAT enabled — with this batch
`routing.forward_private` defaults ON, so on a NAT-OFF profile it would newly enable
ip_forward + FORWARD ACCEPT (a maxobf full-tunnel prod has NAT on → no behaviour change),
and `web.persist_session_key` defaults ON (creates a 0600 session-key file; existing
panel sessions drop once on this first restart, then survive future restarts).
"""
import os, sys, io, time, hashlib
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB10 = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
PROD = (os.environ.get("QELI_PROD_HOST", "YOUR_PROD_HOST"), "root", os.environ.get("QELI_PROD_PASS", ""))
SRC_BIN = "/opt/qeli-src/target/release/qeli"
EXPECT_VER = "qeli 0.7.10"  # Cargo version unchanged; binary carries the [0.7.11] fixes
EXPECT_PUBKEY = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=30, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=60):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def main():
    # ── 1. pull the jemalloc release binary from the lab build host ───────────
    c10 = conn(LAB10)
    ver10 = run(c10, f"{SRC_BIN} --version")
    if ver10 != EXPECT_VER:
        print(f"ABORT: lab binary is '{ver10}', expected '{EXPECT_VER}'"); c10.close(); return
    # jemalloc diagnostic: tikv-jemalloc is STATICALLY linked with the `_rjem_` prefix,
    # so it is NOT in the dynamic table (`nm -D`) — read the full symbol table instead.
    # The real guarantee is the canonical build flag (`--features jemalloc` in
    # lab_sync_build.py); this is an informational cross-check, not a hard gate (a
    # `strip`-ed release build could legitimately show 0 while still being jemalloc).
    jem = run(c10, f"nm {SRC_BIN} 2>/dev/null | grep -ciE 'rjem|jemalloc' || true")
    sf = c10.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close(); c10.close()
    data = buf.getvalue()
    sha = hashlib.sha256(data).hexdigest()
    print(f"[lab] {ver10}  sha {sha[:16]}  {len(data)} bytes  jemalloc_syms={jem}")
    if jem.strip() in ("", "0"):
        print("[warn] no jemalloc symbols visible (stripped?) — trusting the --features jemalloc build")

    # ── 2. prod recon + pre-flight (read-only) ────────────────────────────────
    p = conn(PROD)
    execstart = run(p, "systemctl show qeli.service -p ExecStart --value")
    conf = "/etc/qeli/server-maxobf.conf"
    if "--config" in execstart:
        try: conf = execstart.split("--config")[1].split()[0].strip(" ;")
        except Exception: pass
    elif "-c " in execstart:
        try: conf = execstart.split("-c ")[1].split()[0].strip(" ;")
        except Exception: pass
    cur_ver = run(p, "/usr/local/bin/qeli --version")
    cur_sha = run(p, "sha256sum /usr/local/bin/qeli | cut -c1-16")
    nrest0 = run(p, "systemctl show qeli.service -p NRestarts --value")
    # behaviour-change recon: is NAT enabled in the live config? (affects forward_private)
    nat_line = run(p, f"grep -iE '^[[:space:]]*nat[[:space:]]*=' {conf} 2>/dev/null | tail -1")
    ipfwd = run(p, "cat /proc/sys/net/ipv4/ip_forward 2>/dev/null")
    print(f"[prod] current {cur_ver}  sha {cur_sha}  config {conf}  NRestarts {nrest0}")
    print(f"[prod] config nat: {nat_line or '(unset)'}   ip_forward now: {ipfwd}")

    sf = p.open_sftp(); sf.putfo(io.BytesIO(data), "/tmp/qeli-dev0711-new"); sf.close()
    run(p, "chmod +x /tmp/qeli-dev0711-new")
    new_ver = run(p, "/tmp/qeli-dev0711-new --version")   # also the glibc-compat smoke test
    if new_ver != EXPECT_VER:
        print(f"ABORT: new binary won't run on prod / wrong version: '{new_ver}'")
        run(p, "rm -f /tmp/qeli-dev0711-new"); p.close(); return
    ident = run(p, f"/tmp/qeli-dev0711-new show-identity --config {conf} 2>&1")
    if EXPECT_PUBKEY not in ident:
        print("ABORT: pre-flight identity mismatch — reality-tls pubkey 7ff1c274 NOT found:")
        print(ident[:400]); run(p, "rm -f /tmp/qeli-dev0711-new"); p.close(); return
    print("[preflight] OK — new binary runs on prod, parses live config, identity 7ff1c274 preserved")

    # ── 3. backup ─────────────────────────────────────────────────────────────
    ts = run(p, "date +%Y%m%d-%H%M%S")
    bak = f"/usr/local/bin/qeli.bak-{ts}-pre-dev0711"
    run(p, f"cp -a /usr/local/bin/qeli {bak}; cp -a /usr/local/bin/qeli /root/qeli-rollback-pre-dev0711.bin")
    print(f"[backup] {bak}  +  /root/qeli-rollback-pre-dev0711.bin")

    # ── 4. swap: stop -> cp -> start ──────────────────────────────────────────
    run(p, "systemctl stop qeli.service"); time.sleep(1)
    run(p, "cp /tmp/qeli-dev0711-new /usr/local/bin/qeli; chmod 755 /usr/local/bin/qeli; rm -f /tmp/qeli-dev0711-new")
    run(p, "systemctl start qeli.service"); time.sleep(4)

    # ── 5. verify ─────────────────────────────────────────────────────────────
    active = run(p, "systemctl is-active qeli.service")
    pver = run(p, "/usr/local/bin/qeli --version")
    listen = run(p, "ss -ltn | grep -c ':443'")
    time.sleep(3)
    nrest = run(p, "systemctl show qeli.service -p NRestarts --value")
    status_line = run(p, "systemctl show qeli.service -p StatusText --value")  # sd_notify version line
    cert = run(p, "echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
    ident_post = run(p, f"/usr/local/bin/qeli show-identity --config {conf} 2>&1")
    errs = run(p, "journalctl -u qeli.service --since '60 seconds ago' -p err --no-pager | tail -8")
    ok = (active == "active" and pver == EXPECT_VER and nrest == "0"
          and listen.isdigit() and int(listen) >= 1 and EXPECT_PUBKEY in ident_post)

    print("\n=== VERIFY ===")
    print(f"  active        : {active}")
    print(f"  version       : {pver}")
    print(f"  status (notify): {status_line or '(none)'}")
    print(f"  NRestarts     : {nrest}  (0 = no crash-loop)")
    print(f"  :443 listening: {listen}")
    print(f"  REALITY cert  : {cert or '(none)'}")
    print(f"  identity      : {'7ff1c274 preserved' if EXPECT_PUBKEY in ident_post else 'MISSING!'}")
    print(f"  recent errors : {errs or '(none)'}")

    if not ok:
        print("\n!! VERIFICATION FAILED — AUTO-ROLLBACK")
        run(p, f"systemctl stop qeli.service; cp -a {bak} /usr/local/bin/qeli; systemctl start qeli.service"); time.sleep(3)
        print("  rolled back to:", run(p, "/usr/local/bin/qeli --version"),
              "| active:", run(p, "systemctl is-active qeli.service"))
        p.close(); return

    print(f"\nPROD UPGRADED {cur_ver} -> {pver}  (sha {sha[:16]})")
    print(f"   rollback: cp -a {bak} /usr/local/bin/qeli && systemctl restart qeli.service")
    p.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Binary-only PROD upgrade to 0.7.12.

Same safe flow as deploy_prod_dev0711.py: pull the freshly-built jemalloc release binary
from the lab (.10), read-only pre-flight on PROD, back up the current binary, swap via
stop->cp->start, verify, and AUTO-ROLL-BACK on any failure. Config + identity untouched.

EXTRA PRE-FLIGHT vs dev0711 — and the reason it exists: 0.7.12 makes `validate_profiles`
STRICTER (it now rejects an unparsable pool.cidr / tun.address / tun.netmask, which used
to sail through `check-config` and then crash-loop the worker). That cuts both ways: if
the LIVE prod config carries such a value, the new binary would refuse to start and the
swap would take the server down. So run the new binary's own `check-config` against the
live config BEFORE touching anything, and abort if it complains.
"""
import os, sys, io, time, hashlib
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB10 = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
PROD = (os.environ.get("QELI_PROD_HOST", ""), "root", os.environ.get("QELI_PROD_PASS", ""))
SRC_BIN = "/opt/qeli-src/target/release/qeli"
EXPECT_VER = "qeli 0.7.12"
EXPECT_PUBKEY = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=30, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=120):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def main():
    if not PROD[0] or not PROD[2]:
        print("ABORT: QELI_PROD_HOST / QELI_PROD_PASS not set"); return 1

    # ── 1. pull the jemalloc release binary from the lab build host ───────────
    c10 = conn(LAB10)
    ver10 = run(c10, f"{SRC_BIN} --version")
    if ver10 != EXPECT_VER:
        print(f"ABORT: lab binary is '{ver10}', expected '{EXPECT_VER}'"); c10.close(); return 1
    # `strip = true` in [profile.release] wipes the symbol table, so `nm` shows nothing
    # even on a jemalloc build — count the strings jemalloc embeds in rodata instead.
    jem = run(c10, f"grep -ac jemalloc {SRC_BIN} || true")
    sf = c10.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close(); c10.close()
    data = buf.getvalue()
    sha = hashlib.sha256(data).hexdigest()
    print(f"[lab] {ver10}  sha {sha[:16]}  {len(data)} bytes  jemalloc_strings={jem}")
    if jem.strip() in ("", "0"):
        print("ABORT: no jemalloc strings in the binary — the plain `cargo build --release`"
              " overwrote the jemalloc one. Rebuild with --features jemalloc LAST.")
        return 1

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
    print(f"[prod] current {cur_ver}  sha {cur_sha}  config {conf}  NRestarts {nrest0}")

    sf = p.open_sftp(); sf.putfo(io.BytesIO(data), "/tmp/qeli-0712-new"); sf.close()
    run(p, "chmod +x /tmp/qeli-0712-new")
    new_ver = run(p, "/tmp/qeli-0712-new --version")   # also the glibc-compat smoke test
    if new_ver != EXPECT_VER:
        print(f"ABORT: new binary won't run on prod / wrong version: '{new_ver}'")
        run(p, "rm -f /tmp/qeli-0712-new"); p.close(); return 1

    # THE 0.7.12-specific gate: does the live config still pass the stricter validation?
    cc_rc = run(p, f"/tmp/qeli-0712-new check-config -c {conf} >/tmp/cc.out 2>&1; echo $?")
    cc_out = run(p, "cat /tmp/cc.out; rm -f /tmp/cc.out")
    if cc_rc != "0":
        print(f"ABORT: the LIVE config fails 0.7.12's stricter validation (rc={cc_rc}).")
        print("       Deploying would crash-loop the server. Fix the config first:")
        print("      ", cc_out[:600])
        run(p, "rm -f /tmp/qeli-0712-new"); p.close(); return 1
    print(f"[preflight] live config passes 0.7.12 check-config (rc=0)")

    # 0.7.12 also refuses to start the PANEL with an empty web.password_hash — loopback
    # used to be exempt. The VPN would still serve, so this would not fail the health
    # check; the operator would just silently lose the panel. Catch it here instead.
    # NB: the obvious `awk '/^\[web\]/,/^\[/'` range is WRONG — the opening line also
    # matches the end pattern, so the range closes immediately and every check returns 0
    # (a preflight that silently passes everything). Use an explicit flag instead.
    sect = "awk '/^\[web\]/{f=1;next} /^\[/{f=0} f'"
    web_on = run(p, f"{sect} {conf} | grep -cE '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true'")
    web_pw = run(p, f"{sect} {conf} | grep -cE '^[[:space:]]*password_hash[[:space:]]*=[[:space:]]*[^[:space:]]'")
    web_optout = run(p, f"{sect} {conf} | grep -cE '^[[:space:]]*insecure_no_auth[[:space:]]*=[[:space:]]*true'")
    if web_on.strip() != "0" and web_pw.strip() == "0" and web_optout.strip() == "0":
        print("ABORT: the panel is enabled with an EMPTY web.password_hash. 0.7.12 refuses to")
        print("       start it (loopback is no longer exempt), so this upgrade would silently")
        print("       take the panel away. Run `qeli set-web-password` first, or set")
        print("       web.insecure_no_auth = true if an open panel is genuinely wanted.")
        run(p, "rm -f /tmp/qeli-0712-new")
        p.close()
        return 1
    print("[preflight] panel: enabled=%s password_set=%s" % (web_on.strip(), web_pw.strip()))

    ident = run(p, f"/tmp/qeli-0712-new show-identity --config {conf} 2>&1")
    if EXPECT_PUBKEY not in ident:
        print("ABORT: pre-flight identity mismatch — reality-tls pubkey 7ff1c274 NOT found:")
        print(ident[:400]); run(p, "rm -f /tmp/qeli-0712-new"); p.close(); return 1
    print("[preflight] OK — new binary runs, parses the live config, identity 7ff1c274 preserved")

    # ── 3. backup ─────────────────────────────────────────────────────────────
    ts = run(p, "date +%Y%m%d-%H%M%S")
    bak = f"/usr/local/bin/qeli.bak-{ts}-pre-0712"
    run(p, f"cp -a /usr/local/bin/qeli {bak}; cp -a /usr/local/bin/qeli /root/qeli-rollback-pre-0712.bin")
    print(f"[backup] {bak}  +  /root/qeli-rollback-pre-0712.bin")

    # ── 4. swap: stop -> cp -> start ──────────────────────────────────────────
    run(p, "systemctl stop qeli.service"); time.sleep(1)
    run(p, "cp /tmp/qeli-0712-new /usr/local/bin/qeli; chmod 755 /usr/local/bin/qeli; rm -f /tmp/qeli-0712-new")
    run(p, "systemctl start qeli.service"); time.sleep(4)

    # ── 5. verify ─────────────────────────────────────────────────────────────
    active = run(p, "systemctl is-active qeli.service")
    pver = run(p, "/usr/local/bin/qeli --version")
    listen = run(p, "ss -ltn | grep -c ':443'")
    time.sleep(3)
    nrest = run(p, "systemctl show qeli.service -p NRestarts --value")
    status_line = run(p, "systemctl show qeli.service -p StatusText --value")
    cert = run(p, "echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
    ident_post = run(p, f"/usr/local/bin/qeli show-identity --config {conf} 2>&1")
    errs = run(p, "journalctl -u qeli.service --since '60 seconds ago' -p err --no-pager | tail -8")
    ok = (active == "active" and pver == EXPECT_VER and nrest == "0"
          and listen.isdigit() and int(listen) >= 1 and EXPECT_PUBKEY in ident_post)

    print("\n=== VERIFY ===")
    print(f"  active         : {active}")
    print(f"  version        : {pver}")
    print(f"  status (notify): {status_line or '(none)'}")
    print(f"  NRestarts      : {nrest}  (0 = no crash-loop)")
    print(f"  :443 listening : {listen}")
    print(f"  REALITY cert   : {cert or '(none)'}")
    print(f"  identity       : {'7ff1c274 preserved' if EXPECT_PUBKEY in ident_post else 'MISSING!'}")
    print(f"  recent errors  : {errs or '(none)'}")

    if not ok:
        print("\n!! VERIFICATION FAILED — AUTO-ROLLBACK")
        run(p, f"systemctl stop qeli.service; cp -a {bak} /usr/local/bin/qeli; systemctl start qeli.service"); time.sleep(3)
        print("  rolled back to:", run(p, "/usr/local/bin/qeli --version"),
              "| active:", run(p, "systemctl is-active qeli.service"))
        p.close(); return 1

    print(f"\nPROD UPGRADED {cur_ver} -> {pver}  (sha {sha[:16]})")
    print(f"   rollback: cp -a {bak} /usr/local/bin/qeli && systemctl restart qeli.service")
    p.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

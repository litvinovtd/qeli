#!/usr/bin/env python3
"""Binary-only PROD upgrade 0.7.2 -> 0.7.3 (config + identity untouched).

Pulls the freshly-built 0.7.3 release binary from the lab build host (.10), runs a
read-only pre-flight on PROD (new binary parses the live config + the reality-tls
identity pubkey 7ff1c274 is preserved), backs up the current binary, swaps it via
stop->cp->start (cp over a live binary = "Text file busy"), then verifies and
AUTO-ROLLS-BACK on any failure. The config is NOT modified (0.7.3 is wire/config
compatible with 0.7.2; prod already has bind_static_to_session=true).
"""
import os, sys, io, time, hashlib
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB10 = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
PROD = (os.environ.get("QELI_PROD_HOST", "YOUR_PROD_HOST"), "root", os.environ.get("QELI_PROD_PASS", ""))
SRC_BIN = "/opt/qeli-src/target/release/qeli"
EXPECT_VER = "qeli 0.7.3"
EXPECT_PUBKEY = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=30, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=60):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def main():
    # ── 1. pull the 0.7.3 binary from the lab build host ──────────────────────
    c10 = conn(LAB10)
    ver10 = run(c10, f"{SRC_BIN} --version")
    if ver10 != EXPECT_VER:
        print(f"ABORT: lab binary is '{ver10}', expected '{EXPECT_VER}'"); c10.close(); return
    sf = c10.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close(); c10.close()
    data = buf.getvalue()
    sha = hashlib.sha256(data).hexdigest()
    print(f"[lab] {ver10}  sha {sha[:16]}  {len(data)} bytes")

    # ── 2. prod recon + pre-flight (read-only) ────────────────────────────────
    p = conn(PROD)
    execstart = run(p, "systemctl show qeli.service -p ExecStart --value")
    conf = "/etc/qeli/server-maxobf.conf"
    if "--config" in execstart:
        try: conf = execstart.split("--config")[1].split()[0].strip(" ;")
        except Exception: pass
    cur_ver = run(p, "/usr/local/bin/qeli --version")
    cur_sha = run(p, "sha256sum /usr/local/bin/qeli | cut -c1-16")
    nrest0 = run(p, "systemctl show qeli.service -p NRestarts --value")
    print(f"[prod] current {cur_ver}  sha {cur_sha}  config {conf}  NRestarts {nrest0}")

    sf = p.open_sftp(); sf.putfo(io.BytesIO(data), "/tmp/qeli-073-new"); sf.close()
    run(p, "chmod +x /tmp/qeli-073-new")
    new_ver = run(p, "/tmp/qeli-073-new --version")   # also the glibc-compat smoke test
    if new_ver != EXPECT_VER:
        print(f"ABORT: new binary won't run on prod / wrong version: '{new_ver}'")
        run(p, "rm -f /tmp/qeli-073-new"); p.close(); return
    ident = run(p, f"/tmp/qeli-073-new show-identity --config {conf} 2>&1")
    if EXPECT_PUBKEY not in ident:
        print("ABORT: pre-flight identity mismatch — reality-tls pubkey 7ff1c274 NOT found:")
        print(ident[:400]); run(p, "rm -f /tmp/qeli-073-new"); p.close(); return
    print("[preflight] OK — new binary runs on prod, parses live config, identity 7ff1c274 preserved")

    # ── 3. backup ─────────────────────────────────────────────────────────────
    ts = run(p, "date +%Y%m%d-%H%M%S")
    bak = f"/usr/local/bin/qeli.bak-{ts}-0.7.2"
    run(p, f"cp -a /usr/local/bin/qeli {bak}; cp -a /usr/local/bin/qeli /root/qeli-rollback-pre073.bin")
    print(f"[backup] {bak}  +  /root/qeli-rollback-pre073.bin")

    # ── 4. swap: stop -> cp -> start ──────────────────────────────────────────
    run(p, "systemctl stop qeli.service"); time.sleep(1)
    run(p, "cp /tmp/qeli-073-new /usr/local/bin/qeli; chmod 755 /usr/local/bin/qeli; rm -f /tmp/qeli-073-new")
    run(p, "systemctl start qeli.service"); time.sleep(4)

    # ── 5. verify ─────────────────────────────────────────────────────────────
    active = run(p, "systemctl is-active qeli.service")
    pver = run(p, "/usr/local/bin/qeli --version")
    listen = run(p, "ss -ltn | grep -c ':443'")
    time.sleep(3)
    nrest = run(p, "systemctl show qeli.service -p NRestarts --value")
    cert = run(p, "echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
    ident_post = run(p, f"/usr/local/bin/qeli show-identity --config {conf} 2>&1")
    errs = run(p, "journalctl -u qeli.service --since '60 seconds ago' -p err --no-pager | tail -5")
    ok = (active == "active" and pver == EXPECT_VER and nrest == "0"
          and listen.isdigit() and int(listen) >= 1 and EXPECT_PUBKEY in ident_post)

    print("\n=== VERIFY ===")
    print(f"  active        : {active}")
    print(f"  version       : {pver}")
    print(f"  NRestarts     : {nrest}  (0 = no crash-loop)")
    print(f"  :443 listening: {listen}")
    print(f"  REALITY cert  : {cert or '(none)'}")
    print(f"  identity      : {'7ff1c274 preserved' if EXPECT_PUBKEY in ident_post else 'MISSING!'}")
    print(f"  recent errors : {errs or '(none)'}")

    if not ok:
        print("\n‼️ VERIFICATION FAILED — AUTO-ROLLBACK")
        run(p, f"systemctl stop qeli.service; cp -a {bak} /usr/local/bin/qeli; systemctl start qeli.service"); time.sleep(3)
        print("  rolled back to:", run(p, "/usr/local/bin/qeli --version"),
              "| active:", run(p, "systemctl is-active qeli.service"))
        p.close(); return

    print(f"\n✅ PROD UPGRADED {cur_ver} -> {pver}  (sha {sha[:16]})")
    print(f"   rollback: cp -a {bak} /usr/local/bin/qeli && systemctl restart qeli.service")
    p.close()


if __name__ == "__main__":
    main()

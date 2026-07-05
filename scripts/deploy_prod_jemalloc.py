#!/usr/bin/env python3
"""PROD allocator swap: qeli 0.7.6 glibc -> 0.7.6 + jemalloc (code IDENTICAL, only
the global allocator differs — working tree vs v0.7.6 tag is Cargo.toml+main.rs only).

Pulls the jemalloc binary from the lab build host (.10, /opt/qeli-src/qeli-jemalloc),
pre-flights on PROD (runs, parses live config, identity 7ff1c274 preserved, jemalloc
actually linked), records the current worker RSS baseline, backs up, swaps
stop->cp->start, verifies, records the fresh worker RSS, and AUTO-ROLLS-BACK on any
failure. Config + identity untouched.
"""
import os, sys, io, time, hashlib
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB10 = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
PROD = (os.environ.get("QELI_PROD_HOST", "YOUR_PROD_HOST"), "root", os.environ.get("QELI_PROD_PASS", ""))
SRC_BIN = "/opt/qeli-src/qeli-jemalloc"
EXPECT_VER = "qeli 0.7.6"
EXPECT_PUBKEY = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=30, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=60):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def worker_rss_mb(p):
    w = run(p, "pgrep -f 'qeli _worker' | head -1")
    if not w.isdigit():
        return None, None
    rss = run(p, f"awk '/VmRSS/{{print $2}}' /proc/{w}/status")
    thr = run(p, f"awk '/Threads/{{print $2}}' /proc/{w}/status")
    try: return round(int(rss) / 1024, 1), thr
    except Exception: return None, None


def main():
    # ── 1. pull the jemalloc binary from the lab build host ───────────────────
    c10 = conn(LAB10)
    ver10 = run(c10, f"{SRC_BIN} --version")
    jem10 = run(c10, f"strings {SRC_BIN} | grep -ic jemalloc")
    if ver10 != EXPECT_VER or not (jem10.isdigit() and int(jem10) > 0):
        print(f"ABORT: lab binary '{ver10}' jemalloc-strings={jem10} (want {EXPECT_VER} + jemalloc>0)"); c10.close(); return
    sf = c10.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close(); c10.close()
    data = buf.getvalue(); sha = hashlib.sha256(data).hexdigest()
    print(f"[lab] {ver10}  jemalloc-strings {jem10}  sha {sha[:16]}  {len(data)} bytes")

    # ── 2. prod recon + pre-flight (read-only) ────────────────────────────────
    p = conn(PROD)
    conf = "/etc/qeli/server-maxobf.conf"
    execstart = run(p, "systemctl show qeli.service -p ExecStart --value")
    if "--config" in execstart:
        try: conf = execstart.split("--config")[1].split()[0].strip(" ;")
        except Exception: pass
    new_sha16 = sha[:16]  # sha of the jemalloc binary → definitive post-swap check
    cur_ver = run(p, "/usr/local/bin/qeli --version")
    cur_sha = run(p, "sha256sum /usr/local/bin/qeli | cut -c1-16")
    cur_jem = run(p, "strings /usr/local/bin/qeli | grep -ic jemalloc")
    nrest0 = run(p, "systemctl show qeli.service -p NRestarts --value")
    rss0, thr0 = worker_rss_mb(p)
    print(f"[prod] current {cur_ver}  sha {cur_sha}  jemalloc={cur_jem}  config {conf}  NRestarts {nrest0}")
    print(f"[prod] BASELINE worker RSS: {rss0} MB  ({thr0} threads)  <-- glibc plateau")

    sf = p.open_sftp(); sf.putfo(io.BytesIO(data), "/tmp/qeli-jem-new"); sf.close()
    run(p, "chmod +x /tmp/qeli-jem-new")
    new_ver = run(p, "/tmp/qeli-jem-new --version")
    if new_ver != EXPECT_VER:
        print(f"ABORT: new binary won't run / wrong version: '{new_ver}'"); run(p, "rm -f /tmp/qeli-jem-new"); p.close(); return
    ident = run(p, f"/tmp/qeli-jem-new show-identity --config {conf} 2>&1")
    if EXPECT_PUBKEY not in ident:
        print("ABORT: preflight identity mismatch — 7ff1c274 NOT found:\n", ident[:400]); run(p, "rm -f /tmp/qeli-jem-new"); p.close(); return
    print("[preflight] OK — jemalloc binary runs on prod, parses live config, identity 7ff1c274 preserved")

    # ── 3. backup ─────────────────────────────────────────────────────────────
    ts = run(p, "date +%Y%m%d-%H%M%S")
    bak = f"/usr/local/bin/qeli.bak-{ts}-076-glibc"
    run(p, f"cp -a /usr/local/bin/qeli {bak}; cp -a /usr/local/bin/qeli /root/qeli-rollback-pre-jemalloc.bin")
    print(f"[backup] {bak}  +  /root/qeli-rollback-pre-jemalloc.bin")

    # ── 4. swap: stop -> cp -> start ──────────────────────────────────────────
    run(p, "systemctl stop qeli.service"); time.sleep(1)
    run(p, "cp /tmp/qeli-jem-new /usr/local/bin/qeli; chmod 755 /usr/local/bin/qeli; rm -f /tmp/qeli-jem-new")
    run(p, "systemctl start qeli.service"); time.sleep(4)

    # ── 5. verify ─────────────────────────────────────────────────────────────
    active = run(p, "systemctl is-active qeli.service")
    pver = run(p, "/usr/local/bin/qeli --version")
    # prod lacks `strings`; the installed sha matching the jemalloc binary is proof.
    psha = run(p, "sha256sum /usr/local/bin/qeli | cut -c1-16")
    is_jem = psha == new_sha16
    listen = run(p, "ss -ltn | grep -cE ':443|:243'")
    time.sleep(3)
    nrest = run(p, "systemctl show qeli.service -p NRestarts --value")
    cert = run(p, "echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
    ident_post = run(p, f"/usr/local/bin/qeli show-identity --config {conf} 2>&1")
    errs = run(p, "journalctl -u qeli.service --since '60 seconds ago' -p err --no-pager | tail -5")
    rss1, thr1 = worker_rss_mb(p)
    ok = (active == "active" and pver == EXPECT_VER and is_jem
          and listen.isdigit() and int(listen) >= 1 and EXPECT_PUBKEY in ident_post)

    print("\n=== VERIFY ===")
    print(f"  active         : {active}")
    print(f"  version        : {pver}")
    print(f"  jemalloc (sha) : {psha} {'== jemalloc-bin ✓' if is_jem else '!! MISMATCH'}")
    print(f"  NRestarts      : {nrest}")
    print(f"  :443/:243 listen: {listen}")
    print(f"  REALITY cert   : {cert or '(none)'}")
    print(f"  identity       : {'7ff1c274 preserved' if EXPECT_PUBKEY in ident_post else 'MISSING!'}")
    print(f"  recent errors  : {errs or '(none)'}")
    print(f"  worker RSS      : {rss1} MB  ({thr1} threads)  <-- fresh jemalloc start")

    if not ok:
        print("\n[!] VERIFICATION FAILED — AUTO-ROLLBACK")
        run(p, f"systemctl stop qeli.service; cp -a {bak} /usr/local/bin/qeli; systemctl start qeli.service"); time.sleep(3)
        print("  rolled back to:", run(p, "/usr/local/bin/qeli --version"), "| active:", run(p, "systemctl is-active qeli.service"))
        p.close(); return

    print(f"\n[OK] PROD allocator swap DONE: {cur_ver} glibc -> {pver} jemalloc  (sha {sha[:16]})")
    print(f"     RSS baseline(glibc) {rss0} MB -> fresh(jemalloc) {rss1} MB  (ceiling needs hrs of real load)")
    print(f"     rollback: cp -a {bak} /usr/local/bin/qeli && systemctl restart qeli.service")
    p.close()


if __name__ == "__main__":
    main()

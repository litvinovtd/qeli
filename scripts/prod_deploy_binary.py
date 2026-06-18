#!/usr/bin/env python3
"""Prod BINARY-ONLY deploy — pull the gate-passed release binary from the lab
(.10 /opt/qeli-src/target/release/qeli), swap it into prod, restart, verify,
auto-rollback on failure. **Does NOT touch the prod config or identity keys.**

Use this for changes that are wire-compatible and config-compatible (e.g. the
web-panel rebuild): same protocol version, new config fields are
backward-compatible (serde defaults), so the existing server-maxobf.conf parses
unchanged and the reality-tls identity pubkey must stay 7ff1c274…

Creds from env: QELI_LAB_PASS, QELI_PROD_PASS. Run after the lab gate is PASS."""
import os
import socket
import sys
import time
import tempfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
PROD = ("YOUR_PROD_HOST", "root", os.environ.get("QELI_PROD_PASS", ""))
EXPECT_PUB = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"
CONF = "/etc/qeli/server-maxobf.conf"
LAB_BIN = "/opt/qeli-src/target/release/qeli"
PROD_BIN = "/usr/local/bin/qeli"


def connect(h, attempts=8):
    # Pre-open the TCP socket to the numeric IP ourselves and hand it to paramiko
    # via sock=, bypassing paramiko's getaddrinfo (which flakes with WSANO_DATA on
    # some Windows/Python builds even for IP literals).
    last = None
    for a in range(attempts):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(20)
            s.connect((h[0], 22))
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(h[0], port=22, username=h[1], password=h[2], sock=s,
                      timeout=30, look_for_keys=False, allow_agent=False)
            return c
        except Exception as ex:
            last = ex
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            print(f"[connect] {h[0]} attempt {a + 1}/{attempts} failed: {ex}")
            time.sleep(6)
    raise SystemExit(f"cannot connect to {h[0]}: {last}")


lab = connect(LAB)
prod = connect(PROD)


def P(cmd, t=90):
    i, o, e = prod.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


# 0. sanity: prod service currently healthy + config present (so rollback target is sane)
pre_active = P("systemctl is-active qeli.service")
conf_ok = P(f"test -f {CONF} && echo OK || echo MISSING")
print(f"[pre] qeli.service={pre_active} config={conf_ok} current_ver={P(PROD_BIN + ' --version 2>&1 | head -1')}")
if conf_ok != "OK":
    print("[ABORT] prod config not found at", CONF); lab.close(); prod.close(); sys.exit(1)

# 1. pull gate binary .10 -> local temp -> prod:/usr/local/bin/qeli.new
tmp = os.path.join(tempfile.gettempdir(), "qeli-release-prod")
lab.open_sftp().get(LAB_BIN, tmp)
print("[pull] lab release binary:", os.path.getsize(tmp), "bytes")
psf = prod.open_sftp()
psf.put(tmp, PROD_BIN + ".new")
P(f"chmod +x {PROD_BIN}.new")
print("[push] -> prod:qeli.new sha:", P(f"sha256sum {PROD_BIN}.new | cut -c1-16"),
      "ver:", P(f"{PROD_BIN}.new --version 2>&1 | head -1"))

# 2. backup current binary (timestamped + a stable rollback path)
ts = P("date +%Y%m%d-%H%M%S")
bdir = f"/root/backup/qeli-deploy/{ts}"
print("[backup]", P(f"mkdir -p {bdir} && cp {PROD_BIN} {bdir}/qeli.bin.bak && cp {CONF} {bdir}/server-maxobf.conf.bak "
                    f"&& cp {PROD_BIN} /root/qeli-rollback.bin && ls -la {bdir}"))

# 3. pre-flight: NEW binary parses the LIVE config and the reality-tls identity is preserved
pf = P(f"{PROD_BIN}.new show-identity -c {CONF} 2>&1")
rtls = [l for l in pf.split("\n") if "reality-tls" in l and "tcp://" in l]
got = rtls[0].split()[-1] if rtls else "(none)"
parse_clean = "error" not in pf.lower() and "panic" not in pf.lower()
print("\n=== PRE-FLIGHT ===")
print("  parse:", "clean" if parse_clean else "!! ERRORS")
print("  reality-tls pubkey:", got, "| preserved:", got == EXPECT_PUB)
if not parse_clean:
    print("---- show-identity output ----"); print(pf[-1500:])
if not (parse_clean and got == EXPECT_PUB):
    print("[ABORT] pre-flight failed — NOT swapping. Service still on old binary.")
    P(f"rm -f {PROD_BIN}.new")
    lab.close(); prod.close(); sys.exit(1)

# 4. swap + restart
print("\n[swap] installing new binary")
P(f"cp -f {PROD_BIN}.new {PROD_BIN} && setcap cap_net_admin+ep {PROD_BIN} 2>/dev/null; true")
print("[restart] qeli.service")
P("systemctl restart qeli.service")

# 5. verify — poll readiness for up to ~40s (reality-tls borrows the camouflage
# cert on startup, so binding :443 can take several seconds; a fixed short wait
# would false-negative and trigger a needless rollback).
active = listen = ""
for i in range(20):
    time.sleep(2)
    active = P("systemctl is-active qeli.service")
    listen = P("ss -tlnH '( sport = :443 )' | grep -c LISTEN")
    if active == "active" and listen.endswith("1"):
        print(f"  ready after ~{(i + 1) * 2}s (is-active={active}, :443 LISTEN={listen})")
        break
    if active == "failed":
        print(f"  service entered failed state after ~{(i + 1) * 2}s")
        break
pub = P(f"{PROD_BIN} show-identity -c {CONF} 2>&1 | awk '/reality-tls.*tcp:/{{print $NF}}'")
cert = P("echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
print("\n=== VERIFY ===")
print("  is-active:", active, "| :443 LISTEN:", listen)
print("  reality-tls pubkey:", pub, "| preserved:", pub == EXPECT_PUB)
print("  external TLS cert :", cert)
ok = (active == "active" and listen.endswith("1") and pub == EXPECT_PUB and "microsoft" in cert.lower())

if ok:
    print("\n=== DEPLOY OK ===")
    print("  binary sha:", P(f"sha256sum {PROD_BIN} | cut -c1-16"), "ver:", P(f"{PROD_BIN} --version 2>&1 | head -1"))
    print("  journal:", P("journalctl -u qeli.service -n 4 --no-pager 2>/dev/null | tail -4"))
    P(f"rm -f {PROD_BIN}.new")
    print("  cleaned .new; rollback binary kept at /root/qeli-rollback.bin and", bdir)
    print("\nDEPLOY_RESULT: PASS")
else:
    print("\n!!! VERIFY FAILED — ROLLING BACK !!!")
    print(P(f"cp -f /root/qeli-rollback.bin {PROD_BIN}; setcap cap_net_admin+ep {PROD_BIN} 2>/dev/null; "
            f"systemctl restart qeli.service; sleep 3; echo restored is-active=$(systemctl is-active qeli.service)"))
    print("DEPLOY_RESULT: ROLLED_BACK")

lab.close(); prod.close()

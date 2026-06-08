#!/usr/bin/env python3
"""Prod multipath deploy — SWAP + RESTART + VERIFY (auto-rollback on failure).
Assumes step2 prepared /usr/local/bin/qeli.new and /etc/qeli/server-maxobf.conf.new
and the pre-flight passed."""
import os, sys, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PROD = ("222.167.246.143", "root", os.environ["QELI_PROD_PASS"])
EXPECT_PUB = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"
CONF = "/etc/qeli/server-maxobf.conf"

c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(PROD[0], username=PROD[1], password=PROD[2], timeout=30, look_for_keys=False, allow_agent=False)
def P(cmd, t=90):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()

# guard: both .new files must exist
chk = P("test -x /usr/local/bin/qeli.new && test -f " + CONF + ".new && echo OK || echo MISSING")
if chk != "OK":
    print("[ABORT] .new files missing — run step2 first:", chk); sys.exit(1)

print("[swap] installing new binary + config")
P(f"cp -f /usr/local/bin/qeli.new /usr/local/bin/qeli && cp -f {CONF}.new {CONF}")
print("[restart] qeli.service")
P("systemctl restart qeli.service")
time.sleep(4)

active = P("systemctl is-active qeli.service")
listen = P("ss -tlnH '( sport = :443 )' | grep -c LISTEN")
print("  is-active:", active, "| :443 LISTEN:", listen)

ok = (active == "active" and listen.endswith("1"))
if ok:
    # deeper verification
    pub = P(f"/usr/local/bin/qeli show-identity -c {CONF} 2>&1 | awk '/reality-tls.*tcp:/{{print $NF}}'")
    cert = P("echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
    mpath = P(f"sed -n '/^\\[profile:reality-tls\\]/,/^\\[profile:reality\\]/p' {CONF} | grep -c 'multipath.enabled = true'")
    print("  reality-tls pubkey:", pub, "| preserved:", pub == EXPECT_PUB)
    print("  external TLS cert  :", cert)
    print("  multipath enabled  :", mpath)
    ok = (pub == EXPECT_PUB and "microsoft" in cert.lower() and mpath == "1")

if ok:
    print("\n=== DEPLOY OK ===")
    print("  binary sha:", P("sha256sum /usr/local/bin/qeli | cut -c1-16"), "ver:", P("/usr/local/bin/qeli --version 2>&1|head -1"))
    print("  recent journal:", P("journalctl -u qeli.service -n 4 --no-pager 2>/dev/null | tail -4"))
    P("rm -f /usr/local/bin/qeli.new " + CONF + ".new")
    print("  cleaned .new staging files")
else:
    print("\n!!! VERIFY FAILED — ROLLING BACK !!!")
    print(P(f"cp -f /root/qeli-rollback-preMultipath.bin /usr/local/bin/qeli; "
            f"cp -f $(ls -dt /root/backup/qeli-deploy/*/server-maxobf.conf.bak | head -1) {CONF}; "
            f"systemctl restart qeli.service; sleep 3; echo restored is-active=$(systemctl is-active qeli.service)"))
    print("  rolled back to pre-multipath binary+config")
c.close()

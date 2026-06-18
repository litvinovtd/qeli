#!/usr/bin/env python3
"""Prod multipath deploy — PREP + PRE-FLIGHT only (no swap, no restart).
  1. pull release binary .10 -> local -> prod:/usr/local/bin/qeli.new
  2. backup current binary + config on prod
  3. build server-maxobf.conf.new = current + obf.multipath.* in the reality-tls profile
  4. pre-flight: qeli.new show-identity -c conf.new -> reality-tls pubkey MUST stay 7ff1c274…
Stops before touching the running service. Review output, then run the swap step."""
import os, sys, io, posixpath, tempfile
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB = ("10.66.116.10", "root", os.environ["QELI_LAB_PASS"])
PROD = ("YOUR_PROD_HOST", "root", os.environ["QELI_PROD_PASS"])
EXPECT_PUB = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"
CONF = "/etc/qeli/server-maxobf.conf"
MULTIPATH = [
    "obf.multipath.enabled = true",
    "obf.multipath.max_streams = 4",
    "obf.multipath.adaptive = false",
]


def connect(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=30, look_for_keys=False, allow_agent=False)
    return c


lab = connect(LAB); prod = connect(PROD)
def P(cmd, t=90):
    i, o, e = prod.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()

# 1. pull binary .10 -> local temp -> prod:/usr/local/bin/qeli.new
tmp = os.path.join(tempfile.gettempdir(), "qeli-release-multipath")
lab.open_sftp().get("/opt/qeli-src/target/release/qeli", tmp)
print("[pull] release binary from .10:", os.path.getsize(tmp), "bytes")
psf = prod.open_sftp()
psf.put(tmp, "/usr/local/bin/qeli.new")
P("chmod +x /usr/local/bin/qeli.new")
print("[push] -> prod:/usr/local/bin/qeli.new sha:", P("sha256sum /usr/local/bin/qeli.new | cut -c1-16"),
      "ver:", P("/usr/local/bin/qeli.new --version 2>&1 | head -1"))

# 2. backup
ts = P("date +%Y%m%d-%H%M%S")
bdir = f"/root/backup/qeli-deploy/{ts}"
print("[backup]", P(f"mkdir -p {bdir} && cp /usr/local/bin/qeli {bdir}/qeli.bin.bak && cp {CONF} {bdir}/server-maxobf.conf.bak "
                    f"&& cp /usr/local/bin/qeli /root/qeli-rollback-preMultipath.bin && ls -la {bdir} | tail -2"))

# 3. build conf.new — insert multipath lines into the reality-tls profile only
conf_text = P(f"cat {CONF}")
lines = conf_text.split("\n")
out, in_rtls, inserted = [], False, False
for ln in lines:
    s = ln.strip()
    if s.startswith("[profile:"):
        in_rtls = (s == "[profile:reality-tls]")
    out.append(ln)
    if in_rtls and not inserted and s.startswith("obf.quic.enabled"):
        out.extend(["# stream bonding (multipath): N parallel reality-tls conns -> one session",
                    *MULTIPATH])
        inserted = True
new_conf = "\n".join(out)
if not inserted:
    print("[ERROR] could not find obf.quic.enabled in reality-tls section — aborting, no changes")
    sys.exit(1)
psf.putfo(io.BytesIO((new_conf + "\n").encode()), f"{CONF}.new")
print("[conf.new] multipath lines inserted; reality-tls section now:")
print(P(f"sed -n '/^\\[profile:reality-tls\\]/,/^\\[profile:reality\\]/p' {CONF}.new | grep -nE 'multipath|quic.enabled|perf.tcp'"))

# 4. pre-flight: new binary + new config, identity must be unchanged
pf = P(f"/usr/local/bin/qeli.new show-identity -c {CONF}.new 2>&1")
rtls_line = [l for l in pf.split("\n") if "reality-tls" in l and "tcp://" in l]
got = rtls_line[0].split()[-1] if rtls_line else "(none)"
print("\n=== PRE-FLIGHT ===")
print("  parse errors:", "NONE" if "error" not in pf.lower() and "panic" not in pf.lower() else "!! SEE BELOW")
print("  reality-tls pubkey:", got)
print("  identity preserved:", got == EXPECT_PUB)
if "error" in pf.lower() or "panic" in pf.lower():
    print("---- show-identity output ----"); print(pf[-1500:])
print("\nPREFLIGHT_OK =", (got == EXPECT_PUB and inserted))
print("(no swap done — service still running old binary/config)")
lab.close(); prod.close()

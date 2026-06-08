#!/usr/bin/env python3
"""Sync multipath sources to /opt/qeli-src on .10 and build the release binary.
(Step 1 of the prod multipath deploy — build only; deploy is a separate step.)"""
import os, sys, posixpath
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB = ("10.66.116.10", "root", os.environ["QELI_LAB_PASS"])
LOCAL_SRC = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli\src"
FILES = [
    "config/server.rs", "config/server_ini.rs", "protocol/mod.rs",
    "server/handler.rs", "server/mod.rs", "server/udp_handler.rs",
    "server/control.rs", "client/mod.rs",
]

c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(LAB[0], username=LAB[1], password=LAB[2], timeout=25, look_for_keys=False, allow_agent=False)


def sh(cmd, t=600):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


sf = c.open_sftp()
for f in FILES:
    local = os.path.join(LOCAL_SRC, f.replace("/", os.sep))
    remote = posixpath.join("/opt/qeli-src/src", f)
    sf.put(local, remote)
sf.close()
print("synced", len(FILES), "files to /opt/qeli-src/src")

print("[release build]")
print(sh("export PATH=/root/.cargo/bin:$PATH; cd /opt/qeli-src && cargo build --release --bin qeli 2>&1 | tail -4", t=600))
print("[bin]", sh("ls -la /opt/qeli-src/target/release/qeli; echo sha:$(sha256sum /opt/qeli-src/target/release/qeli | cut -c1-16); file /opt/qeli-src/target/release/qeli | cut -d, -f1-2"))
# quick sanity: --version + a release test run is heavy; just confirm it runs
print("[version]", sh("/opt/qeli-src/target/release/qeli --version 2>&1 | head -1"))
c.close()

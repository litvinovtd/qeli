#!/usr/bin/env python3
"""Sync the changed Rust sources to the .11 client tree and rebuild + restart
the qeli client so it speaks the new keyed OK format."""
import os, sys, posixpath, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LOCAL = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE = "/root/qeli"
HOST = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


def sh(c, cmd, t=900):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.strip(), o.channel.recv_exit_status()


def launch(c, cmd):
    ch = c.get_transport().open_session(); ch.exec_command(cmd); time.sleep(2); ch.close()


c = conn()
# 1. stop client
sh(c, "pkill -9 -f 'qeli client'; ip link del vpn0 2>/dev/null; sleep 1; true")

# 2. sync src + Cargo.toml
sf = c.open_sftp()
n = 0
base = os.path.join(LOCAL, "src")
for root, _, names in os.walk(base):
    for nm in names:
        if nm.endswith((".rs", ".html", ".css", ".js")):
            full = os.path.join(root, nm)
            rel = os.path.relpath(full, LOCAL).replace("\\", "/")
            remote = posixpath.join(REMOTE, rel)
            sh(c, f"mkdir -p {posixpath.dirname(remote)}")
            sf.put(full, remote); n += 1
sf.put(os.path.join(LOCAL, "Cargo.toml"), posixpath.join(REMOTE, "Cargo.toml"))
sf.close()
print(f"[put] {n} src files + Cargo.toml")

# 3. build
print("[build] cargo build --bin qeli ...")
out, rc = sh(c, f"cd {REMOTE} && cargo build --bin qeli 2>&1 | tail -4")
print(out)
if rc != 0:
    print("[build] FAILED"); c.close(); sys.exit(1)

# 4. restart client
launch(c, f"cd {REMOTE} && RUST_LOG=info setsid nohup ./target/debug/qeli client "
          f"-c test_e2e/qeli.conf >> /root/qeli_client.log 2>&1 < /dev/null &")
res = ""
for _ in range(15):
    time.sleep(1)
    res, _ = sh(c, "tail -n 4 /root/qeli_client.log")
    if "Auth OK" in res or "refused" in res.lower() or "failed" in res.lower():
        break
print("\n[client]\n" + res)
print("\n[ping server 10.9.0.1]:", sh(c, "ping -c3 -W2 10.9.0.1 | tail -2")[0])
c.close()

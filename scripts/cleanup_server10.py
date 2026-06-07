#!/usr/bin/env python3
"""Server .10 cleanup: consolidate qeli onto /opt/qeli-src (latest build),
restart the server from there, VERIFY it serves, then delete the redundant
/root/qeli, the android toolchain (server builds no APK), all legacy junk and
old JSON configs. Deletion happens ONLY after the server is verified up."""
import os
import paramiko, time

IP = "10.66.116.10"


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(IP, username="root", password=os.environ.get("QELI_LAB_PASS", ""), timeout=20, look_for_keys=False, allow_agent=False)
    return c


def sh(c, cmd, t=600):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.rstrip(), o.channel.recv_exit_status()


def launch(c, cmd):
    ch = c.get_transport().open_session(); ch.exec_command(cmd); time.sleep(2); ch.close()


c = conn()

# 1. rebuild latest binary in the canonical tree
print("[build] /opt/qeli-src cargo build --bin qeli ...")
out, rc = sh(c, "cd /opt/qeli-src && cargo build --bin qeli 2>&1 | tail -2")
print(out, "rc", rc)
assert rc == 0, "build failed — aborting before any deletion"

# 2. stop the old server, restart from /opt/qeli-src
sh(c, "pkill -9 -f 'qeli server'; sleep 1; true")
launch(c, ": > /var/log/qeli/server_live.log; cd /opt/qeli-src && RUST_LOG=info setsid nohup "
          "./target/debug/qeli server -c /etc/qeli/server.conf >> /var/log/qeli/server_live.log 2>&1 < /dev/null &")
up = ""
for _ in range(15):
    time.sleep(1)
    up, _ = sh(c, "grep -iE 'listening' /var/log/qeli/server_live.log | tail -2")
    if up.strip():
        break
print("[server]", up or "(no listening line!)")
proc, _ = sh(c, "pgrep -af 'target/debug/qeli server' | grep -v bash")
print("[proc]", proc)
assert "listening" in up.lower() and proc.strip(), "server did not come up — ABORTING before deletion"

print("[verify] server runs latest:", sh(c, "/opt/qeli-src/target/debug/qeli --help | grep -c add-client")[0], "(add-client present)")

# 3. NOW safe to delete. Legacy junk, redundant tree, android stack, old configs.
rm_dirs = [
    "/root/qeli",            # redundant: server now runs from /opt/qeli-src
    "/root/android-sdk", "/root/android-project", "/root/gradle-8.11.1",  # server builds no APK
    "/root/vpn_upload", "/root/vpn_upload2", "/root/vpn-src",
    "/root/vpn_android_build", "/root/vpn_project", "/root/backup",
]
rm_files = [
    "/root/gradle.zip", "/root/gradle_build.log", "/root/cargo_out.log", "/root/qeli-server.log",
    "/root/android_project.tar.gz", "/root/build_apk.sh", "/root/android_setup.sh",
    "/etc/qeli/server.json", "/etc/qeli/users.json",
]
print("\n[delete] dirs:")
for d in rm_dirs:
    sz, _ = sh(c, f"du -sh {d} 2>/dev/null | cut -f1")
    out, rc = sh(c, f"rm -rf {d}")
    print(f"  {d:32} {sz or '-':>7}  {'ok' if rc==0 else out}")
print("[delete] files + glob junk:")
for f in rm_files:
    sh(c, f"rm -f {f}")
sh(c, "rm -f /root/vpn_*.zip /root/smoke*.php /root/smoke_dashboard.php /root/vpn_android*.zip")
print("  removed listed files + /root/vpn_*.zip + smoke*.php")

# 4. report final state
print("\n[after] /root top dirs:"); print(sh(c, "cd /root && du -sh */ 2>/dev/null | sort -h")[0])
print("\n[after] /root loose files:"); print(sh(c, "find /root -maxdepth 1 -type f ! -name '.*' -printf '%10s  %p\\n' | sort")[0])
print("\n[after] /etc/qeli:"); print(sh(c, "ls -la /etc/qeli | grep -vE '^d|^total'")[0])
print("\n[after] disk:", sh(c, "df -h / | tail -1")[0])
print("[after] server still serving:", sh(c, "ss -tln | grep ':443' || echo NONE")[0])
c.close()

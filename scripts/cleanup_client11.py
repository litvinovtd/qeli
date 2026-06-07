#!/usr/bin/env python3
"""Client .11 cleanup: restart the qeli client (reconnect to the rebuilt .10
server), VERIFY the tunnel, then delete legacy junk, the stale android copy and
the old JSON config. Keeps the android SDK, emulator AVD, the current build dir
(android-project), the offline maven repo and the qeli client tree."""
import os
import paramiko, time

IP = "10.66.116.11"


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(IP, username="root", password=os.environ.get("QELI_LAB_PASS", ""), timeout=20, look_for_keys=False, allow_agent=False)
    return c


def sh(c, cmd, t=120):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.rstrip(), o.channel.recv_exit_status()


def launch(c, cmd):
    ch = c.get_transport().open_session(); ch.exec_command(cmd); time.sleep(2); ch.close()


c = conn()

# 1. restart client against the rebuilt .10 server, verify tunnel
sh(c, "pkill -9 -f 'qeli client'; ip link del vpn0 2>/dev/null; sleep 1; true")
launch(c, "cd /root/qeli && RUST_LOG=info setsid nohup ./target/debug/qeli client "
          "-c test_e2e/qeli.conf >> /root/qeli_client.log 2>&1 < /dev/null &")
res = ""
for _ in range(15):
    time.sleep(1)
    res, _ = sh(c, "tail -n 3 /root/qeli_client.log")
    if "Auth OK" in res or "refused" in res.lower():
        break
print("[client]", res.splitlines()[-1] if res else "(no log)")
ping, _ = sh(c, "ping -c 3 -W 2 10.9.0.1 | tail -2")
print("[tunnel ping .10]\n" + ping)
assert "0% packet loss" in ping or " 0%" in ping, "tunnel not working — ABORTING before deletion"

# 2. safe to delete
rm_dirs = [
    "/root/qeli-android",   # stale copy; builds use /root/android-project
    "/root/vpn_upload", "/root/vpn_upload2", "/root/vpn-android",
    "/root/vpn_project", "/root/vpn_android_build", "/root/backup",
]
rm_files = [
    "/root/gradle.zip", "/root/logcat.txt", "/root/emu.log", "/root/s.png",
    "/root/cA.log", "/root/cB.log", "/root/client.log", "/root/client2.log",
    "/root/vpn.xml", "/root/qeli-maxobf-config.json", "/root/android_project.tar.gz",
    "/root/cargo_out.log", "/root/gradle_build.log",
    "/etc/qeli/client.json",
]
print("\n[delete] dirs:")
for d in rm_dirs:
    sz, _ = sh(c, f"du -sh {d} 2>/dev/null | cut -f1")
    _, rc = sh(c, f"rm -rf {d}")
    print(f"  {d:28} {sz or '-':>7}  {'ok' if rc==0 else 'ERR'}")
for f in rm_files:
    sh(c, f"rm -f {f}")
sh(c, "rm -f /root/vpn_*.zip /root/smoke*.php /root/smoke_dashboard.php /root/vpn_android*.zip")
print("[delete] removed listed files + /root/vpn_*.zip + smoke*.php + /etc/qeli/client.json")

# 3. report
print("\n[after] /root top dirs:"); print(sh(c, "cd /root && du -sh */ 2>/dev/null | sort -h")[0])
print("\n[after] /root loose files:"); print(sh(c, "find /root -maxdepth 1 -type f ! -name '.*' -printf '%10s  %p\\n' | sort")[0])
print("\n[after] /etc/qeli:", sh(c, "ls /etc/qeli 2>/dev/null || echo '(empty/none)'")[0])
print("[after] disk:", sh(c, "df -h / | tail -1")[0])
print("[after] emulator alive:", sh(c, "pgrep -f qemu-system-x86 >/dev/null && echo yes || echo NO")[0])
print("[after] client connected:", sh(c, "ss -tn | grep ':443' | grep 116.10 || echo NONE")[0])
c.close()

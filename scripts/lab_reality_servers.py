#!/usr/bin/env python3
"""Start/stop the two REALITY handrolled e2e servers on .10 for live client tests:
  • profile e2e   tcp 0.0.0.0:8503  target www.microsoft.com  (AES-256/SHA-384)
  • profile cfe2e tcp 0.0.0.0:8504  target www.cloudflare.com  (AES-128 + hybrid)
Usage:  python lab_reality_servers.py start|stop
"start" prints each profile's pinned pubkey; "stop" kills by pid, restarts the
systemd server and removes the stray test TUNs."""
import os
import sys, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

HOST = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
QELI = "/opt/qeli-src/target/debug/qeli"
JOBS = [
    ("e2e",   "/root/reality-test/server-e2e.conf",    "/root/reality-test/srv-e2e.log",    "/root/reality-test/srv.pid",    8503),
    ("cfe2e", "/root/reality-test/server-cf-e2e.conf", "/root/reality-test/srv-cf-e2e.log", "/root/reality-test/srv-cf.pid", 8504),
]


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=60):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def launch(c, cmd):
    ch = c.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()


def start(c):
    for name, conf, log, pidf, port in JOBS:
        old = run(c, f"cat {pidf} 2>/dev/null")
        if old:
            run(c, f"kill -9 {old} 2>/dev/null; true")
        run(c, f"rm -f {log}; true")
        launch(c, f"RUST_LOG=debug setsid nohup {QELI} server -c {conf} "
                  f">/dev/null 2>&1 < /dev/null & echo $! >{pidf}")
        ok = False
        for _ in range(20):
            time.sleep(1)
            if f"listening on 0.0.0.0:{port}" in run(c, f"cat {log} 2>/dev/null"):
                ok = True; break
        pin = run(c, f"grep -o 'public key (pin on client): [0-9a-f]*' {log} | head -1")
        borrow = run(c, f"grep -o 'BorrowProfile {{.*}}' {log} | head -1")
        print(f"[{name}:{port}] listening={ok}")
        print(f"   {pin}")
        print(f"   {borrow}")


def stop(c):
    for name, conf, log, pidf, port in JOBS:
        pid = run(c, f"cat {pidf} 2>/dev/null")
        if pid:
            run(c, f"kill -9 {pid} 2>/dev/null; true")
    for t in ("e2e0", "cfe2e0"):
        run(c, f"ip link del {t} 2>/dev/null; true")
    print("[stop] killed e2e workers, removed test TUNs")
    print("[stop] restore systemd:", run(c, "systemctl restart qeli-server.service && echo OK"))


if __name__ == "__main__":
    act = sys.argv[1] if len(sys.argv) > 1 else "start"
    c = conn()
    (start if act == "start" else stop)(c)
    c.close()

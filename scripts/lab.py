"""Helper for the qeli VPN test lab (paramiko).

Two Linux VMs:
  SERVER  10.66.116.10  root / $QELI_LAB_PASS
  CLIENT  10.66.116.11  root / $QELI_LAB_PASS

Both can build the Rust project. Usage:
  python lab.py <server|client|both> "<command>"
  python lab.py probe          # connectivity + toolchain probe
"""
import os
import sys
import paramiko

HOSTS = {
    "server": ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", "")),
    "client": ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", "")),
}


def connect(host):
    ip, user, pw = HOSTS[host]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username=user, password=pw, timeout=20, look_for_keys=False, allow_agent=False)
    return c


def run(host, cmd, timeout=600):
    c = connect(host)
    try:
        stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout, get_pty=False)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    finally:
        c.close()


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "probe":
        for h in ("server", "client"):
            try:
                rc, out, err = run(h, "uname -a; echo '--'; (cargo --version 2>&1 || echo NO_CARGO); echo '--'; (rustc --version 2>&1 || echo NO_RUSTC); echo '--'; ls -d /opt/qeli-src 2>/dev/null || echo NO_SRC")
                print(f"=== {h} ({HOSTS[h][0]}) rc={rc} ===")
                print(out)
                if err.strip():
                    print("[stderr]", err)
            except Exception as e:
                print(f"=== {h} ({HOSTS[h][0]}) CONNECT FAIL: {e}")
        return

    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    target = sys.argv[1]
    cmd = sys.argv[2]
    hosts = ["server", "client"] if target == "both" else [target]
    for h in hosts:
        rc, out, err = run(h, cmd)
        print(f"=== {h} ({HOSTS[h][0]}) rc={rc} ===")
        if out:
            print(out)
        if err.strip():
            print("[stderr]", err)


if __name__ == "__main__":
    main()

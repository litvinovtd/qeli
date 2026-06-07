"""Upload changed source files to the SERVER VM and run cargo test.

Keeps /opt/qeli-src in sync with the local tree for the files we touch,
then runs the full test suite. Build/test happens on the Linux VM because
the project is Linux-only (libc TUN/TAP).
"""
import os
import sys
import posixpath
import paramiko

SERVER = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
LOCAL_ROOT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE_ROOT = "/opt/qeli-src"


def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(SERVER[0], username=SERVER[1], password=SERVER[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def all_src_files():
    """Every .rs file under qeli/src, relative to the crate root."""
    base = os.path.join(LOCAL_ROOT, "src")
    out = []
    for root, _, names in os.walk(base):
        for n in names:
            if n.endswith((".rs", ".html", ".css", ".js")):
                full = os.path.join(root, n)
                rel = os.path.relpath(full, LOCAL_ROOT).replace("\\", "/")
                out.append(rel)
    return out


def main():
    files = all_src_files() + ["Cargo.toml"]
    c = connect()
    sftp = c.open_sftp()
    for rel in files:
        local = LOCAL_ROOT + "\\" + rel.replace("/", "\\")
        remote = posixpath.join(REMOTE_ROOT, rel)
        sftp.put(local, remote)
    print(f"[put] {len(files)} src files")
    sftp.close()

    cmd = f"cd {REMOTE_ROOT} && cargo test 2>&1 | tail -60"
    print(f"[run] {cmd}\n")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=900)
    out = stdout.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    print(out)
    print(f"[exit] {rc}")
    c.close()
    sys.exit(rc)


if __name__ == "__main__":
    main()

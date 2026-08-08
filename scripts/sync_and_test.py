"""Upload changed source files and public headers to the SERVER VM and run cargo test.

Keeps /opt/qeli-src in sync with the local tree for the files we touch,
then runs the full test suite. Build/test happens on the Linux VM because
the project is Linux-only (libc TUN/TAP).
"""
import os
import sys
import posixpath
import paramiko
import ssh_hostkey

SERVER = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
LOCAL_ROOT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE_ROOT = "/opt/qeli-src"


def connect():
    c = paramiko.SSHClient()
    ssh_hostkey.harden(c)
    c.connect(SERVER[0], username=SERVER[1], password=SERVER[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def all_src_files():
    """Every build input under qeli/src and qeli/include, relative to the crate root."""
    out = []
    for subtree in ("src", "include"):
        base = os.path.join(LOCAL_ROOT, subtree)
        if not os.path.isdir(base):
            continue
        for root, _, names in os.walk(base):
            for n in names:
                if n.endswith((".rs", ".h", ".html", ".css", ".js")):
                    full = os.path.join(root, n)
                    rel = os.path.relpath(full, LOCAL_ROOT).replace("\\", "/")
                    out.append(rel)
    return out


def ensure_remote_dir(sftp, remote_dir):
    """Create a remote directory and missing parents without shell interpolation."""
    if remote_dir in ("", "/"):
        return
    try:
        sftp.stat(remote_dir)
        return
    except IOError:
        ensure_remote_dir(sftp, posixpath.dirname(remote_dir))
        try:
            sftp.mkdir(remote_dir)
        except IOError:
            sftp.stat(remote_dir)


def main():
    files = all_src_files() + ["Cargo.toml"]
    c = connect()
    sftp = c.open_sftp()
    for rel in files:
        local = LOCAL_ROOT + "\\" + rel.replace("/", "\\")
        remote = posixpath.join(REMOTE_ROOT, rel)
        ensure_remote_dir(sftp, posixpath.dirname(remote))
        sftp.put(local, remote)
    print(f"[put] {len(files)} build inputs")
    sftp.close()

    # Capture cargo's own status. Piping it into `tail` reports tail's zero exit code and
    # can label a failed test suite as successful.
    cmd = f"cd {REMOTE_ROOT} && cargo test 2>&1"
    print(f"[run] {cmd}\n")
    _stdin, stdout, stderr = c.exec_command(cmd, timeout=900)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    combined = (out + err).splitlines()
    print("\n".join(combined[-60:]))
    print(f"[exit] {rc}")
    c.close()
    sys.exit(rc)


if __name__ == "__main__":
    main()

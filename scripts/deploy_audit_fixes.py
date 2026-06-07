"""
Sync the locally-edited Rust source to 10.66.116.10 (server) and run
`cargo build --release`, then stream the result back. Edit-only script —
nothing is restarted on the remote.
"""
from __future__ import annotations

import os
import sys
import stat
import posixpath
from pathlib import Path

import paramiko

HOST = "10.66.116.10"
USER = "root"
PASS = os.environ.get("QELI_LAB_PASS", "")
REMOTE_ROOT = "/opt/qeli-src"

LOCAL_ROOT = Path(r"C:\Users\Administrator\Documents\project\vpn\qeli")

SYNC_FILES = [
    "Cargo.toml",
    "src/server/mod.rs",
    "src/server/handler.rs",
    "src/server/udp_handler.rs",
    "src/client/mod.rs",
    "src/client/dns.rs",
    "src/protocol/mod.rs",
    "src/protocol/tls.rs",
    "src/web/mod.rs",
    "src/web/auth.rs",
    "src/web/api/mod.rs",
    "src/web/api/config.rs",
    "src/web/api/logs.rs",
    "src/web/api/users.rs",
    "src/web/api/paths.rs",
    # Pages and status/hash on remote used the old AuthError = (StatusCode, &str)
    # signature, which no longer matches auth.rs. Push the consistent local copies.
    "src/web/api/status.rs",
    "src/web/api/hash.rs",
    "src/web/pages/mod.rs",
    "src/web/pages/dashboard.rs",
    "src/web/pages/users.rs",
    "src/web/pages/config.rs",
    "src/web/pages/logs.rs",
]


def sftp_mkdirs(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    parts = remote_dir.strip("/").split("/")
    cur = ""
    for p in parts:
        cur = f"{cur}/{p}"
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)


def upload_files(sftp: paramiko.SFTPClient) -> list[str]:
    uploaded: list[str] = []
    for rel in SYNC_FILES:
        local = LOCAL_ROOT / rel.replace("/", os.sep)
        if not local.is_file():
            print(f"[skip] {rel} (not present locally)")
            continue
        remote = posixpath.join(REMOTE_ROOT, rel)
        sftp_mkdirs(sftp, posixpath.dirname(remote))
        sftp.put(str(local), remote)
        st = sftp.stat(remote)
        print(f"[ok ] {rel}  ({st.st_size} bytes)")
        uploaded.append(rel)
    return uploaded


def stream_cmd(client: paramiko.SSHClient, cmd: str) -> int:
    print(f"\n$ {cmd}")
    stdin, stdout, stderr = client.exec_command(cmd, get_pty=False)
    stdout.channel.set_combine_stderr(True)
    while True:
        line = stdout.readline()
        if not line:
            break
        sys.stdout.write(line)
        sys.stdout.flush()
    code = stdout.channel.recv_exit_status()
    print(f"[exit={code}]")
    return code


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {USER}@{HOST} ...")
    client.connect(HOST, username=USER, password=PASS, timeout=15, allow_agent=False, look_for_keys=False)
    try:
        sftp = client.open_sftp()
        try:
            try:
                sftp.stat(REMOTE_ROOT)
            except FileNotFoundError:
                print(f"Remote {REMOTE_ROOT} not found. Aborting — please clone the repo there first.")
                return 2
            print(f"Uploading {len(SYNC_FILES)} files to {REMOTE_ROOT} ...")
            upload_files(sftp)
        finally:
            sftp.close()

        # cargo check first (fast feedback), then release build
        if stream_cmd(client, f"cd {REMOTE_ROOT} && cargo --version") != 0:
            print("cargo not installed on remote; aborting")
            return 3
        rc = stream_cmd(client, f"cd {REMOTE_ROOT} && cargo check --message-format=short 2>&1 | tail -200")
        if rc != 0:
            print("\ncargo check FAILED — not running release build")
            return rc
        rc = stream_cmd(client, f"cd {REMOTE_ROOT} && cargo build --release --message-format=short 2>&1 | tail -200")
        return rc
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())

"""Pull the freshly-built release binary off 10.66.116.10."""
from __future__ import annotations
import os
import paramiko, hashlib, sys
from pathlib import Path

HOST, USER, PASS = "10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", "")
REMOTE = "/opt/qeli-src/target/release/qeli"
LOCAL  = Path(r"C:\Users\Administrator\Documents\project\vpn\release\qeli-linux-amd64")


def main() -> int:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=15,
              allow_agent=False, look_for_keys=False)
    try:
        _, o, _ = c.exec_command(f"sha256sum {REMOTE} && stat -c '%s %y' {REMOTE}")
        o.channel.set_combine_stderr(True)
        print(o.read().decode(errors="replace"))

        sftp = c.open_sftp()
        try:
            st = sftp.stat(REMOTE)
            LOCAL.parent.mkdir(parents=True, exist_ok=True)
            print(f"Downloading {REMOTE} → {LOCAL} ({st.st_size:,} bytes)")
            sftp.get(REMOTE, str(LOCAL))
        finally:
            sftp.close()
    finally:
        c.close()

    h = hashlib.sha256(LOCAL.read_bytes()).hexdigest()
    print(f"local sha256: {h}")
    print(f"local size:   {LOCAL.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

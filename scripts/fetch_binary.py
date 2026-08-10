"""Pull the portable Linux release binary and .deb from the lab build host."""
from __future__ import annotations
import hashlib
import sys
import tomllib
from pathlib import Path

from lab_common import LAB_SRV, connect

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
with (ROOT / "qeli" / "Cargo.toml").open("rb") as manifest:
    VERSION = tomllib.load(manifest)["package"]["version"]
ARTIFACTS = {
    "/opt/qeli-src/target/x86_64-unknown-linux-gnu/release/qeli":
        ROOT / "release" / "qeli-linux-amd64",
    f"/opt/qeli-src/debian/qeli_{VERSION}_amd64.deb":
        ROOT / "qeli" / "debian" / f"qeli_{VERSION}_amd64.deb",
}


def main() -> int:
    c = connect(LAB_SRV)
    try:
        sftp = c.open_sftp()
        try:
            for remote, local in ARTIFACTS.items():
                st = sftp.stat(remote)
                local.parent.mkdir(parents=True, exist_ok=True)
                print(f"Downloading {remote} → {local} ({st.st_size:,} bytes)")
                sftp.get(remote, str(local))
        finally:
            sftp.close()
    finally:
        c.close()

    for local in ARTIFACTS.values():
        h = hashlib.sha256(local.read_bytes()).hexdigest()
        print(f"{local.name}: {local.stat().st_size:,} bytes sha256={h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

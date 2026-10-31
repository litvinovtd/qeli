"""Pull the portable Linux release binary and .deb from the lab build host."""
from __future__ import annotations
import hashlib
import sys
import tomllib
import os
import tempfile
import argparse
from pathlib import Path

from lab_common import LAB_SRV, connect
from linux_release import verify_binary, verify_deb

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
with (ROOT / "qeli" / "Cargo.toml").open("rb") as manifest:
    VERSION = tomllib.load(manifest)["package"]["version"]
def artifact_paths(arch):
    target = {"amd64": "x86_64-unknown-linux-gnu", "arm64": "aarch64-unknown-linux-gnu"}[arch]
    return {
        f"/opt/qeli-src/target/{target}/release/qeli":
            ROOT / "release" / "dist" / f"v{VERSION}" / f"qeli-linux-{arch}",
        f"/opt/qeli-src/debian/qeli_{VERSION}_{arch}.deb":
            ROOT / "qeli" / "debian" / f"qeli_{VERSION}_{arch}.deb",
    }


def main(argv=()) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64"), default="amd64")
    args = parser.parse_args(argv)
    artifacts = artifact_paths(args.arch)
    # Admit all downloads before replacing any already qualified release file.
    with tempfile.TemporaryDirectory(prefix="qeli-linux-admission-") as temporary:
        downloads = []
        c = connect(LAB_SRV)
        try:
            with c.open_sftp() as sftp:
                for remote, local in artifacts.items():
                    st = sftp.stat(remote)
                    staged = Path(temporary) / local.name
                    print(f"Downloading {remote} for admission ({st.st_size:,} bytes)")
                    sftp.get(remote, str(staged))
                    report = verify_deb(staged, args.arch) if local.suffix == ".deb" else verify_binary(staged, args.arch)
                    downloads.append((staged, local, report))
        finally:
            c.close()
        if len({report["sha256"] for _, _, report in downloads}) != 1:
            raise ValueError("Linux binary and package payload are different builds")
        for staged, local, _ in downloads:
            local.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=local.parent, delete=False) as output:
                replacement = Path(output.name)
                output.write(staged.read_bytes())
            try:
                os.replace(replacement, local)
            finally:
                replacement.unlink(missing_ok=True)

    for local in artifacts.values():
        h = hashlib.sha256(local.read_bytes()).hexdigest()
        print(f"{local.name}: {local.stat().st_size:,} bytes sha256={h}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

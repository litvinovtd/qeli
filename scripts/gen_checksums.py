#!/usr/bin/env python3
"""Generate LF-only SHA256SUMS for Qeli release assets.

Usage: python3 scripts/gen_checksums.py [ASSET_DIR]

Regular files in ASSET_DIR (default: current directory) are included; nested
folders and an existing SHA256SUMS are excluded. Asset basenames must use ASCII
letters, digits, dots, underscores, plus or minus, beginning with a letter or
digit, matching Qeli's updater/installer format. Symlinks are refused. Validate
and hash all inputs before atomically replacing SHA256SUMS, so a failed run
preserves the previous manifest. Upload it alongside the assets and verify with
sha256sum -c SHA256SUMS.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile

from linux_release import verify_assets

OUT_NAME = "SHA256SUMS"
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*", re.ASCII)


def sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def generate(directory: Path) -> int:
    output = directory / OUT_NAME
    entries: list[tuple[str, Path]] = []
    # Inspect the output as well: never replace or follow an output symlink.
    with os.scandir(directory) as scan:
        for entry in scan:
            if entry.is_symlink():
                raise ValueError(f"symlink is not a release asset: {entry.name!r}")
            if entry.name == OUT_NAME:
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError(f"{OUT_NAME} must be a regular file")
                continue
            if entry.is_dir(follow_symlinks=False):
                continue
            if not entry.is_file(follow_symlinks=False):
                raise ValueError(f"non-regular release asset: {entry.name!r}")
            if ASSET_NAME.fullmatch(entry.name) is None:
                raise ValueError(f"unsupported release asset name: {entry.name!r}")
            entries.append((entry.name, Path(entry.path)))
    if not entries:
        raise ValueError(f"no files to checksum in {directory}")
    # Never bless an incompatible/repackaged Linux server with a fresh release manifest.
    verify_assets(directory)
    payload = "".join(f"{sha256(path)}  {name}\n" for name, path in sorted(entries)).encode("ascii")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=directory, prefix=".qeli-checksums-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return len(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset_dir", nargs="?", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    if not args.asset_dir.is_dir():
        print(f"not a directory: {args.asset_dir}", file=sys.stderr)
        return 2
    try:
        count = generate(args.asset_dir)
    except (OSError, ValueError) as error:
        print(f"cannot generate {OUT_NAME}: {error}", file=sys.stderr)
        return 1
    print(f"Wrote {count} entries to {args.asset_dir / OUT_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate a SHA256SUMS file over release assets, for the panel / CLI update command
and install-reality-server.sh to verify downloads before installing.

Usage:
    python3 scripts/gen_checksums.py [ASSET_DIR]

ASSET_DIR defaults to the current directory. Every regular file in it (except an
existing SHA256SUMS) is hashed; the result is written to ASSET_DIR/SHA256SUMS in the
standard `sha256sum` format (`<hex>  <bare-filename>`, two spaces). **Upload the
resulting SHA256SUMS file alongside the other assets on the GitHub release** — the
updater looks for an asset literally named `SHA256SUMS` and matches by bare filename.

Verify locally with:  sha256sum -c SHA256SUMS
"""
import hashlib
import os
import sys

OUT_NAME = "SHA256SUMS"


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    if not os.path.isdir(d):
        print(f"not a directory: {d}", file=sys.stderr)
        return 2
    entries = []
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if not os.path.isfile(p) or name == OUT_NAME:
            continue
        entries.append((sha256(p), name))
    if not entries:
        print(f"no files to checksum in {d}", file=sys.stderr)
        return 1
    out_path = os.path.join(d, OUT_NAME)
    with open(out_path, "w", newline="\n") as f:
        for digest, name in entries:
            f.write(f"{digest}  {name}\n")
    print(f"Wrote {len(entries)} entries to {out_path}")
    for digest, name in entries:
        print(f"{digest}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

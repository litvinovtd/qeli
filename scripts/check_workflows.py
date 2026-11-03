#!/usr/bin/env python3
"""Check every workflow with a pinned actionlint; no global install or execution of jobs."""
from __future__ import annotations
import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.7.12"
PINS = {('Windows', 'AMD64'): {'archive': 'actionlint_1.7.12_windows_amd64.zip', 'archive_sha256': '6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9', 'binary': 'actionlint.exe', 'binary_sha256': '54ca21be3de4c7cfa26914aa8b61bd76bf573ef3caac5f80d110558cdf241718'}, ('Linux', 'x86_64'): {'archive': 'actionlint_1.7.12_linux_amd64.tar.gz', 'archive_sha256': '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8', 'binary': 'actionlint', 'binary_sha256': 'c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4'}}
MAX_ARCHIVE = 20 * 1024 * 1024


def workflows(root: Path) -> list[Path]:
    directory = root / ".github/workflows"
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("workflow directory must exist and must not be a symlink")
    paths = sorted(set(directory.glob("*.yml")) | set(directory.glob("*.yaml")))
    if not paths:
        raise ValueError("no workflows found")
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("every workflow must be a regular file, not a symlink")
    return paths


def selected_pin() -> dict:
    key = (platform.system(), platform.machine())
    if key not in PINS:
        raise ValueError(f"no reviewed actionlint artifact for {key}")
    return PINS[key]


def verify_binary(path: Path, pin: dict) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("actionlint must be a regular file")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != pin["binary_sha256"]:
        raise ValueError("actionlint binary SHA256 differs from the reviewed release")


def install(directory: Path, pin: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / pin["binary"]
    if destination.exists() or destination.is_symlink():
        verify_binary(destination, pin)
        return destination
    url = f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}/{pin['archive']}"
    with urllib.request.urlopen(url, timeout=45) as response:
        archive = response.read(MAX_ARCHIVE + 1)
    if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != pin["archive_sha256"]:
        raise ValueError("actionlint archive exceeds limit or SHA256 differs")
    if pin["archive"].endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            payload = source.read(pin["binary"])
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
            member = source.getmember(pin["binary"])
            if not member.isfile():
                raise ValueError("actionlint archive member is not a regular file")
            payload = source.extractfile(member).read()
    if hashlib.sha256(payload).hexdigest() != pin["binary_sha256"]:
        raise ValueError("actionlint extracted binary SHA256 differs")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".qeli-actionlint-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
        temporary.chmod(0o755)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    tools = parser.add_mutually_exclusive_group(required=True)
    tools.add_argument("--actionlint", type=Path)
    tools.add_argument("--install-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        paths = workflows(args.root)
        pin = selected_pin()
        tool = args.actionlint if args.actionlint is not None else install(args.install_dir, pin)
        verify_binary(tool, pin)
        result = subprocess.run([str(tool.resolve()), "-shellcheck=", "-pyflakes=", *[str(p.resolve()) for p in paths]],
                                cwd=args.root, check=False, timeout=120)
        if result.returncode:
            return 1
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        print(f"workflow lint refused: {error}", file=sys.stderr)
        return 1
    print(f"actionlint {VERSION}: {len(paths)} workflows PASS (Actions semantics only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

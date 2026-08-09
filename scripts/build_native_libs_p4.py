#!/usr/bin/env python3
"""Reproducibly rebuild and pull the Windows/macOS whole-client native cores.

The .10 lab receives the exact clean local qeli source, then builds each artifact twice in
independent target directories. Nothing is pulled unless A and B are byte-identical and the
complete 6 Reality + 20 whole-client export surface is present. The final pull writes both
the canonical and client-consumed copies and records evidence for provenance.py.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import paramiko

import ssh_hostkey
from native_repro import (
    DEFAULT_ZIG_VERSION,
    atomic_write_bytes,
    require_clean_source_identity,
    require_lab_password,
    rust_toolchain,
    sha256_bytes,
    write_evidence,
)

REPO = Path(__file__).resolve().parent.parent
LOCAL_QELI = REPO / "qeli"
REMOTE_SOURCE = "/opt/qeli-src"
REMOTE_BUILD_ROOT = "/tmp/qeli-native-repro"
HOST = ("10.66.116.10", os.environ.get("QELI_LAB_USER", "root"))
WIN_TARGET = "x86_64-pc-windows-gnu"
MAC_TARGET = "universal2-apple-darwin"

ARTIFACTS = {
    "native-libs/windows-x64/qeli.dll": {
        "target": WIN_TARGET,
        "file": "qeli.dll",
        "copies": (
            "native-libs/windows-x64/qeli.dll",
            "qeli-win/QeliWin/native/qeli.dll",
        ),
    },
    "native-libs/macos-universal/libqeli.dylib": {
        "target": MAC_TARGET,
        "file": "libqeli.dylib",
        "copies": (
            "native-libs/macos-universal/libqeli.dylib",
            "qeli-mac/QeliMac/native/libqeli.dylib",
        ),
    },
}


def connect(password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    ssh_hostkey.harden(client)
    client.connect(
        HOST[0],
        username=HOST[1],
        password=password,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run(client: paramiko.SSHClient, command: str, timeout: int = 2400) -> tuple[str, int]:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", "replace")
    output += stderr.read().decode("utf-8", "replace")
    return output.strip(), stdout.channel.recv_exit_status()


def checked(
    client: paramiko.SSHClient, command: str, label: str, timeout: int = 2400
) -> str:
    output, return_code = run(client, command, timeout)
    if return_code != 0:
        raise RuntimeError(f"{label} failed (rc={return_code}):\n{output}")
    return output


def first_line(output: str) -> str:
    return output.splitlines()[0].strip() if output.splitlines() else ""


def inventory(client: paramiko.SSHClient, toolchain: str) -> dict[str, str]:
    path = "export PATH=/root/.cargo/bin:$PATH; "
    rustc = first_line(checked(client, f"{path}rustc +{toolchain} --version", "rustc probe"))
    cargo = first_line(checked(client, f"{path}cargo +{toolchain} --version", "cargo probe"))
    zig = first_line(checked(client, f"{path}zig version", "Zig probe"))
    cargo_zigbuild = first_line(
        checked(client, f"{path}cargo zigbuild --version", "cargo-zigbuild probe")
    )
    mingw_linker = first_line(
        checked(
            client,
            "x86_64-w64-mingw32-ld --version",
            "MinGW linker probe",
        )
    )
    if not rustc.startswith(f"rustc {toolchain} "):
        raise RuntimeError(f"lab rustc is not the pinned {toolchain}: {rustc}")
    if zig != DEFAULT_ZIG_VERSION:
        raise RuntimeError(f"lab Zig is {zig}, expected pinned {DEFAULT_ZIG_VERSION}")
    return {
        "rust_toolchain": toolchain,
        "rustc": rustc,
        "cargo": cargo,
        "zig": zig,
        "cargo_zigbuild": cargo_zigbuild,
        "mingw_linker": mingw_linker,
    }


def sync_source(client: paramiko.SSHClient, sftp: paramiko.SFTPClient) -> None:
    remote_src = posixpath.join(REMOTE_SOURCE, "src")
    checked(
        client,
        f"rm -rf {shlex.quote(remote_src)} && mkdir -p {shlex.quote(remote_src)}",
        "clean remote source",
    )
    count = 0
    for root, directories, names in os.walk(LOCAL_QELI / "src"):
        directories.sort()
        for name in sorted(names):
            if not name.endswith(".rs"):
                continue
            local = Path(root) / name
            relative = local.relative_to(LOCAL_QELI).as_posix()
            remote = posixpath.join(REMOTE_SOURCE, relative)
            checked(
                client,
                f"mkdir -p {shlex.quote(posixpath.dirname(remote))}",
                "create remote source directory",
            )
            sftp.put(os.fspath(local), remote)
            count += 1
    for manifest in ("Cargo.toml", "Cargo.lock"):
        sftp.put(os.fspath(LOCAL_QELI / manifest), posixpath.join(REMOTE_SOURCE, manifest))
    print(f"[sync] {count} .rs files + Cargo.toml/.lock -> {HOST[0]}:{REMOTE_SOURCE}")


def artifact_path(pass_name: str, target: str, filename: str) -> str:
    return f"{REMOTE_BUILD_ROOT}/desktop-{pass_name}/{target}/release/{filename}"


def build_pass(
    client: paramiko.SSHClient,
    pass_name: str,
    toolchain: str,
    source_date_epoch: int,
) -> None:
    target_dir = f"{REMOTE_BUILD_ROOT}/desktop-{pass_name}"
    checked(
        client,
        f"rm -rf {shlex.quote(target_dir)} && mkdir -p {shlex.quote(target_dir)}",
        f"clean build pass {pass_name}",
    )
    common = (
        "export PATH=/root/.cargo/bin:$PATH; "
        f"export SOURCE_DATE_EPOCH={source_date_epoch}; "
        "export CARGO_INCREMENTAL=0; "
        "export CARGO_PROFILE_RELEASE_PANIC=unwind; "
        f"export CARGO_TARGET_DIR={shlex.quote(target_dir)}; "
    )
    win_flags = (
        "-D warnings "
        f"--remap-path-prefix={REMOTE_SOURCE}=/usr/src/qeli "
        "-C link-arg=-Wl,--no-insert-timestamp"
    )
    win_command = (
        f"{common}export RUSTFLAGS={shlex.quote(win_flags)}; "
        f"cd {shlex.quote(REMOTE_SOURCE)} && cargo +{toolchain} build --locked --release "
        f"--features transport-core-ffi --lib --target {WIN_TARGET} 2>&1"
    )
    print(f"=== pass {pass_name}: Windows {WIN_TARGET} ===")
    started = time.time()
    output, return_code = run(client, win_command)
    print("\n".join(output.splitlines()[-(160 if return_code else 12) :]))
    print(f"[win/{pass_name}] rc={return_code} in {time.time() - started:.0f}s")
    if return_code != 0:
        raise RuntimeError(f"Windows build pass {pass_name} failed")

    mac_flags = (
        "-D warnings "
        f"--remap-path-prefix={REMOTE_SOURCE}=/usr/src/qeli "
        "-C link-arg=-Wl,-headerpad_max_install_names"
    )
    mac_command = (
        f"{common}export RUSTFLAGS={shlex.quote(mac_flags)}; "
        f"cd {shlex.quote(REMOTE_SOURCE)} && cargo +{toolchain} zigbuild --locked --release "
        f"--features transport-core-ffi --lib --target {MAC_TARGET} 2>&1"
    )
    print(f"=== pass {pass_name}: macOS {MAC_TARGET} ===")
    started = time.time()
    output, return_code = run(client, mac_command)
    print("\n".join(output.splitlines()[-(160 if return_code else 12) :]))
    print(f"[mac/{pass_name}] rc={return_code} in {time.time() - started:.0f}s")
    if return_code != 0:
        raise RuntimeError(f"macOS build pass {pass_name} failed")


def remote_sha256(client: paramiko.SSHClient, path: str) -> str:
    output = checked(client, f"sha256sum {shlex.quote(path)}", f"hash {path}")
    digest = output.split()[0].lower() if output.split() else ""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError(f"invalid SHA256 output for {path}: {output}")
    return digest


def verify_exports(client: paramiko.SSHClient) -> None:
    win = artifact_path("a", WIN_TARGET, "qeli.dll")
    win_size = checked(client, f"stat -c %s {shlex.quote(win)}", "Windows artifact stat")
    reality = checked(
        client,
        f"x86_64-w64-mingw32-objdump -p {shlex.quote(win)} 2>/dev/null "
        "| grep -c qeli_realtls || true",
        "Windows Reality exports",
    )
    core = checked(
        client,
        f"x86_64-w64-mingw32-objdump -p {shlex.quote(win)} 2>/dev/null "
        "| grep -c qeli_client_ || true",
        "Windows client exports",
    )
    print(
        f"[win] qeli.dll={win_size} bytes, qeli_realtls exports={reality}, "
        f"qeli_client exports={core}"
    )
    if reality.strip() != "6" or core.strip() != "20":
        raise RuntimeError("Windows artifact has an incomplete native export surface")

    mac = artifact_path("a", MAC_TARGET, "libqeli.dylib")
    mac_size = checked(client, f"stat -c %s {shlex.quote(mac)}", "macOS artifact stat")
    architecture = checked(client, f"file {shlex.quote(mac)}", "macOS architecture probe")
    reality = checked(
        client,
        f"(llvm-nm-19 {shlex.quote(mac)} 2>/dev/null || "
        f"llvm-nm {shlex.quote(mac)} 2>/dev/null) | grep -c ' T _qeli_realtls' || true",
        "macOS Reality exports",
    )
    core = checked(
        client,
        f"(llvm-nm-19 {shlex.quote(mac)} 2>/dev/null || "
        f"llvm-nm {shlex.quote(mac)} 2>/dev/null) | grep -c ' T _qeli_client_' || true",
        "macOS client exports",
    )
    print(
        f"[mac] libqeli.dylib={mac_size} bytes, qeli_realtls exports={reality}, "
        f"qeli_client exports={core}\n      {architecture}"
    )
    if "x86_64" not in architecture or "arm64" not in architecture:
        raise RuntimeError("macOS artifact is not universal x86_64 + arm64")
    if reality.strip() != "6" or core.strip() != "20":
        raise RuntimeError("macOS artifact has an incomplete native export surface")


def main() -> int:
    identity = require_clean_source_identity(REPO)
    password = require_lab_password()
    toolchain = rust_toolchain()
    client = connect(password)
    try:
        toolchain_inventory = inventory(client, toolchain)
        sftp = client.open_sftp()
        try:
            sync_source(client, sftp)
            build_pass(client, "a", toolchain, identity["source_date_epoch"])
            build_pass(client, "b", toolchain, identity["source_date_epoch"])

            pass_hashes: dict[str, tuple[str, str]] = {}
            for relative, spec in ARTIFACTS.items():
                first = remote_sha256(
                    client, artifact_path("a", spec["target"], spec["file"])
                )
                second = remote_sha256(
                    client, artifact_path("b", spec["target"], spec["file"])
                )
                if first != second:
                    raise RuntimeError(
                        f"{relative}: independent build hashes differ: {first} != {second}"
                    )
                pass_hashes[relative] = (first, second)
                print(f"[reproducible] {relative} sha256={first}")

            verify_exports(client)
            print("=== pull verified pass A into the tree ===")
            for relative, spec in ARTIFACTS.items():
                remote = artifact_path("a", spec["target"], spec["file"])
                with sftp.open(remote, "rb") as stream:
                    data = stream.read()
                digest = sha256_bytes(data)
                if digest != pass_hashes[relative][0]:
                    raise RuntimeError(f"{remote}: SFTP payload changed after verification")
                print(f"[pull] {remote}: {len(data)} bytes, sha256={digest}")
                for destination in spec["copies"]:
                    path = REPO / destination
                    changed = not path.is_file() or path.read_bytes() != data
                    atomic_write_bytes(path, data)
                    print(f"       -> {destination} {'(changed)' if changed else '(identical)'}")
        finally:
            sftp.close()
    finally:
        client.close()

    evidence = write_evidence(
        REPO, "desktop", identity, toolchain_inventory, pass_hashes
    )
    print(f"[evidence] {evidence.relative_to(REPO)}")
    print("[done] Windows/macOS native cores passed independent A/B builds and were pulled.")
    print("Run the Android lab build, then:")
    print("  bash native-libs/verify.sh --update")
    print("  python native-libs/provenance.py --update")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, paramiko.SSHException) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

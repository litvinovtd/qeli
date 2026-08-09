#!/usr/bin/env python3
"""Reproducibly rebuild and pull Android whole-client native cores on lab .11.

The exact clean local qeli source is synchronized to the lab. Each ABI is built twice in
independent output/target directories; only byte-identical pairs with the complete export
surface are pulled into both tracked locations and recorded as provenance evidence.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import paramiko

import ssh_hostkey
from native_repro import (
    DEFAULT_ANDROID_NDK,
    DEFAULT_CARGO_NDK_VERSION,
    atomic_write_bytes,
    require_clean_source_identity,
    require_lab_password,
    rust_toolchain,
    sha256_bytes,
    write_evidence,
)

REPO = Path(__file__).resolve().parent.parent
LOCAL_QELI = REPO / "qeli"
REMOTE_SOURCE = "/root/qeli-src"
REMOTE_BUILD_ROOT = "/tmp/qeli-native-repro"
NDK = f"/root/android-sdk/ndk/{DEFAULT_ANDROID_NDK}"
HOST = ("10.66.116.11", os.environ.get("QELI_LAB_USER", "root"))
ABIS = ("arm64-v8a", "x86_64")

ARTIFACTS = {
    f"native-libs/android/{abi}/libqeli.so": {
        "abi": abi,
        "copies": (
            f"native-libs/android/{abi}/libqeli.so",
            f"qeli-android/app/src/main/jniLibs/{abi}/libqeli.so",
        ),
    }
    for abi in ABIS
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
    cargo_ndk = first_line(checked(client, f"{path}cargo ndk --version", "cargo-ndk probe"))
    ndk_properties = checked(
        client,
        f"cat {shlex.quote(posixpath.join(NDK, 'source.properties'))}",
        "Android NDK probe",
    )
    ndk_revision = ""
    for line in ndk_properties.splitlines():
        if line.strip().startswith("Pkg.Revision") and "=" in line:
            ndk_revision = line.split("=", 1)[1].strip()
            break
    ndk_match = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+)\b", cargo_ndk)
    cargo_ndk_version = ndk_match.group(1) if ndk_match else ""
    if not rustc.startswith(f"rustc {toolchain} "):
        raise RuntimeError(f"lab rustc is not the pinned {toolchain}: {rustc}")
    if ndk_revision != DEFAULT_ANDROID_NDK:
        raise RuntimeError(
            f"lab Android NDK is {ndk_revision or 'unknown'}, expected {DEFAULT_ANDROID_NDK}"
        )
    if cargo_ndk_version != DEFAULT_CARGO_NDK_VERSION:
        raise RuntimeError(
            f"lab cargo-ndk is {cargo_ndk_version or cargo_ndk}, "
            f"expected {DEFAULT_CARGO_NDK_VERSION}"
        )
    return {
        "rust_toolchain": toolchain,
        "rustc": rustc,
        "cargo": cargo,
        "android_ndk": ndk_revision,
        "cargo_ndk_version": cargo_ndk_version,
        "cargo_ndk": cargo_ndk,
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


def output_dir(pass_name: str) -> str:
    return f"{REMOTE_BUILD_ROOT}/android-{pass_name}/out"


def artifact_path(pass_name: str, abi: str) -> str:
    return f"{output_dir(pass_name)}/{abi}/libqeli.so"


def build_pass(
    client: paramiko.SSHClient,
    pass_name: str,
    toolchain: str,
    source_date_epoch: int,
) -> None:
    pass_root = f"{REMOTE_BUILD_ROOT}/android-{pass_name}"
    target_dir = f"{pass_root}/target"
    checked(
        client,
        f"rm -rf {shlex.quote(pass_root)} && mkdir -p {shlex.quote(pass_root)}",
        f"clean Android build pass {pass_name}",
    )
    rust_flags = f"-D warnings --remap-path-prefix={REMOTE_SOURCE}=/usr/src/qeli"
    environment = (
        "export PATH=/root/.cargo/bin:$PATH; "
        f"export ANDROID_NDK_HOME={shlex.quote(NDK)}; "
        "export ANDROID_HOME=/root/android-sdk; "
        f"export SOURCE_DATE_EPOCH={source_date_epoch}; "
        "export CARGO_INCREMENTAL=0; "
        "export CARGO_PROFILE_RELEASE_PANIC=unwind; "
        f"export CARGO_TARGET_DIR={shlex.quote(target_dir)}; "
        f"export RUSTFLAGS={shlex.quote(rust_flags)}; "
    )
    command = (
        f"{environment}cd {shlex.quote(REMOTE_SOURCE)} && cargo +{toolchain} ndk "
        f"-t arm64-v8a -t x86_64 -o {shlex.quote(output_dir(pass_name))} "
        "build --locked --release --features transport-core-ffi --lib 2>&1"
    )
    print(f"=== pass {pass_name}: Android arm64-v8a + x86_64 ===")
    output, return_code = run(client, command)
    print("\n".join(output.splitlines()[-(160 if return_code else 12) :]))
    print(f"[android/{pass_name}] rc={return_code}")
    if return_code != 0:
        raise RuntimeError(f"Android build pass {pass_name} failed")


def remote_sha256(client: paramiko.SSHClient, path: str) -> str:
    output = checked(client, f"sha256sum {shlex.quote(path)}", f"hash {path}")
    digest = output.split()[0].lower() if output.split() else ""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError(f"invalid SHA256 output for {path}: {output}")
    return digest


def verify_exports(client: paramiko.SSHClient) -> None:
    for abi in ABIS:
        artifact = artifact_path("a", abi)
        size = checked(client, f"stat -c %s {shlex.quote(artifact)}", f"{abi} stat")
        reality = checked(
            client,
            f"nm -D {shlex.quote(artifact)} 2>/dev/null | grep -c qeli_realtls || true",
            f"{abi} Reality exports",
        )
        core = checked(
            client,
            f"nm -D {shlex.quote(artifact)} 2>/dev/null | grep -c ' qeli_client_' || true",
            f"{abi} client exports",
        )
        jni = checked(
            client,
            f"nm -D {shlex.quote(artifact)} 2>/dev/null "
            "| grep -c 'Java_com_qeli_TransportCore_' || true",
            f"{abi} JNI exports",
        )
        print(
            f"[{abi}] libqeli.so={size} bytes, qeli_realtls exports={reality}, "
            f"qeli_client exports={core}, TransportCore JNI exports={jni}"
        )
        if reality.strip() != "6" or core.strip() != "20" or jni.strip() != "17":
            raise RuntimeError(f"{abi} artifact has an incomplete native export surface")


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
                first = remote_sha256(client, artifact_path("a", spec["abi"]))
                second = remote_sha256(client, artifact_path("b", spec["abi"]))
                if first != second:
                    raise RuntimeError(
                        f"{relative}: independent build hashes differ: {first} != {second}"
                    )
                pass_hashes[relative] = (first, second)
                print(f"[reproducible] {relative} sha256={first}")

            verify_exports(client)
            print("=== pull verified pass A into the tree ===")
            for relative, spec in ARTIFACTS.items():
                remote = artifact_path("a", spec["abi"])
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
        REPO, "android", identity, toolchain_inventory, pass_hashes
    )
    print(f"[evidence] {evidence.relative_to(REPO)}")
    print("[done] Android cores passed independent A/B builds and were pulled.")
    print("After the desktop lab build, run:")
    print("  bash native-libs/verify.sh --update")
    print("  python native-libs/provenance.py --update")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, paramiko.SSHException) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

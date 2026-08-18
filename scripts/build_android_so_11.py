#!/usr/bin/env python3
"""Reproducibly rebuild and pull Android whole-client native cores on lab .11.

The exact clean local qeli source is synchronized to the lab. Each ABI is built twice in
independent output/target directories; only byte-identical pairs with the complete export
surface are pulled into both tracked locations and recorded as provenance evidence.
"""

from __future__ import annotations

import os
import posixpath
import shlex
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from native_lab import (
    LabConnection,
    cargo_package_version,
    connect_lab,
    ensure_rust_targets,
    first_line,
    installed_cargo_package,
    pull_verified_artifact,
    remote_sha256,
    reset_repro_group,
    sync_qeli_source,
)
from native_repro import (
    DEFAULT_ANDROID_NDK,
    DEFAULT_CARGO_NDK_VERSION,
    collect_reproducible_hashes,
    require_clean_source_identity,
    require_lab_password,
    rust_toolchain,
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


def inventory(client: LabConnection, toolchain: str) -> dict[str, str]:
    path = "export PATH=/root/.cargo/bin:$PATH; "
    rustc = first_line(client.checked(f"{path}rustc +{toolchain} --version", "rustc probe"))
    cargo = first_line(client.checked(f"{path}cargo +{toolchain} --version", "cargo probe"))
    cargo_ndk = installed_cargo_package(client, "cargo-ndk")
    ndk_properties = client.checked(
        f"cat {shlex.quote(posixpath.join(NDK, 'source.properties'))}",
        "Android NDK probe",
    )
    ndk_revision = ""
    for line in ndk_properties.splitlines():
        if line.strip().startswith("Pkg.Revision") and "=" in line:
            ndk_revision = line.split("=", 1)[1].strip()
            break
    cargo_ndk_version = cargo_package_version(cargo_ndk, "cargo-ndk")
    if not rustc.startswith(f"rustc {toolchain} "):
        raise RuntimeError(f"lab rustc is not the pinned {toolchain}: {rustc}")
    if ndk_revision != DEFAULT_ANDROID_NDK:
        raise RuntimeError(
            f"lab Android NDK is {ndk_revision or 'unknown'}, expected {DEFAULT_ANDROID_NDK}"
        )
    if cargo_ndk_version != DEFAULT_CARGO_NDK_VERSION:
        raise RuntimeError(
            f"lab cargo-ndk is {cargo_ndk_version}, "
            f"expected {DEFAULT_CARGO_NDK_VERSION}"
        )
    rust_targets = ensure_rust_targets(
        client, toolchain, ("aarch64-linux-android", "x86_64-linux-android")
    )
    return {
        "rust_toolchain": toolchain,
        "rust_targets": rust_targets,
        "rustc": rustc,
        "cargo": cargo,
        "android_ndk": ndk_revision,
        "cargo_ndk_version": cargo_ndk_version,
        "cargo_ndk": cargo_ndk,
}


def output_dir(pass_name: str) -> str:
    return f"{REMOTE_BUILD_ROOT}/android-{pass_name}/out"


def artifact_path(pass_name: str, abi: str) -> str:
    return f"{output_dir(pass_name)}/{abi}/libqeli.so"


def build_pass(
    client: LabConnection,
    pass_name: str,
    toolchain: str,
    source_date_epoch: int,
) -> None:
    if pass_name not in ("a", "b"):
        raise ValueError(f"invalid build pass: {pass_name}")
    pass_root = f"{REMOTE_BUILD_ROOT}/android-{pass_name}"
    target_dir = f"{pass_root}/target"
    client.checked(
        f"mkdir -p {shlex.quote(pass_root)} {shlex.quote(output_dir(pass_name))}",
        f"create Android build pass {pass_name}",
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
        "build --locked --release --no-default-features --features transport-core-ffi --lib 2>&1"
    )
    print(f"=== pass {pass_name}: Android arm64-v8a + x86_64 ===")
    output, return_code = client.run(command)
    print("\n".join(output.splitlines()[-(160 if return_code else 12) :]))
    print(f"[android/{pass_name}] rc={return_code}")
    if return_code != 0:
        raise RuntimeError(f"Android build pass {pass_name} failed")
    client.checked(
        f"rm -rf {shlex.quote(target_dir)}",
        f"release Android pass {pass_name} cache",
    )


def verify_exports(client: LabConnection) -> None:
    for abi in ABIS:
        artifact = artifact_path("a", abi)
        size = client.checked(f"stat -c %s {shlex.quote(artifact)}", f"{abi} stat")
        reality = client.checked(
            f"nm -D {shlex.quote(artifact)} 2>/dev/null | grep -c qeli_realtls || true",
            f"{abi} Reality exports",
        )
        core = client.checked(
            f"nm -D {shlex.quote(artifact)} 2>/dev/null | grep -c ' qeli_client_' || true",
            f"{abi} client exports",
        )
        jni = client.checked(
            f"nm -D {shlex.quote(artifact)} 2>/dev/null "
            "| grep -c 'Java_com_qeli_TransportCore_' || true",
            f"{abi} JNI exports",
        )
        print(
            f"[{abi}] libqeli.so={size} bytes, qeli_realtls exports={reality}, "
            f"qeli_client exports={core}, TransportCore JNI exports={jni}"
        )
        if reality.strip() != "6" or core.strip() != "20" or jni.strip() != "19":
            raise RuntimeError(f"{abi} artifact has an incomplete native export surface")


def main() -> int:
    identity = require_clean_source_identity(REPO)
    password = require_lab_password()
    toolchain = rust_toolchain()
    client = connect_lab(HOST[0], HOST[1], password)
    try:
        print("[disk] " + reset_repro_group(client, "android"))
        toolchain_inventory = inventory(client, toolchain)
        sftp = client.open_sftp()
        try:
            count = sync_qeli_source(client, sftp, LOCAL_QELI, REMOTE_SOURCE)
            print(f"[sync] {count} .rs files + Cargo.toml/.lock -> {HOST[0]}:{REMOTE_SOURCE}")
            pass_hashes = collect_reproducible_hashes(
                ARTIFACTS,
                lambda pass_name: build_pass(
                    client, pass_name, toolchain, identity["source_date_epoch"]
                ),
                lambda pass_name, relative: remote_sha256(
                    client, artifact_path(pass_name, ARTIFACTS[relative]["abi"])
                ),
            )
            for relative, hashes in pass_hashes.items():
                print(f"[reproducible] {relative} sha256={hashes[0]}")

            verify_exports(client)
            print("=== pull verified pass A into the tree ===")
            for relative, spec in ARTIFACTS.items():
                remote = artifact_path("a", spec["abi"])
                size, digest, changes = pull_verified_artifact(
                    sftp, remote, pass_hashes[relative][0], REPO, spec["copies"]
                )
                print(f"[pull] {remote}: {size} bytes, sha256={digest}")
                for destination, changed in changes:
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
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

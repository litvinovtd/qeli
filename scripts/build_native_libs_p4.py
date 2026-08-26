#!/usr/bin/env python3
"""Reproducibly rebuild and pull the Windows/macOS whole-client native cores.

The .10 lab receives the exact clean local qeli source, then builds each artifact twice in
independent target directories. Nothing is pulled unless A and B are byte-identical and the
complete 6 Reality + 22 whole-client export surface is present. The final pull writes both
the canonical and client-consumed copies and records evidence for provenance.py.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
import time
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
    DEFAULT_CARGO_ZIGBUILD_VERSION,
    DEFAULT_MINGW_LINKER,
    DEFAULT_RCODESIGN,
    DEFAULT_ZIG_VERSION,
    collect_reproducible_hashes,
    require_clean_source_identity,
    require_lab_password,
    rust_toolchain,
    write_evidence,
)

REPO = Path(__file__).resolve().parent.parent
LOCAL_QELI = REPO / "qeli"
REMOTE_SOURCE = "/opt/qeli-src"
REMOTE_BUILD_ROOT = "/tmp/qeli-native-repro"
REMOTE_MACHO_REPRO = f"{REMOTE_BUILD_ROOT}/macho_repro.py"
RCODESIGN = "/usr/local/bin/rcodesign"
HOST = ("10.66.116.10", os.environ.get("QELI_LAB_USER", "root"))
WIN_TARGET = "x86_64-pc-windows-gnu"
MAC_TARGET = "universal2-apple-darwin"
EXPECTED_REALITY_EXPORTS = "6"
EXPECTED_CLIENT_EXPORTS = "22"

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


def inventory(client: LabConnection, toolchain: str) -> dict[str, str]:
    path = "export PATH=/root/.cargo/bin:$PATH; "
    rustc = first_line(client.checked(f"{path}rustc +{toolchain} --version", "rustc probe"))
    cargo = first_line(client.checked(f"{path}cargo +{toolchain} --version", "cargo probe"))
    zig = first_line(client.checked(f"{path}zig version", "Zig probe"))
    cargo_zigbuild = installed_cargo_package(client, "cargo-zigbuild")
    cargo_zigbuild_version = cargo_package_version(cargo_zigbuild, "cargo-zigbuild")
    mingw_linker = first_line(
        client.checked(
            "x86_64-w64-mingw32-ld --version",
            "MinGW linker probe",
        )
    )
    rcodesign = first_line(client.checked(f"{RCODESIGN} --version", "rcodesign probe"))
    rust_targets = ensure_rust_targets(
        client,
        toolchain,
        (WIN_TARGET, "x86_64-apple-darwin", "aarch64-apple-darwin"),
    )
    if not rustc.startswith(f"rustc {toolchain} "):
        raise RuntimeError(f"lab rustc is not the pinned {toolchain}: {rustc}")
    if zig != DEFAULT_ZIG_VERSION:
        raise RuntimeError(f"lab Zig is {zig}, expected pinned {DEFAULT_ZIG_VERSION}")
    if cargo_zigbuild_version != DEFAULT_CARGO_ZIGBUILD_VERSION:
        raise RuntimeError(
            f"lab cargo-zigbuild is {cargo_zigbuild_version}, "
            f"expected pinned {DEFAULT_CARGO_ZIGBUILD_VERSION}"
        )
    if mingw_linker != DEFAULT_MINGW_LINKER:
        raise RuntimeError(
            f"lab MinGW linker is {mingw_linker}, expected pinned {DEFAULT_MINGW_LINKER}"
        )
    if rcodesign != DEFAULT_RCODESIGN:
        raise RuntimeError(
            f"lab rcodesign is {rcodesign}, expected pinned {DEFAULT_RCODESIGN}"
        )
    return {
        "rust_toolchain": toolchain,
        "rust_targets": rust_targets,
        "rustc": rustc,
        "cargo": cargo,
        "zig": zig,
        "cargo_zigbuild": cargo_zigbuild,
        "cargo_zigbuild_version": cargo_zigbuild_version,
        "mingw_linker": mingw_linker,
        "rcodesign": rcodesign,
}


def artifact_path(pass_name: str, _target: str, filename: str) -> str:
    return f"{REMOTE_BUILD_ROOT}/desktop-{pass_name}/artifacts/{filename}"


def macos_rust_flags() -> str:
    # Mach-O otherwise records the pass-specific CARGO_TARGET_DIR as LC_ID_DYLIB. @rpath is
    # the correct stable identity for a dylib embedded beside an app executable. Zig 0.13's
    # random LC_UUID and its one invalid x86_64 GOT index are normalized separately after
    # linking and before ad-hoc signing.
    return (
        "-D warnings "
        f"--remap-path-prefix={REMOTE_SOURCE}=/usr/src/qeli "
        "-C link-arg=-Wl,-headerpad_max_install_names "
        "-C link-arg=-Wl,-install_name,@rpath/libqeli.dylib"
    )


def normalize_and_sign_macos(client: LabConnection, path: str, pass_name: str) -> None:
    client.checked(
        f"python3 {shlex.quote(REMOTE_MACHO_REPRO)} {shlex.quote(path)}",
        f"normalize macOS artifact UUID for pass {pass_name}",
    )
    output, return_code = client.run(f"{RCODESIGN} sign {shlex.quote(path)}")
    lowered = output.lower()
    if return_code != 0 or "error:" in lowered or "failed" in lowered:
        raise RuntimeError(
            f"rcodesign sign failed for pass {pass_name} (rc={return_code}):\n" + output
        )
    # rcodesign's own `verify` warns that it is buggy for ad-hoc signatures and falsely
    # rejects their intentionally empty CMS blob. Structural parsing is reliable: require
    # an ADHOC CodeDirectory for both universal slices instead.
    info, return_code = client.run(
        f"{RCODESIGN} print-signature-info {shlex.quote(path)}"
    )
    if (
        return_code != 0
        or "error:" in info.lower()
        or info.count("CodeSignatureFlags(ADHOC)") != 2
    ):
        raise RuntimeError(
            f"rcodesign signature inspection failed for pass {pass_name} "
            f"(rc={return_code}):\n{info}"
        )


def build_pass(
    client: LabConnection,
    pass_name: str,
    toolchain: str,
    source_date_epoch: int,
) -> None:
    if pass_name not in ("a", "b"):
        raise ValueError(f"invalid build pass: {pass_name}")
    pass_root = f"{REMOTE_BUILD_ROOT}/desktop-{pass_name}"
    target_dir = f"{pass_root}/target"
    artifact_dir = f"{pass_root}/artifacts"
    client.checked(
        f"mkdir -p {shlex.quote(target_dir)} {shlex.quote(artifact_dir)}",
        f"create build pass {pass_name}",
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
        f"--no-default-features --features transport-core-ffi --lib --target {WIN_TARGET} 2>&1"
    )
    print(f"=== pass {pass_name}: Windows {WIN_TARGET} ===")
    started = time.time()
    output, return_code = client.run(win_command)
    print("\n".join(output.splitlines()[-(160 if return_code else 12) :]))
    print(f"[win/{pass_name}] rc={return_code} in {time.time() - started:.0f}s")
    if return_code != 0:
        raise RuntimeError(f"Windows build pass {pass_name} failed")
    built_win = f"{target_dir}/{WIN_TARGET}/release/qeli.dll"
    client.checked(
        f"cp {shlex.quote(built_win)} {shlex.quote(artifact_path(pass_name, WIN_TARGET, 'qeli.dll'))} "
        f"&& rm -rf {shlex.quote(f'{target_dir}/{WIN_TARGET}')}",
        f"preserve Windows artifact and release pass {pass_name} cache",
    )

    mac_flags = macos_rust_flags()
    mac_command = (
        f"{common}export RUSTFLAGS={shlex.quote(mac_flags)}; "
        f"cd {shlex.quote(REMOTE_SOURCE)} && cargo +{toolchain} zigbuild --locked --release "
        f"--no-default-features --features transport-core-ffi --lib --target {MAC_TARGET} 2>&1"
    )
    print(f"=== pass {pass_name}: macOS {MAC_TARGET} ===")
    started = time.time()
    output, return_code = client.run(mac_command)
    print("\n".join(output.splitlines()[-(160 if return_code else 12) :]))
    print(f"[mac/{pass_name}] rc={return_code} in {time.time() - started:.0f}s")
    if return_code != 0:
        raise RuntimeError(f"macOS build pass {pass_name} failed")
    built_mac = f"{target_dir}/{MAC_TARGET}/release/libqeli.dylib"
    normalize_and_sign_macos(client, built_mac, pass_name)
    client.checked(
        f"cp {shlex.quote(built_mac)} "
        f"{shlex.quote(artifact_path(pass_name, MAC_TARGET, 'libqeli.dylib'))} "
        f"&& rm -rf {shlex.quote(target_dir)}",
        f"preserve macOS artifact and release pass {pass_name} cache",
    )


def verify_exports(client: LabConnection) -> None:
    win = artifact_path("a", WIN_TARGET, "qeli.dll")
    win_size = client.checked(f"stat -c %s {shlex.quote(win)}", "Windows artifact stat")
    reality = client.checked(
        f"x86_64-w64-mingw32-objdump -p {shlex.quote(win)} 2>/dev/null "
        "| grep -c qeli_realtls || true",
        "Windows Reality exports",
    )
    core = client.checked(
        f"x86_64-w64-mingw32-objdump -p {shlex.quote(win)} 2>/dev/null "
        "| grep -c qeli_client_ || true",
        "Windows client exports",
    )
    print(
        f"[win] qeli.dll={win_size} bytes, qeli_realtls exports={reality}, "
        f"qeli_client exports={core}"
    )
    if (
        reality.strip() != EXPECTED_REALITY_EXPORTS
        or core.strip() != EXPECTED_CLIENT_EXPORTS
    ):
        raise RuntimeError("Windows artifact has an incomplete native export surface")

    mac = artifact_path("a", MAC_TARGET, "libqeli.dylib")
    mac_size = client.checked(f"stat -c %s {shlex.quote(mac)}", "macOS artifact stat")
    architecture = client.checked(f"file {shlex.quote(mac)}", "macOS architecture probe")
    reality = client.checked(
        f"(llvm-nm-19 {shlex.quote(mac)} 2>/dev/null || "
        f"llvm-nm {shlex.quote(mac)} 2>/dev/null) | grep -c ' T _qeli_realtls' || true",
        "macOS Reality exports",
    )
    core = client.checked(
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
    if (
        reality.strip() != EXPECTED_REALITY_EXPORTS
        or core.strip() != EXPECTED_CLIENT_EXPORTS
    ):
        raise RuntimeError("macOS artifact has an incomplete native export surface")
    for mac_arch in ("x86_64", "arm64"):
        headers = client.checked(
            f"(llvm-objdump-19 --macho --private-headers --arch={mac_arch} "
            f"{shlex.quote(mac)} 2>/dev/null || llvm-objdump --macho --private-headers "
            f"--arch={mac_arch} {shlex.quote(mac)} 2>/dev/null)",
            f"macOS {mac_arch} load commands",
        )
        if "@rpath/libqeli.dylib" not in headers:
            raise RuntimeError(f"macOS {mac_arch} has an unstable dylib install name")
        if "LC_UUID" not in headers:
            raise RuntimeError(f"macOS {mac_arch} has no content-derived LC_UUID")
        indirect = client.checked(
            f"(llvm-objdump-19 --macho --indirect-symbols --arch={mac_arch} "
            f"{shlex.quote(mac)} 2>/dev/null || llvm-objdump --macho --indirect-symbols "
            f"--arch={mac_arch} {shlex.quote(mac)} 2>/dev/null)",
            f"macOS {mac_arch} indirect symbols",
        )
        if re.search(r"^\S.*\s+\d+\s+\?\s*$", indirect, re.MULTILINE):
            raise RuntimeError(f"macOS {mac_arch} has an invalid indirect-symbol index")


def main() -> int:
    identity = require_clean_source_identity(REPO)
    password = require_lab_password()
    toolchain = rust_toolchain()
    client = connect_lab(HOST[0], HOST[1], password)
    try:
        print("[disk] " + reset_repro_group(client, "desktop"))
        toolchain_inventory = inventory(client, toolchain)
        sftp = client.open_sftp()
        try:
            count = sync_qeli_source(client, sftp, LOCAL_QELI, REMOTE_SOURCE)
            print(f"[sync] {count} .rs files + Cargo.toml/.lock -> {HOST[0]}:{REMOTE_SOURCE}")
            sftp.put(os.fspath(REPO / "scripts" / "macho_repro.py"), REMOTE_MACHO_REPRO)
            pass_hashes = collect_reproducible_hashes(
                ARTIFACTS,
                lambda pass_name: build_pass(
                    client, pass_name, toolchain, identity["source_date_epoch"]
                ),
                lambda pass_name, relative: remote_sha256(
                    client,
                    artifact_path(
                        pass_name,
                        ARTIFACTS[relative]["target"],
                        ARTIFACTS[relative]["file"],
                    ),
                ),
            )
            for relative, hashes in pass_hashes.items():
                print(f"[reproducible] {relative} sha256={hashes[0]}")

            verify_exports(client)
            print("=== pull verified pass A into the tree ===")
            for relative, spec in ARTIFACTS.items():
                remote = artifact_path("a", spec["target"], spec["file"])
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
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

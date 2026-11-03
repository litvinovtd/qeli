#!/usr/bin/env python3
"""Shared fail-closed SSH/SFTP harness for qeli native lab builds."""

from __future__ import annotations

import os
import posixpath
import re
import shlex
from pathlib import Path
from typing import Any, Iterable

from native_repro import atomic_write_bytes, sha256_bytes, sha256_file
from ssh_command import run_ssh_command


class LabConnection:
    """Small checked-command wrapper around a Paramiko-compatible SSH client."""

    def __init__(self, client: Any):
        self.client = client

    def run(self, command: str, timeout: int = 2400) -> tuple[str, int]:
        output, status = run_ssh_command(self.client, command, timeout)
        return output.strip(), status

    def checked(self, command: str, label: str, timeout: int = 2400) -> str:
        output, return_code = self.run(command, timeout)
        if return_code != 0:
            raise RuntimeError(f"{label} failed (rc={return_code}):\n{output}")
        return output

    def open_sftp(self) -> Any:
        return self.client.open_sftp()

    def close(self) -> None:
        self.client.close()


def connect_lab(host: str, user: str, password: str) -> LabConnection:
    """Connect with the repository's strict host-key policy and no ambient credentials."""
    client = None
    try:
        import paramiko

        import ssh_hostkey

        client = paramiko.SSHClient()
        ssh_hostkey.harden(client)
        client.connect(
            host,
            username=user,
            password=password,
            timeout=20,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as error:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass  # Preserve the original connection failure.
        raise RuntimeError(f"cannot connect to native build lab {host}: {error}") from error
    return LabConnection(client)


def first_line(output: str) -> str:
    lines = output.splitlines()
    return lines[0].strip() if lines else ""


def installed_cargo_package(connection: LabConnection, package: str) -> str:
    """Read an installed cargo subcommand's exact version without invoking its CLI."""
    if not re.fullmatch(r"[a-z0-9-]+", package):
        raise ValueError(f"invalid cargo package name: {package!r}")
    output = connection.checked(
        "export PATH=/root/.cargo/bin:$PATH; "
        f"cargo install --list | grep -m1 '^{package} v'",
        f"{package} inventory probe",
    )
    return first_line(output)


def cargo_package_version(inventory: str, package: str) -> str:
    """Extract an exact semver from one ``cargo install --list`` package header."""
    if not re.fullmatch(r"[a-z0-9-]+", package):
        raise ValueError(f"invalid cargo package name: {package!r}")
    match = re.fullmatch(
        rf"{re.escape(package)} v([0-9]+\.[0-9]+\.[0-9]+):", inventory.strip()
    )
    if match is None:
        raise RuntimeError(f"invalid {package} inventory line: {inventory!r}")
    return match.group(1)


def ensure_rust_targets(
    connection: LabConnection, toolchain: str, targets: Iterable[str]
) -> str:
    """Idempotently install exact-toolchain standard libraries required by a recipe."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain):
        raise ValueError(f"invalid Rust toolchain: {toolchain!r}")
    required = tuple(targets)
    if not required or any(
        not re.fullmatch(r"[a-z0-9_-]+", target) for target in required
    ):
        raise ValueError("Rust targets must be non-empty validated triples")
    command = (
        "export PATH=/root/.cargo/bin:$PATH; "
        f"rustup target list --toolchain {toolchain} --installed"
    )
    installed = set(connection.checked(command, "Rust target inventory").splitlines())
    missing = [target for target in required if target not in installed]
    if missing:
        connection.checked(
            "export PATH=/root/.cargo/bin:$PATH; "
            f"rustup target add --toolchain {toolchain} {' '.join(missing)}",
            "install pinned Rust targets",
            timeout=1200,
        )
        installed = set(connection.checked(command, "verify Rust targets").splitlines())
        still_missing = [target for target in required if target not in installed]
        if still_missing:
            raise RuntimeError(
                "rustup reported success but targets remain missing: "
                + ", ".join(still_missing)
            )
    return ",".join(required)


REPRO_BUILD_ROOT = "/var/tmp/qeli-native-repro"
MIN_REPRO_FREE_KIB = 8 * 1024 * 1024


def reset_repro_group(connection: LabConnection, group: str) -> str:
    """Check capacity before changing disk; reset only this recipe's pass roots."""
    if not re.fullmatch(r"[a-z0-9-]+", group):
        raise ValueError(f"invalid reproducibility group: {group!r}")
    first = f"{REPRO_BUILD_ROOT}/{group}-a"
    second = f"{REPRO_BUILD_ROOT}/{group}-b"
    free_text = connection.checked(
        f"if test -e {shlex.quote(REPRO_BUILD_ROOT)}; then "
        f"LC_ALL=C df -Pk {shlex.quote(REPRO_BUILD_ROOT)}; else "
        f"LC_ALL=C df -Pk {shlex.quote(posixpath.dirname(REPRO_BUILD_ROOT))}; fi | tail -1",
        "build filesystem free space",
    )
    try:
        free_kib = int(free_text.split()[3])
    except (IndexError, ValueError) as error:
        raise RuntimeError(f"invalid build filesystem inventory: {free_text!r}") from error
    if free_kib < MIN_REPRO_FREE_KIB:
        raise RuntimeError(
            f"{group} reproducible build needs at least 8 GiB free on "
            f"{REPRO_BUILD_ROOT}; found {free_kib // 1024} MiB"
        )
    connection.checked(
        f"rm -rf {shlex.quote(first)} {shlex.quote(second)} "
        f"&& mkdir -p {shlex.quote(REPRO_BUILD_ROOT)}",
        f"clean {group} reproducibility roots",
    )
    return f"{free_kib // 1024} MiB free on {REPRO_BUILD_ROOT}"


def sync_qeli_source(
    connection: LabConnection,
    sftp: Any,
    local_qeli: str | os.PathLike[str],
    remote_source: str,
) -> int:
    """Replace remote sources/assets/manifests/Cargo config with exact local inputs."""
    if not remote_source.startswith("/") or remote_source == "/" or ".." in remote_source.split("/"):
        raise ValueError(f"unsafe remote source root: {remote_source!r}")
    local_root = Path(local_qeli)
    remote_src = posixpath.join(remote_source, "src")
    remote_cargo = posixpath.join(remote_source, ".cargo")
    local_cargo_config = local_root / ".cargo" / "config.toml"
    if not local_cargo_config.is_file():
        raise RuntimeError(f"native build input is missing: {local_cargo_config}")
    trees = ["src"]
    if (local_root / "src/embedded_license_files.rs").is_file():
        if not (local_root / "third-party-notices/rust/INDEX.tsv").is_file():
            raise RuntimeError("embedded CLI license catalogue has no canonical source bundle")
        trees.append("third-party-notices/rust")
    connection.checked(
        f"rm -rf {shlex.quote(remote_src)} {shlex.quote(remote_cargo)} "
        f"&& mkdir -p {shlex.quote(remote_src)} {shlex.quote(remote_cargo)}",
        "clean remote source and Cargo config",
    )
    sftp.put(os.fspath(local_cargo_config), posixpath.join(remote_cargo, "config.toml"))
    count = 0
    created = set()
    for tree in trees:
        if tree != "src":
            destination = posixpath.join(remote_source, tree)
            connection.checked(f"rm -rf {shlex.quote(destination)}", "replace private source notice tree")
        for root, directories, names in os.walk(local_root / tree):
            directories.sort()
            for name in sorted(names):
                local = Path(root) / name
                relative = local.relative_to(local_root).as_posix()
                remote = posixpath.join(remote_source, relative)
                parent = posixpath.dirname(remote)
                if parent not in created:
                    connection.checked(f"mkdir -p {shlex.quote(parent)}", "create remote source directory")
                    created.add(parent)
                sftp.put(os.fspath(local), remote)
                count += 1
    for manifest in ("Cargo.toml", "Cargo.lock"):
        local = local_root / manifest
        if not local.is_file():
            raise RuntimeError(f"native build input is missing: {local}")
        sftp.put(os.fspath(local), posixpath.join(remote_source, manifest))
    return count


def remote_sha256(connection: LabConnection, path: str) -> str:
    output = connection.checked(f"sha256sum {shlex.quote(path)}", f"hash {path}")
    digest = output.split()[0].lower() if output.split() else ""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError(f"invalid SHA256 output for {path}: {output}")
    return digest


def pull_verified_artifact(
    sftp: Any,
    remote: str,
    expected_sha256: str,
    repo_root: str | os.PathLike[str],
    destinations: Iterable[str],
) -> tuple[int, str, list[tuple[str, bool]]]:
    """Read one verified remote blob and atomically replace every in-tree copy."""
    relative_destinations = tuple(destinations)
    root = Path(repo_root).resolve()
    resolved_destinations = []
    for destination in relative_destinations:
        path = (root / destination).resolve()
        if not path.is_relative_to(root):
            raise ValueError(f"artifact destination escapes repository: {destination}")
        resolved_destinations.append(path)

    # The caller has already verified the remote SHA256 over SSH. Avoid transferring a large
    # artifact again when every local consumer is already byte-identical to that digest.
    if resolved_destinations and all(
        path.is_file() and sha256_file(path) == expected_sha256
        for path in resolved_destinations
    ):
        return (
            resolved_destinations[0].stat().st_size,
            expected_sha256,
            [(destination, False) for destination in relative_destinations],
        )

    with sftp.open(remote, "rb") as stream:
        data = stream.read()
    digest = sha256_bytes(data)
    if digest != expected_sha256:
        raise RuntimeError(f"{remote}: SFTP payload changed after verification")

    changes = []
    for destination, path in zip(relative_destinations, resolved_destinations):
        changed = not path.is_file() or path.read_bytes() != data
        atomic_write_bytes(path, data)
        changes.append((destination, changed))
    return len(data), digest, changes

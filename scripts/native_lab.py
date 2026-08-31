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


class LabConnection:
    """Small checked-command wrapper around a Paramiko-compatible SSH client."""

    def __init__(self, client: Any):
        self.client = client

    def run(self, command: str, timeout: int = 2400) -> tuple[str, int]:
        _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", "replace")
        output += stderr.read().decode("utf-8", "replace")
        return output.strip(), stdout.channel.recv_exit_status()

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


def reset_repro_group(connection: LabConnection, group: str) -> str:
    """Remove only this recipe's two rebuildable /tmp roots and report free space."""
    if not re.fullmatch(r"[a-z0-9-]+", group):
        raise ValueError(f"invalid reproducibility group: {group!r}")
    root = "/tmp/qeli-native-repro"
    first = f"{root}/{group}-a"
    second = f"{root}/{group}-b"
    connection.checked(
        f"rm -rf {shlex.quote(first)} {shlex.quote(second)} && mkdir -p {root}",
        f"clean {group} reproducibility roots",
    )
    return connection.checked("df -h / | tail -1", "disk space after reproducibility cleanup")


def sync_qeli_source(
    connection: LabConnection,
    sftp: Any,
    local_qeli: str | os.PathLike[str],
    remote_source: str,
) -> int:
    """Replace remote sources/assets/manifests with the exact local build inputs."""
    if not remote_source.startswith("/") or remote_source == "/" or ".." in remote_source.split("/"):
        raise ValueError(f"unsafe remote source root: {remote_source!r}")
    local_root = Path(local_qeli)
    remote_src = posixpath.join(remote_source, "src")
    connection.checked(
        f"rm -rf {shlex.quote(remote_src)} && mkdir -p {shlex.quote(remote_src)}",
        "clean remote source",
    )
    count = 0
    for root, directories, names in os.walk(local_root / "src"):
        directories.sort()
        for name in sorted(names):
            local = Path(root) / name
            relative = local.relative_to(local_root).as_posix()
            remote = posixpath.join(remote_source, relative)
            connection.checked(
                f"mkdir -p {shlex.quote(posixpath.dirname(remote))}",
                "create remote source directory",
            )
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

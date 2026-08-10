#!/usr/bin/env python3
"""Shared reproducibility contract for qeli native client libraries.

Build scripts produce two independent release builds in separate target directories. Only a
byte-identical pair may be pulled into the repository, and this module records/verifies the
evidence consumed by ``native-libs/provenance.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable

RECIPE = "qeli-native-repro-v1"
DEFAULT_RUST_TOOLCHAIN = "1.97.0"
DEFAULT_ZIG_VERSION = "0.13.0"
DEFAULT_CARGO_ZIGBUILD_VERSION = "0.23.0"
DEFAULT_MINGW_LINKER = "GNU ld (GNU Binutils) 2.44"
DEFAULT_RCODESIGN = "apple-codesign 0.29.0"
DEFAULT_ANDROID_NDK = "26.3.11579264"
DEFAULT_CARGO_NDK_VERSION = "4.1.2"

EVIDENCE_SPECS = {
    "desktop": (
        "native-libs/windows-x64/qeli.dll",
        "native-libs/macos-universal/libqeli.dylib",
    ),
    "android": (
        "native-libs/android/arm64-v8a/libqeli.so",
        "native-libs/android/x86_64/libqeli.so",
    ),
}

CONSUMED_COPIES = {
    "native-libs/windows-x64/qeli.dll": "qeli-win/QeliWin/native/qeli.dll",
    "native-libs/macos-universal/libqeli.dylib": "qeli-mac/QeliMac/native/libqeli.dylib",
    "native-libs/android/arm64-v8a/libqeli.so": (
        "qeli-android/app/src/main/jniLibs/arm64-v8a/libqeli.so"
    ),
    "native-libs/android/x86_64/libqeli.so": (
        "qeli-android/app/src/main/jniLibs/x86_64/libqeli.so"
    ),
}

TOOLCHAIN_FIELDS = {
    "desktop": (
        "rust_toolchain",
        "rust_targets",
        "rustc",
        "cargo",
        "zig",
        "cargo_zigbuild",
        "cargo_zigbuild_version",
        "mingw_linker",
        "rcodesign",
    ),
    "android": (
        "rust_toolchain",
        "rust_targets",
        "rustc",
        "cargo",
        "android_ndk",
        "cargo_ndk_version",
        "cargo_ndk",
    ),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    """Replace a binary artifact without exposing a truncated intermediate file."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", dir=destination.parent, delete=False
        ) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def source_digest(repo_root: str | os.PathLike[str]) -> str:
    """Digest every Rust source and locked manifest that lands in the native cdylibs."""
    root = Path(repo_root)
    files = sorted((root / "qeli" / "src").rglob("*.rs"))
    files.extend(root / "qeli" / name for name in ("Cargo.toml", "Cargo.lock"))
    aggregate = hashlib.sha256()
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes().replace(b"\r\n", b"\n")
        aggregate.update(f"{relative} {sha256_bytes(data)}\n".encode())
    return aggregate.hexdigest()


def require_clean_source_identity(repo_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Return the committed source identity or refuse a dirty/unversioned native build."""
    root = os.fspath(repo_root)
    dirty = subprocess.run(
        [
            "git",
            "status",
            "--porcelain",
            "--",
            "qeli/src",
            "qeli/Cargo.toml",
            "qeli/Cargo.lock",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if dirty:
        raise RuntimeError(
            "native builds require committed qeli/src and Cargo manifests; dirty files:\n"
            + dirty
        )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    epoch_text = subprocess.run(
        ["git", "show", "-s", "--format=%ct", commit],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return {
        "source_digest": source_digest(root),
        "source_commit": commit,
        "source_dirty": False,
        "source_date_epoch": int(epoch_text),
    }


def rust_toolchain() -> str:
    value = os.environ.get("QELI_NATIVE_RUST_TOOLCHAIN", DEFAULT_RUST_TOOLCHAIN)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise RuntimeError("QELI_NATIVE_RUST_TOOLCHAIN must be an exact x.y.z version")
    return value


def require_lab_password() -> str:
    password = os.environ.get("QELI_LAB_PASS", "")
    if not password:
        raise RuntimeError("QELI_LAB_PASS is required for a native lab build")
    return password


def collect_reproducible_hashes(
    artifacts: Iterable[str],
    build_pass: Callable[[str], None],
    digest_for: Callable[[str, str], str],
) -> dict[str, tuple[str, str]]:
    """Run mandatory isolated A/B builds and refuse any byte-level divergence."""
    names = tuple(artifacts)
    if not names:
        raise ValueError("a reproducible build requires at least one artifact")
    for pass_name in ("a", "b"):
        build_pass(pass_name)
    result = {}
    for name in names:
        first = digest_for("a", name)
        second = digest_for("b", name)
        if not re.fullmatch(r"[0-9a-f]{64}", first) or not re.fullmatch(
            r"[0-9a-f]{64}", second
        ):
            raise RuntimeError(f"{name}: build pass returned an invalid SHA256")
        if first != second:
            raise RuntimeError(
                f"{name}: independent build hashes differ: {first} != {second}"
            )
        result[name] = (first, second)
    return result


def toolchain_errors(name: str, toolchain: Any) -> list[str]:
    """Return violations of the pinned build-input inventory for one lab."""
    if name not in TOOLCHAIN_FIELDS:
        return [f"unknown evidence group: {name}"]
    if not isinstance(toolchain, dict):
        return ["toolchain inventory is missing"]
    errors = []
    missing = [
        field
        for field in TOOLCHAIN_FIELDS[name]
        if not isinstance(toolchain.get(field), str) or not toolchain.get(field)
    ]
    if missing:
        errors.append(f"toolchain inventory is missing: {', '.join(missing)}")
    try:
        expected_rust = rust_toolchain()
    except RuntimeError as error:
        errors.append(str(error))
    else:
        if toolchain.get("rust_toolchain") != expected_rust:
            errors.append(
                f"Rust toolchain is not pinned to the recipe ({expected_rust})"
            )
    if name == "desktop":
        if toolchain.get("zig") != DEFAULT_ZIG_VERSION:
            errors.append(f"Zig is not pinned to the recipe ({DEFAULT_ZIG_VERSION})")
        if toolchain.get("cargo_zigbuild_version") != DEFAULT_CARGO_ZIGBUILD_VERSION:
            errors.append(
                "cargo-zigbuild is not pinned to the recipe "
                f"({DEFAULT_CARGO_ZIGBUILD_VERSION})"
            )
        if toolchain.get("mingw_linker") != DEFAULT_MINGW_LINKER:
            errors.append(f"MinGW linker is not pinned to the recipe ({DEFAULT_MINGW_LINKER})")
        if toolchain.get("rcodesign") != DEFAULT_RCODESIGN:
            errors.append(f"rcodesign is not pinned to the recipe ({DEFAULT_RCODESIGN})")
    if name == "android":
        if toolchain.get("android_ndk") != DEFAULT_ANDROID_NDK:
            errors.append(f"Android NDK is not pinned to the recipe ({DEFAULT_ANDROID_NDK})")
        if toolchain.get("cargo_ndk_version") != DEFAULT_CARGO_NDK_VERSION:
            errors.append(
                f"cargo-ndk is not pinned to the recipe ({DEFAULT_CARGO_NDK_VERSION})"
            )
    return errors


def write_evidence(
    repo_root: str | os.PathLike[str],
    name: str,
    identity: dict[str, Any],
    toolchain: dict[str, str],
    pass_hashes: dict[str, tuple[str, str]],
) -> Path:
    """Validate A/B/final hashes and atomically record one platform evidence file."""
    if name not in EVIDENCE_SPECS:
        raise ValueError(f"unknown evidence group: {name}")
    expected = set(EVIDENCE_SPECS[name])
    if set(pass_hashes) != expected:
        raise ValueError(f"{name} evidence paths must be exactly {sorted(expected)}")

    root = Path(repo_root)
    actual_source_digest = source_digest(root)
    if identity.get("source_digest") != actual_source_digest:
        raise RuntimeError("qeli source changed while the independent builds were running")
    if not isinstance(identity.get("source_commit"), str) or not re.fullmatch(
        r"[0-9a-f]{40}", identity["source_commit"]
    ):
        raise RuntimeError("source identity has no full Git commit")
    if identity.get("source_dirty") is not False:
        raise RuntimeError("reproducibility evidence cannot certify a dirty source tree")
    if (
        type(identity.get("source_date_epoch")) is not int
        or identity["source_date_epoch"] <= 0
    ):
        raise RuntimeError("source identity has no valid SOURCE_DATE_EPOCH")
    inventory_errors = toolchain_errors(name, toolchain)
    if inventory_errors:
        raise RuntimeError("invalid toolchain inventory: " + "; ".join(inventory_errors))
    artifacts: dict[str, dict[str, Any]] = {}
    for relative in sorted(expected):
        first, second = pass_hashes[relative]
        if not re.fullmatch(r"[0-9a-f]{64}", first) or not re.fullmatch(
            r"[0-9a-f]{64}", second
        ):
            raise ValueError(f"{relative}: build hashes must be lowercase SHA256")
        if first != second:
            raise RuntimeError(f"{relative}: independent build hashes differ: {first} != {second}")
        final_path = root / relative
        if not final_path.is_file():
            raise RuntimeError(f"{relative}: final artifact is missing")
        final = sha256_file(final_path)
        if final != first:
            raise RuntimeError(f"{relative}: final artifact {final} differs from builds {first}")
        consumed_relative = CONSUMED_COPIES[relative]
        consumed_path = root / consumed_relative
        if not consumed_path.is_file():
            raise RuntimeError(f"{consumed_relative}: consumed artifact is missing")
        consumed = sha256_file(consumed_path)
        if consumed != final:
            raise RuntimeError(
                f"{consumed_relative}: consumed artifact {consumed} differs from {final}"
            )
        artifacts[relative] = {
            "pass_a_sha256": first,
            "pass_b_sha256": second,
            "final_sha256": final,
            "consumed": {consumed_relative: consumed},
            "reproducible": True,
        }

    document = {
        "schema": 1,
        "recipe": RECIPE,
        **identity,
        "toolchain": toolchain,
        "artifacts": artifacts,
    }
    output_dir = root / "native-libs" / "reproducibility"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{name}.json"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=output_dir, delete=False
    ) as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = Path(stream.name)
    os.replace(temporary, output)
    return output


def validate_evidence(
    repo_root: str | os.PathLike[str], expected_source_digest: str
) -> list[str]:
    """Return every reproducibility contract violation without mutating the tree."""
    root = Path(repo_root)
    errors: list[str] = []
    for name, expected_paths in EVIDENCE_SPECS.items():
        path = root / "native-libs" / "reproducibility" / f"{name}.json"
        if not path.is_file():
            errors.append(f"missing reproducibility evidence: {path.relative_to(root)}")
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"invalid {path.relative_to(root)}: {error}")
            continue
        if not isinstance(document, dict):
            errors.append(f"invalid {path.relative_to(root)}: root must be an object")
            continue
        if document.get("schema") != 1 or document.get("recipe") != RECIPE:
            errors.append(f"{path.relative_to(root)}: unsupported schema/recipe")
        if document.get("source_digest") != expected_source_digest:
            errors.append(f"{path.relative_to(root)}: source digest does not match this tree")
        if not isinstance(document.get("source_commit"), str) or not re.fullmatch(
            r"[0-9a-f]{40}", document["source_commit"]
        ):
            errors.append(f"{path.relative_to(root)}: source commit is missing")
        if document.get("source_dirty") is not False:
            errors.append(f"{path.relative_to(root)}: build source was dirty")
        if (
            type(document.get("source_date_epoch")) is not int
            or document["source_date_epoch"] <= 0
        ):
            errors.append(f"{path.relative_to(root)}: SOURCE_DATE_EPOCH is missing")
        toolchain = document.get("toolchain")
        for error in toolchain_errors(name, toolchain):
            errors.append(f"{path.relative_to(root)}: {error}")

        artifacts = document.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != set(expected_paths):
            errors.append(f"{path.relative_to(root)}: artifact set is incomplete")
            continue
        for relative in expected_paths:
            record = artifacts.get(relative, {})
            if not isinstance(record, dict):
                errors.append(f"{relative}: invalid artifact evidence")
                continue
            first = record.get("pass_a_sha256")
            second = record.get("pass_b_sha256")
            final = record.get("final_sha256")
            hashes_are_valid = all(
                isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                for value in (first, second, final)
            )
            if (
                record.get("reproducible") is not True
                or not hashes_are_valid
                or first != second
            ):
                errors.append(f"{relative}: independent build evidence does not match")
                continue
            consumed_relative = CONSUMED_COPIES[relative]
            consumed_records = record.get("consumed")
            if not isinstance(consumed_records, dict) or set(consumed_records) != {
                consumed_relative
            }:
                errors.append(f"{relative}: consumed-copy evidence is incomplete")
                continue
            consumed_hash = consumed_records.get(consumed_relative)
            consumed_path = root / consumed_relative
            if consumed_hash != final:
                errors.append(f"{consumed_relative}: consumed-copy evidence does not match")
            elif not consumed_path.is_file():
                errors.append(f"{consumed_relative}: consumed artifact is missing")
            elif sha256_file(consumed_path) != consumed_hash:
                errors.append(f"{consumed_relative}: consumed artifact differs from evidence")
            artifact = root / relative
            if not artifact.is_file():
                errors.append(f"{relative}: final artifact is missing")
            elif sha256_file(artifact) != final or final != first:
                errors.append(f"{relative}: evidence does not match the final artifact")
    return errors

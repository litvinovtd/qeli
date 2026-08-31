#!/usr/bin/env python3
"""Validate IPv6/roaming evidence for a release candidate.

Automated Linux cases are release-blocking. Physical-device cases remain machine-readable
and tied to exact artifacts when they can be executed, but an unavailable lab or device
does not prevent a release. A physical case that was executed and failed still blocks: an
explicit regression must never be downgraded to an advisory merely because the gate is
physical.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HEX_256 = re.compile(r"^[0-9a-f]{64}$")

# Code owns the release-blocking automated list. Deleting one cannot make preflight pass.
REQUIRED_CASES: dict[str, str] = {
    "linux.outer4.inner4.tcp.full": "automated",
    "linux.outer4.inner6.tcp.full": "automated",
    "linux.outer6.inner4.tcp.full": "automated",
    "linux.outer6.inner6.tcp.full": "automated",
    "linux.outer4.inner4.udp-fake-tls.full": "automated",
    "linux.outer4.inner6.udp-fake-tls.full": "automated",
    "linux.outer6.inner4.udp-fake-tls.full": "automated",
    "linux.outer6.inner6.udp-fake-tls.full": "automated",
    "linux.outer4.inner4.udp-quic.full": "automated",
    "linux.outer4.inner6.udp-quic.full": "automated",
    "linux.outer6.inner4.udp-quic.full": "automated",
    "linux.outer6.inner6.udp-quic.full": "automated",
    "linux.dual.tcp.split": "automated",
    "linux.dual.udp.split": "automated",
    "linux.dns.ipv4-ipv6": "automated",
    "linux.mtu.1280-pmtu-ptb": "automated",
    "linux.leak.ipv4-ipv6": "automated",
    "linux.tap.ndp-ra": "automated",
    "linux.legacy-peer": "automated",
    "linux.roaming-flap-soak": "automated",
}

# These rows are retained as an honest qualification backlog. Pending, blocked,
# deferred and unavailable physical checks are advisory; passed results need the same
# exact evidence as automated cases, while an explicit failed result remains fatal.
ADVISORY_CASES: dict[str, str] = {
    "android.wifi-to-cellular": "physical",
    "android.cellular-to-wifi": "physical",
    "android.carrier-gap-background": "physical",
    "android.sleep-wake-nat-rebind": "physical",
    "android.ipv6-dns-leak": "physical",
    "android.roaming-race-soak": "physical",
    "ios.wifi-cellular-nat64": "physical",
    "ios.sleep-wake-rollback": "physical",
    "ios.per-app-mdm": "physical",
    "ios.roaming-soak": "physical",
    "windows.ethernet-wifi": "physical",
    "windows.sleep-wake": "physical",
    "windows.ipv6-per-app-leak": "physical",
    "windows.roaming-race-soak": "physical",
    "macos.wifi-ethernet": "physical",
    "macos.sleep-wake": "physical",
    "macos.ipv6-pf-per-app-leak": "physical",
    "macos.networkextension-soak": "physical",
    "openwrt.ipv6-roaming-flap-soak": "physical",
    "keenetic.ipv6-roaming-flap-soak": "physical",
    "rollout.canary-legacy-peer": "physical",
}
ADVISORY_NON_BLOCKING_STATUSES = {"pending", "blocked", "deferred", "not_available"}
KNOWN_CASES: dict[str, str] = {**REQUIRED_CASES, **ADVISORY_CASES}


class CertificationError(RuntimeError):
    """The repository identity could not be established safely."""


def repository_source_digest(root: Path = ROOT) -> str:
    """Hash committed release inputs while excluding certification evidence itself."""
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if status.returncode != 0:
        raise CertificationError(
            f"git status failed: {status.stderr.strip() or f'exit {status.returncode}'}"
        )
    if status.stdout.strip():
        raise CertificationError("tracked working tree is dirty; commit before certification")
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "--full-tree", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise CertificationError(
            f"git ls-tree failed: {proc.stderr.strip() or f'exit {proc.returncode}'}"
        )
    rows: list[str] = []
    for row in proc.stdout.splitlines():
        try:
            identity, path = row.split("\t", 1)
        except ValueError as error:
            raise CertificationError(f"unexpected git ls-tree row: {row!r}") from error
        normalized = path.replace("\\", "/")
        if normalized.startswith("release/certification/"):
            continue
        rows.append(f"{identity}\t{normalized}\n")
    if not rows:
        raise CertificationError("git tree is empty; refusing to certify unknown source")
    return hashlib.sha256("".join(rows).encode("utf-8")).hexdigest()


def development_version(root: Path = ROOT) -> str:
    cargo = root / "qeli" / "Cargo.toml"
    for line in cargo.read_text(encoding="utf-8").splitlines():
        if line.startswith("version") and "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
    raise CertificationError(f"cannot read package version from {cargo}")


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _validate_passed_case(
    case_id: str, case: dict[str, Any], expected_source_digest: str
) -> list[str]:
    prefix = f"case {case_id}"
    errors: list[str] = []
    if case.get("source_digest") != expected_source_digest:
        errors.append(f"{prefix}: result belongs to a different source tree")
    artifact = case.get("artifact_sha256")
    if not isinstance(artifact, str) or HEX_256.fullmatch(artifact.lower()) is None:
        errors.append(f"{prefix}: artifact_sha256 must be 64 lowercase hex characters")
    if not _valid_timestamp(case.get("executed_at")):
        errors.append(f"{prefix}: executed_at must be an RFC 3339 timestamp with timezone")
    if not isinstance(case.get("environment"), str) or not case["environment"].strip():
        errors.append(f"{prefix}: environment must identify the test host/device")
    if not isinstance(case.get("evidence"), str) or not case["evidence"].strip():
        errors.append(f"{prefix}: evidence must point to retained logs/results")
    return errors


def validate_manifest(
    document: Any, *, expected_version: str, expected_source_digest: str
) -> list[str]:
    """Return all validation failures instead of hiding later problems."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["manifest root must be a JSON object"]
    if document.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if document.get("release_version") != expected_version:
        errors.append(
            f"release_version={document.get('release_version')!r}, expected {expected_version!r}"
        )
    source_digest = document.get("source_digest")
    if source_digest != expected_source_digest:
        errors.append(
            "source_digest does not identify the committed release tree "
            f"(manifest {str(source_digest)[:16] or '<empty>'}, "
            f"current {expected_source_digest[:16]})"
        )

    cases = document.get("cases")
    if not isinstance(cases, list):
        return errors + ["cases must be a JSON array"]
    by_id: dict[str, dict[str, Any]] = {}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"cases[{index}] must be an object")
            continue
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            errors.append(f"cases[{index}].id must be a non-empty string")
            continue
        if case_id in by_id:
            errors.append(f"duplicate case id {case_id!r}")
            continue
        by_id[case_id] = case

    for case_id, expected_kind in REQUIRED_CASES.items():
        case = by_id.get(case_id)
        if case is None:
            errors.append(f"missing required case {case_id}")
            continue
        prefix = f"case {case_id}"
        if case.get("kind") != expected_kind:
            errors.append(f"{prefix}: kind must be {expected_kind!r}")
        if case.get("status") != "passed":
            errors.append(f"{prefix}: status is {case.get('status')!r}, expected 'passed'")
            continue
        errors.extend(_validate_passed_case(case_id, case, expected_source_digest))

    for case_id, expected_kind in ADVISORY_CASES.items():
        case = by_id.get(case_id)
        if case is None:
            errors.append(f"missing advisory case {case_id}")
            continue
        prefix = f"case {case_id}"
        if case.get("kind") != expected_kind:
            errors.append(f"{prefix}: kind must be {expected_kind!r}")
        status = case.get("status")
        if status == "passed":
            errors.extend(_validate_passed_case(case_id, case, expected_source_digest))
        elif status == "failed":
            errors.append(f"{prefix}: physical qualification failed")
        elif status not in ADVISORY_NON_BLOCKING_STATUSES:
            allowed = ", ".join(sorted(ADVISORY_NON_BLOCKING_STATUSES | {"failed", "passed"}))
            errors.append(f"{prefix}: unsupported advisory status {status!r}; expected {allowed}")
    return errors


def advisory_statuses(document: Any) -> dict[str, int]:
    """Summarize physical qualification without turning unavailable devices into success."""
    if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
        return {}
    statuses: dict[str, int] = {}
    advisory_ids = set(ADVISORY_CASES)
    for case in document["cases"]:
        if not isinstance(case, dict) or case.get("id") not in advisory_ids:
            continue
        status = str(case.get("status", "missing"))
        statuses[status] = statuses.get(status, 0) + 1
    return statuses


def load_and_validate(path: Path, root: Path = ROOT) -> tuple[str, list[str]]:
    version = development_version(root)
    digest = repository_source_digest(root)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return digest, [f"certification manifest is missing: {path}"]
    except (OSError, json.JSONDecodeError) as error:
        return digest, [f"cannot read certification manifest {path}: {error}"]
    return digest, validate_manifest(
        document,
        expected_version=version,
        expected_source_digest=digest,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, help="result JSON; defaults to current version")
    parser.add_argument(
        "--print-source-digest",
        action="store_true",
        help="print the digest that evidence must carry",
    )
    parser.add_argument("--quiet", action="store_true", help="print only failures")
    args = parser.parse_args(argv)
    try:
        version = development_version(ROOT)
        path = args.manifest or ROOT / "release" / "certification" / f"{version}.json"
        digest, errors = load_and_validate(path)
    except CertificationError as error:
        print(f"FAIL: {error}")
        return 1
    if args.print_source_digest:
        print(digest)
    if errors:
        print(f"FAIL: release certification is incomplete ({len(errors)} problem(s))")
        for error in errors:
            print(f"  - {error}")
        return 1
    if not args.quiet:
        document = json.loads(path.read_text(encoding="utf-8"))
        advisory = advisory_statuses(document)
        print(
            f"PASS: {len(REQUIRED_CASES)} required automated cases certify qeli {version} "
            f"source {digest[:16]}"
        )
        if advisory:
            summary = ", ".join(
                f"{status}={count}" for status, count in sorted(advisory.items())
            )
            print(
                f"INFO: {len(ADVISORY_CASES)} physical qualification cases are advisory "
                f"({summary}); only an explicit failed result blocks release"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())

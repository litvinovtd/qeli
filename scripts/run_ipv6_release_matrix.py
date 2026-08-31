#!/usr/bin/env python3
"""Run the automated outer/inner IPv4/IPv6 Linux release matrix.

The shell case creates three isolated network namespaces and executes one real qeli
server/client pair. This orchestrator runs every TCP, UDP fake-TLS and UDP QUIC outer/inner
combination plus dual-stack split tunnel cases, retains machine-readable output and can
atomically promote successful rows into the 0.8.0 certification manifest.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import release_certification

ROOT = Path(__file__).resolve().parent.parent
CASE_SCRIPT = ROOT / "scripts" / "ipv6_netns_case.sh"

DNS_SCRIPT = ROOT / "scripts" / "ipv6_dns_pair.sh"
DNS_CASE_ID = "linux.dns.ipv4-ipv6"
MTU_SCRIPT = ROOT / "scripts" / "ipv6_mtu_pair.sh"
MTU_CASE_ID = "linux.mtu.1280-pmtu-ptb"
SOAK_SCRIPT = ROOT / "scripts" / "linux_roaming_release_soak.sh"
SOAK_CASE_ID = "linux.roaming-flap-soak"
LEGACY_SCRIPT = ROOT / "scripts" / "ipv6_legacy_pair.sh"
LEGACY_CASE_ID = "linux.legacy-peer"
MATRIX_CASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("linux.outer4.inner4.tcp.full", ("4", "4", "tcp", "fake-tls", "full")),
    ("linux.outer4.inner6.tcp.full", ("4", "6", "tcp", "fake-tls", "full")),
    ("linux.outer6.inner4.tcp.full", ("6", "4", "tcp", "fake-tls", "full")),
    ("linux.outer6.inner6.tcp.full", ("6", "6", "tcp", "fake-tls", "full")),
    (
        "linux.outer4.inner4.udp-fake-tls.full",
        ("4", "4", "udp", "fake-tls", "full"),
    ),
    (
        "linux.outer4.inner6.udp-fake-tls.full",
        ("4", "6", "udp", "fake-tls", "full"),
    ),
    (
        "linux.outer6.inner4.udp-fake-tls.full",
        ("6", "4", "udp", "fake-tls", "full"),
    ),
    (
        "linux.outer6.inner6.udp-fake-tls.full",
        ("6", "6", "udp", "fake-tls", "full"),
    ),
    ("linux.outer4.inner4.udp-quic.full", ("4", "4", "udp", "quic", "full")),
    ("linux.outer4.inner6.udp-quic.full", ("4", "6", "udp", "quic", "full")),
    ("linux.outer6.inner4.udp-quic.full", ("6", "4", "udp", "quic", "full")),
    ("linux.outer6.inner6.udp-quic.full", ("6", "6", "udp", "quic", "full")),
    ("linux.dual.tcp.split", ("4", "dual", "tcp", "fake-tls", "split")),
    ("linux.dual.udp.split", ("4", "dual", "udp", "fake-tls", "split")),
)

SPECIAL_CASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "linux.tap.ndp-ra",
        ("4", "6", "tcp", "fake-tls", "full", "tap"),
    ),
)

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def case_ids() -> tuple[str, ...]:
    return tuple(case_id for case_id, _ in MATRIX_CASES)


def update_manifest(
    path: Path,
    *,
    source_digest: str,
    artifact_sha256: str,
    executed_at: str,
    environment: str,
    evidence: str,
    passed_ids: set[str],
) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = document.get("cases")
    if not isinstance(rows, list):
        raise RuntimeError(f"{path}: cases must be an array")
    expected = set(case_ids())
    if expected.issubset(passed_ids):
        # Every full-tunnel cell independently verifies that the ungranted family cannot
        # use a still-reachable native path, so the aggregate leak case is earned only when
        # the whole family/transport matrix passed.
        passed_ids.add("linux.leak.ipv4-ipv6")
    found: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("id") not in passed_ids:
            continue
        found.add(row["id"])
        row.update(
            {
                "status": "passed",
                "source_digest": source_digest,
                "artifact_sha256": artifact_sha256,
                "executed_at": executed_at,
                "environment": environment,
                "evidence": evidence,
            }
        )
    missing = passed_ids - found
    if missing:
        raise RuntimeError(f"manifest is missing result rows: {', '.join(sorted(missing))}")
    document["source_digest"] = source_digest
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="release qeli binary to test")
    parser.add_argument(
        "--evidence",
        type=Path,
        help="output JSON path (default: dated file under release/certification/evidence)",
    )
    parser.add_argument(
        "--include-special",
        action="store_true",
        help="also run live TAP, dual DNS and MTU/PMTU/PTB Linux cases",
    )
    parser.add_argument(
        "--record",
        action="store_true",
        help="promote successful rows into the current-version certification manifest",
    )
    parser.add_argument(
        "--legacy-binary",
        type=Path,
        help="also run bidirectional interop with the qeli 0.7.16 Linux binary",
    )
    parser.add_argument(
        "--include-soak",
        action="store_true",
        help="also run the bounded representative TCP/UDP Linux roaming soak",
    )
    parser.add_argument(
        "--soak-iterations",
        type=int,
        default=100,
        help="committed A/B flips per soak transport (release minimum: 100)",
    )
    args = parser.parse_args(argv)
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("the live matrix requires Linux root privileges")
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"binary is not executable: {binary}")
    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    evidence_path = args.evidence or (
        ROOT / "release" / "certification" / "evidence" / f"ipv6-linux-{stamp}.json"
    )
    legacy_binary = args.legacy_binary.resolve() if args.legacy_binary else None
    if legacy_binary is not None and (
        not legacy_binary.is_file() or not os.access(legacy_binary, os.X_OK)
    ):
        parser.error(f"legacy binary is not executable: {legacy_binary}")
    if args.include_soak and args.soak_iterations < 100:
        parser.error("release soak requires at least 100 iterations per transport")
    artifact = sha256(binary)
    results: list[dict[str, object]] = []
    passed: set[str] = set()
    selected_cases = MATRIX_CASES + (SPECIAL_CASES if args.include_special else ())
    total_cases = (
        len(selected_cases)
        + 2 * int(args.include_special)
        + int(args.include_soak)
        + int(legacy_binary is not None)
    )
    for index, (case_id, parameters) in enumerate(selected_cases, 1):
        print(f"[{index:02d}/{total_cases:02d}] {case_id}", flush=True)
        started = time.monotonic()
        process = subprocess.run(
            ["bash", str(CASE_SCRIPT), str(binary), *parameters],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        duration = round(time.monotonic() - started, 3)
        output = process.stdout + process.stderr
        print(output.rstrip())
        status = "passed" if process.returncode == 0 else "failed"
        if process.returncode == 0:
            passed.add(case_id)
        results.append(
            {
                "id": case_id,
                "parameters": list(parameters),
                "status": status,
                "exit_code": process.returncode,
                "duration_seconds": duration,
                "output": output,
            }
        )
        if process.returncode != 0:
            print(f"FAIL: {case_id}", file=sys.stderr)

    if args.include_special:
        index = len(selected_cases) + 1
        print(f"[{index:02d}/{total_cases:02d}] {DNS_CASE_ID}", flush=True)
        started = time.monotonic()
        process = subprocess.run(
            ["bash", str(DNS_SCRIPT), str(binary)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=360,
        )
        duration = round(time.monotonic() - started, 3)
        output = process.stdout + process.stderr
        print(output.rstrip())
        status = "passed" if process.returncode == 0 else "failed"
        if process.returncode == 0:
            passed.add(DNS_CASE_ID)
        results.append(
            {
                "id": DNS_CASE_ID,
                "parameters": ["dns4", "dns6"],
                "status": status,
                "exit_code": process.returncode,
                "duration_seconds": duration,
                "output": output,
            }
        )
        if process.returncode != 0:
            print(f"FAIL: {DNS_CASE_ID}", file=sys.stderr)

        index += 1
        print(f"[{index:02d}/{total_cases:02d}] {MTU_CASE_ID}", flush=True)
        started = time.monotonic()
        process = subprocess.run(
            ["bash", str(MTU_SCRIPT), str(binary)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=360,
        )
        duration = round(time.monotonic() - started, 3)
        output = process.stdout + process.stderr
        print(output.rstrip())
        status = "passed" if process.returncode == 0 else "failed"
        if process.returncode == 0:
            passed.add(MTU_CASE_ID)
        results.append(
            {
                "id": MTU_CASE_ID,
                "parameters": ["pmtu", "mtu"],
                "status": status,
                "exit_code": process.returncode,
                "duration_seconds": duration,
                "output": output,
            }
        )
        if process.returncode != 0:
            print(f"FAIL: {MTU_CASE_ID}", file=sys.stderr)

    if args.include_soak:
        index = len(selected_cases) + 2 * int(args.include_special) + 1
        print(f"[{index:02d}/{total_cases:02d}] {SOAK_CASE_ID}", flush=True)
        started = time.monotonic()
        process = subprocess.run(
            ["bash", str(SOAK_SCRIPT), str(binary), str(args.soak_iterations)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2400,
        )
        duration = round(time.monotonic() - started, 3)
        output = process.stdout + process.stderr
        print(output.rstrip())
        status = "passed" if process.returncode == 0 else "failed"
        if process.returncode == 0:
            passed.add(SOAK_CASE_ID)
        results.append(
            {
                "id": SOAK_CASE_ID,
                "parameters": ["tcp", "udp-quic", str(args.soak_iterations)],
                "status": status,
                "exit_code": process.returncode,
                "duration_seconds": duration,
                "output": output,
            }
        )
        if process.returncode != 0:
            print(f"FAIL: {SOAK_CASE_ID}", file=sys.stderr)

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    if legacy_binary is not None:
        index = (
            len(selected_cases)
            + 2 * int(args.include_special)
            + int(args.include_soak)
            + 1
        )
        print(f"[{index:02d}/{total_cases:02d}] {LEGACY_CASE_ID}", flush=True)
        started = time.monotonic()
        process = subprocess.run(
            ["bash", str(LEGACY_SCRIPT), str(binary), str(legacy_binary)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=360,
        )
        duration = round(time.monotonic() - started, 3)
        output = process.stdout + process.stderr
        print(output.rstrip())
        status = "passed" if process.returncode == 0 else "failed"
        if process.returncode == 0:
            passed.add(LEGACY_CASE_ID)
        results.append(
            {
                "id": LEGACY_CASE_ID,
                "parameters": [str(legacy_binary)],
                "status": status,
                "exit_code": process.returncode,
                "duration_seconds": duration,
                "output": output,
            }
        )
        if process.returncode != 0:
            print(f"FAIL: {LEGACY_CASE_ID}", file=sys.stderr)

    evidence_document = {
        "schema_version": 1,
        "kind": "qeli-ipv6-linux-netns-matrix",
        "executed_at": now.isoformat().replace("+00:00", "Z"),
        "git_head": head,
        "artifact": str(binary),
        "artifact_sha256": artifact,
        "environment": f"{platform.node()} | {platform.platform()}",
        "passed": len(passed),
        "total": total_cases,
        "legacy_artifact": str(legacy_binary) if legacy_binary else None,
        "legacy_artifact_sha256": sha256(legacy_binary) if legacy_binary else None,
        "results": results,
    }
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(evidence_document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"evidence: {evidence_path}")
    if len(passed) != total_cases:
        return 1
    if args.record:
        source_digest = release_certification.repository_source_digest(ROOT)
        version = release_certification.development_version(ROOT)
        manifest = ROOT / "release" / "certification" / f"{version}.json"
        try:
            evidence_relative = evidence_path.resolve().relative_to(ROOT).as_posix()
        except ValueError as error:
            raise RuntimeError("--record evidence must be stored inside the repository") from error
        update_manifest(
            manifest,
            source_digest=source_digest,
            artifact_sha256=artifact,
            executed_at=now.isoformat(),
            environment=evidence_document["environment"],
            evidence=evidence_relative,
            passed_ids=passed,
        )
        print(f"recorded {len(passed)} matrix rows plus aggregate leak gate in {manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

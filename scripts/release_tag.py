"""Read-only exact release tag/source/version admission; no publishing or builds."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib
from docker_publish_ref import classify
from native_repro import DEFAULT_RUST_TOOLCHAIN
from release_ci_gate import check_release_ci
from release_source import source_identity
from release_certification import CertificationError, load_and_validate

ROOT = Path(__file__).resolve().parent.parent
OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
PENDING_CI = re.compile(r"CI still running \((queued|requested|waiting|pending|in_progress)\)")


def git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, capture_output=True,
                            text=True, encoding="utf-8", errors="strict", timeout=30)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "Release Git query failed")
    return result.stdout.strip()


def admit_tag(root, tag):
    classify("tag", tag)
    try:
        commit = source_identity(root)
    except RuntimeError as error:
        raise ValueError(str(error)) from error
    tagged = git(root, "rev-parse", "--verify", "refs/tags/" + tag + "^{commit}")
    if not OID.fullmatch(commit) or tagged != commit:
        raise ValueError("Release tag does not identify the checked-out commit")
    package = tomllib.loads(git(root, "show", commit + ":qeli/Cargo.toml")).get("package", {})
    version = package.get("version")
    if not isinstance(version, str) or tag != "v" + version:
        raise ValueError("Release tag differs from committed Cargo version")
    return {"commit": commit, "version": version, "rust_toolchain": DEFAULT_RUST_TOOLCHAIN}


def admit_ci(root, tag, identity, wait_seconds=0):
    """Wait only for an otherwise valid exact-commit push CI that is pending."""
    deadline = time.monotonic() + wait_seconds
    while True:
        failures = check_release_ci(root, tag, by_commit=True)
        if admit_tag(root, tag) != identity:
            raise ValueError("Release source changed during CI admission")
        if not failures:
            return
        if (not wait_seconds or len(failures) != 1
                or PENDING_CI.fullmatch(failures[0]) is None):
            raise ValueError("; ".join(failures))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Timed out waiting for release CI: " + failures[0])
        print(f"Waiting for exact-commit CI ({int(remaining)}s remaining)", flush=True)
        time.sleep(min(30, remaining))
        # The source must remain pinned throughout the wait, not only when CI
        # eventually succeeds. A changed/dirty checkout cannot authorize a retry.
        if admit_tag(root, tag) != identity:
            raise ValueError("Release source changed while waiting for CI")
        if time.monotonic() >= deadline:
            raise ValueError("Timed out waiting for release CI: " + failures[0])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--require-ci", action="store_true", help="Require successful CI on this exact commit")
    parser.add_argument("--wait-ci", type=int, default=0, metavar="SECONDS",
                        help="Wait up to 3600 seconds for pending exact-commit CI; requires --require-ci")
    parser.add_argument("--require-certification", action="store_true",
                        help="Require current-source runtime certification before publication")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    if not 0 <= args.wait_ci <= 3600 or (args.wait_ci and not args.require_ci):
        parser.error("--wait-ci must be 0..3600 and requires --require-ci when nonzero")
    try:
        identity = admit_tag(args.repo, args.tag)
        if args.require_certification:
            manifest = args.repo / "release/certification" / (identity["version"] + ".json")
            _, failures = load_and_validate(manifest, args.repo)
            if failures:
                raise CertificationError("Release certification refused: " + "; ".join(failures))
            if admit_tag(args.repo, args.tag) != identity:
                raise ValueError("Release source changed during certification admission")
        if args.require_ci:
            admit_ci(args.repo, args.tag, identity, args.wait_ci)
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
                for key, value in identity.items():
                    stream.write(f"{key}={value}\n")
        print(json.dumps({"status": "PASS", **identity}, sort_keys=True))
        return 0
    except (OSError, ValueError, CertificationError, subprocess.SubprocessError) as error:
        print(f"Release publication refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

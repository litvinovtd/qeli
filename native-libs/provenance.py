#!/usr/bin/env python3
"""Check that the committed native cores were reproducibly built from THIS tree.

WHY. `native-libs/verify.sh` answers "do the two copies of each library match each other".
It cannot answer "does this binary correspond to the Rust source next to it" — and that is
the question that actually went wrong: the cores in this repository were built from the
0.7.12 source and stayed while `qeli/src` moved on, so every GUI client shipped an older
realtls / FFI core than the tree claimed. Nothing in review or CI could see it, because a
`.so` has no readable diff.

The source digest catches source/binary staleness. Reproducibility evidence additionally
binds each final binary to two byte-identical clean builds made in independent target
directories with the pinned build recipe. Updating the digest is refused until both lab
build scripts have produced valid evidence for every first-party native library.

Usage:
  python native-libs/provenance.py --check    # exit 1 if the cores are stale
  python native-libs/provenance.py --update   # after a DELIBERATE rebuild

Run from the repository root.
"""
import os
import json
from datetime import datetime, timezone
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from native_repro import BUILD_INPUTS
from native_repro import source_digest as reproducible_source_digest
from native_repro import validate_evidence

PROVENANCE = os.path.join("native-libs", "PROVENANCE")


def source_digest() -> str:
    """SHA256 over Rust sources, Cargo inputs and executable build recipes."""
    return reproducible_source_digest(".")


def recorded_digest() -> str | None:
    if not os.path.exists(PROVENANCE):
        return None
    with open(PROVENANCE, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("source-digest"):
                return line.split(":", 1)[1].strip()
    return None


def main() -> int:
    if not os.path.isdir(os.path.join("qeli", "src")):
        print("run this from the repository root", file=sys.stderr)
        return 2

    actual = source_digest()
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    if mode not in ("--check", "--update"):
        print("usage: provenance.py [--check|--update]", file=sys.stderr)
        return 2

    if mode == "--update":
        evidence_errors = validate_evidence(".", actual)
        if evidence_errors:
            print(
                "REFUSING TO UPDATE PROVENANCE: native builds lack valid A/B evidence.",
                file=sys.stderr,
            )
            for error in evidence_errors:
                print(f"  - {error}", file=sys.stderr)
            print(
                "Run both native lab build scripts before updating provenance.",
                file=sys.stderr,
            )
            return 1
        # Use the actual A/B source commits, not the possibly newer documentation HEAD.
        evidence = {}
        for platform in ("desktop", "android"):
            with open(f"native-libs/reproducibility/{platform}.json", encoding="utf-8") as stream:
                evidence[platform] = json.load(stream)
        commits = {value["source_commit"] for value in evidence.values()}
        base = next(iter(commits)) if len(commits) == 1 else ", ".join(
            f"{platform}={value['source_commit']}" for platform, value in evidence.items()
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "qeli/src", *BUILD_INPUTS],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if dirty:
            print(
                "REFUSING TO UPDATE PROVENANCE: native build inputs are dirty:\n"
                + dirty,
                file=sys.stderr,
            )
            return 1
        with open(PROVENANCE, encoding="utf-8") as fh:
            text = fh.read()
        out = []
        for line in text.splitlines(keepends=True):
            if line.startswith("source-digest"):
                out.append(f"source-digest : {actual}\n")
            elif line.startswith("base-commit"):
                out.append(f"base-commit   : {base}\n")
            elif line.startswith("dirty-sources"):
                n = len(dirty.splitlines())
                out.append(f"dirty-sources : {n} file(s) modified vs base-commit at build time\n")
            elif line.startswith("toolchain"):
                out.append(
                    "toolchain     : pinned inventories in "
                    "native-libs/reproducibility/{desktop,android}.json\n"
                )
            elif line.startswith("built-on"):
                # source_date_epoch is a reproducibility input, not a wall-clock build time.
                # Do not keep a stale hard-coded date or guess a compilation time on refresh.
                out.append("built-on      : lab .10/.11; independent Windows/macOS and Android A/B jobs; execution timestamps are retained in build journals\n")
            elif line.startswith(("recorded-at", "source-epoch")):
                continue
            else:
                out.append(line)
        out.append("\nrecorded-at   : " + datetime.now(timezone.utc).isoformat() + " (provenance refresh, not compilation time)\n")
        out.append("source-epoch  : " + ", ".join(
            f"{platform}={value['source_date_epoch']}" for platform, value in evidence.items()
        ) + " (reproducibility input, not build time)\n")
        with open(PROVENANCE, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(out)
        print(f"recorded source-digest {actual}")
        return 0

    expected = recorded_digest()
    if expected is None:
        print(f"MISSING: {PROVENANCE} has no source-digest line", file=sys.stderr)
        return 1
    if expected == actual:
        evidence_errors = validate_evidence(".", actual)
        if evidence_errors:
            print("INVALID NATIVE REPRODUCIBILITY EVIDENCE.", file=sys.stderr)
            for error in evidence_errors:
                print(f"  - {error}", file=sys.stderr)
            return 1
        print("OK: native cores match this source and independent A/B builds.")
        return 0
    print(
        "STALE NATIVE CORES.\n"
        f"  recorded : {expected}\n"
        f"  actual   : {actual}\n"
        "\n"
        "A native source or build recipe has changed since the .so/.dll/.dylib build;\n"
        "the GUI clients may ship cores that do not match this tree. Rebuild them:\n"
        "  python scripts/build_native_libs_p4.py   # windows + macos, on lab .10\n"
        "  python scripts/build_android_so_11.py    # android, on lab .11\n"
        "then `bash native-libs/verify.sh --update` and\n"
        "`python native-libs/provenance.py --update`.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

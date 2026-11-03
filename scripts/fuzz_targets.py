"""Read the registered cargo-fuzz targets for smoke and nightly CI."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
NAME = re.compile(r"[a-z][a-z0-9_-]*")


def registered_targets(manifest: Path) -> list[str]:
    manifest = Path(manifest)
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    package = data.get("package", {})
    if package.get("metadata", {}).get("cargo-fuzz") is not True:
        raise ValueError("manifest is not a cargo-fuzz package")
    bins = data.get("bin")
    if not isinstance(bins, list) or not bins:
        raise ValueError("at least one registered fuzz target is required")
    names = []
    base = manifest.parent.resolve()
    for target in bins:
        name, path = target.get("name"), target.get("path")
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError("fuzz target name must be safe for Cargo and CI output")
        if name in names:
            raise ValueError(f"duplicate fuzz target: {name}")
        if not isinstance(path, str) or not path or "\\" in path:
            raise ValueError(f"explicit relative source path required: {name}")
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"source path must stay in the fuzz package: {name}")
        source = base / relative
        if not source.resolve().is_relative_to(base) or not source.is_file():
            raise ValueError(f"missing or external source for fuzz target: {name}")
        names.append(name)
    if len(names) > 256:
        raise ValueError("fuzz target count exceeds the GitHub matrix limit")
    return sorted(names)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "qeli/fuzz/Cargo.toml")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        targets = registered_targets(args.manifest)
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write("targets=" + json.dumps(targets, separators=(",", ":")) + "\n")
        print("\n".join(targets))
        return 0
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f"Fuzz target inventory refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Exercise production build path checks with every build/remove tool mocked.

No Xcode, publish, signing or recursive deletion is run. The fixture is created
inside the supplied audit directory and every shell runs the original build.sh.
"""
from __future__ import annotations
import argparse
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent

def run(bash: str, fixture_root: Path, source: Path, workflow: Path) -> list[tuple[str, bool]]:
    directory = Path(tempfile.mkdtemp(prefix="qeli-build-path-", dir=fixture_root)).resolve()
    assert directory.parent == fixture_root.resolve()
    results = []
    try:
        project = directory / "qeli-mac" / "per-app"
        project.mkdir(parents=True)
        build = project / "build.sh"
        build.write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))
        (project / "generate_project.sh").write_text("#!/bin/sh\nxcodegen generate\n", encoding="utf-8")
        mocks = directory / "tools"; mocks.mkdir()
        events = directory / "commands.log"
        for name in ("rm", "mkdir", "cp", "chmod", "xcodebuild", "xcodegen"):
            (mocks / name).write_text('#!/bin/sh\nprintf "%s\\n" "' + name + ' $*" >> "$QELI_TEST_EVENTS"\n', encoding="utf-8")
        (mocks / "uname").write_text("#!/bin/sh\necho Darwin\n", encoding="utf-8")
        for arch in ("arm64", "x86_64"):
            products = project / "build" / arch / "Build" / "Products" / "Release"
            products.mkdir(parents=True)
            policy = products / "QeliPerAppPolicyTests"
            policy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        # Set executable permissions with real chmod only on known fixture files.
        subprocess.run([bash, "-c", 'chmod +x "$1"/tools/* "$1"/qeli-mac/per-app/*.sh "$1"/qeli-mac/per-app/build/*/Build/Products/Release/QeliPerAppPolicyTests', "fixture", directory.as_posix()], check=True)
        posix = subprocess.check_output([bash, "-c", 'cd "$1" && pwd -P', "fixture", directory.as_posix()], text=True).strip()
        dist = posix + "/qeli-mac/dist"
        env = dict(os.environ, QELI_TEST_EVENTS=events.as_posix())
        cases = [
            ("arm64 leaf", dist + "/per-app-arm64", "arm64", True),
            ("x86 leaf", dist + "/per-app-x86_64", "x86_64", True),
            ("root refused", "/", "arm64", False),
            ("dist itself refused", dist, "arm64", False),
            ("parent traversal refused", dist + "/../victim", "arm64", False),
            ("nested parent traversal refused", dist + "/per-app-arm64/../../victim", "arm64", False),
            ("dot leaf refused", dist + "/.", "arm64", False),
            ("other leaf refused", dist + "/arbitrary", "arm64", False),
            ("mismatched architecture leaf refused", dist + "/per-app-x86_64", "arm64", False),
            ("unknown architecture refused", dist + "/per-app-arm64", "unknown", False),
        ]
        command = re.search(r'run: ./per-app/build\.sh "([^"\n]+)" arm64', workflow.read_text(encoding="utf-8"))
        if command is None: raise ValueError("missing macOS CI per-app build command")
        ci_output = command[1].replace("$PWD", posix + "/qeli-mac")
        cases.append(("CI production output leaf", ci_output, "arm64", True))
        for name, output, arch, accepted in cases:
            events.unlink(missing_ok=True)
            result = subprocess.run([bash, "-c", 'export PATH="$1/tools:$PATH"; /bin/sh "$1/qeli-mac/per-app/build.sh" "$2" "$3"', "fixture", posix, output, arch], env=env, capture_output=True, text=True, timeout=10)
            commands = events.read_text(encoding="utf-8") if events.exists() else ""
            ok = (result.returncode == 0 and "rm -rf " in commands) if accepted else (result.returncode != 0 and not commands)
            results.append((name, ok))
        # POSIX symlinks on hosts that support them; missing support is explicit SKIP.
        target = directory / "victim"; target.mkdir()
        link = directory / "qeli-mac" / "dist"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            print("[SKIP] symlink fixture unavailable on this host")
        else:
            events.unlink(missing_ok=True)
            result = subprocess.run([bash, "-c", 'export PATH="$1/tools:$PATH"; /bin/sh "$1/qeli-mac/per-app/build.sh" "$2" arm64', "fixture", posix, dist + "/per-app-arm64"], env=env, capture_output=True, text=True, timeout=10)
            results.append(("symlinked dist refused", result.returncode != 0 and not events.exists()))
            link.unlink()
        return results
    finally:
        # This one directory was exclusively created here; never follow a link during cleanup.
        assert directory.resolve().parent == fixture_root.resolve()
        shutil.rmtree(directory)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=ROOT / "qeli-mac/per-app/build.sh")
    parser.add_argument("--workflow", type=Path, default=ROOT / ".github/workflows/ci.yml")
    args = parser.parse_args()
    args.fixtures.mkdir(parents=True, exist_ok=True)
    checks = run(args.bash, args.fixtures, args.source, args.workflow)
    for name, ok in checks: print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"BUILD_PATH_CHECKS={len(checks)}; FAILED={sum(not ok for _, ok in checks)}")
    return 0 if all(ok for _, ok in checks) else 1

if __name__ == "__main__": raise SystemExit(main())

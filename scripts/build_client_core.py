#!/usr/bin/env python3
"""Build fresh development/CI native cores without rewriting release provenance.

Host output supports the C ABI and ConfigCore JNI (JVM tests). Android output replaces
all jniLibs inputs through QELI_NATIVE_JNI_DIR. Release A/B recipes remain authoritative
for committed distributable libraries; this script never changes their files/manifests.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
from native_repro import DEFAULT_ANDROID_NDK, DEFAULT_CARGO_NDK_VERSION

ROOT = Path(__file__).resolve().parent.parent

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--android", action="store_true")
    p.add_argument("--abis", nargs="+", choices=["arm64-v8a", "x86_64"], default=["arm64-v8a", "x86_64"])
    p.add_argument("--debug", action="store_true")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--github-env", action="store_true")
    a = p.parse_args()
    env = dict(os.environ)
    env["CARGO_PROFILE_RELEASE_PANIC"] = "unwind"
    target = Path(env.get("CARGO_TARGET_DIR", str(ROOT / "qeli/target"))).resolve()
    env["CARGO_TARGET_DIR"] = str(target)
    stage = target / "client-core" / ("android" if a.android else "host")
    stage.mkdir(parents=True, exist_ok=True)
    command = ["cargo"]
    if a.android:
        sdk = env.get("ANDROID_HOME") or env.get("ANDROID_SDK_ROOT")
        if "ANDROID_NDK_HOME" not in env and sdk:
            env["ANDROID_NDK_HOME"] = str(Path(sdk) / "ndk" / DEFAULT_ANDROID_NDK)
        if not Path(env.get("ANDROID_NDK_HOME", "/missing-ndk")).is_dir():
            p.error(f"Install Android NDK {DEFAULT_ANDROID_NDK} and cargo-ndk {DEFAULT_CARGO_NDK_VERSION}; set ANDROID_NDK_HOME")
        command += ["ndk", "--platform", "28", "-o", str(stage)]
        for abi in a.abis: command += ["-t", abi]
    command += ["build", "--manifest-path", str(ROOT / "qeli/Cargo.toml"), "--locked", "--no-default-features", "--features", "transport-core-ffi", "--lib"]
    if not a.debug: command += ["--release"]
    if a.offline: command += ["--offline"]
    # cargo-ndk reads project metadata before forwarding --manifest-path to cargo.
    subprocess.run(command, cwd=ROOT / "qeli", env=env, check=True)
    variables = {}
    if a.android:
        for abi in a.abis:
            shutil.copy2(stage / abi / "libqeli_core.so", stage / abi / "libqeli.so")
            (stage / abi / "libqeli_core.so").unlink()
        variables["QELI_NATIVE_JNI_DIR"] = str(stage)
    else:
        names = {"Windows": ("qeli_core.dll", "qeli.dll"), "Darwin": ("libqeli_core.dylib", "libqeli.dylib"), "Linux": ("libqeli_core.so", "libqeli.so")}
        source, name = names[platform.system()]
        output = stage / name
        shutil.copy2(target / ("debug" if a.debug else "release") / source, output)
        variables = {"QeliNativeCorePath": str(output), "QELI_CONFIG_NATIVE_LIBRARY": str(output)}
    for name, value in variables.items(): print(f"{name}={value}")
    if a.github_env:
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as f:
            for name, value in variables.items(): f.write(f"{name}={value}\n")

if __name__ == "__main__": main()

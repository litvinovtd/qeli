#!/usr/bin/env python3
"""Rebuild an APK on .11 from the current local source and pull it into dist.

Pushes the repo's committed jniLibs/*.so, syncs Kotlin/resources/gradle WITHOUT
wiping jniLibs, builds offline, then pulls the APK locally (rotating the previous one).
The default is debug; ``--release`` additionally requires a valid APK signature.
"""
import os, sys, posixpath, shlex, shutil
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from native_lab import connect_lab, pull_verified_artifact, remote_sha256
from native_repro import require_lab_password, sha256_file

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCAL = os.fspath(REPO_ROOT / "qeli-android")
CONFORMANCE = REPO_ROOT / "conformance"
REMOTE = "/root/android-project"
HOST = ("10.66.116.11", os.environ.get("QELI_LAB_USER", "root"))
# Build via the project's Gradle wrapper (version pinned in
# gradle/wrapper/gradle-wrapper.properties). AGP 9 requires
# Gradle >= 9.4.1, so the old standalone /root/gradle-8.11.1 can no longer apply
# the android plugin. The wrapper distribution is cached on .11.
SYNC_EXT = (
    ".kt", ".xml", ".kts", ".properties", ".pro", ".png", ".webp", ".json",
    ".jar", ".bat",
)
SYNC_FILES = {"gradlew"}
SKIP_DIRS = {"build", ".gradle", ".kotlin", "dist", ".idea", "jniLibs"}
SKIP_FILES = {"local.properties"}
# These source trees must be mirrors of the checkout. Merely overwriting files
# leaves deleted Kotlin classes/tests behind on the persistent Android builder,
# allowing stale code from an older branch to enter the APK or fail its tests.
# Keep jniLibs outside the list: step 1 installs the independently reproduced
# native cores there, and the lab's signing/local configuration lives elsewhere.
MIRRORED_SOURCE_TREES = (
    "app/src/androidTest",
    "app/src/main/kotlin",
    "app/src/main/res",
    "app/src/test",
)

DIST = os.path.join(LOCAL, "dist")
if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--release"):
    raise SystemExit("usage: rebuild_apk.py [--release]")
RELEASE = len(sys.argv) == 2
VARIANT = "release" if RELEASE else "debug"

def conn():
    return connect_lab(HOST[0], HOST[1], require_lab_password())

def sh(c, cmd, t=1200):
    return c.run(cmd, timeout=t)

c = conn(); sf = c.open_sftp()

# 1. Push the repo's committed .so so .11 builds with the in-repo native core.
print("=== 1. push repo jniLibs/*.so -> .11 ===")
for abi in ("arm64-v8a", "x86_64"):
    lp = os.path.join(LOCAL, "app", "src", "main", "jniLibs", abi, "libqeli.so")
    rp = f"{REMOTE}/app/src/main/jniLibs/{abi}/libqeli.so"
    sh(c, f"mkdir -p {posixpath.dirname(rp)}")
    sf.put(lp, rp)
    print(f"  [push] {abi}/libqeli.so ({os.path.getsize(lp)} bytes)")

# 2. Sync Kotlin/resources/gradle and the repo-level shared conformance fixtures in place
# (skip jniLibs so the freshly rebuilt .so stays). Android's JVM tests deliberately read
# the same fixtures as Rust/C#/Swift; leaving the lab's old copies behind can make a release
# fail or, worse, certify vectors from a different commit.
print("=== 2. sync sources + shared conformance (preserving jniLibs) ===")
for relative in MIRRORED_SOURCE_TREES:
    remote_tree = posixpath.join(REMOTE, relative)
    clean_output, clean_rc = sh(c, f"rm -rf -- {shlex.quote(remote_tree)}")
    if clean_rc != 0:
        raise RuntimeError(f"remote source cleanup failed for {relative}:\n{clean_output}")

sources = []
remote_directories = set()
for root, dirs, names in os.walk(LOCAL):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for nm in names:
        if nm in SKIP_FILES or (nm not in SYNC_FILES and not nm.endswith(SYNC_EXT)):
            continue
        full = os.path.join(root, nm)
        rel = os.path.relpath(full, LOCAL).replace(os.sep, "/")
        remote = posixpath.join(REMOTE, rel)
        sources.append((full, remote))
        remote_directories.add(posixpath.dirname(remote))
for fixture in sorted(CONFORMANCE.glob("*.json")):
    remote = posixpath.join(REMOTE, "conformance", fixture.name)
    sources.append((os.fspath(fixture), remote))
    remote_directories.add(posixpath.dirname(remote))
mkdir_output, mkdir_rc = sh(
    c,
    "mkdir -p " + " ".join(shlex.quote(path) for path in sorted(remote_directories)),
)
if mkdir_rc != 0:
    raise RuntimeError(f"remote source directory creation failed:\n{mkdir_output}")
for full, remote in sources:
    sf.put(full, remote)
print(f"  [sync] {len(sources)} files including shared conformance fixtures")
print("  [versionName on .11]:",
      sh(c, f"grep -E 'versionCode|versionName' {REMOTE}/app/build.gradle.kts")[0])

# 3. Build (clear any stale gradle lock first; offline).
assemble_task = "assembleRelease" if RELEASE else "assembleDebug"
print(f"=== 3. ./gradlew testDebugUnitTest {assemble_task} --offline ===")
sh(c, "pkill -9 -f GradleDaemon 2>/dev/null; rm -rf /root/.gradle/caches/journal-1 2>/dev/null; true")
out, rc = sh(c, f"cd {REMOTE} && chmod +x gradlew && ./gradlew clean testDebugUnitTest {assemble_task} --offline --no-daemon "
                f"--max-workers=1 -Dorg.gradle.vfs.watch=false "
                f"'-Dorg.gradle.jvmargs=-Xmx1536m -Dfile.encoding=UTF-8' 2>&1", t=1200)
print("\n".join(out.splitlines()[-80:]))
if rc != 0 or "BUILD SUCCESSFUL" not in out:
    print(f"[build] FAILED (rc={rc})"); c.close(); sys.exit(1)

apk = f"{REMOTE}/app/build/outputs/apk/{VARIANT}/app-{VARIANT}.apk"
print("[apk on .11]", sh(c, f"stat -c '%y %s bytes' {apk}")[0])
print("  [.so in apk]", sh(c, f"unzip -l {apk} | grep libqeli.so")[0])
# version from the built APK (if aapt is available)
aapt, _ = sh(c, "find /root/android-sdk/build-tools -name aapt 2>/dev/null | head -1")
if aapt:
    print("  [badging]", sh(c, f"{aapt} dump badging {apk} 2>/dev/null | grep -oE \"version(Code|Name)='[^']*'\" | tr '\\n' ' '")[0])
if RELEASE:
    apksigner, _ = sh(c, "find /root/android-sdk/build-tools -name apksigner 2>/dev/null | sort -V | tail -1")
    if not apksigner:
        print("[signing] FAILED: apksigner not found"); c.close(); sys.exit(1)
    signature, signature_rc = sh(c, f"{apksigner} verify --verbose --print-certs {apk} 2>&1")
    print("  [signing]", "verified" if signature_rc == 0 else signature)
    if signature_rc != 0:
        c.close(); sys.exit(1)

# 4. Pull into local dist/ (rotate the previous APK).
print("=== 4. pull APK -> local dist ===")
os.makedirs(DIST, exist_ok=True)
cur = os.path.join(DIST, f"app-{VARIANT}.apk")
digest = remote_sha256(c, apk)
if os.path.exists(cur) and sha256_file(cur) != digest:
    prev = os.path.join(DIST, f"app-{VARIANT}.prev.apk")
    if os.path.exists(prev):
        os.remove(prev)
    # Copy rather than move: a failed SFTP read must leave the current verified APK intact.
    shutil.copy2(cur, prev)
    print(f"  [backup] app-{VARIANT}.apk -> app-{VARIANT}.prev.apk")
size, pulled_digest, _changes = pull_verified_artifact(sf, apk, digest, LOCAL, (f"dist/app-{VARIANT}.apk",))
print(f"  [saved] {cur} ({size} bytes, sha256={pulled_digest})")
sf.close(); c.close()
print("[done]")

#!/usr/bin/env python3
"""Build an APK on .11 from one clean committed snapshot in a private checkout.

Each invocation owns its sources, Cargo target, Gradle project state and local
output directory. Shared tool/dependency caches use their normal locks. Failed
remote checkouts are retained for diagnosis; no service or shared source is reset.
Release signing properties are read from an explicit remote path (legacy default
/root/android-project/keystore.properties), copied privately, then removed.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tarfile

from native_lab import connect_lab, pull_verified_artifact, remote_sha256
from native_repro import require_lab_password, rust_toolchain, source_digest, validate_evidence

REPO_ROOT = Path(__file__).resolve().parent.parent
HOST = ("10.66.116.11", os.environ.get("QELI_LAB_USER", "root"))
SOURCE_PATHS = ("qeli", "qeli-android", "conformance", "LICENSE", "LICENSING.md")
REQUIRED_INPUTS = {
    "LICENSE", "LICENSING.md", "qeli/Cargo.toml", "qeli/Cargo.lock", "qeli/.cargo/config.toml",
    "qeli-android/gradlew", "qeli-android/buildscript-gradle.lockfile",
    "qeli-android/app/gradle.lockfile", "qeli-android/gradle/verification-metadata.xml",
    "qeli-android/gradle/wrapper/gradle-wrapper.jar",
    "qeli-android/gradle/wrapper/gradle-wrapper.properties",
    "qeli-android/gradle/security-versions.properties",
    "qeli-android/app/src/main/jniLibs/arm64-v8a/libqeli.so",
    "qeli-android/app/src/main/jniLibs/x86_64/libqeli.so",
    "qeli/third-party-notices/rust/INDEX.tsv",
    "qeli/third-party-notices/toolchain-sources.tsv",
}
SIGNING_SOURCE = r"""import java.nio.file.*; import java.io.*; import java.util.*;
class PrepareSigning {
 public static void main(String[] a) {
  try {
   Path original=Path.of(a[0]).toRealPath(); Properties p=new Properties();
   try(InputStream in=Files.newInputStream(original)){p.load(in);}
   for(String key: new String[]{"storeFile","storePassword","keyAlias","keyPassword"})
    if(p.getProperty(key)==null || p.getProperty(key).isEmpty()) throw new IOException();
   Path key=original.getParent().resolve(p.getProperty("storeFile")).toRealPath();
   if(!Files.isRegularFile(key)) throw new IOException();
   p.setProperty("storeFile",key.toString());
   try(OutputStream out=Files.newOutputStream(Path.of(a[1]))){p.store(out,"private signing input");}
  } catch(Exception e){System.err.println("Cannot prepare signing properties");System.exit(1);}
 }
}
"""


def git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError("Git snapshot query failed: " + result.stderr.decode("utf8", "replace").strip())
    return result.stdout


def identity(root):
    commit = git(root, "rev-parse", "HEAD^{commit}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise RuntimeError("Invalid APK source commit")
    if git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise RuntimeError("APK build requires clean committed source")
    if any(row and (chr(row[0]).islower() or row[:1] == b"S") for row in git(root, "ls-files", "-v", "-z").split(b"\0")):
        raise RuntimeError("APK source has hidden Git trust flags")
    return commit


def prepare_snapshot(root=REPO_ROOT):
    root = Path(root)
    commit = identity(root)
    digest = source_digest(root)
    errors = validate_evidence(root, digest)
    if errors:
        raise RuntimeError("APK native provenance refused: " + "; ".join(errors))
    entries = {}
    for row in git(root, "ls-tree", "-r", "-z", commit, "--", *SOURCE_PATHS).split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        path = name.decode("utf8")
        if (mode not in ("100644", "100755") or kind != "blob" or
                str(PurePosixPath(path)) != path or PurePosixPath(path).is_absolute() or
                any(part in (".", "..") for part in path.split("/")) or
                "\\" in path or any(ord(char) < 32 or ord(char) == 127 for char in path)):
            raise RuntimeError("Unsafe APK snapshot member")
        entries[path] = oid
    if not REQUIRED_INPUTS <= entries.keys() or not any(path.startswith("conformance/") and path.endswith(".json") for path in entries):
        raise RuntimeError("Missing APK snapshot inputs: locks, JNI, notices or conformance")
    archive = git(root, "archive", "--format=tar", commit, "--", *SOURCE_PATHS)
    if len(archive) > 256 * 1024 * 1024:
        raise RuntimeError("APK snapshot exceeds 256 MiB")
    hashes = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        for member in stream:
            if member.isdir():
                if member.name.rstrip("/") not in {str(PurePosixPath(path).parent) for path in entries} and not any(path.startswith(member.name.rstrip("/")+"/") for path in entries):
                    raise RuntimeError("Unexpected APK snapshot directory")
                continue
            if not member.isfile() or member.name not in entries or member.name in hashes:
                raise RuntimeError("Unexpected/duplicate APK snapshot member")
            data = stream.extractfile(member).read()
            algorithm = "sha1" if len(entries[member.name]) == 40 else "sha256"
            oid = hashlib.new(algorithm, f"blob {len(data)}\0".encode()+data).hexdigest()
            if oid != entries[member.name]:
                raise RuntimeError("Git archive transformed a committed APK input")
            hashes[member.name] = hashlib.sha256(data).hexdigest()
    if hashes.keys() != entries.keys() or identity(root) != commit:
        raise RuntimeError("APK source changed or archive omitted inputs")
    return dict(commit=commit, native_source_digest=digest, archive=archive,
                archive_sha256=hashlib.sha256(archive).hexdigest(), files=hashes)


def conn():
    return connect_lab(HOST[0], HOST[1], require_lab_password())


def sh(c, cmd, t=1200):
    return c.run(cmd, timeout=t)


def deploy_snapshot(c, sf, snapshot):
    remote = c.checked("mktemp -d /var/tmp/qeli-apk-build.XXXXXXXX", "private APK checkout", 30)
    if not re.fullmatch(r"/var/tmp/qeli-apk-build\.[A-Za-z0-9]{8}", remote):
        raise RuntimeError("Invalid private APK checkout")
    print("[private checkout]", remote, flush=True)
    for name, data in [
        ("source.tar", snapshot["archive"]),
        ("source.sha256", "".join(f"{sha}  {path}\n" for path, sha in sorted(snapshot["files"].items())).encode()),
        ("SOURCE.json", json.dumps({key: value for key, value in snapshot.items() if key != "archive"}, sort_keys=True).encode()),
    ]:
        with sf.open(remote+"/"+name, "wb") as output:
            output.write(data)
    if remote_sha256(c, remote+"/source.tar") != snapshot["archive_sha256"]:
        raise RuntimeError("APK source upload SHA mismatch")
    c.checked(f"tar -xf {shlex.quote(remote+'/source.tar')} -C {shlex.quote(remote)}", "extract committed APK snapshot", 60)
    c.checked(f"cd {shlex.quote(remote)} && sha256sum --status -c source.sha256", "verify committed APK inputs", 60)
    return remote


def build(c, sf, release=False, snapshot=None, signing_properties=None, offline=True, gradle_user_home=None, android_sdk="/root/android-sdk"):
    snapshot = prepare_snapshot() if snapshot is None else snapshot
    remote = deploy_snapshot(c, sf, snapshot)
    project = remote+"/qeli-android"
    crate = remote+"/qeli"
    signing_dest = project+"/keystore.properties"
    try:
        if release:
            signing_properties = signing_properties or "/root/android-project/keystore.properties"
            if not signing_properties.startswith("/") or any(ord(char) < 32 for char in signing_properties):
                raise RuntimeError("Signing properties must be an absolute remote path")
            with sf.open(remote+"/PrepareSigning.java", "wb") as output:
                output.write(SIGNING_SOURCE.encode())
            # umask protects the private copy; paths are logged, passwords never are.
            c.checked("umask 077; java " + shlex.quote(remote+"/PrepareSigning.java") + " " +
                      shlex.quote(signing_properties) + " " + shlex.quote(signing_dest), "prepare private APK signing", 60)
        host_core = crate+"/target/debug/libqeli_core.so"
        command = (f"export PATH=/root/.cargo/bin:$PATH CARGO_TARGET_DIR={shlex.quote(crate+'/target')}; cd {shlex.quote(crate)} && "
                   f"timeout --signal=TERM --kill-after=30s 1200s cargo +{rust_toolchain()} build "
                   "--locked --offline --jobs 1 --no-default-features --features transport-core-ffi --lib")
        output, rc = sh(c, command)
        print("\n".join(output.splitlines()[-35:]))
        if rc:
            raise RuntimeError(f"Host core build failed (rc={rc}); retained {remote}")
        exports, rc = sh(c, f"nm -D {shlex.quote(host_core)} | grep -c 'Java_com_qeli_ConfigCore_nativeRequest$'")
        if rc or exports.strip() != "1":
            raise RuntimeError("Host core missing ConfigCore JNI export")
        variant = "release" if release else "debug"
        task = "assembleRelease" if release else "assembleDebug"
        cache = "" if gradle_user_home is None else "GRADLE_USER_HOME="+shlex.quote(gradle_user_home)+" "
        mode = "--offline " if offline else ""
        command = (f"cd {shlex.quote(project)} && chmod +x gradlew && "
                   f"{cache}QELI_NATIVE_JNI_DIR={shlex.quote(project+'/app/src/main/jniLibs')} "
                   f"ANDROID_HOME={shlex.quote(android_sdk)} QELI_CONFIG_NATIVE_LIBRARY={shlex.quote(host_core)} "
                   f"timeout --signal=TERM --kill-after=30s 1200s ./gradlew testDebugUnitTest {task} "
                   f"{mode}--no-daemon --max-workers=1 -Dorg.gradle.vfs.watch=false "
                   "'-Dorg.gradle.jvmargs=-Xmx1536m -Dfile.encoding=UTF-8' 2>&1")
        output, rc = sh(c, command)
        print("\n".join(output.splitlines()[-80:]))
        if rc or "BUILD SUCCESSFUL" not in output:
            raise RuntimeError(f"APK build failed (rc={rc}); retained {remote}")
        artifact = project+f"/app/build/outputs/apk/{variant}/app-{variant}.apk"
        if release:
            signer = c.checked(f"find {shlex.quote(android_sdk+'/build-tools')} -name apksigner -type f | sort -V | tail -1", "find apksigner", 30)
            if not signer:
                raise RuntimeError("apksigner not found")
            c.checked(f"{shlex.quote(signer)} verify --verbose --print-certs {shlex.quote(artifact)}", "APK signature verification", 60)
        c.checked(f"cd {shlex.quote(remote)} && sha256sum --status -c source.sha256", "source inputs preserved after build", 60)
        digest = remote_sha256(c, artifact)
        # Unique local publication: simultaneous builds cannot overwrite a current/prev APK.
        local_run = "dist/"+snapshot["commit"]+"-"+remote.rsplit(".", 1)[1]
        relative = local_run+f"/app-{variant}.apk"
        size, pulled_digest, _changes = pull_verified_artifact(sf, artifact, digest, REPO_ROOT/"qeli-android", (relative,))
        receipt = dict(source_commit=snapshot["commit"], source_archive_sha256=snapshot["archive_sha256"],
                       native_source_digest=snapshot["native_source_digest"], remote_root=remote,
                       artifact_sha256=pulled_digest, size=size, variant=variant,
                       local_artifact=str(REPO_ROOT/"qeli-android"/relative), source_files=len(snapshot["files"]))
        target = REPO_ROOT/"qeli-android"/local_run/"BUILD.json"
        target.write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf8", newline="\n")
        print("[saved]", receipt["local_artifact"], flush=True)
        return receipt
    finally:
        if release:
            c.checked("rm -f -- "+shlex.quote(signing_dest), "remove private signing properties", 30)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--online", action="store_true", help="allow missing Gradle dependencies to download under strict locks/checksums")
    parser.add_argument("--gradle-user-home", help="absolute remote dependency cache directory")
    parser.add_argument("--android-sdk", default="/root/android-sdk", help="absolute remote Android SDK directory")
    parser.add_argument("--signing-properties", help="absolute remote keystore.properties path; --release only")
    args = parser.parse_args(argv)
    if args.signing_properties and not args.release:
        parser.error("--signing-properties requires --release")
    if args.signing_properties and (not args.signing_properties.startswith("/") or any(ord(char) < 32 for char in args.signing_properties)):
        parser.error("--signing-properties requires an absolute remote path")
    if args.gradle_user_home and (not args.gradle_user_home.startswith("/") or any(ord(char) < 32 for char in args.gradle_user_home)):
        parser.error("--gradle-user-home requires an absolute remote path")
    if not args.android_sdk.startswith("/") or any(ord(char) < 32 for char in args.android_sdk):
        parser.error("--android-sdk requires an absolute remote path")
    snapshot = prepare_snapshot(REPO_ROOT)  # Refuse dirty/stale inputs before SSH.
    connection = conn()
    sftp = None
    try:
        sftp = connection.open_sftp()
        build(connection, sftp, args.release, snapshot, args.signing_properties, offline=not args.online, gradle_user_home=args.gradle_user_home, android_sdk=args.android_sdk)
        return 0
    finally:
        try:
            if sftp is not None:
                sftp.close()
        finally:
            connection.close()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())

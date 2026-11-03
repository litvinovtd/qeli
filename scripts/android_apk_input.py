"""Explicit, source-bound debug APK admission for Android lab E2E scripts."""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shlex

from native_lab import LabConnection, remote_sha256
from native_repro import source_digest, validate_evidence
from rebuild_apk import REPO_ROOT, SOURCE_PATHS, git, identity


@dataclass(frozen=True)
class ApkInput:
    source_commit: str
    sha256: str
    payload: bytes


def read_apk_receipt(path, root=REPO_ROOT):
    """Freeze the admitted bytes before SSH; never select latest/shared APK implicitly."""
    path = Path(path)
    if path.stat().st_size > 64 * 1024:
        raise ValueError("APK receipt exceeds 64 KiB")
    receipt = json.loads(path.read_text(encoding="utf8"))
    if not isinstance(receipt, dict) or receipt.get("variant") != "debug":
        raise ValueError("Android E2E requires a debug APK receipt")
    commit = receipt.get("source_commit", "")
    digest = receipt.get("artifact_sha256", "")
    if not isinstance(commit,str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}",commit):
        raise ValueError("Invalid APK source commit")
    if not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{64}",digest):
        raise ValueError("Invalid APK SHA256")
    size = receipt.get("size")
    if type(size) is not int or not 0 < size <= 128 * 1024 * 1024:
        raise ValueError("Invalid APK size")
    # Sibling publication survives copying a whole build directory to another checkout.
    apk = path.parent / "app-debug.apk"
    if apk.stat().st_size != size:
        raise ValueError("APK size differs from its receipt")
    data = apk.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("APK SHA256 differs from its receipt")
    head = identity(root)
    if git(root,"diff","--name-only",commit,head,"--",*SOURCE_PATHS).strip():
        raise ValueError("APK selected source inputs differ from current HEAD")
    native_digest = source_digest(root)
    if receipt.get("native_source_digest") != native_digest or validate_evidence(root,native_digest):
        raise ValueError("APK native provenance differs from current inputs")
    return ApkInput(commit,digest,data)


def read_cli(argv=None, *, kill_switch=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk-receipt",required=True,type=Path,help="local BUILD.json beside the exact app-debug.apk")
    if kill_switch:
        parser.add_argument("--kill-switch",action="store_true")
    args = parser.parse_args(argv)
    try:
        args.apk = read_apk_receipt(args.apk_receipt)
    except (OSError,ValueError,RuntimeError) as error:
        parser.error(str(error))
    print(f"[APK input] source={args.apk.source_commit} SHA256={args.apk.sha256}",flush=True)
    return args


def install_verified_apk(client, artifact: ApkInput, adb="/root/android-sdk/platform-tools/adb"):
    """Upload one immutable blob; refuse SHA/status failures before any VPN setup."""
    connection = LabConnection(client)
    remote = connection.checked("mktemp -d /var/tmp/qeli-apk-test.XXXXXXXX","private APK install input",30)
    if not re.fullmatch(r"/var/tmp/qeli-apk-test\.[A-Za-z0-9]{8}",remote):
        raise RuntimeError("Invalid private APK staging directory")
    target = remote+"/app-debug.apk"
    try:
        with client.open_sftp() as sftp:
            with sftp.open(target,"wb") as output:
                output.set_pipelined(True)
                output.write(artifact.payload)
        if remote_sha256(connection,target) != artifact.sha256:
            raise RuntimeError("Uploaded APK SHA256 mismatch; installation refused")
        command = ("timeout --signal=TERM --kill-after=15s 180s "+shlex.quote(adb)+
                   " install -r -d "+shlex.quote(target))
        output = connection.checked(command,"install exact APK",210)
        if not re.search(r"(?m)^Success\s*$",output) or re.search(r"(?m)^Failure(?:\s|\[)",output):
            raise RuntimeError("ADB did not confirm successful APK installation: "+output[-1000:])
        return output
    finally:
        # Only the exact owned blob/directory; never alter the shared source or cache.
        connection.checked("rm -f -- "+shlex.quote(target)+" && rmdir -- "+shlex.quote(remote),"remove private APK install input",30)

"""Private committed-source gate for the two 32-bit standalone router targets.

No artifacts are published. The remote checkout is retained for inspection,
matching the router build helpers; the caller always closes its SSH connection.
"""
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

from native_lab import remote_sha256
from router_artifact import validate_router_elf
from router_source import (create_router_checkout, sync_router_source,
                           require_router_source_ready, restrict_router_crate_types)
from router_toolchain import ARCH_TARGETS, ensure_router_toolchain, router_build_command

TARGETS = {arch: ARCH_TARGETS[arch] for arch in ("armv7", "mipsel")}
RECIPE_INPUTS = ("qeli", "scripts/release_preflight.py", "scripts/router_release_gate.py",
                 "scripts/release_ci_gate.py", "scripts/router_toolchain.py",
                 "scripts/router_source.py", "scripts/router_artifact.py",
                 "scripts/native_lab.py", "scripts/native_repro.py", "scripts/ssh_hostkey.py",
                 "scripts/ssh_command.py")


def committed_crate_archive(root):
    """Freeze one HEAD before upload; preserve all Git bytes, including binary CR."""
    root = Path(root)
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--", *RECIPE_INPUTS], cwd=root, text=True)
    if dirty.strip():
        raise RuntimeError("router release gate requires committed source and recipe inputs")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root,
                                     text=True).strip()
    archive = subprocess.check_output(["git", "archive", "--format=tar", commit, "qeli"],
                                      cwd=root)
    return commit, archive


def verify_router_release(connection, repo_root, snapshot=None):
    """Build/admit both 32-bit clients through the shared pinned router policy."""
    commit, archive = committed_crate_archive(repo_root) if snapshot is None else snapshot
    with tempfile.TemporaryDirectory(prefix="qeli-router-release-") as temporary:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for member in tar.getmembers():
                parts = Path(member.name).parts
                if (not parts or parts[0] != "qeli" or member.name.startswith("/")
                        or ".." in parts or "\\" in member.name
                        or not (member.isfile() or member.isdir())):
                    raise RuntimeError("unsafe entry in committed router source archive")
            tar.extractall(temporary, filter="data")
        remote = create_router_checkout(connection.client, "openwrt")
        count = sync_router_source(connection.client, Path(temporary)/"qeli", remote)
        require_router_source_ready(connection.client, remote)
    ensure_router_toolchain(connection.client, TARGETS.values())
    restrict_router_crate_types(connection.client, remote)
    results = []
    for arch, target in TARGETS.items():
        command = "export PATH=/root/.cargo/bin:$PATH; " + router_build_command(remote, target)
        row = {"arch": arch, "target": target, "command": command}
        try:
            output, rc = connection.run(command, timeout=1800)
            if rc:
                raise RuntimeError(f"build failed (rc={rc}):\n{output[-4000:]}")
            artifact = remote+"/target/"+target+"/release/qeli-client"
            expected = remote_sha256(connection, artifact)
            with connection.open_sftp() as sftp:
                with sftp.open(artifact, "rb") as stream:
                    data = stream.read()
            if hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError("router artifact changed after remote SHA verification")
            row.update(status="PASS", artifact_sha256=expected,
                       size=len(data), elf=validate_router_elf(data, target))
        except (OSError, RuntimeError) as error:
            row.update(status="FAIL", error=str(error))
        results.append(row)
    return {"source_commit": commit, "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "remote_root": remote, "source_files": count, "results": results}

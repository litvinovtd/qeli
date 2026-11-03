"""Maintainer-only host build gate for Keenetic client feature isolation.

This is a Linux host build, not router ABI/firmware qualification. Every run uses
its own private /var/tmp source/target directory and leaves services untouched.
The failed or successful checkout is retained for inspection; remove it explicitly
when no longer needed. Credentials: QELI_LAB_PASS; optional QELI_LAB_SERVER/USER.
Run: python scripts/keenetic_verify.py. All builds use the committed lockfile and
one compiler job. Missing credentials exit2; any verification failure exits1.
"""
import os
from pathlib import Path
import re
import shlex
import sys

from native_lab import connect_lab, remote_sha256
from router_source import sync_router_source, require_router_source_ready
from router_toolchain import ROUTER_RUST, router_host_cargo_prefix

LOCAL_ROOT = Path(__file__).resolve().parents[1] / "qeli"
CLIENT_FEATURES = "--no-default-features --features client-bin"
SOURCE_TEMPLATE = "/var/tmp/qeli-keenetic-verify.XXXXXX"


def client_graph_without_ring(output):
    """Require a successful forward graph, not a reverse-query error message.

    Caller checks cargo exit status first. Normal/build edges exclude dev-only
    dependencies. Unknown text fails closed rather than being treated as absence.
    """
    packages = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line == "[build-dependencies]":
            continue
        match = re.fullmatch(r"([A-Za-z0-9_-]+) v\S+(?: .*)?", line)
        if match is None:
            raise RuntimeError("unrecognized cargo dependency graph output")
        packages.append(match.group(1))
    if not packages or packages[0] != "qeli":
        raise RuntimeError("client dependency graph is empty or has the wrong root")
    if "ring" in packages:
        raise RuntimeError("ring is present in the client dependency graph")
    return True


def verify(connection, local_root=LOCAL_ROOT):
    # mktemp creates a0700 run directory; validate its output before managed sync.
    remote_root = connection.checked(
        f"mktemp -d {shlex.quote(SOURCE_TEMPLATE)}", "create isolated verification checkout", timeout=30)
    if re.fullmatch(r"/var/tmp/qeli-keenetic-verify\.[A-Za-z0-9]{6,}", remote_root) is None:
        raise RuntimeError("invalid isolated verification checkout path")
    print("Verification checkout:", remote_root)
    count = sync_router_source(connection.client, local_root, remote_root)
    require_router_source_ready(connection.client, remote_root)
    print("Synced source files:", count)
    prefix = ("export PATH=/root/.cargo/bin:$PATH; "
              f"cd {shlex.quote(remote_root)} && ")
    cargo = router_host_cargo_prefix(remote_root)
    print(connection.checked(prefix + f"rustc +{ROUTER_RUST} --version && " + cargo + " --version",
                             "host toolchain inventory", timeout=30))
    commands = (
        ("server_build", "cargo build --locked --release --features jemalloc --bin qeli --jobs 1"),
        ("unit_tests", "cargo test --locked --lib --jobs 1"),
        ("client_build", f"cargo build --locked --release --bin qeli-client {CLIENT_FEATURES} --jobs 1"),
        ("client_clippy", f"cargo clippy --locked --bin qeli-client {CLIENT_FEATURES} --jobs 1 -- -D warnings"),
    )
    for name, command in commands:
        output = connection.checked(prefix + cargo + " " + command.removeprefix("cargo "), name, timeout=1200)
        print("\n".join(output.splitlines()[-20:]))
        print(name + "=OK")
    graph = connection.checked(
        prefix + cargo + f" tree --locked {CLIENT_FEATURES} --edges normal,build --prefix none --format '{{p}}'",
        "client dependency graph", timeout=120)
    client_graph_without_ring(graph)
    artifact = remote_root + "/target/release/qeli-client"
    quoted = shlex.quote(artifact)
    header = connection.checked(
        f"test -s {quoted} && test -x {quoted} && readelf -h {quoted}",
        "nonempty executable ELF client artifact", timeout=30)
    if re.search(r"Magic:\s+7f 45 4c 46(?:\s|$)", header) is None:
        raise RuntimeError("client artifact is not an ELF executable")
    digest = remote_sha256(connection, artifact)
    if digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        raise RuntimeError("client artifact is empty")
    print("ring_absent=OK; host client ELF sha256=" + digest)
    return {"remote_root": remote_root, "artifact_sha256": digest, "kind": "Linux host build only"}


def main():
    password = os.environ.get("QELI_LAB_PASS", "")
    if not password:
        print("QELI_LAB_PASS not set — aborting", file=sys.stderr)
        return 2
    connection = None
    result = 0
    try:
        connection = connect_lab(os.environ.get("QELI_LAB_SERVER", "10.66.116.11"),
                                 os.environ.get("QELI_LAB_USER", "root"), password)
        verify(connection)
    except Exception as error:
        print(f"KEENETIC_PHASE1: FAIL ({error})", file=sys.stderr)
        result = 1
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception as error:
                print(f"KEENETIC_PHASE1: FAIL (SSH close: {error})", file=sys.stderr)
                result = 1
    if result == 0:
        print("KEENETIC_PHASE1: PASS (Linux host; router runtime/ABI unqualified)")
    return result


if __name__ == "__main__":
    sys.exit(main())

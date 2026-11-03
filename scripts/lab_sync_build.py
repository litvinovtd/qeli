"""Compatibility helpers for historical lab consumers.

The standalone host-mutating rebuild is retired. Importing this module
does not connect to SSH; callers remain responsible for isolation.
"""
_DIRECT_RUN_REFUSAL = 'RETIRED: the unisolated lab rebuild stopped working services, killed Qeli processes by name and overwrote a shared source tree. Use component tests, qeli/tests and GitHub Actions; run lab checks only in an owned isolated fixture.'


def main():
    raise SystemExit(_DIRECT_RUN_REFUSAL)


if __name__ == "__main__":
    main()

import os
import posixpath
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko
import ssh_hostkey

# Lab test-VM creds — override via env (QELI_LAB_SERVER / QELI_LAB_PASS) before
# publishing this repo. Defaults are the throwaway lab VMs, not production.
SERVER = (
    os.environ.get("QELI_LAB_SERVER", "10.66.116.10"),
    "root",
    os.environ.get("QELI_LAB_PASS", ""),
)
# Resolve from this script instead of a developer-specific checkout path. Worktrees are
# used for release preparation, and silently uploading an older sibling checkout makes a
# successful lab run actively misleading.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
LOCAL_ROOT = os.path.join(REPO_ROOT, "qeli")
REMOTE_ROOT = "/opt/qeli-src"

def conn(h):
    c = paramiko.SSHClient()
    ssh_hostkey.harden(c)
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c

def run(c, cmd, t=900):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    rc = o.channel.recv_exit_status()
    return rc, out.strip()

def sync_tree(c):
    sf = c.open_sftp()
    made = set()
    def ensure(remote_dir):
        if remote_dir in made or remote_dir in ("", "/"):
            return
        ensure(posixpath.dirname(remote_dir))
        try: sf.stat(remote_dir)
        except IOError:
            try: sf.mkdir(remote_dir)
            except IOError: pass
        made.add(remote_dir)
    files = []
    # Whole Rust source tree plus public C headers. The transport-core ABI tests compile
    # and inspect the checked-in header, so a lab sync that omits include/ tests a hybrid
    # tree rather than the local revision.
    # `debian/` and `config/` are release inputs: syncing only Rust sources can produce
    # a fresh binary inside a stale package skeleton. Keep the portable .deb build rooted
    # in exactly the same local tree as the executable it embeds.
    for subtree in (
        "src",
        "include",
        "debian",
        "config",
        "tests",
        "fuzz/fuzz_targets",
        "web-assets",
    ):
        root = os.path.join(LOCAL_ROOT, subtree)
        if not os.path.isdir(root):
            continue
        for dp, directories, fn in os.walk(root):
            # Dependencies and build outputs are recreated by the remote recipe. Uploading
            # a local node_modules one file at a time makes a source sync take minutes and
            # can also turn the lab into a Windows/npm hybrid tree.
            directories[:] = [
                name
                for name in directories
                if name not in {"node_modules", "target"}
            ]
            for f in fn:
                lp = os.path.join(dp, f)
                rel = os.path.relpath(lp, LOCAL_ROOT).replace("\\", "/")
                files.append((lp, posixpath.join(REMOTE_ROOT, rel)))
    # plus Cargo manifests
    for extra in ("Cargo.toml", "Cargo.lock", "deny.toml", "fuzz/Cargo.toml", "fuzz/README.md"):
        p = os.path.join(LOCAL_ROOT, extra)
        if os.path.exists(p):
            files.append((p, posixpath.join(REMOTE_ROOT, extra)))
    # The integration test intentionally validates the release REALITY template as shipped.
    # Keep that include_str! input current too; otherwise cargo test compiles a fresh test
    # against whatever /opt/release happened to contain from an older lab run.
    reality_template = os.path.join(
        os.path.dirname(LOCAL_ROOT), "release", "reality-tls", "server-reality.conf"
    )
    if os.path.isfile(reality_template):
        files.append((reality_template, "/opt/release/reality-tls/server-reality.conf"))
    # `include_str!("../../../conformance/...")` resolves beside REMOTE_ROOT. Leaving this
    # directory stale tests a hybrid tree: the Rust generator is current but `--check` reads
    # old fixtures. Keep the complete shared fixture directory in the source-of-build sync.
    conformance_root = os.path.join(os.path.dirname(LOCAL_ROOT), "conformance")
    remote_conformance = posixpath.join(posixpath.dirname(REMOTE_ROOT), "conformance")
    if os.path.isdir(conformance_root):
        for dp, _dn, fn in os.walk(conformance_root):
            for f in fn:
                lp = os.path.join(dp, f)
                rel = os.path.relpath(lp, conformance_root).replace("\\", "/")
                files.append((lp, posixpath.join(remote_conformance, rel)))
    n = 0
    for lp, rp in files:
        ensure(posixpath.dirname(rp))
        sf.put(lp, rp); n += 1
    sf.close()
    return n


def download_generated_css(c):
    """Bring the lab-generated embedded stylesheet back to the current checkout."""
    remote = posixpath.join(REMOTE_ROOT, "src/web/assets/app.css")
    local = os.path.join(LOCAL_ROOT, "src", "web", "assets", "app.css")
    sf = c.open_sftp()
    try:
        sf.get(remote, local)
    finally:
        sf.close()


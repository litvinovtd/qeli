"""Sync the current checkout's Rust and panel sources to the lab server.

The lab rebuilds the embedded panel CSS before rustfmt-check, release build, tests, and
clippy, so the executable and the source tree being validated always contain the same UI.

Pass `package` to additionally build the portable glibc-2.28 binary and `.deb`:
  python scripts/lab_sync_build.py package

  SERVER 10.66.116.10  (canonical /opt/qeli-src, systemd qeli-server.service)
"""
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
        for dp, _dn, fn in os.walk(root):
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

def main():
    package = "package" in sys.argv[1:]
    c = conn(SERVER)
    print("Connected to", SERVER[0])
    print("Stopping qeli-server.service for a clean tree...")
    run(c, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true", t=30)
    t0 = time.time()
    n = sync_tree(c)
    print(f"Synced {n} files to {REMOTE_ROOT} in {time.time()-t0:.0f}s")

    # NB: do NOT pipe cargo into `tail` — the pipe's exit status (tail's) masks
    # cargo's real rc. Capture cargo's rc directly and tail the text in Python.
    def tail(s, n):
        return "\n".join(s.splitlines()[-n:])

    print("\n=== npm ci + embedded panel CSS ===")
    rc_w, ow = run(
        c,
        f"cd {REMOTE_ROOT}/web-assets && npm ci --ignore-scripts && npm run build 2>&1",
    )
    print(tail(ow, 30)); print("panel css rc:", rc_w)
    if rc_w == 0:
        download_generated_css(c)
        print("Downloaded generated src/web/assets/app.css")

    print("\n=== cargo fmt --all -- --check ===")
    rc_m, om = run(
        c,
        f"cd {REMOTE_ROOT} && cargo fmt --all -- --check "
        "&& cargo +nightly fmt --manifest-path fuzz/Cargo.toml -- --check 2>&1",
    )
    print(tail(om, 30)); print("fmt rc:", rc_m)

    # The server release binary MUST carry jemalloc — glibc retains freed arenas and
    # the worker RSS plateaus ~180 MB under handshake churn (jemalloc bounds it ~60 MB
    # and returns pages to the OS). A plain `cargo build --release` produced a glibc
    # binary that got deployed to prod and silently reverted the allocator, so the
    # deployable artifact here is always built `--features jemalloc`. The DEFAULT
    # feature set (Windows/router-cdylib isolation) is still compiled below by
    # `cargo test --all` + `cargo clippy` — jemalloc must never leak into those.
    print("\n=== cargo build --release --features jemalloc ===")
    rc_b, ob = run(c, f"cd {REMOTE_ROOT} && cargo build --release --features jemalloc 2>&1")
    print(tail(ob, 25)); print("build rc:", rc_b)

    print("\n=== cargo test --all ===")
    rc_t, ot = run(c, f"cd {REMOTE_ROOT} && cargo test --all 2>&1")
    print(tail(ot, 40)); print("test rc:", rc_t)

    print("\n=== cargo clippy --all-targets -- -D warnings ===")
    rc_c, oc = run(c, f"cd {REMOTE_ROOT} && cargo clippy --all-targets -- -D warnings 2>&1")
    print(tail(oc, 30)); print("clippy rc:", rc_c)

    print("\n=== standalone fuzz harnesses compile ===")
    rc_z, oz = run(
        c,
        f"cd {REMOTE_ROOT} && cargo +nightly check --manifest-path fuzz/Cargo.toml --bins 2>&1",
    )
    print(tail(oz, 30)); print("fuzz harness rc:", rc_z)

    print("\n=== cargo-deny bans/sources ===")
    rc_d, od = run(
        c,
        f"cd {REMOTE_ROOT} && (command -v cargo-deny >/dev/null || "
        "cargo install cargo-deny --version 0.18.4 --locked) && "
        "cargo deny check bans sources 2>&1",
        t=1200,
    )
    print(tail(od, 40)); print("cargo-deny rc:", rc_d)

    print("\n=== cross-language conformance fixtures ===")
    rc_f, of = run(
        c,
        f"cd {REMOTE_ROOT} && cargo run --features conformance-gen "
        "--bin gen-conformance -- --check 2>&1",
    )
    print(tail(of, 30)); print("conformance rc:", rc_f)

    ver = run(c, f"{REMOTE_ROOT}/target/release/qeli --version 2>&1")[1]
    print("\nbinary version:", ver)

    rc_p = 0
    if package:
        print("\n=== make deb-portable (glibc 2.28 + jemalloc) ===")
        rc_p, op = run(c, f"cd {REMOTE_ROOT}/debian && make clean && make deb-portable 2>&1", t=2400)
        print(tail(op, 40)); print("package rc:", rc_p)

    # restart the service so the box is left in a sane state
    run(c, "systemctl start qeli-server.service 2>/dev/null; true", t=30)
    c.close()
    print("\n===== SUMMARY =====")
    print(
        f"fmt={'OK' if rc_m==0 else 'FAIL'} "
        f"panel-css={'OK' if rc_w==0 else 'FAIL'} "
        f"build={'OK' if rc_b==0 else 'FAIL'} "
        f"test={'OK' if rc_t==0 else 'FAIL'} "
        f"clippy={'OK' if rc_c==0 else 'FAIL'} "
        f"fuzz={'OK' if rc_z==0 else 'FAIL'} "
        f"deny={'OK' if rc_d==0 else 'FAIL'} "
        f"conformance={'OK' if rc_f==0 else 'FAIL'} "
        f"package={'OK' if rc_p==0 else 'FAIL'}"
    )
    print(
        "PHASE1_RESULT:",
        "PASS" if (rc_w == 0 and rc_m == 0 and rc_b == 0 and rc_t == 0 and rc_c == 0 and rc_z == 0 and rc_d == 0 and rc_f == 0 and rc_p == 0) else "FAIL",
    )
    if rc_w != 0 or rc_m != 0 or rc_b != 0 or rc_t != 0 or rc_c != 0 or rc_z != 0 or rc_d != 0 or rc_f != 0 or rc_p != 0:
        sys.exit(1)

if __name__ == "__main__":
    main()

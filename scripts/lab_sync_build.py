"""Phase 1: sync local qeli/src + Cargo to the lab server (/opt/qeli-src),
then build (release), test, and clippy. Validates this session's Rust edits.

  SERVER 10.66.116.10  (canonical /opt/qeli-src, systemd qeli-server.service)
"""
import os
import sys, io, os, posixpath, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

# Lab test-VM creds — override via env (QELI_LAB_SERVER / QELI_LAB_PASS) before
# publishing this repo. Defaults are the throwaway lab VMs, not production.
SERVER = (
    os.environ.get("QELI_LAB_SERVER", "10.66.116.10"),
    "root",
    os.environ.get("QELI_LAB_PASS", ""),
)
LOCAL_ROOT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE_ROOT = "/opt/qeli-src"

def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
    # whole src tree
    for dp, _dn, fn in os.walk(os.path.join(LOCAL_ROOT, "src")):
        for f in fn:
            files.append(os.path.join(dp, f))
    # plus Cargo manifests
    for extra in ("Cargo.toml", "Cargo.lock"):
        p = os.path.join(LOCAL_ROOT, extra)
        if os.path.exists(p): files.append(p)
    n = 0
    for lp in files:
        rel = os.path.relpath(lp, LOCAL_ROOT).replace("\\", "/")
        rp = posixpath.join(REMOTE_ROOT, rel)
        ensure(posixpath.dirname(rp))
        sf.put(lp, rp); n += 1
    sf.close()
    return n

def main():
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

    ver = run(c, f"{REMOTE_ROOT}/target/release/qeli --version 2>&1")[1]
    print("\nbinary version:", ver)

    # restart the service so the box is left in a sane state
    run(c, "systemctl start qeli-server.service 2>/dev/null; true", t=30)
    c.close()
    print("\n===== SUMMARY =====")
    print(f"build={'OK' if rc_b==0 else 'FAIL'} test={'OK' if rc_t==0 else 'FAIL'} clippy={'OK' if rc_c==0 else 'FAIL'}")
    print("PHASE1_RESULT:", "PASS" if (rc_b==0 and rc_t==0 and rc_c==0) else "FAIL")

if __name__ == "__main__":
    main()

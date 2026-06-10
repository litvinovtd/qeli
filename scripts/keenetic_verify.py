"""Verify the Keenetic Phase-1 refactor on the lab server (10.66.116.10).

Two things must hold:
  1. The DEFAULT build (server+client) is unregressed by making the server deps
     optional / the module gating / the portable-atomic swap.
  2. The new client-only path compiles WITHOUT `ring`:
       cargo build --release --bin qeli-client --no-default-features --features client-bin
     and `cargo tree -i ring` confirms `ring` is absent from that feature graph.

Creds from QELI_LAB_PASS (see scripts/lab_env.sh / memory). Run:
    $env:QELI_LAB_PASS="..."; python scripts/keenetic_verify.py
"""
import os, sys, posixpath, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

SERVER = (os.environ.get("QELI_LAB_SERVER", "10.66.116.10"), "root",
          os.environ.get("QELI_LAB_PASS", ""))
LOCAL_ROOT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE_ROOT = "/opt/qeli-src"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=1200):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    rc = o.channel.recv_exit_status()
    return rc, out.strip()


def sync_tree(c):
    sf = c.open_sftp(); made = set()
    def ensure(d):
        if d in made or d in ("", "/"):
            return
        ensure(posixpath.dirname(d))
        try: sf.stat(d)
        except IOError:
            try: sf.mkdir(d)
            except IOError: pass
        made.add(d)
    files = []
    for dp, _dn, fn in os.walk(os.path.join(LOCAL_ROOT, "src")):
        for f in fn:
            files.append(os.path.join(dp, f))
    for extra in ("Cargo.toml", "Cargo.lock"):
        p = os.path.join(LOCAL_ROOT, extra)
        if os.path.exists(p): files.append(p)
    n = 0
    for lp in files:
        rel = os.path.relpath(lp, LOCAL_ROOT).replace("\\", "/")
        rp = posixpath.join(REMOTE_ROOT, rel)
        ensure(posixpath.dirname(rp))
        sf.put(lp, rp); n += 1
    sf.close(); return n


def tail(s, n):
    return "\n".join(s.splitlines()[-n:])


def main():
    if not SERVER[2]:
        print("QELI_LAB_PASS not set — aborting"); sys.exit(2)
    c = conn(SERVER); print("Connected to", SERVER[0])
    run(c, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true", t=30)
    # The client entrypoint moved out of src/bin/ (gitignored `**/bin/`). Drop any
    # stale src/bin/ on the remote so cargo's bin auto-discovery can't resurrect an
    # orphaned qeli-client.rs and collide with the explicit [[bin]] in Cargo.toml.
    run(c, "rm -rf /opt/qeli-src/src/bin", t=30)
    t0 = time.time(); n = sync_tree(c)
    print(f"Synced {n} files to {REMOTE_ROOT} in {time.time()-t0:.0f}s")

    print("\n=== [1] DEFAULT build (regression): cargo build --release ===")
    rc_def, o_def = run(c, f"cd {REMOTE_ROOT} && cargo build --release 2>&1")
    print(tail(o_def, 20)); print("default build rc:", rc_def)

    print("\n=== [1b] unit tests (default features): cargo test --lib ===")
    rc_test, o_test = run(c, f"cd {REMOTE_ROOT} && cargo test --lib 2>&1")
    print(tail(o_test, 12)); print("test rc:", rc_test)

    print("\n=== [2] CLIENT-ONLY build: --no-default-features --features client-bin ===")
    rc_cli, o_cli = run(c, f"cd {REMOTE_ROOT} && cargo build --release --bin qeli-client "
                           f"--no-default-features --features client-bin 2>&1")
    print(tail(o_cli, 25)); print("client-bin build rc:", rc_cli)

    print("\n=== [3] CLIENT-ONLY clippy ===")
    rc_clp, o_clp = run(c, f"cd {REMOTE_ROOT} && cargo clippy --bin qeli-client "
                           f"--no-default-features --features client-bin -- -D warnings 2>&1")
    print(tail(o_clp, 20)); print("client-bin clippy rc:", rc_clp)

    print("\n=== [4] ring absent from client graph? (cargo tree -i ring) ===")
    _rc_tree, o_tree = run(c, f"cd {REMOTE_ROOT} && cargo tree --no-default-features "
                              f"--features client-bin -i ring 2>&1")
    ring_absent = ("did not match any packages" in o_tree) or ("nothing to print" in o_tree)
    print(tail(o_tree, 8)); print("ring ABSENT from client build:", ring_absent)

    # sanity: the produced binary exists + is a Linux ELF
    _rc, finfo = run(c, f"file {REMOTE_ROOT}/target/release/qeli-client 2>&1")
    print("\nqeli-client binary:", finfo)

    run(c, "systemctl start qeli-server.service 2>/dev/null; true", t=30)
    c.close()

    ok = (rc_def == 0 and rc_test == 0 and rc_cli == 0 and rc_clp == 0 and ring_absent)
    print("\n===== SUMMARY =====")
    print(f"default_build={'OK' if rc_def==0 else 'FAIL'}  "
          f"unit_tests={'OK' if rc_test==0 else 'FAIL'}  "
          f"client_build={'OK' if rc_cli==0 else 'FAIL'}  "
          f"client_clippy={'OK' if rc_clp==0 else 'FAIL'}  "
          f"ring_absent={'OK' if ring_absent else 'FAIL'}")
    print("KEENETIC_PHASE1:", "PASS" if ok else "FAIL")


if __name__ == "__main__":
    main()

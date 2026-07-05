#!/usr/bin/env python3
"""Sync qeli Rust source to the lab .10 and validate the jemalloc feature:
  1. cargo build --release --features jemalloc   (jemalloc-sys builds + links)
  2. cargo build --release                        (default gate — no regression)
  3. cargo test --all                             (gate)
  4. cargo clippy --all-targets --features jemalloc -- -D warnings
  5. isolation: client-bin build must NOT pull jemalloc; default cdylib neither
  6. confirm the jemalloc binary actually links jemalloc symbols
"""
import os, sys, posixpath, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

SERVER = (os.environ.get("QELI_LAB_SERVER", "10.66.116.10"), "root", os.environ.get("QELI_LAB_PASS", ""))
LOCAL_ROOT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE_ROOT = "/opt/qeli-src"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=1500):
    _i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return o.channel.recv_exit_status(), out.strip()


def sync_tree(c):
    sf = c.open_sftp(); made = set()
    def ensure(d):
        if d in made or d in ("", "/"): return
        ensure(posixpath.dirname(d))
        try: sf.stat(d)
        except IOError:
            try: sf.mkdir(d)
            except IOError: pass
        made.add(d)
    files = []
    for dp, _dn, fn in os.walk(os.path.join(LOCAL_ROOT, "src")):
        for f in fn: files.append(os.path.join(dp, f))
    for extra in ("Cargo.toml", "Cargo.lock", "debian/Makefile"):
        p = os.path.join(LOCAL_ROOT, extra)
        if os.path.exists(p): files.append(p)
    n = 0
    for lp in files:
        rel = os.path.relpath(lp, LOCAL_ROOT).replace("\\", "/")
        rp = posixpath.join(REMOTE_ROOT, rel)
        ensure(posixpath.dirname(rp)); sf.put(lp, rp); n += 1
    sf.close(); return n


def tail(s, n): return "\n".join(s.splitlines()[-n:])


def main():
    c = conn(SERVER); print("Connected", SERVER[0])
    run(c, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true", t=30)
    t0 = time.time(); n = sync_tree(c); print(f"Synced {n} files in {time.time()-t0:.0f}s")

    print("\n=== toolchain for jemalloc-sys (cc/make) ===")
    print(run(c, "which cc gcc make 2>&1; echo '---'; make --version 2>&1 | head -1")[1])

    print("\n=== [1] cargo build --release --features jemalloc ===")
    rc1, o1 = run(c, f"cd {REMOTE_ROOT} && cargo build --release --features jemalloc 2>&1", t=1500)
    print(tail(o1, 20)); print("jemalloc-build rc:", rc1)

    print("\n=== [2] cargo build --release (default gate) ===")
    rc2, o2 = run(c, f"cd {REMOTE_ROOT} && cargo build --release 2>&1", t=1500)
    print(tail(o2, 12)); print("default-build rc:", rc2)

    print("\n=== [3] cargo test --all ===")
    rc3, o3 = run(c, f"cd {REMOTE_ROOT} && cargo test --all 2>&1", t=1500)
    print(tail(o3, 25)); print("test rc:", rc3)

    print("\n=== [4] cargo clippy --all-targets --features jemalloc -D warnings ===")
    rc4, o4 = run(c, f"cd {REMOTE_ROOT} && cargo clippy --all-targets --features jemalloc -- -D warnings 2>&1", t=1500)
    print(tail(o4, 15)); print("clippy rc:", rc4)

    print("\n=== [5] ISOLATION: does client-bin pull jemalloc? (must be 0) ===")
    _, iso = run(c, f"cd {REMOTE_ROOT} && cargo tree --no-default-features --features client-bin 2>/dev/null | grep -ci jemalloc")
    print("client-bin jemalloc deps:", iso)
    _, iso2 = run(c, f"cd {REMOTE_ROOT} && cargo tree --features jemalloc 2>/dev/null | grep -i jemalloc | head -3")
    print("jemalloc-feature tree:\n", iso2)

    print("\n=== [6] jemalloc symbols in the release binary ===")
    _, sym = run(c, f"nm {REMOTE_ROOT}/target/release/qeli 2>/dev/null | grep -ci jemalloc; echo '--strings--'; strings {REMOTE_ROOT}/target/release/qeli 2>/dev/null | grep -i 'jemalloc-' | head -2")
    print(sym)
    print("binary version:", run(c, f"{REMOTE_ROOT}/target/release/qeli --version 2>&1")[1])

    run(c, "systemctl start qeli-server.service 2>/dev/null; true", t=30)
    c.close()
    print("\n===== SUMMARY =====")
    ok = rc1 == 0 and rc2 == 0 and rc3 == 0 and rc4 == 0
    print(f"jemalloc-build={'OK' if rc1==0 else 'FAIL'} default={'OK' if rc2==0 else 'FAIL'} "
          f"test={'OK' if rc3==0 else 'FAIL'} clippy={'OK' if rc4==0 else 'FAIL'}")
    print("GATE:", "PASS" if ok else "FAIL")


if __name__ == "__main__":
    main()

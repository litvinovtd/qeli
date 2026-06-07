#!/usr/bin/env python3
"""п.3 — rebuild libqeli.so (Android cdylib) from the post-п.2 Rust source.

Syncs src/ + Cargo.{toml,lock} to .11:/root/qeli, cross-builds the cdylib for
arm64-v8a + x86_64 via cargo-ndk straight into the android project's jniLibs,
then verifies the JNI symbols are exported. The Android wiring (RealTls.kt /
QeliService reality-tls path) is already in place; only the native core was
stale (AES-128-only, no PQ/SHA-384)."""
import os, sys, posixpath, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LOCAL = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE = "/root/qeli"
JNILIBS = "/root/android-project/app/src/main/jniLibs"
NDK = "/root/android-sdk/ndk/26.3.11579264"
HOST = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))


def conn():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def sh(c, cmd, t=2400):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.strip(), o.channel.recv_exit_status()


c = conn()

# 1. Sync the Rust source (src/ + manifests). Keep the remote target/ cache.
sf = c.open_sftp()
n = 0
base = os.path.join(LOCAL, "src")
for root, _, names in os.walk(base):
    for nm in names:
        if nm.endswith((".rs", ".html", ".css", ".js")):
            full = os.path.join(root, nm)
            rel = os.path.relpath(full, LOCAL).replace("\\", "/")
            remote = posixpath.join(REMOTE, rel)
            sh(c, f"mkdir -p {posixpath.dirname(remote)}")
            sf.put(full, remote); n += 1
sf.put(os.path.join(LOCAL, "Cargo.toml"), posixpath.join(REMOTE, "Cargo.toml"))
sf.put(os.path.join(LOCAL, "Cargo.lock"), posixpath.join(REMOTE, "Cargo.lock"))
sf.close()
print(f"[sync] {n} src files + Cargo.toml + Cargo.lock -> .11:{REMOTE}")

# 2. Cross-build the cdylib for both ABIs straight into jniLibs.
print(f"[build] cargo ndk -t arm64-v8a -t x86_64 (release, lto=fat) ... this is slow")
env = (f"export PATH=/root/.cargo/bin:$PATH; "
       f"export ANDROID_NDK_HOME={NDK}; export ANDROID_NDK_ROOT={NDK}; ")
build = (f"{env} cd {REMOTE} && cargo ndk -t arm64-v8a -t x86_64 "
         f"-o {JNILIBS} build --release --lib 2>&1")
t0 = time.time()
out, rc = sh(c, build, t=2400)
dt = time.time() - t0
tail = "\n".join(out.splitlines()[-25:])
print(tail)
print(f"[build] rc={rc} in {dt:.0f}s")
if rc != 0:
    c.close(); sys.exit(1)

# 3. Verify the JNI symbols + sizes in both .so.
for abi in ("arm64-v8a", "x86_64"):
    so = f"{JNILIBS}/{abi}/libqeli.so"
    size, _ = sh(c, f"stat -c %s {so} 2>/dev/null || echo MISSING")
    syms, _ = sh(c, f"nm -D {so} 2>/dev/null | grep -c Java_com_qeli_RealTls || echo 0")
    ffi, _ = sh(c, f"nm -D {so} 2>/dev/null | grep -c qeli_realtls || echo 0")
    print(f"[so] {abi}: {size} bytes, JNI syms={syms}, ffi syms={ffi}")

c.close()
print("[done] .so rebuilt into jniLibs on .11")

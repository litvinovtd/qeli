"""Rebuild the Android native realtls core (libqeli.so) on the .11 VM from the
current local Rust source, then pull the per-ABI .so into the tracked jniLibs.

  - sync qeli/{src, Cargo.toml, Cargo.lock} -> /root/qeli-src on .11
  - cargo ndk -t arm64-v8a -t x86_64 -o jniLibs build --release --lib
  - download the two libqeli.so into qeli-android/app/src/main/jniLibs/<abi>/
"""
import os
import posixpath
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

HOST = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
LOCAL_QELI = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
LOCAL_JNI = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli-android\app\src\main\jniLibs"
REMOTE = "/root/qeli-src"
NDK = "/root/android-sdk/ndk/26.3.11579264"
OUT = "/root/qeli-jni"


def conn():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=1800):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.strip(), o.channel.recv_exit_status()


def main():
    c = conn()
    sf = c.open_sftp()
    # Sync source: src/** + the two manifests. --lib doesn't need main.rs/examples,
    # but src/ carries lib.rs and all modules, so ship the whole src tree.
    run(c, f"rm -rf {REMOTE}/src && mkdir -p {REMOTE}/src")
    n = 0
    for root, dirs, names in os.walk(os.path.join(LOCAL_QELI, "src")):
        for nm in names:
            if not nm.endswith(".rs"):
                continue
            full = os.path.join(root, nm)
            rel = os.path.relpath(full, LOCAL_QELI).replace(os.sep, "/")
            remote = posixpath.join(REMOTE, rel)
            run(c, f"mkdir -p {posixpath.dirname(remote)}")
            sf.put(full, remote)
            n += 1
    for man in ("Cargo.toml", "Cargo.lock"):
        sf.put(os.path.join(LOCAL_QELI, man), posixpath.join(REMOTE, man))
    print(f"[sync] {n} .rs files + Cargo.toml/.lock -> {HOST[0]}:{REMOTE}")

    env = (f"export PATH=/root/.cargo/bin:$PATH; export ANDROID_NDK_HOME={NDK}; "
           f"export ANDROID_HOME=/root/android-sdk; "
           # Build the FFI cdylib with panic=unwind so the catch_unwind guards in
           # realtls/ffi.rs actually catch a parser panic (they are inert under the
           # crate's default [profile.release] panic=abort → a malformed-input panic
           # would abort the host app instead of returning an error). Env override, so
           # the server binary's own build keeps abort.
           f"export CARGO_PROFILE_RELEASE_PANIC=unwind; ")
    print("[build] cargo ndk -t arm64-v8a -t x86_64 build --release --lib ...")
    out, rc = run(c, f"{env} cd {REMOTE} && cargo ndk -t arm64-v8a -t x86_64 -o {OUT} "
                     f"build --release --lib 2>&1", t=2400)
    print("\n".join(out.splitlines()[-12:]))
    print(f"[build] rc={rc}")
    if rc != 0:
        c.close()
        sys.exit(1)

    for abi in ("arm64-v8a", "x86_64"):
        so = f"{OUT}/{abi}/libqeli.so"
        sz, _ = run(c, f"stat -c %s {so} 2>&1")
        nm, _ = run(c, f"(nm -D {so} 2>/dev/null | grep -c qeli_realtls) || echo 0")
        print(f"[{abi}] libqeli.so = {sz} bytes, qeli_realtls exports = {nm}")
        local_dir = os.path.join(LOCAL_JNI, abi)
        os.makedirs(local_dir, exist_ok=True)
        sf.get(so, os.path.join(local_dir, "libqeli.so"))
    sf.close()
    c.close()
    print("[done] Android .so rebuilt and pulled into jniLibs")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Rebuild libqeli.so with hardware AES (target-feature=+aes) so the realtls
record layer's AES-256-GCM (the microsoft/0x1302 TLS cipher) uses ARMv8 Crypto
Extensions on the phone (aarch64) and AES-NI on x86_64, instead of software AES.
Verifies via objdump that ARMv8 AES instructions (aese/aesmc) are present in the
arm64 .so."""
import os, sys, posixpath, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LOCAL = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE = "/root/qeli"
JNILIBS = "/root/android-project/app/src/main/jniLibs"
NDK = "/root/android-sdk/ndk/26.3.11579264"
HOST = ("10.66.116.11", "root", os.environ["QELI_LAB_PASS"])


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


def sh(c, cmd, t=2400):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8","replace") + e.read().decode("utf-8","replace")
    return out.strip(), o.channel.recv_exit_status()


c = conn()
# sync src (ensure current; no code change since п.3 but be safe)
sf = c.open_sftp(); n = 0
for root, _, names in os.walk(os.path.join(LOCAL, "src")):
    for nm in names:
        if nm.endswith((".rs",)):
            full = os.path.join(root, nm); rel = os.path.relpath(full, LOCAL).replace("\\","/")
            rp = posixpath.join(REMOTE, rel); sh(c, f"mkdir -p {posixpath.dirname(rp)}"); sf.put(full, rp); n += 1
sf.put(os.path.join(LOCAL, "Cargo.toml"), posixpath.join(REMOTE, "Cargo.toml"))
sf.put(os.path.join(LOCAL, "Cargo.lock"), posixpath.join(REMOTE, "Cargo.lock"))
sf.close()
print(f"[sync] {n} rs files")

# count AES instructions in the CURRENT (software) arm64 .so for comparison
OBJD = f"{NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump"
old, _ = sh(c, f"{OBJD} -d {JNILIBS}/arm64-v8a/libqeli.so 2>/dev/null | grep -cE '\\baese|\\baesmc|\\bpmull' || echo 0")
print(f"[before] arm64 .so ARMv8-AES instructions: {old}")

print("[build] cargo ndk with RUSTFLAGS=-C target-feature=+aes ...")
env = (f"export PATH=/root/.cargo/bin:$PATH; export ANDROID_NDK_HOME={NDK}; "
       f'export RUSTFLAGS="-C target-feature=+aes"; ')
t0 = time.time()
out, rc = sh(c, f"{env} cd {REMOTE} && cargo ndk -t arm64-v8a -t x86_64 -o {JNILIBS} build --release --lib 2>&1", t=2400)
print("\n".join(out.splitlines()[-8:]))
print(f"[build] rc={rc} in {time.time()-t0:.0f}s")
if rc != 0:
    c.close(); sys.exit(1)

new, _ = sh(c, f"{OBJD} -d {JNILIBS}/arm64-v8a/libqeli.so 2>/dev/null | grep -cE '\\baese|\\baesmc|\\bpmull' || echo 0")
print(f"[after] arm64 .so ARMv8-AES instructions: {new}  {'✅ HW-AES compiled in' if int(new) > int(old) and int(new) > 0 else '⚠️ check'}")
for abi in ("arm64-v8a", "x86_64"):
    sz, _ = sh(c, f"stat -c %s {JNILIBS}/{abi}/libqeli.so")
    jni, _ = sh(c, f"nm -D {JNILIBS}/{abi}/libqeli.so 2>/dev/null | grep -c Java_com_qeli || echo 0")
    print(f"[so] {abi}: {sz} bytes, JNI syms={jni}")
c.close()
print("[done]")

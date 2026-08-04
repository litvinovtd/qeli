#!/usr/bin/env python3
"""п.4 — rebuild the native realtls FFI libs for the C# clients from the
post-п.2 source on .10 (/opt/qeli-src):
  • Windows  qeli.dll        via target x86_64-pc-windows-gnu (mingw linker)
  • macOS    libqeli.dylib   via cargo-zigbuild universal2 (arm64 + x86_64),
             with -headerpad_max_install_names so rcodesign can sign it later.

The C# P/Invoke bridge (RealTls.cs) and the reality-tls wiring (VpnTunnel.cs)
are already in place and unchanged — п.2 makes the C ABI carry SHA-384/hybrid
transparently, so only the native cores were stale (pre-п.2, AES-128-only)."""
import hashlib
import os
import sys, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

import ssh_hostkey

SRC = "/opt/qeli-src"
NDK = None
HOST = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
WIN_TARGET = "x86_64-pc-windows-gnu"
MAC_TARGET = "universal2-apple-darwin"


def conn():
    c = paramiko.SSHClient(); ssh_hostkey.harden(c)
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


def sh(c, cmd, t=2400):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.strip(), o.channel.recv_exit_status()


c = conn()
# Build the FFI cdylib cores (Windows dll + macOS dylib below) with panic=unwind so the
# catch_unwind guards in realtls/ffi.rs actually catch a parser panic — they are inert
# under the crate's default [profile.release] panic=abort, so a malformed-input panic
# would abort the host app (JVM/.NET) instead of returning an error. Env override, so the
# server binary's own build keeps abort.
env = "export PATH=/root/.cargo/bin:$PATH; export CARGO_PROFILE_RELEASE_PANIC=unwind; "

# ── Windows: qeli.dll (x86_64-pc-windows-gnu, mingw) ─────────────────────────
print("=== Windows build: cargo build --release --features ffi-cdylib --lib --target x86_64-pc-windows-gnu ===")
t0 = time.time()
out, win_rc = sh(c, f"{env} cd {SRC} && cargo build --release --features ffi-cdylib --lib --target {WIN_TARGET} 2>&1", t=2400)
print("\n".join(out.splitlines()[-12:]))
print(f"[win] rc={win_rc} in {time.time()-t0:.0f}s")
win_dll = f"{SRC}/target/{WIN_TARGET}/release/qeli.dll"
if win_rc == 0:
    sz, _ = sh(c, f"stat -c %s {win_dll}")
    exp, _ = sh(c, f"x86_64-w64-mingw32-objdump -p {win_dll} 2>/dev/null | grep -c qeli_realtls || echo 0")
    print(f"[win] qeli.dll = {sz} bytes, exported qeli_realtls symbols = {exp}")

# ── macOS: libqeli.dylib (universal2, headerpad for signing) ─────────────────
print("\n=== macOS build: cargo zigbuild --release --features ffi-cdylib --lib --target universal2-apple-darwin ===")
t0 = time.time()
macenv = env + 'export RUSTFLAGS="-C link-arg=-Wl,-headerpad_max_install_names"; '
out, mac_rc = sh(c, f"{macenv} cd {SRC} && cargo zigbuild --release --features ffi-cdylib --lib --target {MAC_TARGET} 2>&1", t=2400)
print("\n".join(out.splitlines()[-12:]))
print(f"[mac] rc={mac_rc} in {time.time()-t0:.0f}s")
mac_dylib = f"{SRC}/target/{MAC_TARGET}/release/libqeli.dylib"
if mac_rc == 0:
    sz, _ = sh(c, f"stat -c %s {mac_dylib}")
    arch, _ = sh(c, f"file {mac_dylib} | tr ',' '\\n' | grep -iE 'x86_64|arm64' | head -3 | tr '\\n' ' '")
    # llvm-nm for Mach-O exports (symbols prefixed with _)
    nm, _ = sh(c, f"(llvm-nm-19 {mac_dylib} 2>/dev/null || llvm-nm {mac_dylib} 2>/dev/null) | grep -c ' T _qeli_realtls' || echo 0")
    print(f"[mac] libqeli.dylib = {sz} bytes, arch=[{arch}], exported qeli_realtls (T _qeli_realtls) = {nm}")

# ── pull the artefacts into the tree ─────────────────────────────────────────
#
# This step used to be missing, and its absence was silent and dangerous: the script
# printed "rebuilt, pull with the next step" and there WAS no next step — no other script
# in the tree copies these two files. So a rebuild left the freshly built cores on .10 and
# the STALE ones in the repository, and `provenance.py --update` then happily recorded the
# current source digest against binaries that did not come from it. That is precisely the
# lie native-libs/PROVENANCE exists to make impossible, and it is invisible in review:
# every checksum agrees with every other checksum, just not with the source.
# (The Android script has always pulled its own .so — only win/mac were affected.)
#
# Both copies of each library are written: the canonical one under native-libs/ and the
# one the build stack actually consumes. verify.sh checks they match.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PULL = [
    *([(win_dll, ["native-libs/windows-x64/qeli.dll", "qeli-win/QeliWin/native/qeli.dll"])] if win_rc == 0 else []),
    *([(mac_dylib, ["native-libs/macos-universal/libqeli.dylib",
                 "qeli-mac/QeliMac/native/libqeli.dylib"])] if mac_rc == 0 else []),
]
print("\n=== pull into the tree ===")
sf = c.open_sftp()
for remote, locals_ in PULL:
    with sf.open(remote, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    print(f"[pull] {remote}\n       {len(data)} bytes  sha256={digest}")
    for rel in locals_:
        dst = os.path.join(REPO, rel)
        try:
            changed = open(dst, "rb").read() != data
        except FileNotFoundError:
            changed = True
        # Binary mode: these must never go through newline translation.
        with open(dst, "wb") as f:
            f.write(data)
        print(f"       -> {rel} {'(changed)' if changed else '(identical)'}")
sf.close()
c.close()
print("\n[done] native libs rebuilt and pulled. Now run:")
print("  bash native-libs/verify.sh --update")
print("  python native-libs/provenance.py --update")

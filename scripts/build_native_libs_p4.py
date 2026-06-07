#!/usr/bin/env python3
"""п.4 — rebuild the native realtls FFI libs for the C# clients from the
post-п.2 source on .10 (/opt/qeli-src):
  • Windows  qeli.dll        via target x86_64-pc-windows-gnu (mingw linker)
  • macOS    libqeli.dylib   via cargo-zigbuild universal2 (arm64 + x86_64),
             with -headerpad_max_install_names so rcodesign can sign it later.

The C# P/Invoke bridge (RealTls.cs) and the reality-tls wiring (VpnTunnel.cs)
are already in place and unchanged — п.2 makes the C ABI carry SHA-384/hybrid
transparently, so only the native cores were stale (pre-п.2, AES-128-only)."""
import os
import sys, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

SRC = "/opt/qeli-src"
NDK = None
HOST = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
WIN_TARGET = "x86_64-pc-windows-gnu"
MAC_TARGET = "universal2-apple-darwin"


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


def sh(c, cmd, t=2400):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.strip(), o.channel.recv_exit_status()


c = conn()
env = "export PATH=/root/.cargo/bin:$PATH; "

# ── Windows: qeli.dll (x86_64-pc-windows-gnu, mingw) ─────────────────────────
print("=== Windows build: cargo build --release --lib --target x86_64-pc-windows-gnu ===")
t0 = time.time()
out, rc = sh(c, f"{env} cd {SRC} && cargo build --release --lib --target {WIN_TARGET} 2>&1", t=2400)
print("\n".join(out.splitlines()[-12:]))
print(f"[win] rc={rc} in {time.time()-t0:.0f}s")
win_dll = f"{SRC}/target/{WIN_TARGET}/release/qeli.dll"
if rc == 0:
    sz, _ = sh(c, f"stat -c %s {win_dll}")
    exp, _ = sh(c, f"x86_64-w64-mingw32-objdump -p {win_dll} 2>/dev/null | grep -c qeli_realtls || echo 0")
    print(f"[win] qeli.dll = {sz} bytes, exported qeli_realtls symbols = {exp}")

# ── macOS: libqeli.dylib (universal2, headerpad for signing) ─────────────────
print("\n=== macOS build: cargo zigbuild --release --lib --target universal2-apple-darwin ===")
t0 = time.time()
macenv = env + 'export RUSTFLAGS="-C link-arg=-Wl,-headerpad_max_install_names"; '
out, rc = sh(c, f"{macenv} cd {SRC} && cargo zigbuild --release --lib --target {MAC_TARGET} 2>&1", t=2400)
print("\n".join(out.splitlines()[-12:]))
print(f"[mac] rc={rc} in {time.time()-t0:.0f}s")
mac_dylib = f"{SRC}/target/{MAC_TARGET}/release/libqeli.dylib"
if rc == 0:
    sz, _ = sh(c, f"stat -c %s {mac_dylib}")
    arch, _ = sh(c, f"file {mac_dylib} | tr ',' '\\n' | grep -iE 'x86_64|arm64' | head -3 | tr '\\n' ' '")
    # llvm-nm for Mach-O exports (symbols prefixed with _)
    nm, _ = sh(c, f"(llvm-nm-19 {mac_dylib} 2>/dev/null || llvm-nm {mac_dylib} 2>/dev/null) | grep -c ' T _qeli_realtls' || echo 0")
    print(f"[mac] libqeli.dylib = {sz} bytes, arch=[{arch}], exported qeli_realtls (T _qeli_realtls) = {nm}")

c.close()
print("\n[done] native libs rebuilt in /opt/qeli-src/target — pull with the next step")

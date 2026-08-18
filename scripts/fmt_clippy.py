#!/usr/bin/env python3
"""P2#3 helper. Modes (argv[1]):
  push    — upload all local src + Cargo.toml to /opt/qeli-src (lab is source-of-build)
  fmt     — run `cargo fmt` on the lab, then `cargo fmt --check`
  clippy  — run `cargo clippy --all-targets` and print all warnings
  pull    — download every .rs back from the lab into the local tree (after fmt/clippy)
  test    — `cargo test` + `cargo build` (expect 0 warnings)
  transport — test the no-default-features whole-client FFI surface
  ioscheck — install the Rust iOS std target and type-check the static library
  routercheck — strict clippy for the shipped aarch64 client-only profile
  deny    — install the pinned cargo-deny if needed and check bans/sources
You can pass several modes: e.g. `python fmt_clippy.py push fmt clippy`."""
import os, sys, posixpath, paramiko
from pathlib import Path
import ssh_hostkey

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

SERVER = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
LOCAL_ROOT = Path(os.environ.get(
    "QELI_LOCAL_CRATE", Path(__file__).resolve().parents[1] / "qeli"
))
REMOTE_ROOT = "/opt/qeli-src"

def connect():
    c = paramiko.SSHClient(); ssh_hostkey.harden(c)
    c.connect(SERVER[0], username=SERVER[1], password=SERVER[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c

def src_files(exts):
    out = []
    for subtree in ("src", "tests"):
        base = os.path.join(LOCAL_ROOT, subtree)
        for root, _, names in os.walk(base):
            for n in names:
                if n.endswith(exts):
                    full = os.path.join(root, n)
                    out.append(os.path.relpath(full, LOCAL_ROOT).replace("\\", "/"))
    return out

def run(c, cmd, t=900):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    rc = o.channel.recv_exit_status()
    return out, rc

def main():
    modes = sys.argv[1:] or ["push", "fmt", "clippy"]
    c = connect(); sftp = c.open_sftp()
    if "push" in modes:
        files = src_files((".rs", ".html", ".css", ".js")) + [
            "Cargo.toml",
            "include/qeli_transport_core.h",
        ]
        for rel in files:
            sftp.put(os.path.join(LOCAL_ROOT, rel.replace("/", os.sep)), posixpath.join(REMOTE_ROOT, rel))
        print(f"[push] {len(files)} files -> lab")
    if "fmt" in modes:
        out, rc = run(c, f"cd {REMOTE_ROOT} && cargo fmt 2>&1")
        print("[fmt]\n" + (out.strip() or "(no output)"))
        if rc != 0:
            sys.exit(rc)
        out, rc = run(c, f"set -o pipefail; cd {REMOTE_ROOT} && cargo fmt --check 2>&1 | head -40")
        print(f"[fmt --check] rc={rc}\n" + (out.strip() or "(clean)"))
        if rc != 0:
            sys.exit(rc)
    if "clippy" in modes:
        out, rc = run(c, f"cd {REMOTE_ROOT} && cargo clippy --all-targets 2>&1 | grep -E 'warning|error' | grep -v 'generated|Checking|Compiling' | sort | uniq -c | sort -rn | head -60")
        print(f"[clippy summary] rc={rc}\n" + (out.strip() or "(no warnings)"))
    if "clippyfull" in modes:
        out, rc = run(
            c,
            f"set -o pipefail; cd {REMOTE_ROOT} && "
            "cargo clippy --all-targets -- -D warnings 2>&1 | tail -120",
        )
        print(f"[clippy full] rc={rc}\n" + out)
        if rc != 0:
            sys.exit(rc)
    if "pull" in modes:
        files = src_files((".rs",))
        for rel in files:
            sftp.get(posixpath.join(REMOTE_ROOT, rel), os.path.join(LOCAL_ROOT, rel.replace("/", os.sep)))
        print(f"[pull] {len(files)} .rs files <- lab")
    if "test" in modes:
        out, rc = run(c, f"set -o pipefail; cd {REMOTE_ROOT} && cargo test 2>&1 | tail -8")
        print(f"[test] rc={rc}\n" + out)
        if rc != 0:
            sys.exit(rc)
        out, rc = run(c, f"set -o pipefail; cd {REMOTE_ROOT} && cargo build --bin qeli 2>&1 | tail -4")
        print(f"[build] rc={rc}\n" + out)
        if rc != 0:
            sys.exit(rc)
    if "transport" in modes:
        out, rc = run(
            c,
            f"set -o pipefail; cd {REMOTE_ROOT} && cargo test --locked --lib --no-default-features "
            "--features transport-core-ffi 2>&1 | tail -40",
        )
        print(f"[transport test] rc={rc}\n" + out)
        if rc != 0:
            sys.exit(rc)
        out, rc = run(c, "rustup target list --installed 2>&1")
        print(f"[rust targets] rc={rc}\n" + out)
    if "ioscheck" in modes:
        out, rc = run(c, "rustup target add aarch64-apple-ios 2>&1", t=300)
        print(f"[ios target] rc={rc}\n" + out)
        if rc != 0:
            sys.exit(rc)
        out, rc = run(
            c,
            f"set -o pipefail; cd {REMOTE_ROOT} && CARGO_PROFILE_RELEASE_PANIC=unwind "
            "cargo check --locked --lib --no-default-features --features transport-core-ffi "
            "--target aarch64-apple-ios 2>&1 | tail -80",
        )
        print(f"[ios cargo check] rc={rc}\n" + out)
        if rc != 0:
            sys.exit(rc)
    if "routercheck" in modes:
        out, rc = run(
            c,
            f"set -o pipefail; cd {REMOTE_ROOT} && "
            "cargo clippy --locked --release --bin qeli-client --no-default-features "
            "--features client-bin --target aarch64-unknown-linux-musl "
            "-- -D warnings 2>&1 | tail -120",
        )
        print(f"[router clippy] rc={rc}\n" + out)
        if rc != 0:
            sys.exit(rc)
    if "deny" in modes:
        out, rc = run(
            c,
            f"set -o pipefail; cd {REMOTE_ROOT} && "
            "(command -v cargo-deny >/dev/null || "
            "cargo install cargo-deny --version 0.18.4 --locked) && "
            "cargo deny check bans sources 2>&1 | tail -120",
            t=1200,
        )
        print(f"[cargo-deny] rc={rc}\n" + out)
        if rc != 0:
            sys.exit(rc)
    sftp.close(); c.close()

if __name__ == "__main__":
    main()

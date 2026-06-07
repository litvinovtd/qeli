#!/usr/bin/env python3
"""P2#3 helper. Modes (argv[1]):
  push    — upload all local src + Cargo.toml to /opt/qeli-src (lab is source-of-build)
  fmt     — run `cargo fmt` on the lab, then `cargo fmt --check`
  clippy  — run `cargo clippy --all-targets` and print all warnings
  pull    — download every .rs back from the lab into the local tree (after fmt/clippy)
  test    — `cargo test` + `cargo build` (expect 0 warnings)
You can pass several modes: e.g. `python fmt_clippy.py push fmt clippy`."""
import os, sys, posixpath, paramiko

SERVER = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
LOCAL_ROOT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli"
REMOTE_ROOT = "/opt/qeli-src"

def connect():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(SERVER[0], username=SERVER[1], password=SERVER[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c

def src_files(exts):
    base = os.path.join(LOCAL_ROOT, "src"); out = []
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
        files = src_files((".rs", ".html", ".css", ".js")) + ["Cargo.toml"]
        for rel in files:
            sftp.put(LOCAL_ROOT + "\\" + rel.replace("/", "\\"), posixpath.join(REMOTE_ROOT, rel))
        print(f"[push] {len(files)} files -> lab")
    if "fmt" in modes:
        out, _ = run(c, f"cd {REMOTE_ROOT} && cargo fmt 2>&1")
        print("[fmt]\n" + (out.strip() or "(no output)"))
        out, rc = run(c, f"cd {REMOTE_ROOT} && cargo fmt --check 2>&1 | head -40")
        print(f"[fmt --check] rc={rc}\n" + (out.strip() or "(clean)"))
    if "clippy" in modes:
        out, rc = run(c, f"cd {REMOTE_ROOT} && cargo clippy --all-targets 2>&1 | grep -E 'warning|error' | grep -v 'generated|Checking|Compiling' | sort | uniq -c | sort -rn | head -60")
        print(f"[clippy summary] rc={rc}\n" + (out.strip() or "(no warnings)"))
    if "clippyfull" in modes:
        out, rc = run(c, f"cd {REMOTE_ROOT} && cargo clippy --all-targets 2>&1 | tail -120")
        print(f"[clippy full] rc={rc}\n" + out)
    if "pull" in modes:
        files = src_files((".rs",))
        for rel in files:
            sftp.get(posixpath.join(REMOTE_ROOT, rel), LOCAL_ROOT + "\\" + rel.replace("/", "\\"))
        print(f"[pull] {len(files)} .rs files <- lab")
    if "test" in modes:
        out, rc = run(c, f"cd {REMOTE_ROOT} && cargo test 2>&1 | tail -8")
        print(f"[test] rc={rc}\n" + out)
        out, rc = run(c, f"cd {REMOTE_ROOT} && cargo build --bin qeli 2>&1 | tail -4")
        print(f"[build] rc={rc}\n" + out)
    sftp.close(); c.close()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Clean A/B for the data-plane CPU question: build the *committed* 0.6.0 Rust
binary in an ISOLATED tree (/opt/qeli-060) straight from `git archive HEAD` —
without touching the 0.7.0 working tree — then run the identical /proc-delta
multicore probe against it. Compare to the 0.7.0 number measured separately.

Leaves the working tree untouched; /opt/qeli-src (0.7.0) is not modified.
"""
import os, sys, io, tarfile, tempfile, subprocess, posixpath
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import lab_sync_build as lsb        # reuse conn/run/sync_tree
import multicore_probe as mc        # reuse the probe (idle/up/down/bidir)

REMOTE_060 = "/opt/qeli-060"


def main():
    # 1) extract committed 0.6.0 qeli/ source via git archive (no working-tree touch)
    tmp = tempfile.mkdtemp(prefix="qeli060_")
    tar_path = os.path.join(tmp, "q.tar")
    subprocess.run(["git", "archive", "HEAD", "-o", tar_path, "--", "qeli"],
                   cwd=REPO, check=True)
    with tarfile.open(tar_path) as t:
        t.extractall(tmp)           # -> tmp/qeli/...
    local_060 = os.path.join(tmp, "qeli")
    ver_local = subprocess.run(["git", "show", "HEAD:qeli/Cargo.toml"],
                               cwd=REPO, capture_output=True, text=True).stdout
    print("extracted 0.6.0 source; manifest version line:",
          next((l for l in ver_local.splitlines() if l.startswith("version")), "?"))

    # 2) sync that tree to /opt/qeli-060 and build --release (isolated target dir)
    lsb.LOCAL_ROOT = local_060
    lsb.REMOTE_ROOT = REMOTE_060
    c = lsb.conn(lsb.SERVER)
    lsb.run(c, f"systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; mkdir -p {REMOTE_060}; true", t=30)
    n = lsb.sync_tree(c)
    print(f"synced {n} files -> {REMOTE_060}")
    rc, ob = lsb.run(c, f"cd {REMOTE_060} && cargo build --release 2>&1", t=900)
    print("build:", "\n".join(ob.splitlines()[-4:]), "| rc", rc)
    if rc != 0:
        print("BUILD FAILED — aborting A/B"); c.close(); return
    ver = lsb.run(c, f"{REMOTE_060}/target/release/qeli --version")[1]
    sha = lsb.run(c, f"sha256sum {REMOTE_060}/target/release/qeli | cut -c1-16")[1]
    print("0.6.0 binary:", ver, sha)
    c.close()

    # 3) run the identical /proc-delta probe against the 0.6.0 binary
    print("\n################ 0.6.0 multicore probe ################")
    mc.SRC_BIN = f"{REMOTE_060}/target/release/qeli"
    mc.main()


if __name__ == "__main__":
    main()

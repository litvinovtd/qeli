"""Cross-build the qeli CLIENT-only binary for the common OpenWrt arches, on the
lab build host (.10) via cargo-zigbuild — same toolchain as build_keenetic.py.

These prebuilt binaries are for hand-install / packing a per-arch .ipk without the
full OpenWrt SDK. The proper from-source build is the package `Makefile` (rust feed).

  aarch64-unknown-linux-musl   — ARM routers (Filogic, RPi, x86 ARM)
  x86_64-unknown-linux-musl    — x86_64 routers / VMs / x86 APUs
  mipsel-unknown-linux-musl    — MT7621 / 7628 (tier-3 → nightly -Zbuild-std)
  armv7-unknown-linux-musleabihf — older ARMv7 routers (ipq40xx, mvebu v7)

Client-only (`--no-default-features --features client-bin`) → no `ring`, builds on mips.
Creds from QELI_LAB_PASS. Run:  python qeli-openwrt/build/build_openwrt.py [--sync] [arch]
"""
import os
import sys
import posixpath

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
# Reuse the lab connection helpers from scripts/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from lab_common import connect, LAB_SRV  # noqa: E402

REMOTE_ROOT = "/opt/qeli-src"
LOCAL_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "qeli"))
LOCAL_OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dist"))
CLIENT_FEATURES = "--no-default-features --features client-bin"
# The client-only target is `qeli-client` (src/client_main.rs); the default `qeli`
# bin requires server+client features. Invoked directly: `qeli-client --config <f>`.
BIN = "qeli-client"

# arch -> (rust target, needs -Zbuild-std nightly)
TARGETS = {
    "aarch64": ("aarch64-unknown-linux-musl", False),
    "x86_64":  ("x86_64-unknown-linux-musl",  False),
    "mipsel":  ("mipsel-unknown-linux-musl",  True),
    "armv7":   ("armv7-unknown-linux-musleabihf", False),
}


def run(c, cmd, t=1800):
    _i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return o.channel.recv_exit_status(), out.strip()


def tail(s, n=25):
    return "\n".join(s.splitlines()[-n:])


def sync_tree(c):
    run(c, "rm -rf /opt/qeli-src/src/bin", t=30)
    sf = c.open_sftp()
    made = set()

    def ensure(d):
        if d in made or d in ("", "/"):
            return
        ensure(posixpath.dirname(d))
        try:
            sf.stat(d)
        except IOError:
            try:
                sf.mkdir(d)
            except IOError:
                pass
        made.add(d)

    files = []
    for dp, _dn, fn in os.walk(os.path.join(LOCAL_SRC, "src")):
        for f in fn:
            files.append(os.path.join(dp, f))
    for extra in ("Cargo.toml", "Cargo.lock"):
        p = os.path.join(LOCAL_SRC, extra)
        if os.path.exists(p):
            files.append(p)
    n = 0
    for lp in files:
        rel = os.path.relpath(lp, LOCAL_SRC).replace("\\", "/")
        rp = posixpath.join(REMOTE_ROOT, rel)
        ensure(posixpath.dirname(rp))
        sf.put(lp, rp)
        n += 1
    sf.close()
    return n


def ensure_toolchain(c, targets):
    run(c, "rustup toolchain list | grep -q nightly || "
           "rustup toolchain install nightly --profile minimal -c rust-src 2>&1 | tail -2", t=900)
    run(c, "rustup component add rust-src --toolchain nightly 2>/dev/null; true")
    for _arch, (tgt, build_std) in targets.items():
        if not build_std:
            run(c, f"rustup target add {tgt} 2>&1 | tail -1", t=300)
    run(c, "cargo zigbuild --version >/dev/null 2>&1 || "
           "cargo install cargo-zigbuild --locked 2>&1 | tail -2", t=1200)


def build(c, arch, tgt, build_std):
    print(f"### {arch} ({tgt})")
    if build_std:
        # tier-3 mips: nightly + build std; force soft-float (zig links mips fpxx,
        # rust emits soft-float → float-ABI clash on link). Same as keenetic.
        cmd = (f"cd {REMOTE_ROOT} && RUSTFLAGS='-C link-arg=-msoft-float' "
               f"cargo +nightly zigbuild -Z build-std=std,panic_abort --release "
               f"--bin {BIN} {CLIENT_FEATURES} --target {tgt} 2>&1")
    else:
        cmd = (f"cd {REMOTE_ROOT} && cargo zigbuild --release --bin {BIN} "
               f"{CLIENT_FEATURES} --target {tgt} 2>&1")
    rc, out = run(c, cmd, t=1800)
    print(tail(out, 20))
    print(f"{arch} rc: {rc}")
    if rc == 0:
        os.makedirs(LOCAL_OUT, exist_ok=True)
        dst = os.path.join(LOCAL_OUT, f"qeli-openwrt-{arch}")
        sf = c.open_sftp()
        sf.get(f"{REMOTE_ROOT}/target/{tgt}/release/{BIN}", dst)
        sf.close()
        print(f"  pulled -> {dst}")
    return rc


def main():
    args = [a for a in sys.argv[1:] if a != "--sync"]
    do_sync = "--sync" in sys.argv[1:]
    sel = args[0] if args else None
    targets = {sel: TARGETS[sel]} if sel in TARGETS else TARGETS

    c = connect(LAB_SRV)
    print("connected to", LAB_SRV[0])
    if do_sync:
        print("synced", sync_tree(c), "files")
    ensure_toolchain(c, targets)
    results = {a: build(c, a, t, bs) for a, (t, bs) in targets.items()}
    c.close()
    print("\n===== SUMMARY =====")
    for a in targets:
        print(f"  {a}: {'OK' if results[a] == 0 else 'FAIL'}")
    print("OPENWRT_BUILD:", "PASS" if all(v == 0 for v in results.values()) else "PARTIAL/FAIL")


if __name__ == "__main__":
    main()

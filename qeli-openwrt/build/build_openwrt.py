"""⚠️  MAINTAINER-INTERNAL — NOT the way to build qeli for OpenWrt yourself.

This script cross-builds on a PRIVATE lab host over SSH (`LAB_SRV`, creds from
`QELI_LAB_PASS`); it only works on the maintainer's network. If you ran it and got
`Error reading SSH protocol banner` / a connection error, that is why — you are not on
that host's network. To build the OpenWrt client:
  • from source: OpenWrt SDK/buildroot + the package `Makefile` (rust feed):
        make package/qeli/compile V=s
  • or download a prebuilt per-arch binary from GitHub Releases
        (aarch64 / x86_64 / mipsel / armv7 -unknown-linux-musl).
  See docs/eng/manuals/OPENWRT-INSTALL.md.

Cross-build the qeli CLIENT-only binary for the common OpenWrt arches, on the
lab build host (.10) via cargo-zigbuild — same toolchain as build_keenetic.py.

These prebuilt binaries are for hand-install / packing a per-arch .ipk without the
full OpenWrt SDK. The proper from-source build is the package `Makefile` (rust feed).

  aarch64-unknown-linux-musl   — ARM routers (Filogic, RPi, x86 ARM)
  x86_64-unknown-linux-musl    — x86_64 routers / VMs / x86 APUs
  mipsel-unknown-linux-musl    — MT7621 / 7628 (tier-3 → nightly-2026-06-10 -Zbuild-std)
  armv7-unknown-linux-musleabihf — older ARMv7 routers (ipq40xx, mvebu v7)

Client-only (`--no-default-features --features client-bin`) → no `ring`, builds on mips.
Creds from QELI_LAB_PASS. Run:  python qeli-openwrt/build/build_openwrt.py [--sync] [arch]
"""
import argparse
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
# Reuse the lab connection helpers from scripts/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from router_artifact import pull_router_artifact
from ssh_command import run_ssh_command
from router_toolchain import ARCH_TARGETS, ensure_router_toolchain, router_build_command
from router_source import (sync_router_source, require_router_source_ready,
                           create_router_checkout, restrict_router_crate_types as restrict_crate_types)
from lab_common import connect, LAB_SRV  # noqa: E402

REMOTE_ROOT = None
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LOCAL_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "qeli"))
LOCAL_OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dist"))
# The client-only target is `qeli-client` (src/client_main.rs); the default `qeli`
# bin requires server+client features. Invoked directly: `qeli-client --config <f>`.
BIN = "qeli-client"

# Architecture aliases use the shared target/toolchain policy.
TARGETS = dict(ARCH_TARGETS)


def run(c, cmd, t=1800):
    output, status = run_ssh_command(c, cmd, t)
    return status, output.strip()


def tail(s, n=25):
    return "\n".join(s.splitlines()[-n:])

def restrict_router_crate_types(c):
    restrict_crate_types(c, REMOTE_ROOT)


def sync_tree(c):
    """Replace managed sources/assets/manifests/config; keep marker on failure."""
    return sync_router_source(c, LOCAL_SRC, REMOTE_ROOT)


def check_sync_ready(c):
    require_router_source_ready(c, REMOTE_ROOT)


def ensure_toolchain(c, targets):
    selected = targets.values()
    print("router toolchain:", ensure_router_toolchain(c, selected))


def build(c, arch, tgt):
    print(f"### {arch} ({tgt})")
    cmd = router_build_command(REMOTE_ROOT, tgt, BIN)
    rc, out = run(c, cmd, t=1800)
    print(tail(out, 20))
    print(f"{arch} rc: {rc}")
    if rc == 0:
        src = f"{REMOTE_ROOT}/target/{tgt}/release/{BIN}"
        destination = os.path.relpath(
            os.path.join(LOCAL_OUT, f"qeli-client-openwrt-{arch}"), REPO_ROOT
        ).replace("\\", "/")
        size, digest = pull_router_artifact(c, src, tgt, REPO_ROOT, destination)
        print(f"pulled {arch}: {size} bytes, sha256={digest}")
    return rc


def main():
    global REMOTE_ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync", action="store_true", help="compatibility option: every run now uploads this checkout")
    parser.add_argument("arch", nargs="?", choices=tuple(TARGETS))
    args = parser.parse_args()
    targets = {args.arch: TARGETS[args.arch]} if args.arch else TARGETS
    try:
        c = connect(LAB_SRV)
    except Exception as e:
        sys.exit(
            f"\ncannot reach the maintainer's private build host {LAB_SRV[0]}: {type(e).__name__}: {e}\n\n"
            "This is a MAINTAINER-INTERNAL helper — it cross-builds on a private lab host over SSH,\n"
            "it is NOT how you build qeli for OpenWrt yourself. To build the OpenWrt client:\n"
            "  * from source: OpenWrt SDK/buildroot + the package Makefile (rust feed):\n"
            "        make package/qeli/compile V=s\n"
            "  * or download a prebuilt per-arch binary from GitHub Releases\n"
            "        (aarch64 / x86_64 / mipsel / armv7 -unknown-linux-musl).\n"
            "See docs/eng/manuals/OPENWRT-INSTALL.md.\n"
        )
    results = {}
    try:
        REMOTE_ROOT = create_router_checkout(c, "openwrt")
        print("isolated router checkout:", REMOTE_ROOT)
        print("synced", sync_tree(c), "source files")
        check_sync_ready(c)
        ensure_toolchain(c, targets)
        restrict_router_crate_types(c)
        for arch, target in targets.items():
            try:
                results[arch] = build(c, arch, target)
            except (OSError, RuntimeError) as error:
                results[arch] = 1
                print(f"{arch} failed: {error}")
    finally:
        try:
            c.close()
        finally:
            REMOTE_ROOT = None
    print("\n===== SUMMARY =====")
    for a in targets:
        print(f"  {a}: {'OK' if results[a] == 0 else 'FAIL'}")
    passed = all(results.get(arch) == 0 for arch in targets)
    print("OPENWRT_BUILD:", "PASS" if passed else "PARTIAL/FAIL")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

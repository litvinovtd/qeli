"""One explicit toolchain/flag policy for router helpers; not a hermetic build."""
import re
import shlex
from native_lab import LabConnection, ensure_rust_targets
from native_repro import (DEFAULT_RUST_TOOLCHAIN, DEFAULT_ZIG_VERSION,
                          DEFAULT_CARGO_ZIGBUILD_VERSION)

ROUTER_RUST = DEFAULT_RUST_TOOLCHAIN
# Archive date of the existing lab nightly manifest, not its compiler commit date.
ROUTER_NIGHTLY = "nightly-2026-06-10"
ROUTER_ZIG = DEFAULT_ZIG_VERSION
ROUTER_ZIGBUILD = DEFAULT_CARGO_ZIGBUILD_VERSION
# Canonical standalone release profile from qeli/Cargo.toml. FFI libraries keep
# their separate unwind policy; never inherit their ambient profile overrides.
ROUTER_RELEASE_PROFILE = {
    "LTO": "fat",
    "CODEGEN_UNITS": "1",
    "OPT_LEVEL": "3",
    "STRIP": "true",
    "PANIC": "abort",
}


def router_release_environment():
    return {"CARGO_PROFILE_RELEASE_" + key: value
            for key, value in ROUTER_RELEASE_PROFILE.items()}


ARCH_TARGETS = {
    "aarch64": "aarch64-unknown-linux-musl",
    "x86_64": "x86_64-unknown-linux-musl",
    "mipsel": "mipsel-unknown-linux-musl",
    "armv7": "armv7-unknown-linux-musleabihf",
}
TARGETS = {target: arch == "mipsel" for arch, target in ARCH_TARGETS.items()}

def _toolchain_present(inventory, pin):
    return any(line.split() and (line.split()[0] == pin or
               line.split()[0].startswith(pin + "-"))
               for line in inventory.splitlines())

def ensure_router_toolchain(client, targets):
    """Install only named pins; verify Zig, Rust, target std, nightly source and tool."""
    selected = tuple(targets)
    if not selected or any(target not in TARGETS for target in selected):
        raise ValueError("unsupported router toolchain targets")
    connection = LabConnection(client)
    zig = connection.checked("zig version", "router Zig version", timeout=30)
    if zig != ROUTER_ZIG:
        raise RuntimeError(f"router Zig must be {ROUTER_ZIG}, found {zig!r}")
    inventory = connection.checked("rustup toolchain list", "router Rust inventory", timeout=30)
    needed = [ROUTER_RUST]
    if any(TARGETS[target] for target in selected):
        needed.append(ROUTER_NIGHTLY)
    identities = {"zig": zig}
    for pin in needed:
        if not _toolchain_present(inventory, pin):
            connection.checked(f"rustup toolchain install {pin} --profile minimal",
                               "install pinned router Rust", timeout=900)
        version = connection.checked(f"rustc +{pin} --version",
                                     "verify pinned router Rust", timeout=30)
        expected = f"rustc {ROUTER_RUST} " if pin == ROUTER_RUST else "rustc 1.98.0-nightly "
        if not version.startswith(expected):
            raise RuntimeError(f"router Rust identity mismatch for {pin}: {version!r}")
        identities[pin] = version
    stable_targets = [target for target in selected if not TARGETS[target]]
    if stable_targets:
        ensure_rust_targets(connection, ROUTER_RUST, stable_targets)
    if ROUTER_NIGHTLY in needed:
        connection.checked(f"rustup component add rust-src --toolchain {ROUTER_NIGHTLY}",
                           "install pinned router nightly sources", timeout=300)
        components = connection.checked(
            f"rustup component list --toolchain {ROUTER_NIGHTLY} --installed",
            "verify pinned router nightly sources", timeout=30)
        if "rust-src" not in components.splitlines():
            raise RuntimeError("router nightly rust-src still missing after installation")
    expected = f"cargo-zigbuild v{ROUTER_ZIGBUILD}:"
    command = f"cargo +{ROUTER_RUST} install --list"
    inventory = connection.checked(command, "router cargo-zigbuild inventory", timeout=30)
    if expected not in inventory.splitlines():
        connection.checked(
            f"cargo +{ROUTER_RUST} install cargo-zigbuild --version {ROUTER_ZIGBUILD} "
            "--locked --jobs 1 --force", "install pinned router cargo-zigbuild", timeout=1200)
    inventory = connection.checked(command, "verify router cargo-zigbuild inventory", timeout=30)
    if expected not in inventory.splitlines():
        raise RuntimeError("router cargo-zigbuild pin still missing after installation")
    executable = connection.checked("cargo-zigbuild --version",
                                    "verify router cargo-zigbuild executable", timeout=30)
    if executable != f"cargo-zigbuild {ROUTER_ZIGBUILD}":
        raise RuntimeError(f"router cargo-zigbuild executable mismatch: {executable!r}")
    identities["cargo-zigbuild"] = executable
    return identities

def _pinned_cargo_environment(remote_root, pin, flags):
    # +pin selects Cargo, but Cargo may still select build.rustc from config.
    # Resolve the same pin explicitly; a failed/invalid resolution stops first.
    # Owned mktemp source paths otherwise enter file!()/panic locations and LLVM output.
    flags = (flags + " " if flags else "") + f"--remap-path-prefix={remote_root}=/usr/src/qeli"
    profile_env = " ".join(key + "=" + shlex.quote(value)
                           for key, value in router_release_environment().items())
    return (f'QELI_ROUTER_RUSTC="$(rustup which --toolchain {pin} rustc)" && '
            'test -x "$QELI_ROUTER_RUSTC" && '
            "env -u CARGO_ENCODED_RUSTFLAGS -u RUSTC -u CARGO_BUILD_RUSTC "
            "-u CARGO_BUILD_RUSTFLAGS "
            'RUSTC="$QELI_ROUTER_RUSTC" '
            "RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' "
            f"{profile_env} "
            f"RUSTFLAGS={shlex.quote(flags)} "
            f"CARGO_TARGET_DIR={shlex.quote(remote_root + '/target')} "
            f"CARGO_BUILD_BUILD_DIR={shlex.quote(remote_root + '/target')} "
            f"CARGO_INCREMENTAL=0 cargo +{pin}")


def router_host_cargo_prefix(remote_root):
    """Use the same compiler/output policy for the owned Linux verification gate."""
    if re.fullmatch(r"/var/tmp/qeli-keenetic-verify\.[A-Za-z0-9]{6,}", remote_root) is None:
        raise ValueError("unsafe router verification root")
    return _pinned_cargo_environment(remote_root, ROUTER_RUST, "")


def router_cargo_prefix(remote_root, target):
    """Select a pin and compiler flags without encoded/ambient RUSTFLAGS shadowing."""
    if target not in TARGETS:
        raise ValueError("unsupported router build target")
    if re.fullmatch(r"/var/tmp/qeli-router-(keenetic|openwrt)-[A-Za-z0-9]{6}", remote_root) is None:
        raise ValueError("unsafe router build root")
    pin = ROUTER_NIGHTLY if TARGETS[target] else ROUTER_RUST
    flags = "-C link-arg=-msoft-float" if TARGETS[target] else ""
    return _pinned_cargo_environment(remote_root, pin, flags)


def router_build_command(remote_root, target, binary="qeli-client"):
    if binary != "qeli-client":
        raise ValueError("router recipe builds only qeli-client")
    prefix = router_cargo_prefix(remote_root, target)
    build_std = "-Z build-std=std,panic_abort " if TARGETS[target] else ""
    return (f"cd {shlex.quote(remote_root)} && {prefix} zigbuild {build_std}"
            "--locked --jobs 1 --release --bin qeli-client "
            f"--no-default-features --features client-bin --target {target} 2>&1")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-release-profile", action="store_true", required=True,
                        help="print the common standalone router release environment")
    parser.parse_args()
    for key, value in router_release_environment().items():
        print(key + "=" + value)

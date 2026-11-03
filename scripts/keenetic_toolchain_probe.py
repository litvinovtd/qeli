"""Разведка тулчейна на лаб-сервере .10 под Фазу 2 (кросс-сборка Keenetic).

Печатает инвентарь: rustup-тулчейны/таргеты, nightly + rust-src (нужны для
tier-3 mipsel через -Zbuild-std), zig/cargo-zigbuild и поддержку zig'ом
mipsel/aarch64 linux-musl. По выхлопу решаем: zigbuild для обеих арок или
OpenWrt SDK для mipsel.

Креды из QELI_LAB_PASS. Запуск:
    $env:QELI_LAB_PASS="..."; python scripts/keenetic_toolchain_probe.py
"""
import os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(__file__))
from lab_common import connect, run, LAB_SRV
from router_toolchain import ROUTER_RUST, ROUTER_NIGHTLY

def installed_probe(pin, command):
    # Query only an installed named toolchain; diagnostics must never bootstrap
    # the rolling nightly alias or a missing default via a Rustup proxy.
    return ("if rustup toolchain list | awk '{print $1}' | grep -Eq '^" +
            pin.replace('.', r'\.') + "(-|$)'; then " + command +
            "; else echo 'toolchain " + pin + " not installed'; fi")


CMDS = [
    ("rustup toolchains", "rustup toolchain list"),
    ("pinned rustc / cargo", installed_probe(ROUTER_RUST,
        f'"$(rustup which --toolchain {ROUTER_RUST} rustc)" --version && '
        f'"$(rustup which --toolchain {ROUTER_RUST} cargo)" --version')),
    ("pinned installed targets", installed_probe(ROUTER_RUST,
        f"rustup target list --toolchain {ROUTER_RUST} --installed")),
    ("pinned nightly sources", installed_probe(ROUTER_NIGHTLY,
        f"rustup component list --toolchain {ROUTER_NIGHTLY} --installed")),
    ("zig", "command -v zig && zig version || echo 'zig unavailable'"),
    ("cargo-zigbuild", "cargo-zigbuild --version 2>/dev/null || echo 'cargo-zigbuild unavailable'"),
    ("zig mipsel/aarch64", "zig targets 2>/dev/null | grep -oE '\"(mipsel|aarch64|mips)\"' | sort -u || echo 'zig targets failed'"),
    ("musl-cross linkers", "ls /usr/bin /usr/local/bin 2>/dev/null | grep -E 'musl-gcc|openwrt|mipsel.*gcc|aarch64.*linux.*gcc' || echo 'no explicit musl-cross gcc'"),
]


def main():
    c = connect(LAB_SRV)
    try:
        print("Подключено к", LAB_SRV[0], "\n")
        for label, cmd in CMDS:
            print(f"### {label}")
            print(run(c, cmd, timeout=60))
            print()
    finally:
        c.close()


if __name__ == "__main__":
    main()

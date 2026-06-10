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

CMDS = [
    ("rustc / cargo",            "rustc --version; cargo --version"),
    ("rustup toolchains",        "rustup toolchain list"),
    ("targets (default)",        "rustup target list --installed"),
    ("nightly есть?",            "rustup toolchain list | grep -q nightly && echo YES || echo NO"),
    ("nightly rust-src?",        "rustup component list --toolchain nightly 2>/dev/null | grep 'rust-src (installed)' || echo 'нет nightly/rust-src'"),
    ("целевые linux-musl таргеты","rustup target list | grep -E 'mipsel-unknown-linux-musl|aarch64-unknown-linux-musl|^mips-unknown-linux-musl' || true"),
    ("zig",                      "which zig && zig version || echo 'нет zig'"),
    ("cargo-zigbuild",           "cargo zigbuild --version 2>/dev/null || echo 'нет cargo-zigbuild'"),
    ("zig умеет mipsel/aarch64", "zig targets 2>/dev/null | grep -oE '\"(mipsel|aarch64|mips)\"' | sort -u || echo 'zig targets failed'"),
    ("musl-cross линкеры",       "ls /usr/bin /usr/local/bin 2>/dev/null | grep -E 'musl-gcc|openwrt|mipsel.*gcc|aarch64.*linux.*gcc' || echo 'нет явных musl-cross gcc'"),
]


def main():
    c = connect(LAB_SRV)
    print("Подключено к", LAB_SRV[0], "\n")
    for label, cmd in CMDS:
        print(f"### {label}")
        print(run(c, cmd, timeout=60))
        print()
    c.close()


if __name__ == "__main__":
    main()

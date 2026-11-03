"""⚠️  MAINTAINER-INTERNAL — это НЕ способ собрать qeli под Keenetic самому.

Скрипт кросс-собирает на ПРИВАТНОМ лаб-хосте по SSH (`LAB_SRV`, креды из `QELI_LAB_PASS`)
— работает только в сети мейнтейнера. Если запустил и получил `Error reading SSH protocol
banner` / ошибку подключения — причина в этом (ты не в сети того хоста). Чтобы получить
клиент под Keenetic: возьми готовый per-arch бинарь из GitHub Releases (aarch64/mipsel
-unknown-linux-musl), см. docs/*/manuals/KEENETIC-DEPLOY.md.

Кросс-сборка client-only бинаря qeli под роутеры Keenetic — обе арки за прогон.

  aarch64-unknown-linux-musl  — новые ARM-кинетики (Cortex-A53); Rust1.97.0 + Zig0.13.0.
  mipsel-unknown-linux-musl   — основной парк (MT7621/7628); tier-3 → nightly-2026-06-10 -Zbuild-std.

Линкер/cc для обеих арок — zig (уже стоит на .10) через cargo-zigbuild. Сборка
client-only (`--no-default-features --features client-bin`) → без `ring` (нет MIPS).
Скрипт idempotent: ставит недостающие компоненты тулчейна, потом собирает; не падает
на первой ошибке — печатает оба результата. Готовые бинари тянет в release/keenetic/.

Креды из QELI_LAB_PASS. Запуск:
    $env:QELI_LAB_PASS="..."; python scripts/build_keenetic.py
"""
import argparse
import os, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(__file__))
from router_artifact import pull_router_artifact
from native_licenses import check_bundle
from ssh_command import run_ssh_command
from router_toolchain import ARCH_TARGETS, ensure_router_toolchain, router_build_command
from router_source import (sync_router_source, require_router_source_ready,
                           create_router_checkout, restrict_router_crate_types as restrict_crate_types)
from lab_common import connect, LAB_SRV

REMOTE_ROOT = None
REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SRC = REPO_ROOT / "qeli"
LOCAL_OUT = REPO_ROOT / "release" / "keenetic"
TARGETS = {arch: ARCH_TARGETS[arch] for arch in ("aarch64", "mipsel")}
BIN = "qeli-client"


def run(c, cmd, t=120):
    """Выполнить команду; вернуть (rc, combined_out). lab_common.run отдаёт только
    строку — а здесь нужен реальный exit-код, чтобы судить об успехе сборки."""
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


def build(c, arch, target):
    print(f"### Сборка {arch} ({target})")
    cmd = router_build_command(REMOTE_ROOT, target, BIN)
    rc, out = run(c, cmd, t=1800)
    print(tail(out, 25))
    print(f"{arch} build rc:", rc)
    print()
    return rc


def pull(c, arch, target):
    src = f"{REMOTE_ROOT}/target/{target}/release/{BIN}"
    destination = os.path.relpath(
        os.path.join(LOCAL_OUT, f"{BIN}-keenetic-{arch}"), REPO_ROOT
    ).replace("\\", "/")
    size, digest = pull_router_artifact(c, src, target, REPO_ROOT, destination)
    print(f"pulled {arch}: {size} bytes, sha256={digest}")



def main():
    global REMOTE_ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync", action="store_true", help="compatibility option: every run now uploads this checkout")
    parser.add_argument("arch", nargs="?", choices=tuple(TARGETS))
    args = parser.parse_args()
    check_bundle(REPO_ROOT)
    targets = {args.arch: TARGETS[args.arch]} if args.arch else TARGETS
    try:
        c = connect(LAB_SRV)
    except Exception as e:
        sys.exit(
            f"\nне достучаться до приватного лаб-хоста мейнтейнера {LAB_SRV[0]}: {type(e).__name__}: {e}\n\n"
            "Это ВНУТРЕННИЙ скрипт мейнтейнера — он собирает на приватном лаб-хосте по SSH,\n"
            "это НЕ способ собрать qeli под Keenetic самому. Возьми готовый per-arch бинарь\n"
            "из GitHub Releases (aarch64 / mipsel -unknown-linux-musl); см. docs/*/manuals/KEENETIC-DEPLOY.md.\n"
        )
    results = {}
    try:
        REMOTE_ROOT = create_router_checkout(c, "keenetic")
        print("isolated router checkout:", REMOTE_ROOT)
        print("synced", sync_tree(c), "source files")
        check_sync_ready(c)
        ensure_toolchain(c, targets)
        restrict_router_crate_types(c)
        for arch, target in targets.items():
            try:
                results[arch] = build(c, arch, target)
                if results[arch] == 0:
                    pull(c, arch, target)
                    print("license texts are embedded; use qeli-client licenses --export NEW_DIRECTORY")
            except (OSError, RuntimeError) as error:
                results[arch] = 1
                print(f"{arch} failed: {error}")
    finally:
        try:
            c.close()
        finally:
            REMOTE_ROOT = None
    print("\n===== ИТОГ =====")
    for arch in targets:
        print(f"  {arch}: {'OK' if results.get(arch) == 0 else 'FAIL'}")
    passed = all(results.get(arch) == 0 for arch in targets)
    print("KEENETIC_BUILD:", "PASS" if passed else "PARTIAL/FAIL")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

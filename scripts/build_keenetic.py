"""Кросс-сборка client-only бинаря qeli под роутеры Keenetic — обе арки за прогон.

  aarch64-unknown-linux-musl  — новые ARM-кинетики (Cortex-A53); stable + zig-линкер.
  mipsel-unknown-linux-musl   — основной парк (MT7621/7628); tier-3 → nightly -Zbuild-std.

Линкер/cc для обеих арок — zig (уже стоит на .10) через cargo-zigbuild. Сборка
client-only (`--no-default-features --features client-bin`) → без `ring` (нет MIPS).
Скрипт idempotent: ставит недостающие компоненты тулчейна, потом собирает; не падает
на первой ошибке — печатает оба результата. Готовые бинари тянет в release/keenetic/.

Креды из QELI_LAB_PASS. Запуск:
    $env:QELI_LAB_PASS="..."; python scripts/build_keenetic.py
"""
import os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(__file__))
from lab_common import connect, LAB_SRV

REMOTE_ROOT = "/opt/qeli-src"
LOCAL_OUT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\keenetic"
TARGETS = {
    "aarch64": "aarch64-unknown-linux-musl",
    "mipsel": "mipsel-unknown-linux-musl",
}
CLIENT_FEATURES = "--no-default-features --features client-bin"
BIN = "qeli-client"


def run(c, cmd, t=120):
    """Выполнить команду; вернуть (rc, combined_out). lab_common.run отдаёт только
    строку — а здесь нужен реальный exit-код, чтобы судить об успехе сборки."""
    _i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    rc = o.channel.recv_exit_status()
    return rc, out.strip()


def tail(s, n=25):
    return "\n".join(s.splitlines()[-n:])


def ensure_toolchain(c):
    print("### Сетап тулчейна (idempotent)")
    # nightly + rust-src — для -Zbuild-std под tier-3 mipsel
    _, nl = run(c, "rustup toolchain list | grep -q nightly && echo YES || echo NO")
    if "NO" in nl:
        print("  ставлю nightly + rust-src...")
        _, o = run(c, "rustup toolchain install nightly --profile minimal -c rust-src 2>&1 | tail -3", t=600)
        print(o)
    else:
        run(c, "rustup component add rust-src --toolchain nightly 2>/dev/null; true")
        print("  nightly уже есть (+ гарантирую rust-src)")
    # aarch64-musl std (tier-2, ставится из rustup)
    _, o = run(c, "rustup target add aarch64-unknown-linux-musl 2>&1 | tail -1", t=300)
    print("  aarch64-musl target:", o or "ok")
    # cargo-zigbuild (zig как линкер для обеих арок)
    _, zb = run(c, "cargo zigbuild --version 2>/dev/null || echo none")
    if "zigbuild" not in zb:
        print("  ставлю cargo-zigbuild...")
        _, o = run(c, "cargo install cargo-zigbuild --locked 2>&1 | tail -3", t=1200)
        print(o)
    else:
        print("  cargo-zigbuild уже есть:", zb)
    _, zv = run(c, "zig version")
    print("  zig:", zv)
    print()


def build(c, arch, target):
    print(f"### Сборка {arch} ({target})")
    if arch == "mipsel":
        # tier-3: nightly + сборка std из исходников. Rust компилит mipsel в soft-float
        # ABI, а zig по умолчанию линкует mips как fpxx → конфликт float-ABI на линковке.
        # Принуждаем линковку к soft-float (бинарь не использует FPU — идёт на любом mips).
        cmd = (f"cd {REMOTE_ROOT} && RUSTFLAGS='-C link-arg=-msoft-float' "
               f"cargo +nightly zigbuild "
               f"-Z build-std=std,panic_abort --release --bin {BIN} "
               f"{CLIENT_FEATURES} --target {target} 2>&1")
    else:
        cmd = (f"cd {REMOTE_ROOT} && cargo zigbuild --release --bin {BIN} "
               f"{CLIENT_FEATURES} --target {target} 2>&1")
    rc, out = run(c, cmd, t=1800)
    print(tail(out, 25))
    print(f"{arch} build rc:", rc)
    if rc == 0:
        _, info = run(c, f"file {REMOTE_ROOT}/target/{target}/release/{BIN}; "
                         f"ls -lh {REMOTE_ROOT}/target/{target}/release/{BIN} | awk '{{print $5}}'")
        print("  artifact:", info)
    print()
    return rc


def pull(c, arch, target):
    src = f"{REMOTE_ROOT}/target/{target}/release/{BIN}"
    os.makedirs(LOCAL_OUT, exist_ok=True)
    dst = os.path.join(LOCAL_OUT, f"{BIN}-{arch}")
    sf = c.open_sftp()
    try:
        sf.get(src, dst); print(f"  стянул {arch} → {dst}")
    except IOError as e:
        print(f"  не удалось стянуть {arch}: {e}")
    finally:
        sf.close()


def main():
    # Опц. фильтр арки: `python build_keenetic.py mipsel` собирает только её.
    sel = sys.argv[1] if len(sys.argv) > 1 else None
    targets = {sel: TARGETS[sel]} if sel in TARGETS else TARGETS
    c = connect(LAB_SRV)
    print("Подключено к", LAB_SRV[0], "\n")
    ensure_toolchain(c)
    results = {}
    for arch, target in targets.items():
        results[arch] = build(c, arch, target)
        if results[arch] == 0:
            pull(c, arch, target)
    c.close()
    print("\n===== ИТОГ =====")
    for arch in targets:
        print(f"  {arch}: {'OK' if results.get(arch) == 0 else 'FAIL'}")
    print("KEENETIC_BUILD:", "PASS" if all(v == 0 for v in results.values()) else "PARTIAL/FAIL")


if __name__ == "__main__":
    main()

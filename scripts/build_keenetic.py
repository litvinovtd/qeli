"""⚠️  MAINTAINER-INTERNAL — это НЕ способ собрать qeli под Keenetic самому.

Скрипт кросс-собирает на ПРИВАТНОМ лаб-хосте по SSH (`LAB_SRV`, креды из `QELI_LAB_PASS`)
— работает только в сети мейнтейнера. Если запустил и получил `Error reading SSH protocol
banner` / ошибку подключения — причина в этом (ты не в сети того хоста). Чтобы получить
клиент под Keenetic: возьми готовый per-arch бинарь из GitHub Releases (aarch64/mipsel
-unknown-linux-musl), см. docs/*/manuals/KEENETIC-DEPLOY.md.

Кросс-сборка client-only бинаря qeli под роутеры Keenetic — обе арки за прогон.

  aarch64-unknown-linux-musl  — новые ARM-кинетики (Cortex-A53); stable + zig-линкер.
  mipsel-unknown-linux-musl   — основной парк (MT7621/7628); tier-3 → nightly -Zbuild-std.

Линкер/cc для обеих арок — zig (уже стоит на .10) через cargo-zigbuild. Сборка
client-only (`--no-default-features --features client-bin`) → без `ring` (нет MIPS).
Скрипт idempotent: ставит недостающие компоненты тулчейна, потом собирает; не падает
на первой ошибке — печатает оба результата. Готовые бинари тянет в release/keenetic/.

Креды из QELI_LAB_PASS. Запуск:
    $env:QELI_LAB_PASS="..."; python scripts/build_keenetic.py
"""
import os, sys, posixpath
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(__file__))
from lab_common import connect, LAB_SRV

REMOTE_ROOT = "/opt/qeli-src"
REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SRC = REPO_ROOT / "qeli"
LOCAL_OUT = REPO_ROOT / "release" / "keenetic"
ROUTER_MANIFEST_BACKUP = f"{REMOTE_ROOT}/Cargo.toml.router-backup"
PINNED_CARGO_ZIGBUILD = "0.23.0"
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

def restrict_router_crate_types(c):
    """Build only the rlib dependency needed by qeli-client.

    The persistent checkout is restored in ``finally`` by main. MIPS Zig cannot
    link the desktop/mobile cdylib and must never be asked to build that unused
    artifact as a side effect of a client-only binary.
    """
    restore_router_manifest(c)
    command = (
        f"cp {REMOTE_ROOT}/Cargo.toml {ROUTER_MANIFEST_BACKUP} && "
        f"sed -i 's/^crate-type = \\[\"rlib\", \"cdylib\", \"staticlib\"\\]$/"
        f"crate-type = [\"rlib\"]/' {REMOTE_ROOT}/Cargo.toml && "
        f"grep -qxF 'crate-type = [\"rlib\"]' {REMOTE_ROOT}/Cargo.toml"
    )
    rc, output = run(c, command, t=30)
    if rc != 0:
        restore_router_manifest(c)
        raise RuntimeError(f"cannot restrict router crate types:\n{output}")


def restore_router_manifest(c):
    rc, output = run(c, f"test ! -f {ROUTER_MANIFEST_BACKUP} || mv -f {ROUTER_MANIFEST_BACKUP} {REMOTE_ROOT}/Cargo.toml", t=30)
    if rc != 0:
        raise RuntimeError(f"cannot restore router Cargo.toml:\n{output}")



def sync_tree(c):
    """SFTP всего qeli/src + Cargo.toml/lock в /opt/qeli-src (как lab_sync_build).
    Сначала стираем remote src/bin (точка входа теперь src/client_main.rs, иначе
    cargo авто-обнаружит stale-бинарь). Возвращает число залитых файлов."""
    run(c, "rm -rf /opt/qeli-src/src/bin", t=30)
    sf = c.open_sftp()
    made = set()
    def ensure(d):
        if d in made or d in ("", "/"):
            return
        ensure(posixpath.dirname(d))
        try: sf.stat(d)
        except IOError:
            try: sf.mkdir(d)
            except IOError: pass
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
        sf.put(lp, rp); n += 1
    sf.close()
    return n


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
    _, zb = run(c, "cargo install --list | sed -n '/^cargo-zigbuild v/p'")
    if f"cargo-zigbuild v{PINNED_CARGO_ZIGBUILD}:" not in zb:
        print("  ставлю cargo-zigbuild...")
        rc, o = run(c, f"cargo install cargo-zigbuild --version {PINNED_CARGO_ZIGBUILD} --locked --force 2>&1", t=1200)
        print(o)
        if rc != 0:
            raise RuntimeError(f"pinned cargo-zigbuild install failed:\n{o}")
    else:
        print("  cargo-zigbuild уже есть:", zb)
    _, verified = run(c, "cargo install --list | sed -n '/^cargo-zigbuild v/p'")
    if f"cargo-zigbuild v{PINNED_CARGO_ZIGBUILD}:" not in verified:
        raise RuntimeError(f"cargo-zigbuild pin mismatch: {verified}")
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
    # Output name carries "keenetic" so release assets are self-explanatory
    # (still matches the .gitignore `release/keenetic/qeli-client-*` rule).
    dst = os.path.join(LOCAL_OUT, f"{BIN}-keenetic-{arch}")
    sf = c.open_sftp()
    try:
        sf.get(src, dst); print(f"  стянул {arch} → {dst}")
    except IOError as e:
        print(f"  не удалось стянуть {arch}: {e}")
    finally:
        sf.close()


def main():
    # Аргументы: `--sync` (залить текущее дерево перед сборкой) + опц. фильтр арки,
    # напр. `python build_keenetic.py --sync mipsel`.
    args = sys.argv[1:]
    do_sync = "--sync" in args
    args = [a for a in args if a != "--sync"]
    sel = args[0] if args else None
    targets = {sel: TARGETS[sel]} if sel in TARGETS else TARGETS
    try:
        c = connect(LAB_SRV)
    except Exception as e:
        sys.exit(
            f"\nне достучаться до приватного лаб-хоста мейнтейнера {LAB_SRV[0]}: {type(e).__name__}: {e}\n\n"
            "Это ВНУТРЕННИЙ скрипт мейнтейнера — он собирает на приватном лаб-хосте по SSH,\n"
            "это НЕ способ собрать qeli под Keenetic самому. Возьми готовый per-arch бинарь\n"
            "из GitHub Releases (aarch64 / mipsel -unknown-linux-musl); см. docs/*/manuals/KEENETIC-DEPLOY.md.\n"
        )
    print("Подключено к", LAB_SRV[0], "\n")
    if do_sync:
        n = sync_tree(c)
        print(f"Синхронизировано {n} файлов в {REMOTE_ROOT}\n")
    ensure_toolchain(c)
    results = {}
    try:
        restrict_router_crate_types(c)
        for arch, target in targets.items():
            results[arch] = build(c, arch, target)
            if results[arch] == 0:
                pull(c, arch, target)
    finally:
        restore_router_manifest(c)
        c.close()
    print("\n===== ИТОГ =====")
    for arch in targets:
        print(f"  {arch}: {'OK' if results.get(arch) == 0 else 'FAIL'}")
    passed = all(v == 0 for v in results.values())
    print("KEENETIC_BUILD:", "PASS" if passed else "PARTIAL/FAIL")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

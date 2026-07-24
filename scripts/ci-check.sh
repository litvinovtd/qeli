#!/usr/bin/env bash
# Local mirror of the CI checks. Run from anywhere; operates on ../qeli.
# The crate is Linux-only (TUN/TAP via libc) — run on a Linux host / lab VM.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

rc=0
# Docs gate first — it is instant and needs no toolchain, so a broken link or an
# undocumented config key fails before the multi-minute Rust build.
echo "== docs (links / index / parity / config keys / source refs / version) =="
(cd "$ROOT" && python3 scripts/check_docs.py) || rc=1

cd "$ROOT/qeli" || exit 1
echo "== build (release) =="
cargo build --bin qeli --release || rc=1
echo "== test =="
cargo test --all || rc=1

# Gated (tree is normalized): formatting + clippy `-D warnings` must be clean.
echo "== rustfmt =="
cargo fmt --check || rc=1
echo "== clippy (-D warnings) =="
cargo clippy --all-targets -- -D warnings || rc=1

[ $rc -eq 0 ] && echo "ALL GREEN" || echo "FAILURES (rc=$rc)"
exit $rc

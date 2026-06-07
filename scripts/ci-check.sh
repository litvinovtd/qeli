#!/usr/bin/env bash
# Local mirror of the CI checks. Run from anywhere; operates on ../qeli.
# The crate is Linux-only (TUN/TAP via libc) — run on a Linux host / lab VM.
set -uo pipefail
cd "$(dirname "$0")/../qeli" || exit 1

rc=0
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

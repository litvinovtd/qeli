#!/usr/bin/env bash
# Local mirror of core CI checks (not package/platform release qualification).
# Run from anywhere; operates on ../qeli.
# The crate is Linux-only (TUN/TAP via libc) — run on a Linux host / lab VM.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Share the native/CI Rust pin; never silently validate against a moving stable.
toolchain="$(cd "$ROOT" && python3 -c 'from scripts.native_repro import DEFAULT_RUST_TOOLCHAIN; print(DEFAULT_RUST_TOOLCHAIN)')" || exit 1
if [[ ! "$toolchain" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "invalid pinned Rust toolchain" >&2
    exit 1
fi
export RUSTUP_TOOLCHAIN="$toolchain"
# Explicit selection also rejects a system Cargo that ignores RUSTUP_TOOLCHAIN.
CARGO=(cargo "+$toolchain")

rc=0
# Run cheap checks first; keep all independent failures in the aggregate result.
echo "== docs (all configured checks) =="
(cd "$ROOT" && python3 scripts/check_docs.py) || rc=1
echo "== panel editor regression tests =="
(cd "$ROOT" && python3 scripts/check_panel.py && node scripts/test_panel_editors.cjs) || rc=1
echo "== version consistency (build files + docs banners) =="
(cd "$ROOT" && python3 scripts/sync_version.py) || rc=1
echo "== generated configuration bindings =="
(cd "$ROOT" && python3 scripts/gen_config_bindings.py --check) || rc=1
echo "== self-contained audit regressions =="
(cd "$ROOT" && python3 -B -m unittest discover -s scripts -p 'test_audit_test_suite.py' &&
    python3 -B -m unittest discover -s scripts -p 'test_ci_check.py' &&
    python3 -B scripts/audit_test_suite.py --group portable &&
    python3 -B scripts/audit_test_suite.py --group linux &&
    node scripts/test_openwrt_luci.js) || rc=1

cd "$ROOT/qeli" || exit 1
echo "== build (release) =="
"${CARGO[@]}" build --locked --bin qeli --release --features jemalloc || rc=1
echo "== server library and standalone client feature boundaries =="
"${CARGO[@]}" check --locked --no-default-features --features server --lib || rc=1
"${CARGO[@]}" check --locked --no-default-features --features client-bin --bin qeli-client || rc=1
echo "== test =="
"${CARGO[@]}" test --locked --workspace -- --test-threads=1 || rc=1
echo "== minimal feature library tests =="
for feature in server client-bin transport-core-ffi; do
    "${CARGO[@]}" test --locked --no-default-features --features "$feature" --lib -- --test-threads=1 || rc=1
done
echo "== configuration and transport-core ABI tests =="
"${CARGO[@]}" test --locked --features transport-core-ffi --test config_editor || rc=1
CARGO_PROFILE_RELEASE_PANIC=unwind "${CARGO[@]}" test --locked --features transport-core-ffi transport_core -- --test-threads=1 || rc=1
echo "== minimal release transport-core ABI =="
CARGO_PROFILE_RELEASE_PANIC=unwind "${CARGO[@]}" build --locked --release --no-default-features --features transport-core-ffi || rc=1
cc -x c -std=c11 -fsyntax-only include/qeli_transport_core.h || rc=1
echo "== generated conformance fixtures =="
"${CARGO[@]}" run --locked --features conformance-gen --bin gen-conformance -- --check || rc=1

# Gated (tree is normalized): formatting + clippy `-D warnings` must be clean.
echo "== rustfmt =="
"${CARGO[@]}" fmt --check || rc=1
"${CARGO[@]}" fmt --manifest-path fuzz/Cargo.toml --check || rc=1
echo "== clippy (-D warnings) =="
"${CARGO[@]}" clippy --locked --all-targets -- -D warnings || rc=1
CARGO_PROFILE_RELEASE_PANIC=unwind "${CARGO[@]}" clippy --locked --no-default-features --features transport-core-ffi --lib -- -D warnings || rc=1

[ $rc -eq 0 ] && echo "ALL GREEN" || echo "FAILURES (rc=$rc)"
exit $rc

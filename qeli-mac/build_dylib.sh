#!/usr/bin/env bash
#
# Build the native REALITY core (libqeli.dylib) for macOS and drop it into
# QeliMac/native/ so the .csproj ships it next to the executable (DllImport "qeli").
#
# The C ABI is qeli/src/protocol/realtls/ffi.rs; the Rust crate is ../qeli.
# Produces a UNIVERSAL (arm64 + x86_64) dylib so a single file serves both
# osx-arm64 and osx-x64 publishes.
#
#   ./build_dylib.sh
#
# On macOS it builds both Apple targets natively and lipo's them together.
# On Linux it cross-compiles with cargo-zigbuild (Zig supplies the macOS
# libSystem stubs — no Xcode SDK needed):
#   cargo install cargo-zigbuild && rustup target add aarch64-apple-darwin x86_64-apple-darwin
#   (and have `zig` on PATH: https://ziglang.org/download/)
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CRATE="$(cd "$ROOT/../qeli" && pwd)"
DEST="$ROOT/QeliMac/native"
mkdir -p "$DEST"

echo "==> Rust crate: $CRATE"
cd "$CRATE"

# Build the FFI cdylib with panic=unwind so the catch_unwind guards in
# realtls/ffi.rs actually catch a parser panic (they are inert under the crate's default
# [profile.release] panic=abort → a malformed-input panic would abort the host app
# instead of returning an error). Env override, so the server binary's build keeps abort.
export CARGO_PROFILE_RELEASE_PANIC=unwind

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "==> Native macOS build (cargo + lipo)…"
  rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true
  cargo build --release --lib --target aarch64-apple-darwin
  cargo build --release --lib --target x86_64-apple-darwin
  lipo -create -output "$DEST/libqeli.dylib" \
    "target/aarch64-apple-darwin/release/libqeli.dylib" \
    "target/x86_64-apple-darwin/release/libqeli.dylib"
else
  echo "==> Cross build from Linux (cargo-zigbuild → universal2)…"
  command -v cargo-zigbuild >/dev/null || { echo "need cargo-zigbuild: cargo install cargo-zigbuild"; exit 1; }
  command -v zig >/dev/null            || { echo "need zig on PATH (https://ziglang.org/download/)"; exit 1; }
  rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true
  cargo zigbuild --release --lib --target universal2-apple-darwin
  cp "target/universal2-apple-darwin/release/libqeli.dylib" "$DEST/libqeli.dylib"
fi

echo "==> Wrote $DEST/libqeli.dylib"
file "$DEST/libqeli.dylib" 2>/dev/null || true

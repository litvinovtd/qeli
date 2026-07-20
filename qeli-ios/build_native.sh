#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
RUST_MANIFEST="${QELI_RUST_MANIFEST:-$ROOT/../qeli/Cargo.toml}"
OUT="$ROOT/QeliCore/Native/Qeli.xcframework"
BUILD="$ROOT/build/native"
CARGO_TARGET_DIR="${QELI_CARGO_TARGET_DIR:-$BUILD/cargo}"

if [ ! -f "$RUST_MANIFEST" ]; then
  echo "Rust crate not found: $RUST_MANIFEST" >&2
  exit 1
fi

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
export CARGO_PROFILE_RELEASE_PANIC=unwind
export CARGO_TARGET_DIR

cargo build --locked --release --lib --no-default-features --manifest-path "$RUST_MANIFEST" --target aarch64-apple-ios
cargo build --locked --release --lib --no-default-features --manifest-path "$RUST_MANIFEST" --target aarch64-apple-ios-sim
cargo build --locked --release --lib --no-default-features --manifest-path "$RUST_MANIFEST" --target x86_64-apple-ios

mkdir -p "$BUILD/device" "$BUILD/simulator"
cp "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libqeli.a" "$BUILD/device/libqeli.a"
lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libqeli.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libqeli.a" \
  -output "$BUILD/simulator/libqeli.a"
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$BUILD/device/libqeli.a" -headers "$ROOT/QeliCore/Native/include" \
  -library "$BUILD/simulator/libqeli.a" -headers "$ROOT/QeliCore/Native/include" \
  -output "$OUT"

echo "Built $OUT"

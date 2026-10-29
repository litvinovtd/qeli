#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
RUST_MANIFEST="${QELI_RUST_MANIFEST:-$ROOT/../qeli/Cargo.toml}"
OUT="$ROOT/QeliCore/Native/Qeli.xcframework"
BUILD="$ROOT/build/native"
CARGO_TARGET_DIR="${QELI_CARGO_TARGET_DIR:-$BUILD/cargo}"
RUST_FEATURES="${QELI_RUST_FEATURES:-transport-core-ffi experimental-roaming}"
PUBLIC_HEADER="$ROOT/../qeli/include/qeli_transport_core.h"
IOS_HEADER="$ROOT/QeliCore/Native/include/qeli_transport_core.h"

if [ ! -f "$RUST_MANIFEST" ]; then
  echo "Rust crate not found: $RUST_MANIFEST" >&2
  exit 1
fi

if [ ! -f "$PUBLIC_HEADER" ]; then
  echo "Transport header not found: $PUBLIC_HEADER" >&2
  exit 1
fi

cp "$PUBLIC_HEADER" "$IOS_HEADER"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
export CARGO_PROFILE_RELEASE_PANIC=unwind
export CARGO_TARGET_DIR

cargo build --locked --release --lib --no-default-features --features "$RUST_FEATURES" --manifest-path "$RUST_MANIFEST" --target aarch64-apple-ios
cargo build --locked --release --lib --no-default-features --features "$RUST_FEATURES" --manifest-path "$RUST_MANIFEST" --target aarch64-apple-ios-sim
cargo build --locked --release --lib --no-default-features --features "$RUST_FEATURES" --manifest-path "$RUST_MANIFEST" --target x86_64-apple-ios

# Verify every slice before creating an XCFramework: a matching header alone must not
# conceal an older archive that cannot satisfy the ABI 1.17 diagnostic reader.
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  if ! xcrun nm -g "$CARGO_TARGET_DIR/$target/release/libqeli_core.a" | grep -q ' T _qeli_client_carrier_diagnostics$'; then
    echo "$target archive lacks the ABI 1.17 carrier diagnostics API" >&2
    exit 1
  fi
done

mkdir -p "$BUILD/device" "$BUILD/simulator"
cp "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libqeli_core.a" "$BUILD/device/libqeli.a"
lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libqeli_core.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libqeli_core.a" \
  -output "$BUILD/simulator/libqeli.a"
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$BUILD/device/libqeli.a" -headers "$ROOT/QeliCore/Native/include" \
  -library "$BUILD/simulator/libqeli.a" -headers "$ROOT/QeliCore/Native/include" \
  -output "$OUT"

echo "Built $OUT"

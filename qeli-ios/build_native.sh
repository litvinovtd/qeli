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
# Rust archives can contain LLVM bitcode newer than Xcode's nm understands.
# Inspect them with the tools from the same active Rust toolchain, fail closed
# if those tools cannot read an archive (never hide nm errors in a grep pipeline).
rustup component add llvm-tools
RUST_HOST="$(rustc -vV | sed -n 's/^host: //p')"
RUST_NM="$(rustc --print sysroot)/lib/rustlib/$RUST_HOST/bin/llvm-nm"
if [ -z "$RUST_HOST" ] || [ ! -x "$RUST_NM" ]; then
  echo "Rust toolchain llvm-nm not found: $RUST_NM" >&2
  exit 1
fi
export CARGO_PROFILE_RELEASE_PANIC=unwind
export CARGO_TARGET_DIR

cargo build --locked --release --lib --no-default-features --features "$RUST_FEATURES" --manifest-path "$RUST_MANIFEST" --target aarch64-apple-ios
cargo build --locked --release --lib --no-default-features --features "$RUST_FEATURES" --manifest-path "$RUST_MANIFEST" --target aarch64-apple-ios-sim
cargo build --locked --release --lib --no-default-features --features "$RUST_FEATURES" --manifest-path "$RUST_MANIFEST" --target x86_64-apple-ios

# Verify every slice before creating an XCFramework: a matching header alone must not
# conceal an older archive that cannot satisfy the ABI 1.17 diagnostic reader.
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  sh "$ROOT/../scripts/check_ios_native_exports.sh" "$RUST_NM" \
    "$CARGO_TARGET_DIR/$target/release/libqeli_core.a"
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

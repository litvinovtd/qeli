#!/bin/sh
# Read the whole archive successfully before accepting its defined public symbol.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: check_ios_native_exports.sh RUST_LLVM_NM ARCHIVE" >&2
  exit 2
fi

symbols=$(mktemp)
trap 'rm -f "$symbols"' EXIT HUP INT TERM
"$1" --extern-only --defined-only "$2" > "$symbols"
if ! grep -Eq '(^|[[:space:]])T _qeli_client_carrier_diagnostics$' "$symbols"; then
  echo "$2 archive lacks the ABI 1.17 carrier diagnostics API" >&2
  exit 1
fi

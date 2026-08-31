#!/usr/bin/env bash
# Prove both directions of the supported 0.7.16 ↔ 0.8.0 IPv4 compatibility contract.
set -eu
set -o pipefail
export LC_ALL=C

NEW=${1:-}
OLD=${2:-}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CASE_SCRIPT="$SCRIPT_DIR/ipv6_netns_case.sh"

if [ ! -x "$NEW" ] || [ ! -x "$OLD" ]; then
  echo "usage: $0 <new-qeli-binary> <legacy-qeli-binary>" >&2
  exit 2
fi
NEW=$(readlink -f "$NEW")
OLD=$(readlink -f "$OLD")

echo "new_version=$($NEW --version)"
echo "new_sha256=$(sha256sum "$NEW" | cut -d' ' -f1)"
echo "legacy_version=$($OLD --version)"
echo "legacy_sha256=$(sha256sum "$OLD" | cut -d' ' -f1)"
if ! "$OLD" --version | grep -q '^qeli 0\.7\.16$'; then
  echo "legacy binary must be qeli 0.7.16" >&2
  exit 2
fi

echo "=== new server -> 0.7.16 client ==="
QELI_SERVER_BIN="$NEW" QELI_CLIENT_BIN="$OLD" QELI_EXPECT_CLIENT_IPV4_PREFIX=24 \
  bash "$CASE_SCRIPT" "$NEW" 4 4 tcp fake-tls full legacy

echo "=== 0.7.16 server -> new client ==="
QELI_SERVER_BIN="$OLD" QELI_CLIENT_BIN="$NEW" QELI_EXPECT_CLIENT_IPV4_PREFIX=32 \
  bash "$CASE_SCRIPT" "$NEW" 4 4 tcp fake-tls full legacy

echo "=== RESULT legacy peer: both directions passed ==="

#!/bin/sh
set -eu
cd "$(dirname "$0")"
command -v xcodegen >/dev/null 2>&1 || {
  echo "XcodeGen is required: brew install xcodegen" >&2
  exit 1
}
xcodegen generate
echo "Generated QeliIOS.xcodeproj"


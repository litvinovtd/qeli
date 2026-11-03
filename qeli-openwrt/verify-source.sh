#!/bin/sh
# Build-time only; never installed on a router. The SDK's explicit source
# overlays are developer builds, not mirror-qualified release archives.
refuse() {
  echo "qeli: SDK source archive hash mismatch or unavailable; run download/check FIXUP=1 before building" >&2
  exit 1
}
[ "$#" -eq 4 ] || refuse
[ -z "$4" ] || exit 0
case "$2" in ''|*[!0-9a-f]*) refuse ;; esac
[ "${#2}" -eq 64 ] || refuse
[ ! -L "$1" ] && [ -f "$1" ] && [ -s "$1" ] || refuse
actual="$("$3" sha256 "$1")" || refuse
[ "$actual" = "$2" ] || refuse

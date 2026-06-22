#!/bin/sh
# qeli container entrypoint.
#   docker run ... qeli:0.7.2 server          # default
#   docker run ... qeli:0.7.2 client
#   docker run ... qeli:0.7.2 server --config /etc/qeli/server-multiprofile.conf
# Override the config path with $QELI_CONFIG or a trailing --config.
set -e

ROLE="${1:-server}"
case "$ROLE" in
  server|client) shift ;;
  # `docker run qeli --config X` (no role word) → assume server, pass everything through.
  *) ROLE="server" ;;
esac

CONF="${QELI_CONFIG:-/etc/qeli/${ROLE}.conf}"

# First run: seed a writable config from the baked-in example, then ask the
# operator to edit it. Mount /etc/qeli as a volume so the edits AND the identity
# key generated on first start survive container restarts.
if [ ! -f "$CONF" ] && [ -f "${CONF}.example" ]; then
  echo "[qeli] $CONF not found — seeding it from ${CONF}.example."
  echo "[qeli] EDIT $CONF (set users/keys/bind), then restart the container."
  cp "${CONF}.example" "$CONF"
fi

# /dev/net/tun is required for both roles (the data-plane interface).
if [ ! -c /dev/net/tun ]; then
  echo "[qeli] WARNING: /dev/net/tun is missing." >&2
  echo "[qeli]   run with:  --device /dev/net/tun --cap-add NET_ADMIN" >&2
fi

# Server NAT (routing.nat.enabled = true) needs IPv4 forwarding. Best-effort
# here; the reliable way is `--sysctl net.ipv4.ip_forward=1` on `docker run`
# (and the host kernel must have nf_nat / iptable_nat for MASQUERADE).
if [ "$ROLE" = "server" ]; then
  echo 1 >/proc/sys/net/ipv4/ip_forward 2>/dev/null \
    || echo "[qeli] note: could not set ip_forward (use --sysctl net.ipv4.ip_forward=1)" >&2
fi

echo "[qeli] starting role=$ROLE config=$CONF"
exec /usr/local/bin/qeli "$ROLE" --config "$CONF" "$@"

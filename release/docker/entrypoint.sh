#!/bin/sh
# qeli container entrypoint.
#   docker run ... qeli:latest server          # default
#   docker run ... qeli:latest client
#   docker run ... qeli:latest server --config /etc/qeli/server-multiprofile.conf
# Override the config path with $QELI_CONFIG or a trailing --config.
set -e

ROLE="${1:-server}"
case "$ROLE" in
  server|client) shift ;;
  # `docker run qeli --config X` (no role word) → assume server, pass everything through.
  *) ROLE="server" ;;
esac

CONF="${QELI_CONFIG:-/etc/qeli/${ROLE}.conf}"
EXAMPLE="/usr/share/qeli/${ROLE}.conf.example"

# First run: seed a writable config from the baked-in example (kept in
# /usr/share/qeli so a volume mounted at /etc/qeli doesn't hide it). Mount
# /etc/qeli as a volume so the edits AND the identity key generated on first
# start survive container restarts.
if [ ! -f "$CONF" ] && [ -f "$EXAMPLE" ]; then
  echo "[qeli] $CONF not found — seeding it from $EXAMPLE."
  echo "[qeli] EDIT $CONF (set users/keys/bind), then restart the container."
  cp "$EXAMPLE" "$CONF"
fi

# Docker bind-mounts /etc/resolv.conf, which qeli's default client DNS management
# (dns = tunnel) cannot atomically replace → it errors and reconnect-loops. The
# router escape hatch `dns = off` is the right setting in a container.
if [ "$ROLE" = "client" ] && [ -f "$CONF" ] && ! grep -qiE '^[[:space:]]*dns[[:space:]]*=[[:space:]]*off' "$CONF"; then
  echo "[qeli] WARNING: client config has no 'dns = off'. In Docker /etc/resolv.conf" >&2
  echo "[qeli]   is a bind-mount; the default 'dns = tunnel' fails (EBUSY) and loops." >&2
  echo "[qeli]   Add 'dns = off' under [qeli] for a container client." >&2
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

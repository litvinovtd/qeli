#!/bin/sh
# qeli container entrypoint.
#   docker run ... qeli:latest server          # default
#   docker run ... qeli:latest client
#   docker run ... qeli:latest server --config /etc/qeli/server-multiprofile.conf
# Override the config path with $QELI_CONFIG or a trailing --config.
set -e
umask 077

ROLE="${1:-server}"
case "$ROLE" in
  server|client) if [ "$#" -gt 0 ]; then shift; fi ;;
  # `docker run qeli --config X` (no role word) → assume server, pass everything through.
  *) ROLE="server" ;;
esac

CONF="${QELI_CONFIG:-/etc/qeli/${ROLE}.conf}"
EXAMPLE="/usr/share/qeli/${ROLE}.conf.example"


# Respect the CLI path before touching the volume. Pass an explicit option only
# once: clap rejects duplicate --config arguments rather than choosing the last.
CLI_CONFIG=0
CONFIG_PENDING=0
for arg in "$@"; do
  if [ "$CONFIG_PENDING" = 1 ]; then
    CONF="$arg"
    CONFIG_PENDING=0
    continue
  fi
  case "$arg" in
    --) break ;;
    -h|--help|-V|--version) exec /usr/local/bin/qeli "$ROLE" "$@" ;;
    -c|--config)
      [ "$CLI_CONFIG" = 0 ] || { echo '[qeli] duplicate config option' >&2; exit 1; }
      CLI_CONFIG=1
      CONFIG_PENDING=1
      ;;
    --config=*|-c?*)
      [ "$CLI_CONFIG" = 0 ] || { echo '[qeli] duplicate config option' >&2; exit 1; }
      CLI_CONFIG=1
      case "$arg" in --config=*) CONF="${arg#--config=}" ;; *) CONF="${arg#-c}" ;; esac
      ;;
  esac
done
[ "$CONFIG_PENDING" = 0 ] && [ -n "$CONF" ] || { echo '[qeli] missing config path' >&2; exit 1; }

# Publish a complete owner-only file without replacing a concurrent creator.
# Never open the final name for writing: in particular a dangling symlink must
# not turn first-run seeding into truncation of a different volume file.
SEED_TMP=''
cleanup_seed() { [ -z "$SEED_TMP" ] || rm -f -- "$SEED_TMP"; }
trap cleanup_seed EXIT
trap 'cleanup_seed; exit 130' INT
trap 'cleanup_seed; exit 143' TERM
seed_file() {
  dest="$1"
  source="$2"
  if [ -L "$dest" ] || { [ -e "$dest" ] && [ ! -f "$dest" ]; }; then
    echo "[qeli] refusing nonregular or linked file: $dest" >&2
    exit 1
  fi
  [ ! -f "$dest" ] || return 0
  mkdir -p -- "$(dirname -- "$dest")"
  SEED_TMP="$(mktemp "${dest}.qeli-XXXXXX")"
  if [ -n "$source" ]; then cat "$source" > "$SEED_TMP"; fi
  if ! ln -T -- "$SEED_TMP" "$dest" 2>/dev/null; then
    # A regular concurrent winner is preserved. Other errors refuse startup.
    [ ! -L "$dest" ] && [ -f "$dest" ] || {
      echo "[qeli] could not publish file: $dest" >&2
      exit 1
    }
  fi
  cleanup_seed
  SEED_TMP=''
}

# First run: seed a writable config from the baked-in example (kept in
# /usr/share/qeli so a volume mounted at /etc/qeli doesn't hide it). Mount
# /etc/qeli as a volume so the edits AND the identity key generated on first
# start survive container restarts.
if [ ! -e "$CONF" ] && [ ! -L "$CONF" ]; then
  echo "[qeli] $CONF not found — seeding it from $EXAMPLE."
  echo "[qeli] EDIT $CONF (set keys/bind), then restart the container."
fi
seed_file "$CONF" "$EXAMPLE"

# Users live in a separate file (auth.users_file, default /etc/qeli/users.conf).
# Create it EMPTY so `qeli add-client` has somewhere to append (older builds error if
# it's missing) — never seed the shipped users.conf.example, it carries a sample user
# with a KNOWN hash (see /usr/share/qeli/users.conf.example for the format reference).
if [ "$ROLE" = "server" ]; then
  seed_file /etc/qeli/users.conf ''
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
if [ "$CLI_CONFIG" = 1 ]; then
  exec /usr/local/bin/qeli "$ROLE" "$@"
fi
exec /usr/local/bin/qeli "$ROLE" --config "$CONF" "$@"

#!/usr/bin/env bash
#
# qeli — one-shot installer for a REALITY-TLS server on :443.
#
# What it does, end to end:
#   1. installs dependencies,
#   2. downloads + installs the latest qeli .deb from GitHub Releases,
#   3. writes /etc/qeli/server.conf with ONLY the reality-tls profile (taken from
#      the packaged multi-profile example) on port 443, full-tunnel NAT on,
#   4. generates the server identity key,
#   5. creates 5 users and saves their ready-to-use qeli:// connection strings
#      under /etc/qeli/client-links/,
#   6. enables + starts the service.
#
# After it finishes you only paste/scan a connection string into the app.
#
# Usage (run as root — directly, or via sudo if you have it; sudo is NOT required
# and is never installed):
#   ./install-reality-server.sh [PUBLIC_HOST]          # when already root
#   sudo ./install-reality-server.sh [PUBLIC_HOST]     # when sudo is available
#     PUBLIC_HOST  Address clients connect to (IP or hostname). If omitted, the
#                  public IP is auto-detected — pass it explicitly if your box has
#                  separate inbound/outbound IPs or you use a domain.
#
set -euo pipefail

REPO="litvinovtd/qeli"
PROFILE="reality-tls"
PORT=443
NUM_USERS=5
USER_PREFIX="phone"
CONF="/etc/qeli/server.conf"
EXAMPLE="/etc/qeli/server-multiprofile.conf.example"
LINKS_DIR="/etc/qeli/client-links"

log(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# Must run as root. Run it directly as root (no sudo needed), or — if you are a
# normal user AND sudo is installed — it re-execs itself under sudo. We never
# install sudo: on a root-only box (no sudo) just run it as root.
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "Not root — re-running under sudo…"
    exec sudo -E bash "$0" "$@"
  fi
  die "must run as root, and 'sudo' is not installed. Switch to root and re-run:  su -"
fi
export DEBIAN_FRONTEND=noninteractive
PUBLIC_HOST="${1:-}"

# ── 1. dependencies ─────────────────────────────────────────────────────────
log "Installing dependencies"
apt-get update -y
apt-get install -y curl ca-certificates jq iptables iproute2 openssl

# ── 2. obtain the .deb ──────────────────────────────────────────────────────
# By default: newest GitHub release (the releases are pre-releases, so we read
# /releases, not /releases/latest). Override with QELI_DEB=<local path or URL> for
# an offline / air-gapped install or to pin a specific build.
log "Obtaining the qeli .deb"
CLEANUP_DEB=0
if [ -n "${QELI_DEB:-}" ] && [ -f "$QELI_DEB" ]; then
  echo "  using local .deb: $QELI_DEB"
  TMP_DEB="$QELI_DEB"
else
  if [ -n "${QELI_DEB:-}" ]; then
    DEB_URL="$QELI_DEB"
  else
    DEB_URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
      | jq -r 'map(select(.draft|not)) | .[0].assets[]
               | select(.name|endswith(".deb")) | .browser_download_url' | head -n1)
    [ -n "$DEB_URL" ] || die "no .deb asset found in the latest release."
  fi
  echo "  downloading: $DEB_URL"
  TMP_DEB="$(mktemp --suffix=.deb)"; CLEANUP_DEB=1
  curl -fL --retry 3 -o "$TMP_DEB" "$DEB_URL"
fi

# ── 3. install the package (pulls iptables / iproute2) ──────────────────────
log "Installing the package"
apt-get install -y "$TMP_DEB" || { dpkg -i "$TMP_DEB" || true; apt-get install -y -f; }
[ "$CLEANUP_DEB" -eq 1 ] && rm -f "$TMP_DEB"
command -v qeli >/dev/null || die "qeli is not on PATH after install."
[ -f "$EXAMPLE" ] || die "$EXAMPLE missing — package too old (need >= 0.7.2)."

# ── 4. build server.conf: reality-tls profile only, from the example ────────
log "Configuring the ${PROFILE} profile on :${PORT}"
{
  # global sections ([auth]/[logging]/[web]) — everything before the first profile
  awk '/^\[profile:/{exit} {print}' "$EXAMPLE"
  # only the reality-tls profile block (header until the next [profile:)
  awk -v p="[profile:${PROFILE}]" '$0==p{f=1;print;next} /^\[profile:/{f=0} f{print}' "$EXAMPLE"
} > "$CONF"
# this deployment gets its own random REALITY short_id (not the example sample)
SID="$(openssl rand -hex 8)"
sed -i "s|^obf.tls.reality_proxy.short_ids = .*|obf.tls.reality_proxy.short_ids = ${SID}|" "$CONF"
# leave routing.nat.interface unset so it auto-detects the WAN interface
sed -i "/^routing.nat.interface/d" "$CONF"

# ── 5. server identity key (created + printed; pinned automatically in the link)
log "Generating the server identity key"
qeli show-identity --config "$CONF"
PUBKEY=$(qeli show-identity --config "$CONF" 2>/dev/null | awk -v p="$PROFILE" '$1==p{print $NF}')
chown -R qeli:qeli "$CONF" /etc/qeli/identity 2>/dev/null || true

# ── 6. public host clients will connect to ──────────────────────────────────
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(curl -fsS https://api.ipify.org 2>/dev/null || true)"
  echo "  Auto-detected public IP: ${PUBLIC_HOST:-<unknown>}"
  echo "  (Separate inbound/outbound IPs or a domain? Re-run with it as an argument.)"
fi
[ -n "$PUBLIC_HOST" ] || die "could not determine PUBLIC_HOST — pass it as an argument."

# ── 7. create users + save ready qeli:// connection strings ─────────────────
log "Creating ${NUM_USERS} users + connection strings"
mkdir -p "$LINKS_DIR"; chmod 700 "$LINKS_DIR"
# add-client appends to the users file; make sure it exists (older builds error if not).
[ -f /etc/qeli/users.conf ] || : > /etc/qeli/users.conf
SUMMARY="${LINKS_DIR}/CONNECTION-STRINGS.txt"
: > "$SUMMARY"
for i in $(seq 1 "$NUM_USERS"); do
  U="${USER_PREFIX}${i}"
  P="$(openssl rand -hex 12)"   # URL-safe (hex) — embedded straight into the link
  LINK=$(qeli add-client "$U" --password "$P" --link \
           --host "${PUBLIC_HOST}:${PORT}" --link-profile "$PROFILE" \
           --config "$CONF" | grep -m1 '^qeli://')
  [ -n "$LINK" ] || die "add-client did not return a link for $U."
  echo "$LINK" > "${LINKS_DIR}/${U}.qeli"
  printf 'user: %s\npass: %s\nlink: %s\n\n' "$U" "$P" "$LINK" >> "$SUMMARY"
  echo "  + ${U}"
done
chmod 600 "$LINKS_DIR"/*
chown -R qeli:qeli /etc/qeli/users.conf 2>/dev/null || true

# ── 8. enable + start ───────────────────────────────────────────────────────
log "Starting the service"
systemctl enable --now qeli
sleep 2
systemctl is-active --quiet qeli || die "qeli failed to start — see: journalctl -u qeli -e"

# ── done ────────────────────────────────────────────────────────────────────
log "Done"
cat <<EOF
Server:        ${PROFILE} on ${PUBLIC_HOST}:${PORT}   (full-tunnel NAT enabled)
Identity key:  ${PUBKEY:-<run: qeli show-identity --config $CONF>}
Users:         ${NUM_USERS}  (${USER_PREFIX}1 … ${USER_PREFIX}${NUM_USERS})

Connection strings (qeli:// — paste or scan into the app):
  ${LINKS_DIR}/<user>.qeli           one file per user
  ${SUMMARY}                          all of them (with passwords)

NEXT STEPS:
  • Open inbound TCP ${PORT} in your cloud firewall / security group.
  • Add a connection string to the app — that's all. To print one:
      cat ${LINKS_DIR}/${USER_PREFIX}1.qeli
EOF

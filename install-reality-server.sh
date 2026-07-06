#!/usr/bin/env bash
#
# qeli — one-shot installer for a disguised-TLS server on :443. During the run it
# asks which profile to deploy: reality-tls (default) or fake-tls.
#
# What it does, end to end:
#   1. installs dependencies,
#   2. downloads + installs the latest qeli .deb from GitHub Releases,
#   3. asks for the profile (reality-tls | fake-tls) and writes /etc/qeli/server.conf
#      with ONLY that profile (taken from the packaged multi-profile example) on
#      port 443, full-tunnel NAT on,
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
#     PUBLIC_HOST   Address clients connect to (IP or hostname). If omitted, the
#                   public IP is auto-detected — pass it explicitly if your box has
#                   separate inbound/outbound IPs or you use a domain.
#     QELI_PROFILE  Optional. Pick the profile non-interactively (skips the prompt):
#                   QELI_PROFILE=reality-tls | fake-tls. Handy for curl|bash / automation.
#
set -euo pipefail

REPO="litvinovtd/qeli"
PROFILE=""            # chosen interactively below (or non-interactively via QELI_PROFILE)
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

# ── 0. choose the profile: reality-tls (default) or fake-tls ────────────────
# Both disguise the tunnel as HTTPS on :443; they differ in HOW:
#   reality-tls — completes a REAL TLS session with a front site (e.g. www.microsoft.com)
#                 and tunnels inside it. Strongest disguise (a real cert is relayed);
#                 slightly heavier. This is the prod-grade default.
#   fake-tls    — mimics a TLS-1.3 handshake without relaying a real cert. Lighter,
#                 no upstream front dependency; a shade less robust to deep probing.
# Priority: $QELI_PROFILE (non-interactive) → terminal prompt → default reality-tls.
# Under `curl … | bash` stdin IS the script, so the prompt is read from /dev/tty; with
# no controlling terminal at all we fall back to the default (overridable via the env).
choose_profile() {
  local sel="${QELI_PROFILE:-}"
  if [ -n "$sel" ]; then
    case "$sel" in
      reality-tls|reality) PROFILE="reality-tls" ;;
      fake-tls|fake)       PROFILE="fake-tls" ;;
      1)                   PROFILE="reality-tls" ;;
      2)                   PROFILE="fake-tls" ;;
      *) die "QELI_PROFILE must be 'reality-tls' or 'fake-tls' (got '$sel')." ;;
    esac
    echo "Profile (from QELI_PROFILE): ${PROFILE}"
    return
  fi
  if [ -r /dev/tty ]; then
    {
      printf '\n\033[1;36m== Which server profile to install?\033[0m\n'
      printf '  1) reality-tls  — real TLS to a front site, strongest disguise   [default]\n'
      printf '  2) fake-tls     — TLS-1.3-mimicking handshake, lighter, no front\n'
      printf 'Choose [1/2] (default 1): '
    } > /dev/tty
    local ans=""
    read -r ans < /dev/tty || ans=""
    case "$ans" in
      2|fake-tls|fake)               PROFILE="fake-tls" ;;
      ""|1|reality-tls|reality)      PROFILE="reality-tls" ;;
      *) printf 'Unrecognised (%s) — using reality-tls.\n' "$ans" > /dev/tty
         PROFILE="reality-tls" ;;
    esac
  else
    PROFILE="reality-tls"
    echo "No terminal for a prompt and no QELI_PROFILE set — defaulting to ${PROFILE}."
    echo "(Pick fake-tls non-interactively with:  QELI_PROFILE=fake-tls $0 …)"
  fi
  echo "Selected profile: ${PROFILE}"
}
choose_profile

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
  SHA_URL=""
  if [ -n "${QELI_DEB:-}" ]; then
    DEB_URL="$QELI_DEB"
  else
    RELEASES_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases")
    DEB_URL=$(printf '%s' "$RELEASES_JSON" | jq -r 'map(select(.draft|not)) | .[0].assets[]
               | select(.name|endswith(".deb")) | .browser_download_url' | head -n1)
    [ -n "$DEB_URL" ] || die "no .deb asset found in the latest release."
    # SHA256SUMS asset (published since 0.7.6) — used to verify the download below.
    SHA_URL=$(printf '%s' "$RELEASES_JSON" | jq -r 'map(select(.draft|not)) | .[0].assets[]
               | select(.name=="SHA256SUMS") | .browser_download_url' | head -n1)
  fi
  echo "  downloading: $DEB_URL"
  TMP_DEB="$(mktemp --suffix=.deb)"; CLEANUP_DEB=1
  curl -fL --retry 3 -o "$TMP_DEB" "$DEB_URL"
  # Verify the .deb against the release's SHA256SUMS when it publishes one; refuse to
  # install on a mismatch. Older releases (no SHA256SUMS) fall back to TLS-only trust.
  if [ -n "$SHA_URL" ]; then
    echo "  verifying SHA256"
    TMP_SHA="$(mktemp)"
    curl -fL --retry 3 -o "$TMP_SHA" "$SHA_URL"
    DEB_NAME="$(basename "$DEB_URL")"
    WANT="$(awk -v n="$DEB_NAME" '$2==n{print $1}' "$TMP_SHA" | head -n1)"
    GOT="$(sha256sum "$TMP_DEB" | awk '{print $1}')"
    rm -f "$TMP_SHA"
    if [ -z "$WANT" ]; then
      echo "  WARNING: $DEB_NAME not listed in SHA256SUMS — skipping checksum verify"
    elif [ "$WANT" != "$GOT" ]; then
      rm -f "$TMP_DEB"
      die "SHA256 mismatch for $DEB_NAME (want $WANT, got $GOT) — refusing to install."
    else
      echo "  SHA256 OK"
    fi
  else
    echo "  (no SHA256SUMS in the release — skipping checksum verify)"
  fi
fi

# ── 3. install the package (pulls iptables / iproute2) ──────────────────────
# --no-install-recommends: the package Recommends systemd-resolved (only useful
# for the CLIENT's resolvectl path). A server doesn't need it, and letting apt
# pull it in repoints /etc/resolv.conf to the systemd stub mid-install, which can
# transiently break DNS (e.g. the public-IP lookup below). Skip it on servers.
log "Installing the package"
apt-get install -y --no-install-recommends "$TMP_DEB" || { dpkg -i "$TMP_DEB" || true; apt-get install -y --no-install-recommends -f; }
[ "$CLEANUP_DEB" -eq 1 ] && rm -f "$TMP_DEB"
command -v qeli >/dev/null || die "qeli is not on PATH after install."
[ -f "$EXAMPLE" ] || die "$EXAMPLE missing — package too old (need >= 0.7.2)."

# ── 4. build server.conf: the selected profile only, from the example ───────
log "Configuring the ${PROFILE} profile on :${PORT}"
{
  # global sections ([auth]/[logging]/[web]) — everything before the first profile
  awk '/^\[profile:/{exit} {print}' "$EXAMPLE"
  # only the selected profile block (header until the next [profile:)
  awk -v p="[profile:${PROFILE}]" '$0==p{f=1;print;next} /^\[profile:/{f=0} f{print}' "$EXAMPLE"
} > "$CONF"
# Force the listener onto :$PORT regardless of the example's per-profile port
# (reality-tls already ships on 443; fake-tls ships on 8444 in the example).
sed -i "s|^bind.port = .*|bind.port = ${PORT}|" "$CONF"
# reality-tls carries a REALITY short_id — give THIS deployment its own random one
# (not the example sample). fake-tls has no reality_proxy, so there is nothing to do.
if grep -q '^obf.tls.reality_proxy.short_ids' "$CONF"; then
  SID="$(openssl rand -hex 8)"
  sed -i "s|^obf.tls.reality_proxy.short_ids = .*|obf.tls.reality_proxy.short_ids = ${SID}|" "$CONF"
  echo "  generated REALITY short_id: ${SID}"
fi
# leave routing.nat.interface unset so it auto-detects the WAN interface
sed -i "/^routing.nat.interface/d" "$CONF"

# ── 5. server identity key (created + printed; pinned automatically in the link)
log "Generating the server identity key"
qeli show-identity --config "$CONF"
PUBKEY=$(qeli show-identity --config "$CONF" 2>/dev/null | awk -v p="$PROFILE" '$1==p{print $NF}')
chown -R qeli:qeli "$CONF" /etc/qeli/identity 2>/dev/null || true

# ── 6. public host clients will connect to ──────────────────────────────────
if [ -z "$PUBLIC_HOST" ]; then
  # 1) External echo services — authoritative public IP (esp. behind NAT). Try a
  #    few, each time-bounded so a blocked/unreachable one can't hang the install.
  PUBLIC_HOST="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUBLIC_HOST" ] || PUBLIC_HOST="$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
  [ -n "$PUBLIC_HOST" ] || PUBLIC_HOST="$(curl -fsS --max-time 5 https://icanhazip.com 2>/dev/null || true)"
  # 2) Local fallback — src address of the default route. Works even with a /32 WAN
  #    IP (as many cloud VMs have). On a NAT'd box this is the PRIVATE IP, so warn.
  if [ -z "$PUBLIC_HOST" ]; then
    PUBLIC_HOST="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)"
    [ -n "$PUBLIC_HOST" ] && echo "  (external lookup failed — using the local WAN address ${PUBLIC_HOST}; if this box is behind NAT, re-run with the real public IP)"
  fi
  PUBLIC_HOST="$(printf '%s' "$PUBLIC_HOST" | tr -d '[:space:]')"
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

# ── 8. OS tuning for mobile / LTE paths (PMTU black-hole fix) ───────────────
# The post-quantum reality-tls / fake-tls ClientHello is one large TCP segment; on
# LTE/CGNAT the path MTU is < 1500 and the ICMP "fragmentation needed" is dropped, so
# that segment black-holes and the handshake hangs ("works on wired, fails on LTE").
# Fixed here:
#   • clamp the MSS the server advertises on its listening port (the OUTER handshake —
#     the in-tunnel vpn+ clamp from routing.nat does NOT cover it),
#   • enable TCP PMTU probing + BBR/fq (also lifts throughput).
# All reversible — see the revert note printed at the end.
log "Applying OS tuning (outer MSS clamp + sysctl) for mobile/LTE"
MSS_RULE="-p tcp --sport ${PORT} --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340"
if iptables -t mangle -C OUTPUT $MSS_RULE 2>/dev/null; then
  echo "  MSS clamp already present on :${PORT}"
else
  iptables -t mangle -A OUTPUT $MSS_RULE && echo "  + MSS clamp 1340 on :${PORT}"
fi
# Persist across reboots (best-effort).
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
else
  mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi
cat > /etc/sysctl.d/99-qeli-perf.conf <<'SYSCTL'
# qeli TCP throughput + PMTU tuning (reversible: delete this file + sysctl --system)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_mtu_probing=1
SYSCTL
modprobe tcp_bbr 2>/dev/null || true
echo tcp_bbr > /etc/modules-load.d/qeli-bbr.conf 2>/dev/null || true
sysctl -p /etc/sysctl.d/99-qeli-perf.conf >/dev/null 2>&1 || true

# ── 8b. web admin panel: enable over HTTPS with a generated password ─────────
log "Enabling the web admin panel (HTTPS, generated password)"
PANEL_PORT=8080
PANEL_PW="$(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 20)"
if [ -n "$PANEL_PW" ] && qeli set-web-password --password "$PANEL_PW" --config "$CONF" >/dev/null 2>&1; then
  # set-web-password enabled the panel + wrote username/password_hash. Expose it on
  # all interfaces over self-signed TLS (the fail-closed public-bind check is satisfied
  # by the password we just set); pre-fill the public host for share links/QR.
  sed -i 's/^bind = 127\.0\.0\.1/bind = 0.0.0.0/' "$CONF"
  sed -i 's/^# *tls = true$/tls = true/' "$CONF"
  grep -qE '^tls = ' "$CONF" || sed -i '/^port = 8080/a tls = true' "$CONF"
  sed -i "s|^# *public_host = .*|public_host = ${PUBLIC_HOST}|" "$CONF"
  chown qeli:qeli "$CONF" 2>/dev/null || true
else
  PANEL_PW=""
  echo "  (could not set a panel password — admin UI stays disabled; enable later: qeli set-web-password)"
fi

# ── 9. enable + start ───────────────────────────────────────────────────────
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
Web panel:     $([ -n "$PANEL_PW" ] && echo "https://${PUBLIC_HOST}:${PANEL_PORT}  →  login: admin  /  ${PANEL_PW}" || echo "disabled (set: qeli set-web-password)")
$([ -n "$PANEL_PW" ] && printf '               \342\232\240 SAVE THIS PASSWORD NOW — shown once, only the hash is stored.\n')
Mobile/LTE:    OS tuning applied (MSS clamp 1340 on :${PORT} + BBR/PMTU probing).
               Revert: iptables -t mangle -D OUTPUT ${MSS_RULE} ; rm
               /etc/sysctl.d/99-qeli-perf.conf /etc/modules-load.d/qeli-bbr.conf && sysctl --system

Connection strings (qeli:// — paste or scan into the app):
  ${LINKS_DIR}/<user>.qeli           one file per user
  ${SUMMARY}                          all of them (with passwords)

NEXT STEPS:
  • Open inbound TCP ${PORT}${PANEL_PW:+ and ${PANEL_PORT} (panel)} in your cloud firewall / security group.
  • Add a connection string to the app — that's all. To print one:
      cat ${LINKS_DIR}/${USER_PREFIX}1.qeli
EOF

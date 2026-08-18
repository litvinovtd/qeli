#!/usr/bin/env bash
#
# qeli — one-shot server installer. During the run it asks which profile to deploy
# (reality-tls default, fake-tls, or udp-quic) and which port to listen on (default :443).
#
# What it does, end to end:
#   1. installs dependencies,
#   2. gets qeli onto the box AND sets up everything the .deb does (the `qeli` user,
#      /etc/qeli + state dirs, *.conf.example files, the systemd unit, the polkit rule):
#      by default it downloads + installs the latest .deb from GitHub Releases; with
#      QELI_BIN=<path> it installs that prebuilt binary and reproduces the same layout
#      itself (add QELI_SRC=<repo checkout> for a fully offline / build-from-source run),
#   3. asks for the profile (reality-tls | fake-tls | udp-quic) + listen port and writes
#      /etc/qeli/server.conf with ONLY that profile (taken from the packaged
#      multi-profile example) on the chosen port, full-tunnel NAT on,
#   4. generates the server identity key,
#   5. creates 5 users and saves their ready-to-use qeli:// connection strings
#      under /etc/qeli/client-links/,
#   6. enables + (re)starts the service.
#
# It is a FIRST install: if /etc/qeli/server.conf already exists it refuses to run,
# because rewriting that file mints a new REALITY short_id and kills every qeli://
# link already issued. To upgrade an installed server use update-qeli-server.sh;
# QELI_FORCE_RECONFIG=1 (below) overrides, keeping a timestamped backup.
#
# After it finishes you only paste/scan a connection string into the app.
#
# Usage (run as root — directly, or via sudo if you have it; sudo is NOT required
# and is never installed):
#   ./install-qeli-server.sh [PUBLIC_HOST]          # when already root
#   sudo ./install-qeli-server.sh [PUBLIC_HOST]     # when sudo is available
#     PUBLIC_HOST   Address clients connect to (IP or hostname). If omitted, the
#                   public IP is auto-detected — pass it explicitly if your box has
#                   separate inbound/outbound IPs or you use a domain.
#     QELI_PROFILE  Optional. Pick the profile non-interactively (skips the prompt):
#                   QELI_PROFILE=reality-tls | fake-tls | udp-quic. For curl|bash / automation.
#     QELI_PORT     Optional. Pick the listen port non-interactively (default 443;
#                   1-65535, and not 8080 which the web panel uses). udp-quic listens on UDP.
#     QELI_BIN      Optional. Path to a prebuilt qeli binary — install from it and
#                   reproduce the .deb layout instead of downloading a .deb.
#     QELI_SRC      Optional. Path to a repo checkout; with QELI_BIN, copy the exact
#                   unit / examples from it (offline). Without it they are taken from the
#                   SHA256-verified .deb of the release that matches the binary.
#     QELI_REF      Optional. Release tag to take that unit / those examples from
#                   (default: v<the version `qeli version` reports>).
#     QELI_RUN_AS    Optional. OS user the service runs as: `qeli` (default,
#                   unprivileged, least-privilege) or `root`. `root` removes privilege
#                   separation — only pick it when the qeli user cannot work (a kernel/
#                   container without ambient capabilities) or to avoid the /etc/qeli
#                   ownership + polkit setup. Applied via `qeli set-service-user`.
#     QELI_FORCE_RECONFIG=1
#                   Required to run against an EXISTING /etc/qeli/server.conf. The
#                   installer REWRITES that file from scratch and mints a new REALITY
#                   short_id, which kills every qeli:// link already handed out. With
#                   the opt-in set, the old config is backed up with a timestamp first.
#     QELI_PANEL_PUBLIC=1
#                   Publish the web panel on 0.0.0.0 instead of loopback. REQUIRES
#                   QELI_PANEL_ALLOWED_IPS=<ip[,ip…]> (the panel's source-IP allowlist).
#                   Default: loopback only — reach it over an SSH tunnel.
#
set -euo pipefail

# Everything this script creates is either a secret or config for a secret, so default to
# owner-only and widen deliberately where a file must be readable (e.g. /etc/qeli itself,
# chmod 755 below). Without this the umask decided: on a default 022 shell, server.conf —
# which carries the panel's Argon2id hash and every profile's settings — landed 0644, and
# `qeli set-web-password` only rewrites the file, it does not narrow the mode.
# (Audit 2026-08-04.)
umask 077

# Clean up on ANY exit, not just the happy path.
#
# The downloaded .deb and the directory `dpkg-deb -x` unpacks it into were removed only on
# the paths that reached the removal statements; `set -e`, a failed dpkg, or the operator
# pressing Ctrl-C left both behind in /tmp — a world-listable directory holding an unpacked
# copy of the package tree, once per attempt. (Audit 2026-08-04.)
QELI_TMP_PATHS=()
cleanup_tmp() {
  local p
  for p in "${QELI_TMP_PATHS[@]:-}"; do
    [ -n "$p" ] && rm -rf -- "$p" 2>/dev/null || true
  done
}
trap cleanup_tmp EXIT INT TERM

REPO="litvinovtd/qeli"
PROFILE=""            # chosen interactively below (or non-interactively via QELI_PROFILE)
PORT=443             # default listen port; overridable via QELI_PORT / the prompt below
PANEL_PORT=8080      # web admin panel — reserved (the VPN port cannot reuse it)
NUM_USERS=5
USER_PREFIX="phone"
CONF="/etc/qeli/server.conf"
EXAMPLE="/etc/qeli/server-multiprofile.conf.example"
LINKS_DIR="/etc/qeli/client-links"
RUN_STAMP="$(date +%Y%m%d-%H%M%S)"   # suffix for every backup this run makes

log(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
warn(){ printf '\033[1;33mWARNING: %s\033[0m\n' "$*" >&2; }
# true iff $1 is a decimal port in 1..65535
_valid_port(){ case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

# ── obtaining the packaged unit / config examples for the QELI_BIN path ───────
# These files used to be pulled with a bare `curl https://raw.githubusercontent.com/
# <repo>/main/<path>` and written straight to /lib/systemd/system/qeli.service and
# /etc/polkit-1/rules.d/ — no integrity check at all, off a MOVING branch, while the
# .deb path two screens down is fail-closed on SHA256. So the unit that runs as root
# could differ from the binary's release, and a bad response was installed verbatim.
# Now there are exactly two sources, both verifiable (Audit 2026-07-27, O2):
#   • QELI_SRC=<repo checkout>  — the operator's own files (offline / air-gapped),
#   • otherwise the .deb of the release matching the installed binary, downloaded and
#     SHA256-verified against that release's SHA256SUMS, then unpacked. Same artifact
#     the .deb path installs, so the unit always matches the binary.
PKG_PAYLOAD=""          # unpacked .deb tree, populated on demand
PKG_PAYLOAD_TRIED=0

# Populate $PKG_PAYLOAD from the release .deb matching the installed binary. Fails
# (non-zero) rather than falling back to anything unverified.
_ensure_pkg_payload(){
  [ -z "$PKG_PAYLOAD" ] || return 0
  [ "$PKG_PAYLOAD_TRIED" -eq 0 ] || return 1
  PKG_PAYLOAD_TRIED=1
  command -v dpkg-deb >/dev/null 2>&1 || { warn "dpkg-deb is missing — cannot unpack the release package."; return 1; }
  local ref ver json deb_url sha_url tmp_deb tmp_sha want got dest
  ref="${QELI_REF:-}"
  if [ -z "$ref" ]; then
    # The tag that matches the binary the operator handed us — NOT `main`.
    ver="$(qeli version 2>/dev/null | awk '{print $2}')"
    [ -n "$ver" ] || { warn "cannot read the version from 'qeli version' — pass QELI_REF=<tag> or QELI_SRC=<checkout>."; return 1; }
    ref="v${ver}"
  fi
  echo "  taking the unit + config examples from release ${ref} (SHA256-verified)"
  json="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${ref}" 2>/dev/null || true)"
  [ -n "$json" ] || { warn "release ${ref} not found on GitHub — pass QELI_SRC=<repo checkout> (offline) or QELI_REF=<existing tag>."; return 1; }
  deb_url="$(printf '%s' "$json" | jq -r '.assets[]? | select(.name|endswith(".deb")) | .browser_download_url' | head -n1)"
  sha_url="$(printf '%s' "$json" | jq -r '.assets[]? | select(.name=="SHA256SUMS") | .browser_download_url' | head -n1)"
  [ -n "$deb_url" ] || { warn "release ${ref} publishes no .deb — pass QELI_SRC=<repo checkout>."; return 1; }
  [ -n "$sha_url" ] || { warn "release ${ref} publishes no SHA256SUMS — refusing to install an unverifiable systemd unit. Pass QELI_SRC=<repo checkout>."; return 1; }
  tmp_deb="$(mktemp --suffix=.deb)"; tmp_sha="$(mktemp)"
  # Register both for the EXIT trap so an abort (set -e, Ctrl-C, a failed dpkg) does not
  # strand them in /tmp. The explicit rm calls below stay: they free the space earlier.
  QELI_TMP_PATHS+=("$tmp_deb" "$tmp_sha")
  if ! curl -fL --retry 3 -o "$tmp_deb" "$deb_url" || ! curl -fL --retry 3 -o "$tmp_sha" "$sha_url"; then
    rm -f "$tmp_deb" "$tmp_sha"; warn "download from release ${ref} failed."; return 1
  fi
  want="$(awk -v n="$(basename "$deb_url")" '$2==n{print $1}' "$tmp_sha" | head -n1)"
  got="$(sha256sum "$tmp_deb" | awk '{print $1}')"
  rm -f "$tmp_sha"
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    rm -f "$tmp_deb"
    warn "SHA256 check failed for the ${ref} package (want '${want:-<unlisted>}', got ${got}) — refusing to use it."
    return 1
  fi
  dest="$(mktemp -d)"
  QELI_TMP_PATHS+=("$dest")
  if ! dpkg-deb -x "$tmp_deb" "$dest" 2>/dev/null; then
    rm -rf "$tmp_deb" "$dest"; warn "could not unpack the ${ref} package."; return 1
  fi
  rm -f "$tmp_deb"
  PKG_PAYLOAD="$dest"
}

# Install one packaged file. $1 = path inside a repo checkout, $2 = path inside the
# .deb payload, $3 = destination. Returns non-zero when neither source has it.
_pkg_file(){
  local rel="$1" pkgrel="$2" dest="$3"
  if [ -n "${QELI_SRC:-}" ] && [ -f "${QELI_SRC}/${rel}" ]; then
    install -m644 "${QELI_SRC}/${rel}" "$dest"
    return 0
  fi
  _ensure_pkg_payload || return 1
  [ -f "${PKG_PAYLOAD}/${pkgrel}" ] || return 1
  install -m644 "${PKG_PAYLOAD}/${pkgrel}" "$dest"
}

# Set `KEY = VALUE` inside the [web] section of $CONF: drop any existing definition
# (commented-out ones included) and write ours, appending when the section has none.
#
# Written with awk over a temp file instead of `sed -i "s|^…|key = ${VALUE}|"` because
# the values here are not trusted: public_host comes from $1 or from a third-party echo
# service, and a single `|` in it ended the s||| command and turned the remainder into
# further sed commands run against the server config, as root. awk takes the value via
# -v, so it is data and can never become syntax. It also replaces the pair of sed
# expressions that used to enable TLS, one of which could never match (the example line
# is `# tls = true      # panel then speaks HTTPS …`, so a `$` anchor after `true`
# fails). (Audit 2026-07-27, O3/O4)
_conf_web_set(){
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$val" '
    BEGIN { insec = 0; done = 0 }
    /^\[/ {
      insec = ($0 == "[web]")
      print
      if (insec && !done) { print k " = " v; done = 1 }
      next
    }
    insec && $0 ~ ("^[[:space:]]*#?[[:space:]]*" k "[[:space:]]*=") { next }
    { print }
    END { if (!done) { print ""; print "[web]"; print k " = " v } }
  ' "$CONF" > "$tmp"
  # Never let a failed rewrite truncate the config we are standing on.
  [ -s "$tmp" ] || { rm -f "$tmp"; die "failed to set web.${key} in ${CONF}."; }
  cat "$tmp" > "$CONF"          # keep the original inode/owner/mode
  rm -f "$tmp"
}

# Install from a prebuilt binary ($QELI_BIN) and reproduce EXACTLY what the .deb sets
# up — the binary, the `qeli` system user, /etc/qeli + /var/{log,lib}/qeli, the shipped
# *.conf.example files, an empty users.conf, the systemd unit, ownership, and the polkit
# rule. Used instead of downloading the .deb (build-from-source or air-gapped installs).
# Point QELI_SRC at a repo checkout to copy the exact artifacts offline; otherwise they
# come from the SHA256-verified .deb of the matching release (see _ensure_pkg_payload).
from_source_install(){
  log "Installing from binary ${QELI_BIN} (reproducing the .deb layout)"
  [ -x "$QELI_BIN" ] || die "QELI_BIN=$QELI_BIN is not an executable file."
  # 1) binary — 0755 root:root, no file caps (the unit grants caps via AmbientCapabilities).
  install -m755 "$QELI_BIN" /usr/bin/qeli
  setcap -r /usr/bin/qeli 2>/dev/null || true
  # 2) system user (mirrors postinst: adduser --system --group --no-create-home).
  if ! getent passwd qeli >/dev/null 2>&1; then
    adduser --system --group --no-create-home qeli 2>/dev/null \
      || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin qeli
  fi
  # 3) directories.
  mkdir -p /etc/qeli /var/log/qeli /var/lib/qeli
  # 4) example configs — the same five the .deb ships.
  local name
  for name in server server-multiprofile users client client-reality; do
    _pkg_file "qeli/config/${name}.conf" "etc/qeli/${name}.conf.example" "/etc/qeli/${name}.conf.example" \
      || die "could not obtain a VERIFIED ${name}.conf example (pass QELI_SRC=<repo checkout> for an offline install, or QELI_REF=<release tag>)."
  done
  # 5) empty users.conf so add-client can append (never seed the sample — it has a known hash).
  [ -f /etc/qeli/users.conf ] || : > /etc/qeli/users.conf
  # 6) systemd unit — the exact one the .deb installs. This one runs as root, so it is
  #    never taken from an unverified source. (Audit 2026-07-27, O2)
  _pkg_file "qeli/debian/qeli.service" "lib/systemd/system/qeli.service" /lib/systemd/system/qeli.service \
    || die "could not obtain a VERIFIED qeli.service unit (pass QELI_SRC=<repo checkout>, or QELI_REF=<release tag>)."
  # 7) ownership + perms (mirrors postinst).
  chown -R qeli:qeli /etc/qeli /var/log/qeli /var/lib/qeli
  chmod 755 /etc/qeli
  systemctl daemon-reload 2>/dev/null || true
  command -v qeli >/dev/null || die "qeli is not on PATH after install."
  # 8) polkit rule — reuse the binary's own installer (identical to the .deb's rule); if
  #    this binary predates `install-polkit`, fall back to the shipped rule file.
  if ! qeli install-polkit >/dev/null 2>&1; then
    install -d /etc/polkit-1/rules.d
    _pkg_file "qeli/debian/49-qeli.rules" "etc/polkit-1/rules.d/49-qeli.rules" /etc/polkit-1/rules.d/49-qeli.rules \
      || echo "  (polkit rule not installed — panel 'Apply & Restart' needs it; run 'qeli install-polkit' later)"
  fi
  # The unpacked package tree was only a source of files — drop it.
  [ -z "$PKG_PAYLOAD" ] || rm -rf "$PKG_PAYLOAD"
  echo "  from-binary install complete: binary, user, dirs, examples, unit, polkit rule."
}

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
# OS user the service will run as (default the unprivileged `qeli`). Validated up front so
# a typo fails before we install anything; applied just before the service is started.
QELI_RUN_AS="${QELI_RUN_AS:-qeli}"
case "$QELI_RUN_AS" in
  qeli|root) ;;
  *) die "QELI_RUN_AS must be 'qeli' or 'root' (got '$QELI_RUN_AS')." ;;
esac

# ── pre-flight: never silently destroy a working deployment ─────────────────
# This is a FIRST-INSTALL script: it writes /etc/qeli/server.conf from scratch and
# mints a fresh REALITY short_id, which invalidates every qeli:// link already handed
# out. Re-running it on a configured box used to do exactly that with no check at all,
# also wiping anything added by hand (extra profiles, [web] allowed_ips, the panel
# password_hash, perf.connection.max_clients) — and then DIE half-way, because
# `qeli add-client phone1` refuses to recreate an existing user and the failing
# pipeline killed the script under `set -e` before the service was ever restarted.
# The box was left with a rewritten config, dead links and the OLD daemon running.
# Refuse by default; the opt-in below keeps a timestamped backup of everything it
# replaces. (Audit 2026-07-27, K2)
if [ -e "$CONF" ]; then
  if [ "${QELI_FORCE_RECONFIG:-0}" = "1" ]; then
    warn "QELI_FORCE_RECONFIG=1 — ${CONF} will be BACKED UP and rewritten; existing qeli:// links stop working."
  else
    die "${CONF} already exists — this server is already configured, and re-running
  the installer would rewrite it: a new REALITY short_id (every qeli:// link already
  issued stops working) and the loss of every hand-made edit.
    • upgrade the binary, keeping the config:  ./update-qeli-server.sh
    • add a user:                              qeli add-client <name> --link --host <host:port>
    • show the panel/link data again:          cat ${LINKS_DIR}/CONNECTION-STRINGS.txt
    • really reconfigure from scratch (a timestamped backup is kept):
        QELI_FORCE_RECONFIG=1 $0${1:+ $1}"
  fi
fi

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
      udp-quic|quic|udp)   PROFILE="udp-quic" ;;
      1)                   PROFILE="reality-tls" ;;
      2)                   PROFILE="fake-tls" ;;
      3)                   PROFILE="udp-quic" ;;
      *) die "QELI_PROFILE must be 'reality-tls', 'fake-tls' or 'udp-quic' (got '$sel')." ;;
    esac
    echo "Profile (from QELI_PROFILE): ${PROFILE}"
    return
  fi
  if [ -r /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then
    {
      printf '\n\033[1;36m== Which server profile to install?\033[0m\n'
      printf '  1) reality-tls  — real TLS to a front site, strongest disguise   [default]\n'
      printf '  2) fake-tls     — TLS-1.3-mimicking handshake, lighter, no front\n'
      printf '  3) udp-quic     — QUIC/HTTP3-shaped UDP (no TCP-over-TCP; good on lossy/mobile)\n'
      printf 'Choose [1/2/3] (default 1): '
    } > /dev/tty
    local ans=""
    read -r ans < /dev/tty || ans=""
    case "$ans" in
      2|fake-tls|fake)               PROFILE="fake-tls" ;;
      3|udp-quic|quic|udp)           PROFILE="udp-quic" ;;
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

# ── 0b. choose the listen port (default 443) ────────────────────────────────
# 443 mimics HTTPS and is the recommended choice; some networks prefer 8443/993/etc.
# Priority mirrors the profile: $QELI_PORT (non-interactive) → terminal prompt →
# default 443. The panel port (8080) is reserved and refused here.
choose_port() {
  local sel="${QELI_PORT:-}"
  if [ -n "$sel" ]; then
    _valid_port "$sel" || die "QELI_PORT must be a number 1-65535 (got '$sel')."
    [ "$sel" -ne "$PANEL_PORT" ] || die "QELI_PORT ${sel} is reserved for the web panel — pick another."
    PORT="$sel"; echo "Port (from QELI_PORT): ${PORT}"; return
  fi
  if [ -r /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then
    local ans=""
    while :; do
      printf 'Listen port [1-65535] (default %s): ' "$PORT" > /dev/tty
      read -r ans < /dev/tty || ans=""
      [ -z "$ans" ] && break                              # empty → keep the default
      if ! _valid_port "$ans"; then
        printf 'Not a valid port (1-65535) — try again.\n' > /dev/tty; continue
      fi
      if [ "$ans" -eq "$PANEL_PORT" ]; then
        printf 'Port %s is reserved for the web panel — pick another.\n' "$PANEL_PORT" > /dev/tty; continue
      fi
      PORT="$ans"; break
    done
  else
    echo "No terminal for a prompt and no QELI_PORT set — using default port ${PORT}."
  fi
  echo "Selected port: ${PORT}"
}
choose_port

# Transport of the chosen profile — udp-* profiles listen on UDP, the rest on TCP.
# Drives the (TCP-only) outer MSS clamp below and the firewall hint at the end.
case "$PROFILE" in
  udp-*) TRANSPORT="udp" ;;
  *)     TRANSPORT="tcp" ;;
esac
TRANSPORT_UC="$(printf '%s' "$TRANSPORT" | tr '[:lower:]' '[:upper:]')"

# ── 1. dependencies ─────────────────────────────────────────────────────────
log "Installing dependencies"
apt-get update -y
apt-get install -y curl ca-certificates jq iptables iproute2 openssl

# ── 2. obtain + install qeli ────────────────────────────────────────────────
# Two ways to get qeli onto the box, both ending in the SAME .deb layout:
#   • QELI_BIN=<path>  → install that prebuilt binary and reproduce the .deb setup
#                        (user, dirs, examples, unit, polkit) — no download needed.
#                        Add QELI_SRC=<repo checkout> for a fully offline install.
#   • otherwise        → download + install the .deb from GitHub Releases (default).
if [ -n "${QELI_BIN:-}" ]; then
  from_source_install
else
# By default: newest GitHub release (the releases are pre-releases, so we read
# /releases, not /releases/latest). Override with QELI_DEB=<local path or URL> for
# an offline / air-gapped install or to pin a specific build.
log "Obtaining the qeli .deb"
CLEANUP_DEB=0
HOST_DEB_ARCH="$(dpkg --print-architecture)"
if [ -n "${QELI_DEB:-}" ] && [ -f "$QELI_DEB" ]; then
  echo "  using local .deb: $QELI_DEB"
  TMP_DEB="$QELI_DEB"
else
  SHA_URL=""
  if [ -n "${QELI_DEB:-}" ]; then
    DEB_URL="$QELI_DEB"
  else
    RELEASES_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases")
    DEB_URL=$(printf '%s' "$RELEASES_JSON" | jq -r --arg arch "$HOST_DEB_ARCH" 'map(select(.draft|not)) | .[0].assets[]
               | select(.name|endswith("_" + $arch + ".deb")) | .browser_download_url' | head -n1)
    [ -n "$DEB_URL" ] || die "no .deb asset for Debian architecture ${HOST_DEB_ARCH} found in the latest release."
    # SHA256SUMS asset (published since 0.7.6) — used to verify the download below.
    SHA_URL=$(printf '%s' "$RELEASES_JSON" | jq -r 'map(select(.draft|not)) | .[0].assets[]
               | select(.name=="SHA256SUMS") | .browser_download_url' | head -n1)
  fi
  echo "  downloading: $DEB_URL"
  TMP_DEB="$(mktemp --suffix=.deb)"; CLEANUP_DEB=1
  QELI_TMP_PATHS+=("$TMP_DEB")
  curl -fL --retry 3 -o "$TMP_DEB" "$DEB_URL"
  # Verify the .deb against the release's SHA256SUMS — FAIL CLOSED (S-10). A GitHub
  # download is trusted only once its SHA256 matches the signed sums file; a missing
  # sums file or an unlisted .deb aborts unless the operator opts out with
  # QELI_ALLOW_UNVERIFIED=1. A QELI_DEB the operator supplied (path or URL) is exempt.
  ALLOW_UNVERIFIED="${QELI_ALLOW_UNVERIFIED:-0}"
  if [ -n "$SHA_URL" ]; then
    echo "  verifying SHA256"
    TMP_SHA="$(mktemp)"
    QELI_TMP_PATHS+=("$TMP_SHA")
    curl -fL --retry 3 -o "$TMP_SHA" "$SHA_URL"
    DEB_NAME="$(basename "$DEB_URL")"
    WANT="$(awk -v n="$DEB_NAME" '$2==n{print $1}' "$TMP_SHA" | head -n1)"
    GOT="$(sha256sum "$TMP_DEB" | awk '{print $1}')"
    rm -f "$TMP_SHA"
    if [ -z "$WANT" ]; then
      if [ "$ALLOW_UNVERIFIED" = "1" ]; then
        echo "  WARNING: $DEB_NAME not listed in SHA256SUMS — installing anyway (QELI_ALLOW_UNVERIFIED=1)"
      else
        rm -f "$TMP_DEB"
        die "$DEB_NAME is not listed in the release SHA256SUMS — refusing to install an unverifiable download. Set QELI_ALLOW_UNVERIFIED=1 to override."
      fi
    elif [ "$WANT" != "$GOT" ]; then
      rm -f "$TMP_DEB"
      die "SHA256 mismatch for $DEB_NAME (want $WANT, got $GOT) — refusing to install."
    else
      echo "  SHA256 OK"
    fi
  elif [ -z "${QELI_DEB:-}" ]; then
    # Downloaded from GitHub but the release published NO SHA256SUMS — fail closed.
    if [ "$ALLOW_UNVERIFIED" = "1" ]; then
      echo "  WARNING: release has no SHA256SUMS — installing unverified (QELI_ALLOW_UNVERIFIED=1)"
    else
      rm -f "$TMP_DEB"
      die "the release publishes no SHA256SUMS — cannot verify the download. Set QELI_ALLOW_UNVERIFIED=1 to override, or pass QELI_DEB=<path>."
    fi
  fi
fi

# ── 3. install the package (pulls iptables / iproute2) ──────────────────────
# Never pass a package for another CPU architecture to apt. Besides producing a
# confusing dependency failure, choosing the first .deb asset used to install the
# wrong package whenever a release carried more than one architecture. Explicit
# QELI_DEB paths/URLs are checked as well because their file names are not trusted.
DEB_ARCH="$(dpkg-deb -f "$TMP_DEB" Architecture 2>/dev/null)" || die "cannot read Debian package metadata from $TMP_DEB."
case "$DEB_ARCH" in
  "$HOST_DEB_ARCH"|all) ;;
  *) die "package architecture ${DEB_ARCH} is incompatible with host architecture ${HOST_DEB_ARCH}." ;;
esac

# --no-install-recommends: the package Recommends systemd-resolved (only useful
# for the CLIENT's resolvectl path). A server doesn't need it, and letting apt
# pull it in repoints /etc/resolv.conf to the systemd stub mid-install, which can
# transiently break DNS (e.g. the public-IP lookup below). Skip it on servers.
log "Installing the package"
apt-get install -y --no-install-recommends "$TMP_DEB" || { dpkg -i "$TMP_DEB" || true; apt-get install -y --no-install-recommends -f; }
[ "$CLEANUP_DEB" -eq 1 ] && rm -f "$TMP_DEB"
fi   # end obtain+install (from-binary vs .deb)
command -v qeli >/dev/null || die "qeli is not on PATH after install."
[ -f "$EXAMPLE" ] || die "$EXAMPLE missing — package too old (need >= 0.7.2)."

# ── 4. build server.conf: the selected profile only, from the example ───────
log "Configuring the ${PROFILE} profile on :${PORT}"
# Only reachable with QELI_FORCE_RECONFIG=1 (see the guard at the top). Keep the
# previous config: it is the only copy of the identity pinning, the panel
# password_hash and any hand-written profile this run is about to throw away.
# (Audit 2026-07-27, K2)
if [ -e "$CONF" ]; then
  CONF_BAK="${CONF}.bak-${RUN_STAMP}"
  cp -a "$CONF" "$CONF_BAK"
  echo "  previous config backed up → ${CONF_BAK}"
fi
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
# Validate the moment it is known, BEFORE it reaches a config file or a share link.
# The value is either $1 or whatever api.ipify.org / ifconfig.me / icanhazip.com
# answered, and it used to be spliced straight into `sed -i "s|…|public_host = $X|"` —
# so a `|` in it closed the s||| command and everything after it executed as further
# sed commands against server.conf, as root. Accept only characters an IP or hostname
# can legitimately contain, and bound the length. (Audit 2026-07-27, O3)
case "$PUBLIC_HOST" in
  *[!A-Za-z0-9._:-]*)
    die "PUBLIC_HOST '${PUBLIC_HOST}' contains characters that cannot appear in an IP or hostname — pass a clean address as the first argument." ;;
  -*)
    die "PUBLIC_HOST '${PUBLIC_HOST}' starts with '-' — that is not an address." ;;
esac
[ "${#PUBLIC_HOST}" -le 253 ] || die "PUBLIC_HOST is ${#PUBLIC_HOST} characters long — no hostname is (max 253)."
case "$PUBLIC_HOST" in
  *:*) die "PUBLIC_HOST '${PUBLIC_HOST}' is an IPv6 literal, but current qeli clients support IPv4 server endpoints only. Pass an IPv4 address or a hostname with an A record." ;;
esac

# ── 7. create users + save ready qeli:// connection strings ─────────────────
log "Creating ${NUM_USERS} users + connection strings"
mkdir -p "$LINKS_DIR"; chmod 700 "$LINKS_DIR"
# add-client appends to the users file; make sure it exists (older builds error if not).
[ -f /etc/qeli/users.conf ] || : > /etc/qeli/users.conf
SUMMARY="${LINKS_DIR}/CONNECTION-STRINGS.txt"
SUMMARY_BAK=""
# This file is the ONLY place the generated passwords exist in the clear, so a forced
# re-run must not truncate it before we know which users are being kept.
# (Audit 2026-07-27, K2)
if [ -s "$SUMMARY" ]; then
  SUMMARY_BAK="${SUMMARY}.bak-${RUN_STAMP}"
  cp -a "$SUMMARY" "$SUMMARY_BAK"
  echo "  previous connection-string list backed up → ${SUMMARY_BAK}"
fi
: > "$SUMMARY"
for i in $(seq 1 "$NUM_USERS"); do
  U="${USER_PREFIX}${i}"
  # A user that is already there (only possible on a QELI_FORCE_RECONFIG re-run) is
  # KEPT, not recreated: `qeli add-client` refuses to overwrite one. That refusal used
  # to abort the whole installer, because `LINK=$(qeli add-client … | grep …)` is an
  # assignment from a pipeline — `set -e` killed the script at the assignment, so the
  # explicit `die` on the next line was unreachable and the service never got started.
  # (Audit 2026-07-27, K2)
  if grep -q "^\[user:${U}\]" /etc/qeli/users.conf 2>/dev/null; then
    echo "  = ${U} already exists — kept (password unchanged; its old link is stale if the short_id changed)"
    printf 'user: %s\npass: <unchanged — see %s>\nlink: <stale — this run minted a new REALITY short_id>\n      re-issue from the web panel, or drop [user:%s] from /etc/qeli/users.conf\n      and re-run the installer to recreate it with a fresh password.\n\n' \
      "$U" "${SUMMARY_BAK:-the previous install}" "$U" >> "$SUMMARY"
    continue
  fi
  P="$(openssl rand -hex 12)"   # URL-safe (hex) — embedded straight into the link
  # Run add-client as its own command so a FAILURE is both survivable and visible.
  # Password on STDIN, never in argv: /proc/<pid>/cmdline is world-readable, so
  # `--password "$P"` handed every credential this script generates to any local
  # account polling /proc, and put it into auditd execve records besides.
  # (Audit 2026-08-04.)
  if ! ADD_OUT="$(printf '%s' "$P" | qeli add-client "$U" --password-stdin --link \
           --host "${PUBLIC_HOST}:${PORT}" --link-profile "$PROFILE" \
           --config "$CONF" 2>&1)"; then
    printf '%s\n' "$ADD_OUT" >&2
    die "add-client failed for ${U} (output above)."
  fi
  LINK="$(printf '%s\n' "$ADD_OUT" | grep -m1 '^qeli://' || true)"
  [ -n "$LINK" ] || die "add-client did not return a link for $U."
  echo "$LINK" > "${LINKS_DIR}/${U}.qeli"
  printf 'user: %s\npass: %s\nlink: %s\n\n' "$U" "$P" "$LINK" >> "$SUMMARY"
  echo "  + ${U}"
done
chmod 600 "$LINKS_DIR"/* 2>/dev/null || true
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
# The outer MSS clamp is TCP-only — it fixes the large PQ ClientHello black-holing on
# LTE/CGMAT for the TCP wire modes. A udp-quic profile has no outer TCP handshake to
# clamp (QUIC handles its own PMTU over UDP), so skip it there.
MSS_RULE=""
MSS_APPLIED=0
# The clamp is a PERFORMANCE tweak, never a reason to abandon a half-finished install.
# `iptables -t mangle -A OUTPUT $MSS_RULE && echo …` used to run bare under `set -e`, so
# on a host without the mangle table (LXC/OpenVZ) or with an nft backend that rejects the
# rule, the installer died HERE — config written, users created, service never enabled.
# Both the rule and its persistence are best-effort now, and a failure only warns.
# (Audit 2026-07-27, O5)
apply_mss_clamp(){
  # shellcheck disable=SC2086  # $MSS_RULE is a deliberate multi-word argument list
  if iptables -t mangle -C OUTPUT $MSS_RULE 2>/dev/null; then
    echo "  MSS clamp already present on :${PORT}"; return 0
  fi
  # shellcheck disable=SC2086  # same
  if iptables -t mangle -A OUTPUT $MSS_RULE 2>/dev/null; then
    echo "  + MSS clamp 1340 on :${PORT}"; return 0
  fi
  return 1
}
persist_iptables(){
  # NEVER clobber an existing persisted ruleset. `iptables-save > /etc/iptables/rules.v4`
  # overwrites whatever iptables-persistent manages with the CURRENT live state, which
  # silently drops every rule that file loads but the running kernel does not have.
  # (Audit 2026-07-27, O5)
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 \
      || echo "  (netfilter-persistent save failed — the clamp will not survive a reboot)"
  elif [ ! -e /etc/iptables/rules.v4 ]; then
    mkdir -p /etc/iptables 2>/dev/null || true
    iptables-save > /etc/iptables/rules.v4 2>/dev/null \
      || echo "  (could not persist the clamp — it will not survive a reboot)"
  else
    echo "  (/etc/iptables/rules.v4 exists and is managed elsewhere — NOT overwriting it;"
    echo "   add the clamp there yourself if it should survive a reboot)"
  fi
}
if [ "$TRANSPORT" = "tcp" ]; then
  MSS_RULE="-p tcp --sport ${PORT} --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340"
  if apply_mss_clamp; then
    MSS_APPLIED=1
    persist_iptables
  else
    warn "could not install the outer MSS clamp (no mangle table on this host, or an nft
         backend refused the rule). The install CONTINUES — this only means large
         post-quantum ClientHellos may black-hole on LTE/CGNAT paths. Retry by hand:
           iptables -t mangle -A OUTPUT ${MSS_RULE}"
  fi
else
  echo "  udp-quic: UDP transport has no outer TCP handshake — skipping MSS clamp."
fi
# /etc/sysctl.d and /etc/modules-load.d may be absent on a minimal base (no procps/
# systemd yet) — create them so the heredoc write below can't abort the run (set -e).
mkdir -p /etc/sysctl.d /etc/modules-load.d
cat > /etc/sysctl.d/99-qeli-perf.conf <<'SYSCTL'
# qeli throughput + PMTU tuning (reversible: delete this file + sysctl --system)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_mtu_probing=1
# UDP has NO receive-buffer autotuning. Current qeli explicitly requests 4 MiB per UDP
# listener, so rmem_max must permit it; the default values also protect older qeli builds
# and other UDP sockets on the host. Left at 208 KB, one scheduling stall makes the kernel
# drop datagrams; each lost datagram is a lost TCP segment INSIDE the tunnel, so the inner
# connection halves its window. qeli logs the effective SO_RCVBUF and warns when clamped.
net.core.rmem_default=4194304
net.core.wmem_default=4194304
net.core.netdev_max_backlog=4000
SYSCTL
modprobe tcp_bbr 2>/dev/null || true
echo tcp_bbr > /etc/modules-load.d/qeli-bbr.conf 2>/dev/null || true
sysctl -p /etc/sysctl.d/99-qeli-perf.conf >/dev/null 2>&1 || true

# ── 8b. web admin panel: enable over HTTPS with a generated password ─────────
# BIND POLICY (Audit 2026-07-27, O4). This used to `sed 's/^bind = 127\.0\.0\.1/
# bind = 0.0.0.0/'` unconditionally: every install published an admin panel on the
# public internet with NO allowed_ips filter, protected by one generated password —
# and, because the sed that was supposed to turn TLS on could never match the example
# line, it reached HTTPS only via a fallback insert. One grep matching something else
# and the panel would have been on the internet in cleartext.
#
# The default is now LOOPBACK, which costs an SSH tunnel and removes the whole
# exposure. Publishing it is a deliberate act: QELI_PANEL_PUBLIC=1 AND a non-empty
# QELI_PANEL_ALLOWED_IPS — a public bind without a source allowlist is refused
# outright rather than quietly accepted. TLS is enabled through ONE mechanism
# (_conf_web_set), so there is nothing left that can silently fail to match.
log "Enabling the web admin panel (HTTPS, generated password)"
PANEL_PUBLIC=0
PANEL_ALLOWED="${QELI_PANEL_ALLOWED_IPS:-}"
if [ "${QELI_PANEL_PUBLIC:-0}" = "1" ]; then
  [ -n "$PANEL_ALLOWED" ] || die "QELI_PANEL_PUBLIC=1 needs QELI_PANEL_ALLOWED_IPS=<ip[,ip…]> — publishing the admin panel on 0.0.0.0 with no source allowlist is refused. Use your own address, or drop QELI_PANEL_PUBLIC and reach the panel through an SSH tunnel:  ssh -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} root@${PUBLIC_HOST}"
  # Same reasoning as PUBLIC_HOST: this value lands in the config, so it is data only.
  # Comma-separated, no spaces (e.g. QELI_PANEL_ALLOWED_IPS=203.0.113.4,198.51.100.0/24).
  case "$PANEL_ALLOWED" in
    *[!A-Za-z0-9./,:-]*) die "QELI_PANEL_ALLOWED_IPS must be a comma-separated list of addresses/CIDRs with no spaces (got '${PANEL_ALLOWED}')." ;;
  esac
  PANEL_PUBLIC=1
fi
PANEL_PW="$(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 20)"
# Password on stdin, not in argv — see the note on add-client above.
if [ -n "$PANEL_PW" ] && printf '%s' "$PANEL_PW" \
     | qeli set-web-password --password-stdin --config "$CONF" >/dev/null 2>&1; then
  # set-web-password enabled the panel + wrote username/password_hash. TLS on either
  # way: even on loopback the password should not cross an unencrypted socket that
  # any local user could read.
  _conf_web_set tls true
  _conf_web_set public_host "$PUBLIC_HOST"     # default host for share links/QR
  if [ "$PANEL_PUBLIC" = "1" ]; then
    _conf_web_set bind 0.0.0.0
    _conf_web_set allowed_ips "$PANEL_ALLOWED"
    PANEL_URL="https://${PUBLIC_HOST}:${PANEL_PORT}"
  else
    _conf_web_set bind 127.0.0.1
    PANEL_URL="https://127.0.0.1:${PANEL_PORT}  (loopback only — tunnel in: ssh -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} root@${PUBLIC_HOST})"
  fi
  chown qeli:qeli "$CONF" 2>/dev/null || true
else
  PANEL_PW=""
  PANEL_URL=""
  echo "  (could not set a panel password — admin UI stays disabled; enable later: qeli set-web-password)"
fi

# ── 9. enable + start ───────────────────────────────────────────────────────
# `enable --now` only STARTS a stopped unit: on a re-run it is a no-op against an
# already-active service, so the daemon kept serving the OLD config (old short_id, old
# users) while this script printed "Done" and `systemctl is-active` passed on the stale
# process. enable + restart makes the running daemon match the file we just wrote.
# (Audit 2026-07-27, O1)
# Run-as user: default `qeli` (least privilege). QELI_RUN_AS=root writes a systemd
# drop-in (via the binary's own helper) BEFORE the first start, so the service comes up
# as the chosen user. Reverting later: `qeli set-service-user qeli`.
if [ "$QELI_RUN_AS" = root ]; then
  log "Configuring the service to run as root (QELI_RUN_AS=root — privilege separation off)"
  qeli set-service-user root
fi

log "Starting the service"
systemctl enable qeli
systemctl restart qeli
sleep 2
systemctl is-active --quiet qeli || die "qeli failed to start — see: journalctl -u qeli -e"

# ── done ────────────────────────────────────────────────────────────────────
# Perf/revert note has three cases: the clamp went in, the clamp was REFUSED by this
# host (which is no longer fatal — see O5 above), or the profile is UDP and never
# wanted one. Reporting a revert command for a rule that was never installed would
# send the operator chasing a rule that is not there.
if [ "$MSS_APPLIED" = "1" ]; then
  PERF_NOTE="Mobile/LTE:    MSS clamp 1340 on :${PORT} + BBR/PMTU probing.
               Revert: iptables -t mangle -D OUTPUT ${MSS_RULE} ; rm /etc/sysctl.d/99-qeli-perf.conf /etc/modules-load.d/qeli-bbr.conf && sysctl --system"
elif [ "$TRANSPORT" = "tcp" ]; then
  PERF_NOTE="Mobile/LTE:    BBR/PMTU sysctl applied; the outer MSS clamp could NOT be installed
               on this host (see the warning above) — large post-quantum ClientHellos may
               black-hole on LTE/CGNAT. Add it once iptables works:
                 iptables -t mangle -A OUTPUT ${MSS_RULE}
               Revert: rm /etc/sysctl.d/99-qeli-perf.conf /etc/modules-load.d/qeli-bbr.conf && sysctl --system"
else
  PERF_NOTE="Perf tuning:   BBR/PMTU sysctl applied (udp-quic has no outer TCP → no MSS clamp).
               Revert: rm /etc/sysctl.d/99-qeli-perf.conf /etc/modules-load.d/qeli-bbr.conf && sysctl --system"
fi

log "Done"
cat <<EOF
Server:        ${PROFILE} (${TRANSPORT_UC}) on ${PUBLIC_HOST}:${PORT}   (full-tunnel NAT enabled)
Identity key:  ${PUBKEY:-<run: qeli show-identity --config $CONF>}
Users:         ${NUM_USERS}  (${USER_PREFIX}1 … ${USER_PREFIX}${NUM_USERS})
Web panel:     $([ -n "$PANEL_PW" ] && echo "${PANEL_URL}  →  login: admin  /  ${PANEL_PW}" || echo "disabled (set: qeli set-web-password)")
$([ -n "$PANEL_PW" ] && printf '               \342\232\240 SAVE THIS PASSWORD NOW — shown once, only the hash is stored.\n')
${PERF_NOTE}

Connection strings (qeli:// — paste or scan into the app):
  ${LINKS_DIR}/<user>.qeli           one file per user
  ${SUMMARY}                          all of them (with passwords)

NEXT STEPS:
  • Open inbound ${TRANSPORT_UC} ${PORT}$([ "$PANEL_PUBLIC" = "1" ] && printf ' and TCP %s (panel)' "$PANEL_PORT") in your cloud firewall / security group.
  • Add a connection string to the app — that's all. To print one:
      cat ${LINKS_DIR}/${USER_PREFIX}1.qeli
$([ "$PANEL_PUBLIC" = "1" ] && printf '  \342\200\242 The panel is PUBLIC on 0.0.0.0:%s, restricted to allowed_ips = %s.\n    Widen or narrow it in the [web] section of %s.\n' "$PANEL_PORT" "$PANEL_ALLOWED" "$CONF")
$([ "$PANEL_PUBLIC" = "0" ] && [ -n "$PANEL_PW" ] && printf '  \342\200\242 The panel listens on LOOPBACK only. Reach it with an SSH tunnel:\n      ssh -L %s:127.0.0.1:%s root@%s   then open https://127.0.0.1:%s\n    To publish it instead, set web.bind = 0.0.0.0 AND web.allowed_ips in %s.\n' "$PANEL_PORT" "$PANEL_PORT" "$PUBLIC_HOST" "$PANEL_PORT" "$CONF")
EOF

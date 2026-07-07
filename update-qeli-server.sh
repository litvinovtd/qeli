#!/usr/bin/env bash
#
# qeli — in-place updater for a server installed from a .deb (or a Docker image).
#
# Upgrades ONLY the qeli package/binary and restarts the service. It NEVER touches
# your /etc/qeli state — server.conf, users.conf, the identity key and the client
# links are all preserved (the package ships only the *.example config, not your
# generated one). Safe to re-run; a no-op when you are already on the newest build.
#
# It mirrors the installer's release handling: newest GitHub release (pre-releases
# included), SHA256-verified before install. If the new binary fails to start it
# rolls the previous binary back so the tunnel does not stay down.
#
# Usage (run as root — directly, or via sudo if you have it):
#   ./update-qeli-server.sh              # update to the newest release, if newer
#   ./update-qeli-server.sh --force      # reinstall even if already newest
#   QELI_DEB=/path/qeli.deb ./update-qeli-server.sh   # install a specific .deb (offline)
#
# Note: a binary upgrade restarts qeli, which drops any live sessions (clients
# reconnect on their own). There is no in-place reload for a new binary.
#
set -euo pipefail

REPO="${QELI_REPO:-litvinovtd/qeli}"
SERVICE="qeli"
FORCE="${QELI_FORCE:-0}"

log(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
usage(){ cat <<'USAGE'
qeli server updater — upgrades the qeli package/binary only (never touches
/etc/qeli: config, users, identity and client links are preserved).

Usage (run as root, or via sudo):
  ./update-qeli-server.sh              update to the newest release, if newer
  ./update-qeli-server.sh --force      reinstall even if already on the newest
  QELI_DEB=/path/qeli.deb ./update-qeli-server.sh   install a specific .deb (offline)

A binary upgrade restarts qeli, dropping live sessions (clients reconnect).
USAGE
}

# Make sure the tools the update path needs are present. The installer normally
# pulls these, but install them here too so the updater is self-sufficient on a
# box that happens to lack jq/curl. Runs as root; apt-get is present on the .deb
# servers this targets. jq is only needed for the GitHub lookup, not a local .deb.
ensure_deps() {
  local need=()
  command -v curl >/dev/null 2>&1 || need+=(curl)
  if ! { [ -n "${QELI_DEB:-}" ] && [ -f "${QELI_DEB}" ]; }; then
    command -v jq >/dev/null 2>&1 || need+=(jq)
  fi
  if [ "${#need[@]}" -gt 0 ] && command -v apt-get >/dev/null 2>&1; then
    log "Installing missing tools: ${need[*]}"
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends "${need[@]}" || true
  fi
  command -v curl >/dev/null 2>&1 || die "curl is required and could not be installed automatically."
  if ! { [ -n "${QELI_DEB:-}" ] && [ -f "${QELI_DEB}" ]; }; then
    command -v jq >/dev/null 2>&1 \
      || die "jq is required for the GitHub lookup (or pass QELI_DEB=<path>) and could not be installed automatically."
  fi
}

for a in "$@"; do
  case "$a" in
    -f|--force) FORCE=1 ;;
    -h|--help)  usage; exit 0 ;;
    *) die "unknown argument: $a  (try --help)" ;;
  esac
done

# Must run as root. Run it directly as root, or — if you are a normal user AND sudo
# is installed — it re-execs under sudo. We never install sudo.
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "Not root — re-running under sudo…"
    exec sudo -E bash "$0" "$@"
  fi
  die "must run as root, and 'sudo' is not installed. Switch to root and re-run:  su -"
fi
export DEBIAN_FRONTEND=noninteractive

command -v qeli >/dev/null 2>&1 || command -v docker >/dev/null 2>&1 \
  || die "qeli is not installed — run install-reality-server.sh first."

# Strip a leading 'v' from a tag so v0.7.9 and 0.7.9 compare equal.
norm(){ printf '%s' "$1" | sed 's/^v//'; }

CUR=""
if command -v qeli >/dev/null 2>&1; then
  CUR="$(qeli version 2>/dev/null | awk '{print $2}')"
fi
echo "Installed version: ${CUR:-unknown}"

# ── Docker deployment? update by pulling the image + recreating the container ──
# (Detected host-side: a running container named qeli, when qeli is NOT a dpkg pkg.)
if ! dpkg -s qeli >/dev/null 2>&1 \
   && command -v docker >/dev/null 2>&1 \
   && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$SERVICE"; then
  log "Docker deployment detected — pulling the latest image"
  docker pull "ghcr.io/${REPO}:latest"
  log "Restarting the container"
  docker restart "$SERVICE"
  echo "Done. (If you run the container from compose, prefer: docker compose up -d.)"
  exit 0
fi

# ── 1. resolve the .deb to install ──────────────────────────────────────────
ensure_deps
LATEST_TAG=""
CLEANUP=0
if [ -n "${QELI_DEB:-}" ] && [ -f "${QELI_DEB}" ]; then
  log "Using local .deb: $QELI_DEB"
  TMP_DEB="$QELI_DEB"
  DEB_NAME="$(basename "$QELI_DEB")"
  SHA_URL=""
else
  log "Checking the latest release"
  RELEASES_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases")"
  LATEST_TAG="$(printf '%s' "$RELEASES_JSON" | jq -r 'map(select(.draft|not))|.[0].tag_name // empty')"
  DEB_URL="$(printf '%s' "$RELEASES_JSON" | jq -r 'map(select(.draft|not))|.[0].assets[]
             | select(.name|endswith(".deb")) | .browser_download_url' | head -n1)"
  SHA_URL="$(printf '%s' "$RELEASES_JSON" | jq -r 'map(select(.draft|not))|.[0].assets[]
             | select(.name=="SHA256SUMS") | .browser_download_url' | head -n1)"
  [ -n "$DEB_URL" ] || die "no .deb asset found in the latest release."
  echo "  latest release: ${LATEST_TAG:-?}"

  # Skip when already current (or when the installed build is NEWER than the
  # release, e.g. a local/pre-release build) — unless --force / QELI_FORCE=1.
  if [ "$FORCE" != "1" ] && [ -n "$LATEST_TAG" ] && [ -n "$CUR" ]; then
    L="$(norm "$LATEST_TAG")"
    if [ "$L" = "$CUR" ]; then
      echo "Already on the latest version ($CUR) — nothing to do.  (--force to reinstall.)"
      exit 0
    fi
    NEWEST="$(printf '%s\n%s\n' "$CUR" "$L" | sort -V | tail -n1)"
    if [ "$NEWEST" = "$CUR" ]; then
      echo "Installed version ($CUR) is newer than the latest release ($L) — skipping.  (--force to override.)"
      exit 0
    fi
    echo "  update available: ${CUR} → ${L}"
  fi

  log "Downloading the .deb"
  echo "  $DEB_URL"
  TMP_DEB="$(mktemp --suffix=.deb)"; CLEANUP=1
  curl -fL --retry 3 -o "$TMP_DEB" "$DEB_URL"
  DEB_NAME="$(basename "$DEB_URL")"
fi

# ── 2. verify the download against SHA256SUMS when the release publishes one ──
if [ -n "${SHA_URL:-}" ]; then
  echo "  verifying SHA256"
  TMP_SHA="$(mktemp)"
  curl -fL --retry 3 -o "$TMP_SHA" "$SHA_URL"
  WANT="$(awk -v n="$DEB_NAME" '$2==n{print $1}' "$TMP_SHA" | head -n1)"
  GOT="$(sha256sum "$TMP_DEB" | awk '{print $1}')"
  rm -f "$TMP_SHA"
  if [ -z "$WANT" ]; then
    echo "  WARNING: $DEB_NAME not listed in SHA256SUMS — skipping checksum verify"
  elif [ "$WANT" != "$GOT" ]; then
    [ "$CLEANUP" = "1" ] && rm -f "$TMP_DEB"
    die "SHA256 mismatch for $DEB_NAME (want $WANT, got $GOT) — refusing to install."
  else
    echo "  SHA256 OK"
  fi
fi

# ── 3. back up the current binary for emergency rollback ────────────────────
QBIN="$(command -v qeli || true)"
BAK=""
if [ -n "$QBIN" ] && [ -f "$QBIN" ]; then
  BAK="${QBIN}.prev-${CUR:-unknown}"
  cp -a "$QBIN" "$BAK" 2>/dev/null && echo "  backed up current binary → $BAK" || BAK=""
fi

# ── 4. install the package (deps already satisfied from the first install) ──
log "Installing the update"
apt-get install -y --no-install-recommends "$TMP_DEB" \
  || { dpkg -i "$TMP_DEB" || true; apt-get install -y --no-install-recommends -f; }
[ "$CLEANUP" = "1" ] && rm -f "$TMP_DEB"

# ── 5. restart + health check; roll the old binary back on failure ──────────
log "Restarting ${SERVICE}"
systemctl restart "$SERVICE"
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
  NEW="$(qeli version 2>/dev/null | awk '{print $2}')"
  log "Done — ${CUR:-?} → ${NEW:-?}"
  [ -n "$LATEST_TAG" ] && echo "Release notes: https://github.com/${REPO}/releases/tag/${LATEST_TAG}"
  # keep only the most recent rollback binary; drop older ones
  [ -n "$BAK" ] && find "$(dirname "$QBIN")" -maxdepth 1 -name "$(basename "$QBIN").prev-*" \
      ! -name "$(basename "$BAK")" -delete 2>/dev/null || true
  exit 0
fi

echo "Service failed to start after the update — attempting rollback…" >&2
if [ -n "$BAK" ] && [ -f "$BAK" ]; then
  systemctl stop "$SERVICE" 2>/dev/null || true
  if cp -a "$BAK" "$QBIN"; then
    systemctl restart "$SERVICE"; sleep 2
    if systemctl is-active --quiet "$SERVICE"; then
      die "update failed to start — rolled back to ${CUR}. Investigate: journalctl -u ${SERVICE} -e"
    fi
  fi
fi
die "update failed AND rollback failed — ${SERVICE} is DOWN. Check now: journalctl -u ${SERVICE} -e"

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

# ── Docker deployment? update by pulling the image + RECREATING the container ──
# (Detected host-side: a running container named qeli, when qeli is NOT a dpkg pkg.)
if ! dpkg -s qeli >/dev/null 2>&1 \
   && command -v docker >/dev/null 2>&1 \
   && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$SERVICE"; then
  IMG="ghcr.io/${REPO}:latest"
  log "Docker deployment detected — pulling the latest image"
  docker pull "$IMG"

  # A plain `docker restart` re-runs the SAME container from its ORIGINAL image — it does
  # NOT pick up the image we just pulled. The container must be RECREATED. (S-09)
  proj="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' "$SERVICE" 2>/dev/null || true)"
  workdir="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' "$SERVICE" 2>/dev/null || true)"
  if [ -n "$proj" ] && docker compose version >/dev/null 2>&1; then
    log "Compose deployment ($proj) — recreating with docker compose up -d"
    if [ -n "$workdir" ] && [ -d "$workdir" ]; then
      ( cd "$workdir" && docker compose up -d )
    else
      docker compose -p "$proj" up -d
    fi
    echo "Done."
    exit 0
  fi

  # Non-compose: if the running container already IS the freshly pulled image, a restart
  # is all that's needed. Otherwise recreating requires the original `docker run` flags,
  # which cannot be reconstructed reliably — refuse to pretend a restart updated it. (S-09)
  running_img="$(docker inspect -f '{{ .Image }}' "$SERVICE" 2>/dev/null || true)"
  pulled_img="$(docker image inspect -f '{{ .Id }}' "$IMG" 2>/dev/null || true)"
  if [ -n "$running_img" ] && [ "$running_img" = "$pulled_img" ]; then
    log "Container already runs the latest image — restarting"
    docker restart "$SERVICE"
    echo "Done — already on the newest image."
    exit 0
  fi
  die "pulled a newer image, but '$SERVICE' was not started from compose, so this script
cannot recreate it safely (its original run flags are unknown — a plain restart would keep
the OLD image). Recreate it yourself:
  docker stop $SERVICE && docker rm $SERVICE
  docker run -d --name $SERVICE <your original flags> $IMG
or, if you use compose:  docker compose up -d"
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

# ── 2. verify the download against SHA256SUMS — FAIL CLOSED (S-10) ──────────
# A download pulled from GitHub is only trusted once its SHA256 is checked against the
# release's signed SHA256SUMS. A missing sums file or an unlisted .deb aborts the install
# unless the operator explicitly opts out with QELI_ALLOW_UNVERIFIED=1. A locally supplied
# QELI_DEB is the operator's own artefact and is exempt.
ALLOW_UNVERIFIED="${QELI_ALLOW_UNVERIFIED:-0}"
if [ -n "${SHA_URL:-}" ]; then
  echo "  verifying SHA256"
  TMP_SHA="$(mktemp)"
  curl -fL --retry 3 -o "$TMP_SHA" "$SHA_URL"
  WANT="$(awk -v n="$DEB_NAME" '$2==n{print $1}' "$TMP_SHA" | head -n1)"
  GOT="$(sha256sum "$TMP_DEB" | awk '{print $1}')"
  rm -f "$TMP_SHA"
  if [ -z "$WANT" ]; then
    if [ "$ALLOW_UNVERIFIED" = "1" ]; then
      echo "  WARNING: $DEB_NAME not listed in SHA256SUMS — installing anyway (QELI_ALLOW_UNVERIFIED=1)"
    else
      [ "$CLEANUP" = "1" ] && rm -f "$TMP_DEB"
      die "$DEB_NAME is not listed in the release SHA256SUMS — refusing to install an unverifiable download. Set QELI_ALLOW_UNVERIFIED=1 to override."
    fi
  elif [ "$WANT" != "$GOT" ]; then
    [ "$CLEANUP" = "1" ] && rm -f "$TMP_DEB"
    die "SHA256 mismatch for $DEB_NAME (want $WANT, got $GOT) — refusing to install."
  else
    echo "  SHA256 OK"
  fi
elif [ -z "${QELI_DEB:-}" ]; then
  # Downloaded from GitHub but the release published NO SHA256SUMS at all — fail closed.
  if [ "$ALLOW_UNVERIFIED" = "1" ]; then
    echo "  WARNING: release has no SHA256SUMS — installing unverified (QELI_ALLOW_UNVERIFIED=1)"
  else
    [ "$CLEANUP" = "1" ] && rm -f "$TMP_DEB"
    die "the release publishes no SHA256SUMS — cannot verify the download. Set QELI_ALLOW_UNVERIFIED=1 to override, or pass QELI_DEB=<path>."
  fi
fi

# Optional: verify the signed attestation (R-02). A checksum only says "this matches what
# the release lists" — an attacker who can rewrite the assets rewrites SHA256SUMS too. The
# attestation is signed via OIDC and bound to the repository, so it survives that. Requires
# the `gh` CLI, which servers generally do not have, so this is opt-in rather than a new
# hard dependency: set QELI_VERIFY_ATTESTATION=1 to require it.
if [ "${QELI_VERIFY_ATTESTATION:-0}" = "1" ] && [ -z "${QELI_DEB:-}" ]; then
  if command -v gh >/dev/null 2>&1; then
    echo "  verifying build attestation"
    gh attestation verify "$TMP_DEB" --repo "$REPO" >/dev/null 2>&1 \
      || { [ "$CLEANUP" = "1" ] && rm -f "$TMP_DEB"
           die "attestation verification FAILED for $DEB_NAME — this artifact was not attested by $REPO. Refusing to install."; }
    echo "  attestation OK"
  else
    [ "$CLEANUP" = "1" ] && rm -f "$TMP_DEB"
    die "QELI_VERIFY_ATTESTATION=1 but the 'gh' CLI is not installed — cannot verify. Install gh, or unset the variable to rely on the SHA256 check alone."
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
# `is-active` alone flips true momentarily even for a crash-restart loop, so a binary
# that starts and immediately dies would look healthy and never roll back. Gate on the
# MainPID being NON-ZERO and STABLE across a short window: if it changes (respawn) or
# goes to 0 (dead), the update is unhealthy and we roll back. (S-19)
log "Restarting ${SERVICE}"
systemctl restart "$SERVICE"
sleep 2
PID0="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
sleep 3
PID1="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
if systemctl is-active --quiet "$SERVICE" && [ "$PID0" != "0" ] && [ "$PID0" = "$PID1" ]; then
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

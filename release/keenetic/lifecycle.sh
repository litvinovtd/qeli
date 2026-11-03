# Shared POSIX lifecycle exclusion for Keenetic init, wan.d and installation.
# A stale directory is deliberately retained after SIGKILL/power loss: never
# guess whether another owner is still active or remove somebody else's lock.
QELI_LOCK_DIR=/var/run/qeli.lifecycle.lock
QELI_LOCK_HELD=0

# Firmware may expose /var as a symlink (and /opt may itself be linked).
# Resolve only /var; the core still refuses links/foreign owners below it and
# creates its journal directory privately. Never chmod a pre-existing state path.
# Keeping the physical /var/lib/qeli location also keeps pending recovery state.
qeli_export_state_directory() {
  local root
  root="$(readlink -f /var)" || return 1
  case "$root" in /*) ;; *) return 1 ;; esac
  [ -d "$root" ] || return 1
  STATE_DIRECTORY="${root%/}/lib/qeli"
  export STATE_DIRECTORY
}

QELI_PLAN_LOCK_HELD=0
# Independent of lifecycle: start waits for the client to publish its first plan.
# The core uses the same atomic mkdir and holds it only around file publication.
qeli_plan_lock_acquire() {
  QELI_PLAN_LOCK_DIR="$1.publish-lock"
  (umask 077; mkdir "$QELI_PLAN_LOCK_DIR") 2>/dev/null || {
    echo "qeli-client: network-plan publication busy or stale lock; retry required" >&2
    return 1
  }
  QELI_PLAN_LOCK_HELD=1
}
qeli_plan_lock_release() {
  [ "$QELI_PLAN_LOCK_HELD" = 1 ] || return 0
  rmdir "$QELI_PLAN_LOCK_DIR" || {
    echo "qeli-client: network-plan lock release failed; review required" >&2
    return 1
  }
  QELI_PLAN_LOCK_HELD=0
}
qeli_lock_acquire() {
  (umask 077; mkdir -p "${QELI_LOCK_DIR%/*}" && mkdir "$QELI_LOCK_DIR") || {
    echo "qeli-client: lifecycle busy or stale lock ($QELI_LOCK_DIR); retry/review required" >&2
    return 1
  }
  QELI_LOCK_HELD=1
}
qeli_lock_release() {
  [ "$QELI_LOCK_HELD" = 1 ] || return 0
  rmdir "$QELI_LOCK_DIR" || {
    echo "qeli-client: lifecycle lock release failed ($QELI_LOCK_DIR)" >&2
    return 1
  }
  QELI_LOCK_HELD=0
}

# A failed installer may leave a mixed code bundle. Stop remains available;
# admission is only for start/wan.d/install, and older scripts do not cooperate.
QELI_INSTALL_PENDING=/opt/etc/qeli/install-pending
qeli_install_ready() {
  [ ! -e "$QELI_INSTALL_PENDING" ] && [ ! -L "$QELI_INSTALL_PENDING" ] || {
    echo "qeli-client: installation pending; review recovery state ($QELI_INSTALL_PENDING)" >&2
    return 1
  }
}

# Keep preflight and the asynchronous client on one private INI inode. Metadata
# is preserved so copying cannot authorize commands from an untrusted source.
# Original config stays editable; a running client keeps this snapshot until stop.
QELI_LAUNCH_DIR=/opt/var/run/qeli-launch
QELI_LAUNCH_CONF=""
qeli_launch_dir_valid() {
  [ ! -L "$QELI_LAUNCH_DIR" ] && [ -d "$QELI_LAUNCH_DIR" ] &&
    [ "$(stat -c '%u:%a' "$QELI_LAUNCH_DIR")" = 0:700 ]
}
qeli_prepare_launch_config() {
  local source="$1" parent tmp
  parent="${source%/*}"
  # The installer already creates this private root-owned config directory.
  # Refuse links/unsafe parents instead of upgrading their trust while copying.
  [ ! -L "$source" ] && [ -f "$source" ] && [ -s "$source" ] &&
    [ ! -L "$parent" ] && [ -d "$parent" ] &&
    [ "$(stat -c '%u:%a' "$parent")" = 0:700 ] || {
      echo "qeli-client: regular INI in root-owned 0700 config directory required" >&2
      return 1
    }
  if [ ! -e "$QELI_LAUNCH_DIR" ] && [ ! -L "$QELI_LAUNCH_DIR" ]; then
    (umask 077; mkdir "$QELI_LAUNCH_DIR") || return 1
  fi
  qeli_launch_dir_valid || return 1
  QELI_LAUNCH_CONF="$QELI_LAUNCH_DIR/client.conf"
  [ ! -L "$QELI_LAUNCH_CONF" ] &&
    { [ ! -e "$QELI_LAUNCH_CONF" ] || [ -f "$QELI_LAUNCH_CONF" ]; } || return 1
  tmp="$(mktemp "$QELI_LAUNCH_DIR/.client.conf.XXXXXX")" || return 1
  # POSIX shells count file-size blocks differently. Either bound exceeds the
  # core's 256 KiB INI limit; the core still owns syntax/size admission.
  (ulimit -f 2048 && cp -p "$source" "$tmp") && mv -f "$tmp" "$QELI_LAUNCH_CONF" || {
    rm -f "$tmp"
    return 1
  }
}
qeli_clear_launch_config() {
  [ -e "$QELI_LAUNCH_DIR" ] || [ -L "$QELI_LAUNCH_DIR" ] || return 0
  qeli_launch_dir_valid || return 1
  local path="$QELI_LAUNCH_DIR/client.conf"
  [ ! -L "$path" ] && { [ ! -e "$path" ] || [ -f "$path" ]; } || return 1
  rm -f "$path"
}

#!/bin/sh
# Install on Keenetic/Entware from the staged release bundle. No automatic restart.
set -e
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
PKGDIR="$(cd "$(dirname "$0")" && pwd)"
BIN_TMP=""; INIT_TMP=""; CONF_TMP=""; LIB_TMP=""; MARKER_TMP=""
BIN_BACK=""; INIT_BACK=""; LIB_BACK=""
BIN_CHANGED=0; INIT_CHANGED=0; LIB_CHANGED=0
PUBLISH_STARTED=0; COMMITTED=0; PENDING_CREATED=0; QELI_LOCK_HELD=0
INSTALL_PENDING=/opt/etc/qeli/install-pending

regular_or_absent() {
  [ ! -L "$1" ] && { [ ! -e "$1" ] || [ -f "$1" ]; }
}
restore_file() {
  target="$1"; backup="$2"
  regular_or_absent "$target" || return 1
  if [ -n "$backup" ]; then
    [ -f "$backup" ] && mv -f "$backup" "$target"
  else
    rm -f "$target"
  fi
}
cleanup() {
  status=$?
  trap - 0 HUP INT TERM
  set +e
  keep_backups=0
  if [ "$PUBLISH_STARTED" = 1 ] && [ "$COMMITTED" != 1 ]; then
    rollback_failed=0
    [ "$INIT_CHANGED" != 1 ] || restore_file /opt/etc/init.d/S99qeli "$INIT_BACK" || rollback_failed=1
    [ "$BIN_CHANGED" != 1 ] || restore_file /opt/bin/qeli-client "$BIN_BACK" || rollback_failed=1
    [ "$LIB_CHANGED" != 1 ] || restore_file /opt/etc/qeli/lifecycle.sh "$LIB_BACK" || rollback_failed=1
    if [ "$rollback_failed" = 0 ]; then
      rm -f "$INSTALL_PENDING" || { keep_backups=1; status=1; }
    else
      keep_backups=1; status=1
      # A signal after marker removal but before commit can still enter rollback.
      if [ ! -e "$INSTALL_PENDING" ] && [ ! -L "$INSTALL_PENDING" ]; then
        (umask 077; printf 'qeli-install-recovery-v1\nbinary_backup=%s\ninit_backup=%s\nlibrary_backup=%s\nempty_backup=originally_absent\n' \
          "$BIN_BACK" "$INIT_BACK" "$LIB_BACK" > "$INSTALL_PENDING") || {
          echo "qeli-client: cannot recreate installation recovery marker" >&2
        }
      fi
      echo "qeli-client: installation rollback incomplete; retain $INSTALL_PENDING and review backups" >&2
      printf 'binary=%s\ninit=%s\nlibrary=%s\n' "$BIN_BACK" "$INIT_BACK" "$LIB_BACK" >&2
    fi
  elif [ "$PENDING_CREATED" = 1 ] && [ "$COMMITTED" != 1 ]; then
    rm -f "$INSTALL_PENDING" || { keep_backups=1; status=1; }
  fi
  for tmp in "$BIN_TMP" "$INIT_TMP" "$CONF_TMP" "$LIB_TMP" "$MARKER_TMP"; do
    [ -z "$tmp" ] || rm -f "$tmp" || status=1
  done
  if [ "$keep_backups" = 0 ]; then
    for backup in "$BIN_BACK" "$INIT_BACK" "$LIB_BACK"; do
      [ -z "$backup" ] || rm -f "$backup" || status=1
    done
  fi
  [ "$QELI_LOCK_HELD" != 1 ] || qeli_lock_release || status=1
  exit "$status"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

ARCH="$(opkg print-architecture | awk '{print $2}' | grep -E 'aarch64|mipsel|mips' | head -n1)"
echo "арка пакетов: ${ARCH:-неизвестна} (uname -m: $(uname -m))"
case "$ARCH" in
  *aarch64*) SUFFIX=aarch64 ;;
  *mipsel*) SUFFIX=mipsel ;;
  *) echo "арка '$ARCH' не поддерживается (big-endian mips не собирается)"; exit 1 ;;
esac
# Canonical names match build_keenetic.py; retain old manually prepared bundles.
BINSRC="$PKGDIR/qeli-client-keenetic-$SUFFIX"
[ -f "$BINSRC" ] || BINSRC="$PKGDIR/qeli-client-$SUFFIX"
[ -s "$BINSRC" ] || { echo "нет непустого бинарника для $SUFFIX рядом со скриптом"; exit 1; }
[ -s "$PKGDIR/S99qeli" ] || { echo "нет S99qeli рядом со скриптом"; exit 1; }
[ -s "$PKGDIR/lifecycle.sh" ] || { echo "нет lifecycle.sh рядом со скриптом"; exit 1; }
if [ ! -f /opt/etc/qeli/client.conf ]; then
  [ -s "$PKGDIR/client.conf.example" ] || { echo "нет client.conf.example"; exit 1; }
fi

. "$PKGDIR/lifecycle.sh" || exit 1
qeli_lock_acquire || exit 1
qeli_install_ready || exit 1
for tool in stat cp mktemp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "qeli-client: required command missing ($tool)"; exit 1; }
done
[ ! -L /opt/etc/qeli ] && { [ ! -e /opt/etc/qeli ] || {
  [ -d /opt/etc/qeli ] && [ "$(stat -c '%u' /opt/etc/qeli)" = 0 ];
}; } || { echo "qeli-client: root-owned config directory required"; exit 1; }

# Publication targets must be regular files or absent; never chmod a linked config.
for target in /opt/bin/qeli-client /opt/etc/init.d/S99qeli /opt/etc/qeli/client.conf /opt/etc/qeli/lifecycle.sh; do
  regular_or_absent "$target" || { echo "qeli-client: publication target is not a regular file ($target)"; exit 1; }
done

# Stop using the installed template before replacing a running/uncertain generation.
for state in /opt/var/run/qeli-client.pid /opt/var/run/qeli-client.pid.*; do
  [ -e "$state" ] || continue
  echo "qeli-client: stop/review installed client before upgrade ($state)"; exit 1
done

# Mandatory package errors stop installation; no partial client publication follows.
opkg update
opkg install ip-full iptables
command -v ip >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1 || {
  echo "обязательные команды ip/iptables недоступны после установки"; exit 1;
}
if ! command -v ip6tables >/dev/null 2>&1; then
  opkg install ip6tables || echo "ВНИМАНИЕ: ip6tables не установлен — проверь поддержку IPv6 перед запуском"
fi
[ -e /dev/net/tun ] || echo "ВНИМАНИЕ: нет /dev/net/tun — включи компонент VPN в KeeneticOS"

mkdir -p /opt/bin /opt/etc/init.d /opt/etc/qeli /opt/var/log /opt/var/run
chmod 700 /opt/etc/qeli
# Prepare all new code and the optional config before any publication.
BIN_TMP="$(mktemp /opt/bin/.qeli-client.XXXXXX)"
INIT_TMP="$(mktemp /opt/etc/init.d/.S99qeli.XXXXXX)"
LIB_TMP="$(mktemp /opt/etc/qeli/.lifecycle.XXXXXX)"
install -m755 "$BINSRC" "$BIN_TMP"
install -m755 "$PKGDIR/S99qeli" "$INIT_TMP"
install -m600 "$PKGDIR/lifecycle.sh" "$LIB_TMP"
if [ ! -f /opt/etc/qeli/client.conf ]; then
  CONF_TMP="$(mktemp /opt/etc/qeli/.client.conf.XXXXXX)"
  install -m600 "$PKGDIR/client.conf.example" "$CONF_TMP"
fi

# Same-directory backups preserve old bytes/modes. No service runs during this
# cooperating lifecycle action; old scripts/admin and abrupt power loss are separate.
if [ -f /opt/bin/qeli-client ]; then
  BIN_BACK="$(mktemp /opt/bin/.qeli-client.rollback.XXXXXX)"
  cp -p /opt/bin/qeli-client "$BIN_BACK"
fi
if [ -f /opt/etc/init.d/S99qeli ]; then
  INIT_BACK="$(mktemp /opt/etc/init.d/.S99qeli.rollback.XXXXXX)"
  cp -p /opt/etc/init.d/S99qeli "$INIT_BACK"
fi
if [ -f /opt/etc/qeli/lifecycle.sh ]; then
  LIB_BACK="$(mktemp /opt/etc/qeli/.lifecycle.rollback.XXXXXX)"
  cp -p /opt/etc/qeli/lifecycle.sh "$LIB_BACK"
fi
MARKER_TMP="$(mktemp /opt/etc/qeli/.install-pending.XXXXXX)"
chmod 600 "$MARKER_TMP"
printf 'qeli-install-recovery-v1\nbinary_backup=%s\ninit_backup=%s\nlibrary_backup=%s\nempty_backup=originally_absent\n' \
  "$BIN_BACK" "$INIT_BACK" "$LIB_BACK" > "$MARKER_TMP"
qeli_install_ready || exit 1
PENDING_CREATED=1
mv -f "$MARKER_TMP" "$INSTALL_PENDING"
MARKER_TMP=""
for target in /opt/bin/qeli-client /opt/etc/init.d/S99qeli /opt/etc/qeli/client.conf /opt/etc/qeli/lifecycle.sh; do
  regular_or_absent "$target" || { echo "qeli-client: publication target changed ($target)"; exit 1; }
done

# Set rollback intent before rename, including a signal or rename failure.
PUBLISH_STARTED=1
LIB_CHANGED=1
if mv -f "$LIB_TMP" /opt/etc/qeli/lifecycle.sh; then
  LIB_TMP=""
else
  # A same-directory failed rename retaining its source did not publish.
  [ ! -e "$LIB_TMP" ] || LIB_CHANGED=0
  exit 1
fi
BIN_CHANGED=1
if mv -f "$BIN_TMP" /opt/bin/qeli-client; then
  BIN_TMP=""
else
  # A same-directory failed rename retaining its source did not publish.
  [ ! -e "$BIN_TMP" ] || BIN_CHANGED=0
  exit 1
fi
INIT_CHANGED=1
if mv -f "$INIT_TMP" /opt/etc/init.d/S99qeli; then
  INIT_TMP=""
else
  # A same-directory failed rename retaining its source did not publish.
  [ ! -e "$INIT_TMP" ] || INIT_CHANGED=0
  exit 1
fi
regular_or_absent /opt/etc/qeli/client.conf || exit 1
if [ -n "$CONF_TMP" ]; then
  mv -f "$CONF_TMP" /opt/etc/qeli/client.conf
  CONF_TMP=""
  echo "положил болванку /opt/etc/qeli/client.conf — ОТРЕДАКТИРУЙ её"
else
  chmod 600 /opt/etc/qeli/client.conf
fi
rm -f "$INSTALL_PENDING"
PENDING_CREATED=0
COMMITTED=1

echo
echo "Готово. Дальше:"
echo "  1) vi /opt/etc/qeli/client.conf   # server/user/pass/key/mode + ipv6/gateway/dns"
echo "  2) /opt/etc/init.d/S99qeli start"
echo "  3) tail -f /opt/var/log/qeli-client.log   # ищи 'Auth OK'"

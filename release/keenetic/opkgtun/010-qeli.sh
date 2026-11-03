#!/bin/sh
# /opt/etc/ndm/wan.d/010-qeli.sh — регистрация qeli-tun как нативного OpkgTun-интерфейса
# ndm (KeeneticOS 5.0+), чтобы он был виден в вебморде и доступен в «Приоритетах
# подключений» / статических маршрутах.
#
# Вызывается САМИМ ndm на сетевых событиях → ndmc работает в правильном контексте.
# (Из init.d / non-login shell ndmc падает с `ndmc: system failed [0xcffd0060]`,
# поэтому регистрация живёт здесь, а не в S99qeli.)
#
# ТРЕБУЕТ в client.conf: dev = opkgtun0 И dev_attach = true — qeli ПРИЦЕПЛЯЕТСЯ к
# созданному ndm устройству и НЕ трогает L3. Всё остальное (адрес/линк/маршруты) держит
# ndm — иначе интерфейс залипает в `connected: no` и ndm не маршрутит через него.
#
# МОДЕЛЬ (KeenOS 5.0), критично соблюсти порядок и владение:
#   (1) ndm создаёт интерфейс OpkgTun0 → появляется kernel-device opkgtun0;
#   (2) qeli цепляется к нему (dev_attach), при auth пишет выданный сервером IP в TUNIP;
#   (3) ndm ставит этот IP как /32 + global + up → connected: yes → маршрутизация работает.
# Если L3 поставит qeli, а не ndm — ndm застрянет в `link: pending / connected: no`
# (проверено на устройстве). Если qeli сам СОЗДАСТ opkgtun0 — ndm даст `system failed
# [0xcffd00a9]`. Хук идемпотентен; ndm дёргает wan.d на событиях → регистрация докручивается.

STATE=/opt/var/run/qeli.opkgtun          # маркер: S99qeli пишет сюда имя tun в OpkgTun-режиме
TUNIP=/opt/var/run/qeli.tunip            # qeli пишет сюда выданный сервером IP (attach-режим)
PENDING="$STATE.apply-pending"           # incomplete apply must always retry
APPLIED="$STATE.applied"                 # complete IF + NetworkPlan after checked save
LOG=/opt/var/log/qeli-client.log
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The initial absent-marker fast path is repeated under the common lock.
[ -f "$STATE" ] || exit 0
. /opt/etc/qeli/lifecycle.sh || exit 1
qeli_lock_acquire || exit 1
trap 'status=$?; qeli_plan_lock_release || status=1; qeli_lock_release || status=1; trap - 0; exit "$status"' 0
trap 'exit 1' HUP INT TERM
qeli_install_ready || exit 1

[ -f "$STATE" ] || exit 0                 # OpkgTun-режим в S99qeli выключен — выходим тихо
IF="$(cat "$STATE" 2>/dev/null)"          # имя kernel-tun (напр. opkgtun0)
case "$IF" in opkgtun*) ;; *) exit 1 ;; esac
SUFFIX="${IF#opkgtun}"
case "$SUFFIX" in ''|*[!0-9]*) exit 1 ;; esac
[ "${#IF}" -le 15 ] || exit 1
NDM_IF="OpkgTun$SUFFIX"             # opkgtun0 -> OpkgTun0 (ndm капитализирует)

# Разведка формата событий (раскомментируй ОДИН раз на устройстве, потом верни назад):
# { echo "--- wan.d/010-qeli $(date) ---"; env; } >> "$LOG" 2>&1

# Адреса, которые qeli выдал сервер. Новый формат содержит family=address/prefix;
# первая строка остаётся legacy primary address для старых хуков.
# Capture one atomically published file, so its families/MTU are from one read.
read_plan() {
  PLAN="$(cat "$TUNIP" 2>/dev/null)" || PLAN=""
  WANT_IP="$(printf '%s\n' "$PLAN" | sed -n 's/^ipv4=\([^/]*\)\/.*/\1/p' | head -n1)"
  [ -n "$WANT_IP" ] || WANT_IP="$(printf '%s\n' "$PLAN" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  WANT_IP6_CIDR="$(printf '%s\n' "$PLAN" | sed -n 's/^ipv6=//p' | head -n1)"
  WANT_IP6="${WANT_IP6_CIDR%/*}"
}
read_plan
# Freeze a ready plan before show/no-op or mutation. With no plan, create the
# attach device and wait WITHOUT this lock: the core needs that device first.
if [ -n "$WANT_IP" ] || [ -n "$WANT_IP6" ]; then
  qeli_plan_lock_acquire "$TUNIP" || exit 1
  read_plan
fi

# Only our last complete, saved application can qualify a no-op. Addresses alone
# cannot prove that MTU/MSS/global/security/save completed, or that the plan is new.
# Compare literal address tokens, never regexes or substrings (10.8.0.2 != .20).
address_present() {
  printf '%s\n' "$CUR" | awk -v want="$1" '
    { for (i=1; i<=NF; i++) { split($i, token, "/"); if (token[1]==want) found=1 } }
    END { exit !found }'
}

ipv4_address_is_current() {
  # A gateway/peer mentioning the old IP cannot authorize the broad IPv4 reset.
  printf '%s\n' "$CUR" | awk -v want="$1" '
    $1=="address:" { split($2, token, "/"); if (token[1]==want) found=1 }
    END { exit !found }'
}

plan_is_current() {
  [ "$(cat "$STATE" 2>/dev/null)" = "$IF" ] &&
    [ "$(cat "$TUNIP" 2>/dev/null)" = "$PLAN" ]
}
# The matching core writer is excluded by the publication lock. Keep checks for
# older/non-cooperative writers and administrator changes; these retain retry intent.
require_current_plan() {
  plan_is_current || {
    (umask 077; : >> "$PENDING") || return 1
    echo "wan.d/010-qeli: plan/marker changed for $NDM_IF; retry required" >> "$LOG"
    return 1
  }
}

EXPECTED="$(printf '%s\n%s\n' "$IF" "$PLAN")"
CUR="$(ndmc -c "show interface $NDM_IF" 2>/dev/null)"; SHOW_RC=$?
if [ "$SHOW_RC" -eq 0 ] && [ ! -e "$PENDING" ] \
   && { [ -n "$WANT_IP" ] || [ -n "$WANT_IP6" ]; } \
   && [ "$(cat "$APPLIED" 2>/dev/null)" = "$EXPECTED" ] \
   && printf '%s\n' "$CUR" | awk '$1=="connected:" && $2=="yes" && NF==2 {found=1} END {exit !found}' \
   && { [ -z "$WANT_IP" ] || ipv4_address_is_current "$WANT_IP"; } \
   && { [ -z "$WANT_IP6" ] || address_present "$WANT_IP6"; }; then
  require_current_plan || exit 1
  exit 0
fi

# (1) Убеждаемся, что интерфейс есть в ndm (заводит kernel-device opkgtun0 для attach'а qeli).
# Создание идемпотентно; если интерфейс УЖЕ существует (персистентный конфиг / ndm его
# пере-инициализирует после реконнекта qeli), ndmc может вернуть не-ноль — это НЕ ошибка,
# поэтому фатально считаем только реальное отсутствие интерфейса (show тоже не находит).
ndmc -c "interface $NDM_IF" >/dev/null 2>&1
if ! ndmc -c "show interface $NDM_IF" >/dev/null 2>&1; then
  echo "wan.d/010-qeli: $NDM_IF недоступен в ndm (KeeneticOS <5.0? не тот контекст?)" >> "$LOG"
  exit 0
fi

# (2) Ждём, пока qeli приатачится и запишет выданный сервером IPv4 в TUNIP-файл.
# В attach-режиме qeli НЕ ставит адрес сам (иначе ndm застрянет в connected:no), поэтому
# IP берём из файла, а не с интерфейса. Таймаут короткий, чтобы не блокировать обработчик
# событий ndm — если qeli ещё в backoff, регистрацию докрутит следующий вызов хука.
i=0; IP="$WANT_IP"; IP6="$WANT_IP6"; IP6_CIDR="$WANT_IP6_CIDR"
while [ -z "$IP" ] && [ -z "$IP6" ] && [ $i -lt 10 ]; do
  read_plan
  IP="$WANT_IP"; IP6="$WANT_IP6"; IP6_CIDR="$WANT_IP6_CIDR"
  if [ -n "$IP" ] || [ -n "$IP6" ]; then
    break
  fi
  i=$((i + 1)); sleep 1
done
[ -n "$IP" ] || [ -n "$IP6" ] || { echo "wan.d/010-qeli: $NDM_IF создан, ждём attach qeli (нет IP в $TUNIP)" >> "$LOG"; exit 0; }

if [ "$QELI_PLAN_LOCK_HELD" != 1 ]; then
  qeli_plan_lock_acquire "$TUNIP" || exit 1
  read_plan
  IP="$WANT_IP"; IP6="$WANT_IP6"; IP6_CIDR="$WANT_IP6_CIDR"
  [ -n "$IP" ] || [ -n "$IP6" ] || exit 1
fi

MTU="$(printf '%s\n' "$PLAN" | sed -n 's/^mtu=\([0-9][0-9]*\)$/\1/p' | head -n1)"
case "$MTU" in
  ''|*[!0-9]*) MTU=1400 ;;
  *) [ "$MTU" -ge 576 ] && [ "$MTU" -le 16602 ] || MTU=1400 ;;
esac

# (3) Ставим L3 через ndm — ndm ДОЛЖЕН владеть адресом/линком, иначе connected:no и нет
# маршрутизации. Команды декларативные → повторный вызов с теми же значениями безопасен.
# `ip global auto` = «для выхода в интернет» (без него маршруты через интерфейс не идут).
# `security-level public` = ndm сам делает masquerade/firewall (свой NAT не нужен).
# Глобальный default здесь не ставим: без отдельного bypass для адреса qeli-сервера
# он заворачивает несущее соединение в сам туннель. Policy-routing включается в Keenetic UI,
# где ndm может атомарно учесть приоритеты и исключения.
ndm_apply() {
  require_current_plan || return 1
  ndmc -c "$1" || {
    echo "wan.d/010-qeli: ndm rejected configuration for $NDM_IF; retry required" >> "$LOG"
    return 1
  }
}
# Keep both the last saved plan and a possibly partially applied plan until
# their old addresses have been retired. Empty pending files from older bundles
# remain readable; they carry retry intent but cannot prove address ownership.
retire_addresses() {
  local record="$1" previous_if previous_ndm previous_suffix previous4 previous6 previous6_ip
  [ -n "$record" ] || return 0
  previous_if="$(printf '%s\n' "$record" | head -n1)"
  case "$previous_if" in opkgtun*) ;; *) return 1 ;; esac
  previous_suffix="${previous_if#opkgtun}"
  case "$previous_suffix" in ''|*[!0-9]*) return 1 ;; esac
  [ "${#previous_if}" -le 15 ] || return 1
  previous_ndm="OpkgTun$previous_suffix"
  previous4="$(printf '%s\n' "$record" | sed -n 's/^ipv4=\([^/]*\)\/.*/\1/p' | head -n1)"
  [ -n "$previous4" ] || previous4="$(printf '%s\n' "$record" | sed -n '2p' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')"
  previous6="$(printf '%s\n' "$record" | sed -n 's/^ipv6=//p' | head -n1)"
  case "$previous4" in *[!0-9.]*) return 1 ;; esac
  case "$previous6" in *[!0-9A-Fa-f:/]*) return 1 ;; esac
  previous6_ip="${previous6%/*}"
  # IPv4 setters replace the single static address. Clearing an absent family
  # has no address argument, so first prove the current address is the old one.
  if { [ -n "$previous4" ] && { [ -z "$IP" ] || [ "$previous_if" != "$IF" ]; }; } ||
     { [ -n "$previous6" ] && { [ "$previous6" != "$IP6_CIDR" ] || [ "$previous_if" != "$IF" ]; }; }; then
    require_current_plan || return 1
    CUR="$(ndmc -c "show interface $previous_ndm" 2>/dev/null)" || return 1
    if [ -n "$previous4" ] && { [ -z "$IP" ] || [ "$previous_if" != "$IF" ]; } && ipv4_address_is_current "$previous4"; then
      ndm_apply "interface $previous_ndm no ip address" || return 1
    fi
    if [ -n "$previous6" ] && { [ "$previous6" != "$IP6_CIDR" ] || [ "$previous_if" != "$IF" ]; } && address_present "$previous6_ip"; then
      ndm_apply "interface $previous_ndm no ipv6 address $previous6" || return 1
    fi
  fi
}

[ ! -L "$PENDING" ] && { [ ! -e "$PENDING" ] || [ -f "$PENDING" ]; } || exit 1
(umask 077; : >> "$PENDING") || exit 1
[ ! -L "$APPLIED" ] && { [ ! -e "$APPLIED" ] || [ -f "$APPLIED" ]; } || exit 1
OLD_APPLIED=""; OLD_PENDING=""
[ ! -e "$APPLIED" ] || OLD_APPLIED="$(cat "$APPLIED")" || exit 1
[ ! -e "$PENDING" ] || OLD_PENDING="$(cat "$PENDING")" || exit 1
# Preserve the previous pending payload while retiring it. A failed deletion or
# independently published plan must not forget an address from partial apply.
(umask 077; : >> "$PENDING") || exit 1
retire_addresses "$OLD_APPLIED" || exit 1
retire_addresses "$OLD_PENDING" || exit 1
require_current_plan || exit 1
PENDING_TMP="$(umask 077; mktemp "$PENDING.XXXXXX")" || exit 1
if ! chmod 600 "$PENDING_TMP" || ! printf '%s\n%s\n' "$IF" "$PLAN" > "$PENDING_TMP" ||
   ! mv -f "$PENDING_TMP" "$PENDING"; then
  rm -f "$PENDING_TMP"
  exit 1
fi
ndm_apply "interface $NDM_IF description qeli-VPN" || exit 1
ndm_apply "interface $NDM_IF ip global auto" || exit 1
[ -z "$IP" ] || ndm_apply "interface $NDM_IF ip address $IP 255.255.255.255" || exit 1
[ -z "$IP6_CIDR" ] || ndm_apply "interface $NDM_IF ipv6 address $IP6_CIDR" || exit 1
ndm_apply "interface $NDM_IF ip mtu $MTU" || exit 1
ndm_apply "interface $NDM_IF ip tcp adjust-mss pmtu" || exit 1
ndm_apply "interface $NDM_IF security-level public" || exit 1
ndm_apply "interface $NDM_IF up" || exit 1
ndm_apply "system configuration save" || exit 1
# Non-cooperative replacement must not publish a complete application receipt.
require_current_plan || exit 1
# The private sibling is published only after every mutation and save succeeded.
# A publication/removal failure retains PENDING so matching addresses cannot hide it.
APPLIED_TMP="$(umask 077; mktemp "$APPLIED.XXXXXX")" || exit 1
if [ -d "$APPLIED" ] || ! chmod 600 "$APPLIED_TMP" \
   || ! printf '%s\n%s\n' "$IF" "$PLAN" > "$APPLIED_TMP" \
   || ! mv -f "$APPLIED_TMP" "$APPLIED"; then
  rm -f "$APPLIED_TMP"
  exit 1
fi
require_current_plan || exit 1
rm -f "$PENDING" || exit 1
require_current_plan || exit 1
echo "wan.d/010-qeli: $NDM_IF up (IPv4=${IP:-none}, IPv6=${IP6:-none}, mtu $MTU) — L3 держит ndm" >> "$LOG"

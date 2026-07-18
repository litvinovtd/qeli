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
LOG=/opt/var/log/qeli-client.log
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin

[ -f "$STATE" ] || exit 0                 # OpkgTun-режим в S99qeli выключен — выходим тихо
IF="$(cat "$STATE" 2>/dev/null)"          # имя kernel-tun (напр. opkgtun0)
case "$IF" in opkgtun[0-9]*) ;; *) exit 0 ;; esac
NDM_IF="OpkgTun${IF#opkgtun}"             # opkgtun0 -> OpkgTun0 (ndm капитализирует)

# Разведка формата событий (раскомментируй ОДИН раз на устройстве, потом верни назад):
# { echo "--- wan.d/010-qeli $(date) ---"; env; } >> "$LOG" 2>&1

# IP, который qeli выдал сервер (нужен и для guard'а, и для регистрации ниже).
WANT_IP="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TUNIP" 2>/dev/null | head -n1)"

# Уже поднят, подключён и с нужным адресом? Тихо выходим — работы нет (идемпотентность +
# защита от петли событий ndm: наш `... up`/`ip route` ниже сами генерят события wan.d).
CUR="$(ndmc -c "show interface $NDM_IF" 2>/dev/null)"
if echo "$CUR" | grep -q "connected: yes" \
   && { [ -z "$WANT_IP" ] || echo "$CUR" | grep -q "address: $WANT_IP"; }; then
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
i=0; IP="$WANT_IP"
while [ -z "$IP" ] && [ $i -lt 10 ]; do
  IP="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TUNIP" 2>/dev/null | head -n1)"
  [ -n "$IP" ] && break
  # запасной источник: вытащить из лога qeli ("Auth OK, assigned IP: 10.9.0.3")
  IP="$(sed -n 's/.*assigned IP: \([0-9.]*\).*/\1/p' "$LOG" 2>/dev/null | tail -n1)"
  [ -n "$IP" ] && break
  i=$((i + 1)); sleep 1
done
[ -n "$IP" ] || { echo "wan.d/010-qeli: $NDM_IF создан, ждём attach qeli (нет IP в $TUNIP)" >> "$LOG"; exit 0; }

MTU=1400   # MTU туннеля (в логе qeli: "TUN MTU: 1400"). Поменяй, если сервер пушит другой.

# (3) Ставим L3 через ndm — ndm ДОЛЖЕН владеть адресом/линком, иначе connected:no и нет
# маршрутизации. Команды декларативные → повторный вызов с теми же значениями безопасен.
# `ip global auto` = «для выхода в интернет» (без него маршруты через интерфейс не идут).
# `security-level public` = ndm сам делает masquerade/firewall (свой NAT не нужен).
# `ip route default $NDM_IF` даёт policy-routing через tun; конкретные маршруты — из UI/ndmc.
ndmc -c "interface $NDM_IF description qeli-VPN"
ndmc -c "interface $NDM_IF ip global auto"
ndmc -c "interface $NDM_IF ip address $IP 255.255.255.255"
ndmc -c "interface $NDM_IF ip mtu $MTU"
ndmc -c "interface $NDM_IF ip tcp adjust-mss pmtu"
ndmc -c "interface $NDM_IF security-level public"
ndmc -c "interface $NDM_IF up"
ndmc -c "ip route default $NDM_IF"
ndmc -c "system configuration save"
echo "wan.d/010-qeli: $NDM_IF up ($IP/32, mtu $MTU) — L3 держит ndm" >> "$LOG"

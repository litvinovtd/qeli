# OpenWrt и Keenetic: ручной режим и управление клиентом

Русский · [English](../../eng/manuals/ROUTER-INTEGRATION.md)

Экспериментальная интеграция добавлена в `dev` коммитом `33805e96`.
Нужны совместимые **бинарник клиента и пакет/шаблоны**. Номер `0.8.5` сам по себе
не подтверждает наличие функции: проверьте команду `qeli-client router --help`.
Текущий pin/hash публичного OpenWrt feed ещё указывает на прежний исходный код;
его обновление и выпуск пакетов выполняются отдельно. Сервер обновлять для
появления этих локальных команд недостаточно.

Установка базового клиента: [OpenWrt](OPENWRT-INSTALL.md),
[Keenetic](KEENETIC-DEPLOY.md), [регистрация OpkgTun](../../../release/keenetic/opkgtun/README.md).
Эта инструкция настраивает **существующие** сети и WAN. Wi-Fi, DHCP, подключение
провайдера и разрешение forwarding в fw4/KeeneticOS должны быть настроены заранее.

## 1. Как выбрать режим

Здесь три независимых выбора:

1. **Кто управляет маршрутами и ограничениями:** ваши скрипты/прошивка либо
   отдельный контроллер Qeli. По умолчанию управление остаётся внешним.
2. **Куда выходит клиентская сеть:** `direct`, `vpn_only` или `vpn_fallback`.
3. **Кто создаёт TUN:** обычный клиент либо KeeneticOS/NDM в режиме OpkgTun.
   Выбор OpkgTun не включает контроллер маршрутов Qeli автоматически.

| Владелец маршрутов `routing` | Владелец ограничений `firewall` | Когда выбирать |
|---|---|---|
| `external` | `external` | Уже работают собственные скрипты, mwan3/PBR или политики KeeneticOS |
| `client` | `client` | Нужны встроенные политики существующих сетей, проверка путей и ограничивающий firewall/NAT |
| `client` | `external` | Qeli выбирает пути, а администратор отдельно обеспечивает firewall; `vpn_only` в этой комбинации запрещён |
| `external` | `client` | Маршруты остаются у прошивки/скриптов, Qeli добавляет ограничивающие правила и NAT в TUN |

Во внешнем режиме Qeli по-прежнему подключает VPN и выдаёт статус. Режим не
устанавливает вместо вас маршруты, DNS или запрет утечки в WAN. Прежний
full-tunnel (`gateway=true`) — отдельная возможность ядра, а не синоним
`components.routing=client`. Для нового контроллера full-tunnel нужно отключить.

При `routing=external` выбор `vpn_fallback` в JSON сам по себе не создаёт
переключение маршрутов: это обязанность внешнего владельца. Без управляемой
маршрутизации guard опирается на нативное состояние туннеля, а не на WAN/TUN
ICMP-пробы контроллера.

Не включайте двух владельцев для одной сети. Переход в `client` не удаляет
старые самописные правила. Переносите только правила выбранных сетей; общая
остановка mwan3/PBR может затронуть другие сети и административное подключение.

### Политики сети при `routing=client`

| `networks[].policy` | VPN доступен | VPN недоступен |
|---|---|---|
| `direct` | Выбранный физический WAN | Физический WAN |
| `vpn_only` | TUN | Выход в WAN блокируется; разрешённый локальный доступ сохраняется |
| `vpn_fallback` | Новые соединения предпочитают TUN | Новые соединения выбирают доступный WAN |

Порядок `uplinks` задаёт предпочтение: первый исправный WAN используется для
новых соединений. При возврате WAN1 живые TCP/UDP-соединения через WAN2 сохраняют
свой путь. Аналогично уже открытые WAN-соединения не обязаны немедленно перейти
в восстановившийся VPN. Отказавшее обычное TCP-соединение не переносится между
разными внешними IP — приложению может понадобиться переподключение.

`local_subnets` задаёт разрешённые локальные назначения. INPUT и административные
SSH/веб-порты контроллер не открывает. Ответы на разрешённые прошивкой входящие
соединения и DNAT возвращаются через входной WAN/TUN; ответное направление
conntrack не считается новым исходящим соединением VPN-only клиента.

## 2. Условия встроенного режима

- Выполняйте команды от root; `ip-full` и выбранный firewall backend должны быть
  доступны. Для OpenWrt nftables нужны `nftables-json` и `kmod-nft-nat`.
- Отключите software/hardware forwarding offload в прошивке. Только после этого
  укажите `offload_disabled: true`; флаг не отключает ускорение самостоятельно.
- Контроллер и валидатор статуса используют доступные через procfs network
  namespaces: в том числе `/proc/thread-self/ns/net` и `/proc/<PID>/ns/net`.
  Совместимость базового клиента с ядром без `CONFIG_NET_NS` **не распространяется**
  автоматически на эти новые функции; в таком случае оставьте внешний режим.
- Для управляемых маршрутов нужны `gateway=false`, `kill_switch=false`,
  `route_local=false`, `pull_routes=false`, `dns=off/system`; также выключите
  `gateway_nat`, `forward`, `exit_node`. На OpenWrt `pull_routes=false` добавляет
  renderer при выборе `router_routing=client`.
- Для VPN-only на Keenetic нужен постоянный запрет WAN, реально настроенный
  средствами KeeneticOS до запуска Entware. `persistent_guard=true` только
  подтверждает его наличие. Entware после монтирования `/opt` не может обеспечить
  защиту более раннего этапа загрузки. На OpenWrt эту роль выполняет `qeli-guard`.

При удалённом переходе с full-tunnel сначала обеспечьте проверенный альтернативный
административный вход. Изменение VPN-профиля может перезапустить сам VPN;
120-секундный откат политик не восстанавливает профиль, пароль, произвольные UCI
сети, старые пользовательские скрипты или административные настройки.

## 3. OpenWrt: настроить через LuCI

1. Откройте **Services → qeli VPN → Router integration**. Если секции нет,
   обновите клиент, init-файлы и LuCI из совместимого комплекта.
2. Для ручной схемы оставьте **Routing owner = External / manual scripts** и
   **Scoped firewall owner = External / manual scripts**. Остальные шаги этого
   раздела нужны для встроенных политик.
3. Узнайте Linux-имена существующих сетей и WAN:

   ```sh
   qeli-client router discover
   ubus call network.interface.wan status
   ip -br address
   ```

   UCI-имя `wan2` может соответствовать устройству `lan1` или `pppoe-wan2`.
   В JSON указывается **Linux-устройство**, не подпись SSID и не логическое UCI-имя.
   Настройка резервного провайдера DHCP/PPPoE выполняется отдельно в OpenWrt.
4. Отключите offload, full-tunnel, core kill-switch и `route_local`, оставьте
   `dns=off/system`. Выберите владельцев `client` / `client`.
5. Вставьте в **Advanced router policy (JSON)** пример ниже, заменив устройства,
   подсети и адреса сервера. Нажмите **Save & Apply**. Служба проверяет кандидат
   перед публикацией; затем контроллер применяет политику с автооткатом.
6. Включите независимую службу политик в автозапуск, проверьте новое SSH/веб-
   подключение к роутеру и выход **с устройства каждой выбранной сети**. В течение
   120 секунд нажмите **Confirm router policy**. Один ping с самого роутера
   не проверяет политику клиентской Wi-Fi-сети.

   ```sh
   /etc/init.d/qeli-router enable
   ```

   После проверки отдельно подтвердите:

   ```sh
   /etc/init.d/qeli-router confirm_policy
   ```

### JSON для двух WAN и двух клиентских сетей

`192.0.2.10` — адрес из документационного диапазона. Замените его адресом своего
сервера и перечислите все используемые A/AAAA. Автоматического DNS-refresh этого
списка пока нет. Пример использует разрешённый fallback в WAN; для строгой сети
замените только её `policy` на `vpn_only`.

```json
{
  "offload_disabled": true,
  "uplinks": [
    {"device": "wan", "probes": ["1.1.1.1", "8.8.8.8"]},
    {"device": "lan1", "probes": ["1.1.1.1", "8.8.8.8"]}
  ],
  "networks": [
    {"device": "br-vpn", "subnets": ["192.168.77.0/24"], "policy": "vpn_fallback"},
    {"device": "br-lan", "subnets": ["192.168.1.0/24"], "policy": "direct"}
  ],
  "local_subnets": ["192.168.1.0/24"],
  "server_addresses": ["192.0.2.10"],
  "health": {
    "tunnel_probes": ["1.0.0.1"],
    "interval_secs": 3,
    "timeout_secs": 1,
    "up": 2,
    "down": 3
  }
}
```

Сеть `br-vpn` должна уже существовать с адресом/DHCP. Этот JSON не создаёт SSID,
VLAN или зону, разрешающую forwarding. Список `subnets` содержит канонические
исходные префиксы выбранной сети; `/0` и пересечения клиентских подсетей запрещены.

### Та же настройка через UCI

Сохраните адаптированный JSON из примера в `/tmp/qeli-router-policy.json` с
правами 0600. UCI option `router_policy` содержит **весь документ**; одноимённое
JSON-поле `router_policy` относится к трафику самого роутера и должно оставаться
`null` либо быть пропущено.

```sh
uci set qeli.main.gateway='0'
uci set qeli.main.kill_switch='0'
uci set qeli.main.route_local='0'
uci set qeli.main.dns='off'
uci set qeli.main.router_routing='client'
uci set qeli.main.router_firewall='client'
uci set qeli.main.router_policy="$(cat /tmp/qeli-router-policy.json)"
uci commit qeli
/etc/init.d/qeli-router enable
/etc/init.d/qeli reload
```

После проверки нового административного входа и каждой клиентской сети
отдельно выполните:

```sh
/etc/init.d/qeli-router confirm_policy
```

Команды предполагают, что параметры сервера/пароль и намерение запуска VPN уже
заданы по [инструкции установки](OPENWRT-INSTALL.md). Подтверждайте только после
успешной проверки, а не автоматически следующей строкой установщика.

Для смешанного режима замените нужный UCI owner на `external`; при
`routing=client, firewall=external` используйте только `direct`/`vpn_fallback`
и настройте внешний firewall самостоятельно. В LuCI используются те же поля.

### Службы, файлы и возврат к скриптам

| Объект | Назначение |
|---|---|
| `/etc/config/qeli` | UCI-намерение, JSON и выбор владельцев |
| `/etc/qeli/router.json` | Сгенерированная эффективная политика; вручную не редактировать |
| `/etc/init.d/qeli-guard` | START=17: ранний ограничивающий firewall, до сети |
| `/etc/init.d/qeli-router` | START=18: отдельный procd-контроллер политик |
| `/etc/init.d/qeli` | Процесс VPN и его профиль |
| `/var/run/qeli/router/health.json` | Результаты проверок WAN/TUN |

Выбор управляемого firewall включает `qeli-guard`. Hotplug из пакета повторяет
применение при ifup/ifupdate. Policy-only reload может сохранить VPN-процесс,
если INI/пароль не изменились. Остановка VPN или `qeli-router stop` сохраняет
guard; это не команда возврата в ручной режим.

```sh
# Очистить только объекты нового контроллера и записать external/external в UCI:
/etc/init.d/qeli-router disable_policy
```

После этого активируйте подготовленные внешние правила выбранных сетей. Не
подменяйте `disable_policy` простым удалением JSON или остановкой процесса.
Если контроллер ещё никогда не включался, достаточно выбрать оба `external`
в LuCI/UCI; для него ещё нет объектов, которые нужно очищать.

При ручной установке новых функций кроме `qeli.init` нужны файлы
`qeli.router.init` → `/etc/init.d/qeli-router`, `qeli.guard.init` →
`/etc/init.d/qeli-guard`, `98-qeli-policy` → `/etc/hotplug.d/iface/98-qeli-policy`
и `qeli.sysupgrade` → `/lib/upgrade/keep.d/qeli` из того же комплекта.
Init/hotplug-файлы должны быть исполняемыми; готовый совместимый пакет
устанавливает их сам. При обновлении не заменяйте свой `/etc/config/qeli`
пустым примером из репозитория.

## 4. Keenetic: обычный TUN и OpkgTun

Сначала выберите способ владения интерфейсом; он не зависит от owner политик:

| Вариант | Шаблон | INI | Владелец адреса и линка |
|---|---|---|---|
| Обычный TUN Entware | `release/keenetic/S99qeli` | `dev=vpn0`, `dev_attach=false` | Qeli |
| OpkgTun | `release/keenetic/opkgtun/S99qeli` и wan.d hook | `dev=opkgtun0`, `dev_attach=true` | KeeneticOS/NDM |

Имена приведены как пример и должны совпасть с `TUN`/`OPKGTUN` установленного
шаблона. Для OpkgTun сначала выполните его [отдельную регистрацию](../../../release/keenetic/opkgtun/README.md).
Новый контроллер не регистрирует OpkgTun и не назначает ему адрес вместо NDM.

### Ручные маршруты или политики KeeneticOS

Оставьте `components` внешними и не запускайте `policy-start`. Само наличие
`/opt/etc/qeli/router.json` не активирует режим: нужен приватный `router.enabled`.
Если контроллер уже работал, верните внешний режим командой:

```sh
/opt/etc/init.d/S99qeli policy-disable
```

Для полностью внешнего NAT/маршрутов задайте `GATEWAY=no` в S99qeli и выключите
core `gateway_nat`/`forward`/`exit_node`. Это отличается от прежней схемы
«весь LAN через VPN», где gateway/NAT намеренно включает ядро либо legacy-шаблон.
В OpkgTun маршруты и NAT можно оставить NDM. Не накладывайте на те же сети
новые метки Qeli одновременно с действующей селективной политикой NDM.

### Включить встроенный контроллер

1. Проверьте `/opt/bin/qeli-client router --help`, существующие Linux-устройства
   через `router discover`, offload и поддержку namespace-интерфейсов procfs.
2. Подготовьте работающий split-tunnel профиль. В существующей секции `[qeli]`
   **замените**, а не продублируйте параметры:

   ```ini
   gateway = false
   gateway_nat = false
   forward = false
   exit_node = false
   kill_switch = false
   route_local = false
   pull_routes = false
   dns = off
   ```

   Сохраните сервер, учётные данные и маскировку. Обычный TUN оставляет
   `dev=vpn0`, `dev_attach=false`; OpkgTun — `dev=opkgtun0`, `dev_attach=true`.
   Для этого сценария установите `GATEWAY=no` в S99qeli. Изменение INI требует
   отдельного stop/start VPN; `policy-start` не применяет INI работающего процесса.
3. Создайте **кандидат**, не перезаписывая действующую политику:

   ```sh
   umask 077
   /opt/bin/qeli-client router example --platform keenetic > /opt/etc/qeli/router.candidate.json
   vi /opt/etc/qeli/router.candidate.json
   ```

   В полном примере задайте `"components": {"routing": "client", "firewall": "client"}`, оставьте
   `backend: "iptables"`, задайте реальные `uplinks`, `networks`, `local_subnets`,
   `server_addresses`, `health.tunnel_probes` по примеру OpenWrt. Укажите
   `offload_disabled: true`, `router_policy: null`. Пути Keenetic уже заданы:
   status в `/tmp/qeli-status/status.json`, PID в `/opt/var/run/qeli-client.pid`,
   runtime контроллера в `/tmp/qeli-router`. Для OpkgTun измените `device` на
   `opkgtun0`. Не переносите с OpenWrt `managed_boot` или `client_metadata`.
4. Для `vpn_only` сначала настройте постоянную защиту в прошивке и только затем
   укажите `persistent_guard: true`. Для разрешённого `vpn_fallback` оставьте
   значение по умолчанию `false`.
5. Проверьте кандидат и опубликуйте его. Каталог `/opt/etc/qeli` должен быть
   root-owned 0700, JSON — 0600. Сохраните копию прежнего JSON, если он существует.

   ```sh
   /opt/bin/qeli-client router check --policy /opt/etc/qeli/router.candidate.json &&
       mv /opt/etc/qeli/router.candidate.json /opt/etc/qeli/router.json &&
       /opt/etc/init.d/S99qeli policy-start
   ```

   После проверки нового входа и каждой сети, до истечения 120 секунд,
   отдельно выполните:

   ```sh
   /opt/etc/init.d/S99qeli policy-confirm
   ```

`policy-start` создаёт `router.enabled`, запускает независимый процесс и включает
его подхват последующими запусками S99qeli. После изменения JSON повторный
`policy-start` заменяет только контроллер. Это не регистрация службы внутри NDM.
Если старт был отклонён из-за ещё не появившегося устройства/маршрута, устраните
причину и повторите запуск; полноценный NDM-adapter поздней загрузки не реализован.

| Команда S99qeli | Эффект |
|---|---|
| `start` / `stop` / `restart` | Управляет процессом VPN; отдельный guard сохраняется |
| `policy-start` | Запускает/обновляет контроллер выбранной политики |
| `policy-stop` | Останавливает только контроллер, guard остаётся |
| `policy-confirm` | Подтверждает текущую 120-секундную транзакцию |
| `policy-disable` | Удаляет собственные объекты/маркер активации и записывает внешних владельцев |
| `status` | Показывает процесс и отдельно валидированный статус туннеля |

## 5. Параметры и проверки путей

| Поле JSON | Что задавать |
|---|---|
| `uplinks` | Физические WAN в порядке предпочтения; DHCP/PPPoE уже настроены прошивкой |
| `uplinks[].routing_table` | Необязательная существующая таблица прошивки, если обнаружены неоднозначные шлюзы |
| `uplinks[].probes` | 1–4 IP-адреса ICMP-целей; достаточно одного успешного ответа за цикл |
| `networks` | Linux-устройство, его исходные подсети и политика |
| `local_subnets` | Явные локальные префиксы; не `/0` |
| `server_addresses` | Все фактически используемые IP сервера; обновляются администратором |
| `health.tunnel_probes` | IP-цели для проверки интернета именно через TUN |
| `health.interval_secs` | Пауза между циклами, по умолчанию 3 с; не полное время переключения |
| `health.timeout_secs` | Тайм-аут пробы, по умолчанию 1 с |
| `health.up` / `health.down` | Последовательные успехи/ошибки для смены состояния, по умолчанию 2/3 |
| `backend` | `nft` для OpenWrt по умолчанию; `iptables` в примере Keenetic |
| `router_policy` | Оставить `null`: исходящий трафик самого роутера пока управляется извне |

Номера выделяемых таблиц, приоритеты и биты маркировки Qeli выбирает сам.
Не копируйте номер 100 или маску из чужого скрипта. При изменении backend,
порядка WAN, имени TUN или числа слотов сначала явно отключите прежний контроллер
и подготовьте внешнюю политику на время перехода.

При irewall=client IPv6-обход через физический WAN для VPN-сетей блокируется. Это касается и
`vpn_fallback`: прямой IPv6 fallback не предоставляется; IPv6 через TUN зависит
от плана сервера. DNS-путь не следует автоматически из политики сети: резолвер
на самом роутере отправляет собственный трафик. DoH/DoT и DNS interception
пока настраиваются внешними средствами.

## 6. Статус и диагностика

OpenWrt:

```sh
ubus call luci.qeli service_status '{}'
qeli-client router check --policy /etc/qeli/router.json
cat /var/run/qeli/router/health.json
logread -e qeli
```

Keenetic:

```sh
/opt/etc/init.d/S99qeli status
/opt/bin/qeli-client router check --policy /opt/etc/qeli/router.json
cat /tmp/qeli-router/health.json
tail -n 100 /opt/var/log/qeli-client.log
```

`router check` проверяет политику без применения маршрутов. На OpenWrt передавайте
эффективный `/etc/qeli/router.json`, а не сырой UCI JSON, которому renderer ещё
не подставил владельцев, пути и метаданные. `health.json` создаётся контроллером
управляемой маршрутизации; в ручном режиме его отсутствие нормально.

Процесс, туннель и интернет — отдельные признаки. Успех `/etc/init.d/qeli status`
или код 0 у `S99qeli status` не доказывает `Connected`. Нативные состояния:
`connecting`, `connected`, `reconnecting`, `stopped`, `error`. Отсутствующий,
устаревший или чужой отчёт даёт `available:false` / «статус недоступен».
Проверяются boot/PID/поколение, namespace, ifindex, UP и согласованные IP-адреса.
При OpkgTun до назначения адреса NDM остаётся Connecting. Простой без трафика
не считается обрывом. Connected подтверждает состояние сессии Qeli;
`health.json.vpn` дополнительно учитывает TUN Internet-пробу.

| Ошибка/симптом | Что проверить |
|---|---|
| `unrecognized subcommand router` | Нужен новый клиентский бинарник вместе с шаблонами |
| Конфликт gateway/kill-switch/pull_routes | Совместимые split-tunnel параметры и фактически применённый INI |
| `existing source/device policy` / конфликт mark | Прежние правила для той же сети; оставьте внешний режим либо перенесите их явно |
| `selected Linux device does not exist` | Реальное имя устройства, запуск DHCP/PPPoE, создание bridge прошивкой |
| `persistent_guard` / `offload_disabled` | Настроить требуемую защиту/отключение ускорения, затем подтверждать флагом |
| Применение вернулось назад | Не было подтверждения за 120 с; проверьте восстановленную политику и журнал |
| `this policy was rolled back` | Исправьте отклонённое намерение; автоматическое повторное применение того же JSON заблокировано |
| Процесс работает, статус недоступен | Совместимость бинарника/шаблона, procfs namespaces, поколение процесса, адрес TUN и свежесть отчёта |

При откате сохраняются последняя подтверждённая политика и запись отклонённого
намерения. Простое редактирование UCI не отменяет причину отказа. Не удаляйте
защитные правила/файлы наугад, особенно при единственном доступе через VPN.

## 7. Пароль и обновление

**OpenWrt.** `retain_secrets=0` — прежний RAM-only режим. Для хранения между
перезагрузками включите **Retain credentials across reboot** и примените выбор
перед вводом нового пароля/obfs-key. Через UCI:

```sh
uci set qeli.main.retain_secrets='1'
uci commit qeli
# Ввести секрет через LuCI либо stdin из уже подготовленного закрытого файла:
/etc/init.d/qeli set_secret pass < /root/qeli-password
```

Файл-источник должен содержать одну строку с завершающим переводом строки и быть
доступен только root. Не помещайте настоящий пароль в команду/историю shell.
Постоянная копия — `/etc/qeli/secrets/{password,obfs-key}`, права 0600, каталог
0700. При первом явном opt-in старт также переносит существующее RAM-значение;
затем постоянная копия восстанавливается перед запуском. Выключение опции или
**Clear volatile secret** не удаляет сохранённую копию. Для удаления используйте
кнопку **Delete retained credentials** либо команду init-службы:

```sh
/etc/init.d/qeli forget_retained_secrets
```

**Keenetic.** Для файлового пароля замените inline `pass` в `[qeli]` на
`password_file=/tmp/qeli-status/password`. Выбор хранения:

```sh
# Постоянный пароль: S99qeli восстановит его в RAM при следующем старте.
umask 077
/opt/bin/qeli-client router store-secret --directory /opt/etc/qeli/secrets --name pass < /opt/etc/qeli/password.input
# Либо RAM-only: после перезагрузки ввести заново.
/opt/bin/qeli-client router store-secret --directory /tmp/qeli-status --name pass < /opt/etc/qeli/password.input
```

Нативное хранилище требует физических root-owned каталогов без symlink в пути;
алиас /opt на конкретной прошивке нужно проверить до выбора этого способа.
Это **альтернативные** команды. Удаление постоянной копии:
`router forget-secret --directory /opt/etc/qeli/secrets --name pass`.
Файл-источник также root-only; отдельно решите, хранить ли его после импорта.
S99qeli восстанавливает имеющуюся постоянную копию при старте: для перехода к
RAM-only удалите её явно. Нового INI-поля для файла obfs-key на Keenetic нет.
Изменение пароля в файле не переавторизует уже работающую сессию без restart.

OpenWrt sysupgrade сохраняет `/etc/config/qeli` и `/etc/qeli/`: opt-in секреты,
identity, pinning, политики и служебные записи подтверждения. Бинарные пакеты
обычный sysupgrade не гарантирует — включите Qeli в образ или переустановите
совместимый комплект. Runtime/таблицы/правила создаются заново, если нужные
службы включены в автозапуск. На Keenetic сохранность `/opt` зависит от носителя
Entware; он должен монтироваться до запуска S99qeli.

## 8. Границы реализации и проверки

Мастер создания SSID/DHCP, отдельные DNS-группы DoH/DoT, автоматический refresh
адресов сервера, аутентифицированная проверка Qeli через каждый WAN, резервные
VPN-профили и создание политик NDM пока не реализованы. Маршрут внешних сокетов
сохраняет транспорт/прошивка; ICMP Internet-проба WAN не доказывает доступность
сервера Qeli через этот WAN. Неизвестные поля JSON отклоняются.

На Linux amd64 проверены nftables/iptables, VPN-only/fallback, WAN failover/
failback, симметричные ответы и DNAT, сохранение живых TCP/UDP, независимый
watchdog и секреты. Реальный fake-TLS клиент проверен с обычным TUN и
`dev_attach`, где адрес назначает внешний тестовый владелец. Сценарии:
`scripts/router_policy_netns_fixture.py`, `scripts/router_status_netns_fixture.py`.
Это не испытание скорости, загрузки прошивки или конкретного физического
Keenetic/OpenWrt и не квалификация всех musl-архитектур релиза.

# qeli-client на Keenetic — пошаговый деплой

> **0.8.3, issue #205:** обновляйте бинарник и комплект init/lifecycle вместе.
> Оба шаблона (обычный и OpkgTun) передают реальную цель `/var` + `/lib/qeli`
> как `STATE_DIRECTORY`. Это тот же физический каталог журналов, без обхода
> `O_NOFOLLOW`, chmod небезопасных путей и потери recovery. Identity/TOFU остаются
> в `/opt/etc/qeli`. [Каталог и ручной запуск](OPERATIONS.md#восстановление-физических-маршрутов-клиента).
> Ядро прошивки должно поддерживать `SO_NETNS_COOKIE`, также при `dns=off`;
> архитектура CPU и успешная сборка не подтверждают это требование.

> **Область benchmark:** все Reality-оценки скорости или двойного фрейминга в этом документе
> относятся к legacy carrier вплоть до 0.7.16. Нынешнему настоящему H2 нужен отдельный router benchmark.

Развёртывание qeli-VPN-клиента на роутере Keenetic (Entware) как шлюза для всего LAN.
Архитектура и обоснование порта — [KEENETIC-PORT.md](../reference/KEENETIC-PORT.md). Файлы бандла —
в `release/keenetic/`.

> **OpenWrt:** нативный клиент использует то же ядро. Исправления появляются после
> обновления клиентского бинарника; обновление одного сервера их не переносит на роутер.

> **Границы 0.8.2:** физические Keenetic/OpenWrt исключены из согласованного аудита.
> Прежние аппаратные результаты не квалифицируют эти новые файлы. Проверены исходники,
> целевые ELF, SDK export/prepare и изолированные lifecycle-сценарии, с указанными
> в отчётах ограничениями. Имена интерфейсов и firewall проверь под свою прошивку.

---

## Предусловия

- На роутере установлен **Entware** (пакетный менеджер `opkg`, каталог `/opt`).
- Включён **SSH** и есть доступ к шеллу роутера.
- Включён компонент **VPN** в KeeneticOS (любой из WireGuard/OpenVPN/IPsec) — он
  обеспечивает наличие `/dev/net/tun`. Добавляется в веб-морде: *Управление → Общие
  настройки → Изменить набор компонентов*.
- Есть рабочий **сервер qeli** с профилем и заведённым для роутера клиентом.

---

## Шаг 0. Разведка роутера (по SSH на роутер)

```sh
opkg print-architecture | grep -E 'aarch64|mipsel|mips'   # арка пакетов
cat /proc/cpuinfo | grep -E 'cpu model|FPU|system type'   # CPU/FPU
ls -l /dev/net/tun                                         # должен существовать
df -h /opt                                                 # запас для бинарника, зависимостей, старой и временной копий
```

- `mipsel-…` → бинарь `qeli-client-mipsel` (MT7621/7628 и т.п.).
- `aarch64-…` → бинарь `qeli-client-aarch64` (новые ARM-модели).
- Нет `/dev/net/tun` → вернись к предусловиям и включи компонент VPN.

---

## Шаг 1. Получить готовый комплект (на рабочем компьютере)

После публикации выбери точную версию на [GitHub Releases](https://github.com/litvinovtd/qeli/releases).
Скачай `qeli-keenetic-files.tar.gz`, подходящий `qeli-client-keenetic-aarch64` или
`qeli-client-keenetic-mipsel` и `SHA256SUMS` из того же релиза. ELF занимает 8,93 МиБ
(aarch64) или 10,87 МиБ (mipsel); нужны дополнительное место для зависимостей,
старого бинарника и временного файла обновления.

Например, для aarch64 на компьютере с `sha256sum`:

```sh
grep -E ' [ *](qeli-keenetic-files[.]tar[.]gz|qeli-client-keenetic-aarch64)$' SHA256SUMS > selected.sha256
test "$(wc -l < selected.sha256)" -eq 2
sha256sum -c selected.sha256
tar -xzf qeli-keenetic-files.tar.gz
cp qeli-client-keenetic-aarch64 qeli-keenetic/
```

Для mipsel замени имя бинарника в фильтре и `cp`. Архив содержит интеграцию и примеры,
а ELF нужно положить рядом с `install-keenetic.sh` внутри `qeli-keenetic/`.
Отдельный installer из загрузок не заменяет остальные файлы архива.

### Необязательно: собственная сборка для мейнтейнера

```sh
python scripts/build_keenetic.py --sync
# → release/keenetic/qeli-client-keenetic-aarch64   (static ARM aarch64)
# → release/keenetic/qeli-client-keenetic-mipsel    (static-pie MIPS32r2)
```

Можно собрать только нужную арку: `python scripts/build_keenetic.py --sync mipsel`.

Helper предназначен для мейнтейнера и требует доступа к приватной лабе.
Каждый запуск helper создаёт приватный каталог0700
/var/tmp/qeli-router-keenetic-XXXXXX или /var/tmp/qeli-router-openwrt-XXXXXX,
загружает текущий checkout и использует собственный target. --sync оставлен для
совместимости: загрузка выполняется и без него. Общий /opt/qeli-src и backup
Cargo.toml больше не используются. Ограничение crate-type до rlib меняет только
приватную копию. Ошибка upload/close оставляет .router-sync-incomplete и останавливает
запуск; повтор создаёт новый checkout. Каталоги сохраняются для диагностики:
после завершения проверь и удали только напечатанный каталог конкретного запуска.
Автоматической очистки нет. Компиляция Qeli использует --locked, --jobs1, без incremental
cache. Установленные toolchain и download cache Cargo всё ещё могут быть общими.

Перед атомарной публикацией тот же SHA256-проверенный снимок должен быть ELF
little-endian нужной разрядности/архитектуры с исполняемой точкой входа, без
PT_INTERP и DT_NEEDED; ARMv7 обязан объявлять EABI5 hard-float. Отказ сохраняет
предыдущий локальный бинарник, в том числе при совпадении его hash с remote cache.
Проверка не доказывает musl, CPU ISA, полный float ABI MIPS, воспроизводимость
сборки или работу прошивки. Общая политика выбирает Rust1.97.0, nightly-2026-06-10 для MIPS,
Zig0.13.0 и cargo-zigbuild0.23.0. Неверная версия вызывает отказ; недостающие
именованные Rust/target components устанавливаются без изменения default toolchain.
Оба helper используют эту политику. Encoded/внешние RUSTFLAGS не подменяют recipe;
MIPS сохраняет явный soft-float linker argument. Compiler overrides очищаются,
Rust wrappers отключаются для компиляции Qeli. Global Cargo config, PATH, общие
cache/tool installations и изменения файлов при upload пока не позволяют заявлять
герметичную или воспроизводимую сборку. SDK использует собственный Rust feed. См. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).


---

## Шаг 2. Получить креды клиента от сервера (на сервере qeli)

```sh
# Завести клиента и сразу получить qeli://-ссылку (и пароль — печатается ОДИН раз):
qeli add-client router1 --link --host <публичный_адрес_сервера>

# Публичный ключ сервера для пиннинга (анти-MITM):
qeli show-identity
```

Из ссылки/вывода понадобятся: `server` (host:port), `proto` (tcp/udp), `user`, `pass`,
`key` (server pubkey), `mode` (fake-tls/obfs/plain/…), `sni`.

---

## Шаг 3. Скопировать подготовленный каталог на роутер

```sh
scp -r qeli-keenetic <user>@<router-ip>:/opt/tmp/keenetic
# <user> — аккаунт роутера с доступом к /opt (обычно admin/root). Альтернатива — USB.
```

---

После собственной сборки helper вместо `qeli-keenetic` копируй `release/keenetic` вместе с ELF.

## Шаг 4. Установка (на роутере)

```sh
cd /opt/tmp/keenetic
sh install-keenetic.sh
```

Скрипт: определит арку → положит нужный бинарь в `/opt/bin/qeli-client`; поставит
`ip-full` и `iptables` (busybox-`ip` Кинетика урезан — нет `tuntap`); проверит
`/dev/net/tun`; разложит `S99qeli` и болванку конфига.

Установщик development0.8.2 использует canonical qeli-client-keenetic-aarch64/mipsel;
старые qeli-client-aarch64/mipsel остаются fallback. Отказ обязательных пакетов
останавливает публикацию. Existing INI content сохраняется, mode ограничен0600.
Копии готовятся заранее, файлы публикуются атомарным rename по отдельности; весь
bundle не является транзакцией. Ошибку устранить и повторить установку; VPN сам
не перезапускается. Отказ optional ip6tables требует проверить IPv6 support.
[Q31 fixture evidence](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md) не квалифицирует
настоящие opkg/ELF/ABI/power-loss/firmware runtime.

---

## Шаг 5. Заполнить конфиг (на роутере)

```sh
vi /opt/etc/qeli/client.conf
```

Подставь значения из Шага 2.

В обычном режиме Qeli создаёт TUN и в обновлённом Linux-клиенте задаёт очередь
`1000` пакетов. Необязательный `[qeli] tun.tx_queue_len = 1000` (`1..32767`, без auto)
можно добавить в `/opt/etc/qeli/client.conf`; после правки остановить/запустить
именно клиент. Установленный бинарник должен содержать эту доработку development 0.8.2;
проверки на Linux amd64 не заменяют проверку новой сборки на конкретном роутере.
В режиме OpkgTun/`dev_attach=true` **не задавай ключ**: очередь принадлежит `ndm`,
а явный параметр отклоняется. [Полный контракт](CONFIG.md#client-tun-tx-queue).

Для роутера-шлюза важны `gateway` и `dns` в примере ниже:

```ini
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = router1
pass   = <пароль>
# Пиннинг статического ключа сервера (анти-MITM). Пусто/все нули = TOFU.
key    = <server pubkey из show-identity>
# H-1 (с 0.7.1, ВКЛ по умолчанию): привязка сессионных ключей к статике сервера.
# ДОЛЖНА СОВПАДАТЬ с сервером (у обоих дефолт true). ТРЕБУЕТ реального key. С TOFU-ключом
# (нули) поставь false; с реальным key — оставь по умолчанию (удали строку). Если у клиента
# false, а у сервера дефолт true — коннект упадёт с «decryption failed» после хендшейка.
bind_static = false
# Режим маскировки — должен совпадать с сервером. MIPS: fake-tls | obfs | plain
# (ChaCha20). reality-tls на mipsel очень медленный (двойной AEAD) — только для ARM.
mode   = fake-tls
# SNI для fake-tls (фронт-домен). Для obfs не нужен.
sni    = www.cloudflare.com
# ТОЛЬКО для mode = reality-tls (с 0.7.1 short_id обязателен). reality-tls ТРЕБУЕТ реального key → убери `bind_static = false` (оставь дефолт true), иначе «decryption failed».
# reality_sid = <hex>

# ── Router / шлюз ────────────────────────────────────────────────────────────
# full-tunnel: весь трафик LAN в туннель (+ NAT в S99qeli)
gateway = true
# НЕ трогать резолвер роутера (им владеет прошивка)
dns     = off
# kill_switch: блокировка утечек через iptables (теперь работает на Keenetic, где
# iptables и так есть). На шлюзе firewall делает S99qeli, так что можно оставить выключенным. Дефолт off.
# kill_switch = false

[logging]
level = info
file  = /opt/var/log/qeli-client.log
# метка времени в строке: datetime (дефолт) | rfc3339 | time | epoch | none.
# Здесь лог пишется в свой файл, а не в syslog, поэтому метка нужна; rfc3339
# удобен, если потом сводить этот лог с серверным.
time_format = datetime
```

**H-1 / `bind_static` (важно с 0.7.1):** по умолчанию клиент привязывает сессию к
запиненному статическому ключу сервера. Флаг **должен совпадать на клиенте и сервере**
(у обоих дефолт `true`): при рассинхроне KDF расходится (разные HKDF-соли) и коннект
падает с `Connection error: decryption failed` сразу после `reading server auth proof`.
Два рабочих варианта для роутера:
- **Безопасно (рекомендуется):** впиши реальный `key` (из `qeli show-identity`) и
  оставь `bind_static` по умолчанию (on). TOFU-пин сохраняется в `QELI_KNOWN_HOSTS`
  (в `S99qeli` это `/opt/etc/qeli/known_hosts` — переживает ребут, в отличие от `/var`).
- **TOFU (проще):** `key` = нули и `bind_static = false` — доверие при первом коннекте.
- **`mode = reality-tls`:** реальный `key` + `reality_sid` обязательны (TOFU-нули не
  работают), поэтому `bind_static` тут **обязан быть `true`** — просто убери строку
  `bind_static = false`. Оставленный `false` = гарантированный `decryption failed`.

---

## Шаг 6. Проверить интерфейсы для NAT (на роутере)

```sh
ip a            # найди LAN-бридж (обычно br0) и убедись, что tun будет vpn0
```

Если LAN-бридж не `br0` или tun не `vpn0` — поправь переменные в начале `S99qeli`:

```sh
vi /opt/etc/init.d/S99qeli      # TUN=…, LAN_IF=…, GATEWAY=yes
```

---

## Шаг 7. Запуск

```sh
/opt/etc/init.d/S99qeli start
tail -f /opt/var/log/qeli-client.log
```

Жди строку `Auth OK, assigned IP: 10.x.x.x` — это успешное подключение к серверу.
Init-скрипт с префиксом `S` Entware запускает **автоматически при загрузке роутера**.

---

## Шаг 8. Проверить туннель

На роутере:

```sh
ip a show vpn0                                  # у tun есть адрес 10.x.x.x
ip route | grep -E 'default|vpn0'               # при gateway=true — default via vpn0
iptables -t nat -L POSTROUTING -n | grep MASQUERADE   # NAT на vpn0 стоит
curl -s https://ifconfig.me ; echo             # внешний IP = адрес VPN-сервера
```

С любого LAN-клиента (телефон/ПК за роутером):

```sh
# внешний IP должен стать адресом VPN-сервера; DNS и сайты открываются
curl -s https://ifconfig.me ; echo
```

---

## Селективный режим (только часть трафика через VPN)

Вместо full-tunnel (`gateway=true`) можно заворачивать лишь нужные адреса:
`gateway = false` в конфиге + `ipset` + `iptables` + DNS-оверрайды на dnsmasq
роутера (подход как у проектов `kvas` / `antizapret` для Keenetic). Это гибче и не
режет скорость на не-VPN трафике, но настройка ручная и вне этого бандла.

---

## OpkgTun — интерфейс в вебморде (KeeneticOS 5.0+)

Опциональный режим: tun отдаётся `ndm` как нативный `OpkgTun`-интерфейс, виден в вебморде
и доступен в «Приоритетах подключений». Это отдельный аддон со своими оговорками (владение
L3, статический IP, ручная регистрация) — вся настройка и разбор в
[`release/keenetic/opkgtun/README.md`](../../../release/keenetic/opkgtun/README.md).

## Диагностика

| Симптом | Причина / что делать |
|---|---|
| `нет /dev/net/tun` при старте | Включить компонент VPN в KeeneticOS (предусловия) |
| `ip: ... tuntap` не работает | `opkg install ip-full` (busybox-`ip` урезан) |
| Нет `Auth OK`, `SERVER KEY MISMATCH` | Неверный `key` — сверь с `qeli show-identity` на сервере |
| `decryption failed` сразу после `reading server auth proof` | `bind_static` не совпадает с сервером (у обоих дефолт `true`): убери `bind_static = false` на клиенте (для reality-tls он обязан быть `true`) ИЛИ выстави одинаково на сервере. Также проверь, что версии qeli на роутере и сервере совпадают (`qeli --version`) |
| Нет `Auth OK`, ошибка про `bind_static`/all-zero TOFU | H-1 (0.7.1) ВКЛ по умолчанию: впиши реальный `key` ИЛИ поставь `bind_static = false` для TOFU |
| Нет `Auth OK`, `auth failed` | Неверные `user`/`pass`, либо `mode`/`sni` не совпадают с профилем сервера |
| `kill-switch: iptables is not installed` | Убедись, что `iptables` в PATH (на Keenetic он есть); иначе `kill_switch = false` |
| LAN без интернета, роутер с интернетом | Проверь `ip_forward`, `MASQUERADE`, правильное имя `LAN_IF` в `S99qeli` |
| После ребута сервер видит «новое устройство» / повторный TOFU | `QELI_DEVICE_ID_FILE` и `QELI_KNOWN_HOSTS` должны быть на `/opt` (в `S99qeli` уже так; `/var` — tmpfs) |
| Очень медленно (mipsel) | Потолок CPU без AES-NI; ставь `mode = obfs`/`plain`, не `reality-tls` |
| OpkgTun-режим (вебморда) | Отдельная диагностика — [`release/keenetic/opkgtun/README.md`](../../../release/keenetic/opkgtun/README.md) |
| Туннель рвётся | Авто-reconnect включён; смотри `/opt/var/log/qeli-client.log` |

---

## Обновление / удаление

```sh
# обновить бинарь: останови, замени, запусти
/opt/etc/init.d/S99qeli stop
install -m755 qeli-client-<арка> /opt/bin/qeli-client
/opt/etc/init.d/S99qeli start

# удалить полностью
/opt/etc/init.d/S99qeli stop
rm -f /opt/etc/init.d/S99qeli /opt/bin/qeli-client
rm -rf /opt/etc/qeli /opt/var/log/qeli-client.log
```

## Восстановление legacy gateway при обновлении шаблонов

Шаблоны development0.8.2 используют tagged qeli-keenetic-legacy firewall rules и
forwarding checkpoint version2 с сохранёнными интерфейсами и отмеченными семействами.
После ошибки очистки checkpoint остаётся, start/restart блокируются. Устранить
причину и повторить; восстановление использует сохранённые интерфейсы даже после
смены режима шаблона. Legacy-пути требуется iptables comment extension. Совместимость
настоящего роутера не подтверждена: аудит использовал изолированные модели команд/файлов.

Перед заменой работающего legacy-шаблона остановить его предыдущим скриптом и
проверить старые правила и forwarding values. Старый checkpoint без version2
требует ручной сверки владения и восстановления: новый скрипт сохраняет его и
отказывается от автоматической очистки. Сохранить исходные значения до проверки
восстановления; не удалять checkpoint для обхода отказа. Совпадающие нетегированные
правила администратора автоматически не удаляются. См. [результаты и оставшиеся ограничения Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Процесс клиента и формат PID

Init-шаблоны development0.8.2 сохраняют `PID start_ticks` в PID-файле0600 и проверяют
Linux proc start time/executable перед сигналами. Старый single-PID record и
непроверенный процесс требуют ручной сверки identity; автоматически не принимаются.
Перед обновлением остановить предыдущим установленным шаблоном и проверить процесс/
правила. Установщик отказывает при существующем PID или pending publication files.

Stop посылает TERM и ждёт до15 проверок по одной секунде до compatibility cleanup.
Timeout или ошибка сигнала сохраняет process record, plan и OpkgTun marker; restart
не запускает новый клиент. Устранить причину и повторить. Pending publication file
требует сверки владения, его нельзя просто удалить для обхода отказа. Автоматического
KILL escalation нет. Status codes:0 running,3 stopped,4 unverified. Время жизни TUN,
включая persistent TUN, оставлено core/kernel/ndm. Успешный start подтверждает живой
executable, не authentication/connectivity. Shell/proc checks не дают atomic pidfd
identity и сериализации всех операций. Linux native-helper tests проверяют порядок
wrapper; настоящий router integration исключён. См. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).


## Запись о применении плана OpkgTun

Хук пишет `/opt/var/run/qeli.opkgtun.applied` (0600) только после всех успешных команд ndm и save. Изменение плана, включая один MTU, или отсутствие записи требует повторной настройки. Совпадения connected/адресов недостаточно для пропуска. Ошибка публикации/удаления сохраняет `.apply-pending`; устранить причину и повторить. Успешный stop удаляет обе записи после завершения клиента. Запись подтверждает команды, не является блокировкой или чтением всех настроек: параллельные события, внешние изменения и настоящая прошивка не квалифицированы. См. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).


## Проверка host-сборки для мейнтейнера

`python scripts/keenetic_verify.py` использует `QELI_LAB_PASS`, необязательные `QELI_LAB_SERVER` (default10.66.116.11) и `QELI_LAB_USER` (defaultroot). Сборка идёт в новом приватном `/var/tmp/qeli-keenetic-verify.*` с собственным target, locked dependencies и одной compiler job; сервисы продолжают работать. Напечатанный каталог сохраняется для разбора, после использования его нужно удалить. Exit0 означает успех host build/tests/Clippy/graph/ELF/hash; exit1 — verification/connect/close failure; exit2 — нет credentials. Host success не подтверждает MIPS/ARM ABI или firmware. [Подробности аудита](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).


## Владелец gateway через INI-парсер ядра

Текущий standalone binary поддерживает:

```sh
qeli-client --config /opt/etc/qeli/client.conf --print-gateway-owner
```

Команда проверяет INI по тем же правилам, что runtime, и выводит только `core`,
если включён `gateway_nat`, `forward` или `exit_node`; иначе `legacy`. Соединение,
hooks и настройка сети не запускаются. Оба init-шаблона вызывают её один раз перед
gateway startup. Кавычки/регистр/on/BOM обрабатываются ядром; ошибочный config или
unsupported/invalid reply запрещает запуск. При `GATEWAY=no` или активном OpkgTun
legacy ownership query не требуется.

Обновлять standalone binary и шаблон вместе: старый binary без команды не сможет
запустить compatibility gateway. Core ownership отключает wrapper LAN NAT, в том
числе для exit-node. Legacy ownership сохраняет fallback при false/отсутствующих
core flags. Init теперь проверяет и запускает одну приватную копию, описанную ниже.
Для применения изменённого INI используй restart. Настоящая firmware и
параллельное владение поколениями не квалифицированы. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Общая блокировка lifecycle и обновление (development0.8.2)

Устанавливай весь комплект: installer также публикует
/opt/etc/qeli/lifecycle.sh с правами0600. Оба init-варианта и OpkgTun wan.d-hook
требуют общую библиотеку; копирование одного нового шаблона недостаточно.
Для старой установки сначала остановить/проверить клиента, затем обновлять вместе
библиотеку, binary, init и установленный hook.

Start/stop/restart, wan.d и установка используют /var/run/qeli.lifecycle.lock.
Занятая операция возвращает ошибку без конкурирующих изменений; повторить после
завершения владельца. Restart держит один lock для stop и start. Hook-события
не стоят в очереди. Обычный выход/сигналы освобождают lock; после SIGKILL сначала
убедиться, что init/hook/installer-владельца больше нет, затем удалить только пустой
каталог через rmdir. PID/plan/forwarding/pending recovery-файлы сохранить.
Автоматического удаления stale-lock и убийства процессов нет; перезагрузка роутера
обычно очищает временный /var/run.

Hook проверяет смену плана/marker перед L3/save и перед applied receipt.
Обнаруженная замена оставляет pending для повтора; выполненные ndm-команды не
откатываются. Ядро использует отдельную блокировку публикации плана, описанную
ниже; в lifecycle-lock ядро не участвует. Согласованный комплект core/hook
сериализует публикацию файла и применение; полная атомарность NDM и порядок
на реальной прошивке остаются неквалифицированными.
Directory publication targets отвергаются installer до работы с зависимостями.

Installer сохраняет backup прежних binary/init/helper в тех же каталогах и
recovery record0600 /opt/etc/qeli/install-pending на время публикации кода.
Обычная ошибка публикации и обработанный сигнал завершения возвращают прежние
bytes/modes либо удаляют новый код, которого раньше не было. Если restore не
удался, оставшиеся backup и marker сохраняются. Retry installer, start обоих
обновлённых init и обновлённый активный wan.d hook отказываются работать; stop
доступен. Содержимое существующего INI сохраняется. Уже опубликованная болванка
и ужесточённый mode600 конфига могут остаться после поздней ошибки; изменения
пакетов/зависимостей не откатываются.

Если install-pending остался, не запускай клиент: проверь record и оставшиеся
backup. Перед восстановлением убедись, что init/hook/installer не владеют lifecycle
action, затем восстанови согласованный комплект binary/init/helper. Пустое поле
backup означает, что файла раньше не было; отсутствующий именованный backup мог
уже быть восстановлен и не разрешает слепо удалять текущий файл. После проверки
восстановления удали install-pending и, если SIGKILL оставил lock, только пустой
lifecycle lock directory. PID/plan/forwarding recovery records не удаляй. Старые
установленные скрипты могут не соблюдать marker: остановка/проверка обязательны.
Автоматическое recovery после SIGKILL/power loss и fsync-backed transaction всего
bundle не заявляются. Symlink/nonregular targets и linked /opt/etc/qeli отвергаются
до package updates. Root/admin replacement путей во время установки остаётся вне
этого cooperative protocol.

Перед start/restart обновлённый шаблон проверяет конфигурацию общим парсером
бинарника: dev должен совпадать с TUN в шаблоне, device_type должен быть tun.
Обычный шаблон требует dev_attach=false; активный OpkgTun — dev_attach=true
и совпадение dev с OPKGTUN. В OpkgTun отключи gateway_nat, forward и exit_node:
L3/gateway принадлежат ndm. Проверка действует и при GATEWAY=no.

При несоответствии запуск отвергается до создания процесса и изменения старого
состояния. Согласуй INI и шаблон, затем повтори start. Обновляй binary и template
вместе: старый binary не понимает новые --expect-router-device/
--expect-router-attach и откажет в проверке. Проверка и запуск используют
одну приватную копию INI, описанную ниже.

## INI, проверенный перед запуском (development0.8.2)

Оба init-шаблона перед проверкой создают `/opt/var/run/qeli-launch/client.conf`
и передают этот же путь проверке ядра и клиенту. Исходный
`/opt/etc/qeli/client.conf` остаётся редактируемым; замена после проверки не меняет
конфигурацию текущего запуска. Повторный start работающего клиента сохраняет копию,
restart после успешного stop читает свежий исходный INI. Hook-переменная
`QELI_CONFIG_PATH` указывает на runtime-копию. Редактировать нужно исходный файл.

Требуются `stat -c`, `cp -p` и `mktemp`. Исходный INI должен быть обычным непустым
файлом без symlink, его каталог — root-owned0700. Установщик проверяет владельца
существующего каталога до package updates, затем ограничивает права0700;
не переназначает чужой каталог root. Runtime-каталог тоже root-owned0700;
ссылки, нестандартные targets и небезопасные права запрещают запуск.
Владелец и mode файла сохраняются при копировании: оно не повышает доверие ядра
к командам в конфиге. Ограниченный по размеру copy предшествует INI-парсеру;
точный лимит256KiB и правила INI остаются в ядре.

Успешный stop удаляет копию после подтверждённого выхода клиента и очистки сети.
При неудачном join/cleanup она сохраняется вместе с recovery state. Ошибка проверки
до запуска может оставить приватную копию; следующий допустимый start заменит её.
После SIGKILL/power loss проверяй владельца lifecycle и временные копии вручную.
Не удаляй runtime-copy у работающего или неопределённого клиента. Прямой запуск
binary вне шаблона не использует этот протокол. Замена приватных путей root/admin,
core plan generation/ABA и настоящая firmware этим исправлением не квалифицированы.

## Компилятор и промежуточные build files (development0.8.2)

Общий helper router-сборки теперь находит rustc выбранного pin через
`rustup which --toolchain ... rustc`, проверяет executable и явно передаёт его
Cargo. `CARGO_TARGET_DIR` и `CARGO_BUILD_BUILD_DIR` направлены в target собственного
запуска: обычные Cargo build.rustc/build.build-dir и ambient build-dir не могут
молча перенаправить эти два входа. Router CI использует ту же политику.
Linux gate `keenetic_verify.py` теперь требует Rust1.97.0 с установленным Clippy,
а не default host toolchain; ошибка поиска компилятора останавливает Cargo.
Wrapper/encoded Rust flags подчиняются общей политике.

Это ограниченная изоляция окружения. Cargo home/ancestor config, forced environment,
profile/source/linker overrides, PATH/shared registry/tool caches и clean независимые
Qeli A/B ещё не квалифицированы.7 real-Cargo methods используют маленькие Linux
fixtures без зависимостей; fresh Qeli cross build, Zig invocation, SDK Rust toolchain
и router ABI/runtime ими не подтверждаются. См. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Публикация NetworkPlan и применение NDM

<!-- normative-sync: plan-publication-lock-v1 -->

На Linux публикация дополнительно захватывает соседний каталог
`$QELI_TUNIP_FILE.publish-lock` через атомарный `mkdir`. Согласованный Keenetic-хук
удерживает ту же блокировку от финального снимка плана до завершения NDM apply/save
и публикации receipt. Клиент ждёт в пределах общего бюджета NetworkPlan
(не более 15 секунд); занятый хук возвращает ошибку для повторной попытки на следующем
событии. Это отдельная блокировка от `/var/run/qeli.lifecycle.lock`: создание
attach-интерфейса и ожидание первого адреса идут без блокировки публикации.
Хук освобождает её до следующей публикации ядра, а ядро — до post-up хука.
Для нового опубликованного плана по-прежнему требуется следующее событие wan.d.

Обновляй binary, `lifecycle.sh` и хук вместе. Старые версии и записи администратора
не участвуют в протоколе. Команды NDM последовательны и могут выполниться частично;
pending/applied сохраняют ownership адресов для повтора. Штатный выход, Rust unwind
и обработанные shell-сигналы снимают блокировку. После SIGKILL или потери питания
каталог может остаться; release-паника с `panic=abort` также не выполняет Drop.
Не удаляй блокировку активного или неизвестного владельца.
После независимой проверки остановки клиента и хука сверь сохранённые/pending
адреса, затем удали только пустой зависший каталог публикации через `rmdir`.
Не удаляй план и recovery receipts для обхода этой проверки.

# qeli на Keenetic через OpkgTun (интерфейс в вебморде)

Опциональный режим для **KeeneticOS 5.0+**: qeli-tun отдаётся `ndm` как нативный
интерфейс `OpkgTunN`, который виден в вебморде и доступен в **«Приоритетах подключений»**
и статических маршрутах. Тогда per-device / selective роутинг настраивается мышкой в UI,
без самодельного NAT из `S99qeli`.

Это **аддон**, изолированный в этой папке. Базовый gateway-режим (надёжный, без зависимости
от ndm) — в `release/keenetic/`. Если UI-роутинг не нужен — используй его, он проще и
переживает ребут без нюансов ниже.

> ⚠️ **Честно о зрелости.** OpkgTun-интеграция рабочая, но **хрупкая и полу-ручная**:
> - авто-регистрация через wan.d-хук на раннем бусте **ненадёжна** (ndmc в этом контексте
>   часто не отвечает) — рабочая регистрация делается вручную из ssh-логина;
> - переживание ребута требует **статического IP на сервере** (иначе адрес «уплывает» и
>   сохранённый в ndm конфиг устаревает);
> - нативного тумблера вкл/выкл в «Других подключениях» у OpkgTun нет (фича-реквест Keenetic).
>
> Разумно на ARM-моделях; на mipsel — только лёгкие режимы маскировки.

## Модель владения (ключевое, проверено на устройстве)

На 5.0 устройство `opkgtun0` **создаёт и держит САМ `ndm`**, а приложение к нему
**прицепляется**, и **L3 (адрес + линк) тоже ставит ndm, а не приложение**. Две ловушки:

- qeli сам создаёт `opkgtun0` → `ndm` не заводит интерфейс:
  `Opkg::Interface::Tun error: "OpkgTun0": system failed [0xcffd00a9]`,
  а qeli — `interface 'opkgtun0' already exists … refusing to take it over`.
- qeli сам ставит адрес/поднимает линк → `ndm` навсегда залипает в
  `link: pending / connected: no` и **не маршрутизирует** через интерфейс. Только когда
  адрес ставит ndm (`ip address … /32` + `up`), интерфейс переходит в `connected: yes`.

Поэтому qeli в **attach-режиме** (`dev_attach = true`): открывает существующее
ndm-устройство **только для перекачки пакетов** — не создаёт его, не ставит адрес, не
поднимает линк, не трогает маршруты, не удаляет при выходе. После успешного commit всего
аутентифицированного NetworkPlan qeli атомарно пишет выданные IPv4/IPv6 и MTU в
`$QELI_TUNIP_FILE`; частично применённый и затем откаченный план в файл не попадает. Хук
читает только этот committed-файл (не старые строки лога) и передаёт IPv6 в ndm вместе с
согласованным host-prefix, обычно `/128`.
Адрес/линк/маршруты держит `ndm` (через хук).

Очередью этого внешнего TUN также управляет `ndm`. Не добавляйте клиентский
`tun.tx_queue_len` при `dev_attach=true`: в поддерживающем ключ Linux-клиенте
явное значение отклоняется, а отсутствие ключа сохраняет очередь владельца.
Дефолт `1000` относится только к TUN/TAP, создаваемому самим Qeli, и не означает
автоматическое изменение `opkgtun0`.
[Контракт](../../../docs/ru/manuals/CONFIG.md#client-tun-tx-queue).

> ℹ️ **Про «gvisor only».** Форумные упоминания, что «на OpkgTun разрешён только gvisor»,
> относятся к ВНУТРЕННИМ tun-stack режимам Clash/sing-box (`system`/`gvisor`/`mixed` — опция
> самого приложения), а НЕ к ndm. Обычный kernel-tun через OpkgTun работает (так живёт,
> например, AmneziaWG-Go). Затык `0xcffd00a9` был не в gvisor, а в порядке/владении устройством.

## Файлы в этой папке

- `010-qeli.sh` — wan.d-хук: создаёт `OpkgTun0`, ждёт IPv4 и/или IPv6 и MTU из NetworkPlan qeli, ставит
  dual-stack L3 через ndmc.
- `S99qeli` — init-скрипт с преднастроенным `OPKGTUN=opkgtun0` (в OpkgTun-режиме свой NAT
  выключен; сигналит хуку и экспортит `QELI_TUNIP_FILE`).
- `client.conf.example` — пример (`dev = opkgtun0`, `dev_attach = true`, `gateway = false`,
  `ipv6 = auto`).

## Установка

1. Клиент (общий бинарь) и базовый деплой — по `release/keenetic/README.md`.
2. Скопируй OpkgTun-файлы:
   ```sh
   cp opkgtun/S99qeli            /opt/etc/init.d/S99qeli
   mkdir -p /opt/etc/ndm/wan.d
   cp opkgtun/010-qeli.sh        /opt/etc/ndm/wan.d/010-qeli.sh
   chmod +x /opt/etc/init.d/S99qeli /opt/etc/ndm/wan.d/010-qeli.sh
   ```
3. В `/opt/etc/qeli/client.conf` задай `dev = opkgtun0`, `dev_attach = true`, `gateway = false`
   (см. `opkgtun/client.conf.example`).
4. **Пин статических IPv4/IPv6 на сервере** для этого пользователя (обязательно для
   стабильного сохранённого L3 после ребута) — см. ниже.
5. `/opt/etc/init.d/S99qeli start`.

## Статические IPv4/IPv6 (обязательно для переживания ребута)

Сервер по умолчанию выдаёт адреса из пулов, и после ребута они могут смениться → сохранённый
в ndm L3 устареет. Зафиксируй обе используемые семьи на сервере:

- **веб-панель**: пользователь → поле статического IP;
- **CLI (новый юзер)**: `qeli add-client <user> --static-ip 10.9.0.2 --static-ipv6 fd71:e1:1234:1::2 …`;
- **конфиг сервера**: `static_ip = "10.9.0.2"` в `[user:<name>]`, либо
  `static_ipv6 = "fd71:e1:1234:1::2"`; профильные эквиваленты —
  `pool.reservation.<user>` и `pool.ipv6.reservation.<user>`.

Применяется на следующем коннекте (user db читается на auth в реальном времени).

## Регистрация вручную (надёжный путь)

wan.d-хук на бусте часто не может выполнить ndmc. Рабочий способ — **из ssh-ЛОГИНА**
(не из `exec sh` — иначе `0xcffd0060`), порядок тот же, что в хуке:

```sh
ndmc -c "interface OpkgTun0"                 # 1. ndm создаёт kernel-device opkgtun0
/opt/etc/init.d/S99qeli start                # 2. qeli цепляется, пишет IP в файл
IP=$(sed -n 's/^ipv4=\([^/]*\)\/.*/\1/p' /opt/var/run/qeli.tunip | head -n1)
IP6_CIDR=$(sed -n 's/^ipv6=//p' /opt/var/run/qeli.tunip | head -n1)
MTU=$(sed -n 's/^mtu=\([0-9][0-9]*\)$/\1/p' /opt/var/run/qeli.tunip | head -n1)
[ -n "$MTU" ] || MTU=1400
ndmc -c "interface OpkgTun0 ip global auto"
[ -z "$IP" ] || ndmc -c "interface OpkgTun0 ip address $IP 255.255.255.255"
[ -z "$IP6_CIDR" ] || ndmc -c "interface OpkgTun0 ipv6 address $IP6_CIDR"
ndmc -c "interface OpkgTun0 ip mtu $MTU"
ndmc -c "interface OpkgTun0 ip tcp adjust-mss pmtu"
ndmc -c "interface OpkgTun0 security-level public"
ndmc -c "interface OpkgTun0 up"
ndmc -c "system configuration save"
ndmc -c "show interface OpkgTun0" | grep -E "connected|global|address" # обе семьи должны совпасть
```
Снять интерфейс: `ndmc -c "no interface OpkgTun0"`.

## Маршрутизация

- **Весь трафик устройства → VPN**: «Интернет → Приоритеты подключений» → профиль с
  `OpkgTun0` выше WAN → привязать устройство. Работает для любых адресов/CDN, ndm сам NAT'ит.
- **Точечный маршрут**: `ndmc -c "ip route <сеть> <маска> OpkgTun0"` + `system configuration save`.
  UI-статик ненадёжен: маршрут ложится в table `main`, которую трафик клиента не смотрит
  (сначала `from all lookup 4096`), плюс баг вебморды сбрасывает выбор интерфейса на дефолт.
- Интерфейс обязан быть `connected: yes` и `global: yes` — иначе маршруты не активируются.
- НЕ ставь `ip route default OpkgTun0` для роутера в целом — завернётся и соединение qeli с
  сервером → петля. Заворачивай клиентов через Приоритеты.
- `dev_attach = true` означает, что L3 полностью владеет ndm. Хук автоматически переносит
  адреса и MTU, но server-pushed маршруты и DNS в Keenetic не устанавливает: их нужно задать
  в «Приоритетах подключений»/статических маршрутах и в настройках DNS самого Keenetic.

Проверка exit-IP туннеля (минуя роутинг/DNS): `curl --interface opkgtun0 -s https://api.ipify.org`.

## Диагностика

| Симптом | Причина / что делать |
|---|---|
| `system failed [0xcffd00a9]` + qeli `already exists` | Инверсия владения: поставь `dev_attach = true`, дай ndm создать интерфейс первым |
| Маршрут не идёт; `show interface` = `connected: no` / `link: pending`, `global: no` | L3 должен держать ndm. Проверь `dev_attach = true`, что qeli пишет IP в `/opt/var/run/qeli.tunip`, и что адрес `/32` + `ip global` ставит ndm |
| Хук: `OpkgTun0 недоступен` / `не принял` | ndmc в контексте wan.d (особенно на бусте) не отвечает — зарегистрируй вручную из ssh-логина |
| После ребута маршрут отвалился, адрес сменился | Нет `static_ip`/`static_ipv6` → закрепи используемые семьи на сервере |
| Файла `/opt/var/run/qeli.tunip` нет | `OPKGTUN=` пуст в S99qeli, либо старый бинарь без dual-stack `dev_attach` |
| Нет тумблера вкл/выкл в «Других подключениях» | Штатно не поддерживается (фича-реквест Keenetic); управляй через `ndmc interface OpkgTun0 up/down` + стоп qeli |

## Удаление / откат на gateway

```sh
/opt/etc/init.d/S99qeli stop
ndmc -c "no interface OpkgTun0"                 # из ssh-логина
rm -f /opt/etc/ndm/wan.d/010-qeli.sh
cp ../S99qeli /opt/etc/init.d/S99qeli           # базовый gateway-скрипт
# в client.conf: dev = vpn0, gateway = true, убрать dev_attach
```

## Ошибки регистрации (development0.8.2)

Hook принимает marker только вида `opkgtun` + цифры, максимум15 символов. Каждая
команда изменения ndm и сохранения конфигурации проверяется; после отказа hook
возвращает ошибку и не сообщает interface up. Ранее применённые ndm changes могут
остаться: устранить причину и повторить hook/ручную регистрацию, проверяя результат
каждой команды. Нет interface/плана — диагностическое ожидание следующего события.
IPv4/IPv6/MTU читаются одним snapshot опубликованного файла. Stop/generation races,
параллельные обновления и настоящая firmware behavior этим не квалифицированы.
[Текущий Q31 audit](../../../docs/ru/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

После частичного отказа хук сохраняет `/opt/var/run/qeli.opkgtun.apply-pending`
до успешного применения и сохранения конфигурации. Следующий вызов повторяет
команды даже при уже совпадающих адресах. Маркер не является блокировкой
параллельных обработчиков; выполненные команды автоматически не откатываются.

Legacy gateway использует правила с тегом `qeli-keenetic-legacy` и forwarding
checkpoint `version=2`. Ошибка очистки сохраняет состояние и блокирует перезапуск.
Старый checkpoint без версии требует ручной сверки; он не удаляется автоматически.
Перед заменой работающего legacy-шаблона остановить его предыдущим скриптом и
проверить правила/sysctl. Подробности: [восстановление при обновлении](../../../docs/ru/manuals/KEENETIC-DEPLOY.md).

PID-файл нового шаблона хранит `PID start_ticks`. До обновления остановить клиент
предыдущим установленным шаблоном и проверить завершение: установщик блокирует
существующий PID/pending record. Stop ждёт TERM перед очисткой; при timeout состояние
сохраняется, restart не запускает ещё один клиент. Старые single-PID записи требуют
сверки владельца. Status:0 running,3 stopped,4 unverified. Шаблон не удаляет TUN
напрямую. [Порядок остановки и обновления](../../../docs/ru/manuals/KEENETIC-DEPLOY.md).

Хук сохраняет приватный `qeli.opkgtun.applied` только после успешных команд и save.
Изменение полного плана, включая только MTU, повторяет настройку. No-op требует
этой записи, connected и буквального совпадения адресов; подстроки не принимаются.
Stop удаляет запись после выхода клиента. Это не блокировка, поколение клиента
или полное чтение настроек ndm. Внешние изменения и параллельные события остаются OPEN.

Gateway fallback больше не разбирает INI в shell. При GATEWAY=yes без OpkgTun
шаблон читает `qeli-client --config ... --print-gateway-owner`: core для
gateway_nat/forward/exit_node, legacy при выключенных flags. Ответ/ошибка
проверяются до запуска; старый binary без команды отказывает. Обновлять binary
и шаблон вместе; проверка и запуск используют общую приватную копию INI. Для OpkgTun или
GATEWAY=no этот compatibility query не нужен. [Подробности](../../../docs/ru/manuals/KEENETIC-DEPLOY.md).

## Общий lifecycle (development0.8.2)

Базовый installer доставляет обязательную библиотеку
/opt/etc/qeli/lifecycle.sh (0600). Обновляй её вместе с binary/init и установленным
wan.d hook; старые скрипты общей блокировки не соблюдают. Init, hook и installer
используют /var/run/qeli.lifecycle.lock. Занятый вызов возвращает ошибку — повторить
после завершения владельца. Обычный выход/сигналы освобождают lock; после SIGKILL
нужна сверка отсутствия init/hook/installer-владельца перед rmdir пустого каталога.
Recovery-файлы PID/plan/forwarding/pending не удалять. Hook-события не очередятся;
обнаруженная смена плана прерывает L3/save/receipt и оставляет pending. Атомарность
core-поколений/ABA/firmware этим не доказана.

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

## Поколение сетевого плана (development0.8.2)

Ядро добавляет `generation=<число>` в runtime-файл `$QELI_TUNIP_FILE` после MTU.
Первая строка адреса и поля ipv4/ipv6/mtu сохраняются. Это существующее поколение
аутентифицированного NetworkPlan, а не параметр INI. Hook сравнивает весь файл:
повторная аутентификация с теми же адресами и новым поколением требует нового
apply/save; A→B→A во время apply/save внутри одного адаптера оставляет pending
вместо устаревшего APPLIED receipt. Следующее событие может повторить применение.
Старые файлы без generation читаются, но не дают этого различения.

Счётчик локален адаптеру и может сбрасываться при его пересоздании. Поле не делает
всю настройку ndm атомарной. Координация согласованных writer/hook теперь
использует отдельный publication-lock, описанный ниже; root/admin replacement
и смешанный комплект старых/новых компонентов остаются вне этого протокола. Новые сборки
бинарника содержат поле; ранее опубликованные бинарники автоматически не обновляются.

При новом launch обновлённый OpkgTun init сохраняет APPLIED как сведения о ранее
настроенных адресах и создаёт/сохраняет pending перед запуском: даже сброс
локального generation требует свежего hook apply/save. Start уже работающего
проверенного клиента сохраняет обе записи без принудительного apply. Stop после
join удаляет marker и текущий plan, но оставляет APPLIED и непустой pending,
поскольку L3 остаётся у ndm. Отказ проверки INI не очищает recovery state;
symlink/nonregular pending или receipt запрещает свежий launch.

Hook повторно проверяет план/marker после show перед cached no-op, после публикации
receipt и после удаления pending. Обнаруженная смена возвращает ошибку и оставляет
или восстанавливает pending. Уже выполненные ndm-команды не откатываются; следующий
вызов повторяет применение. Старый APPLIED вместе с pending не означает завершение.
Согласованный core/hook удерживает publication-lock через финальный receipt.
Некооперирующие компоненты и полная атомарность ndm остаются за его пределами.

## Release-профиль standalone helpers (development0.8.2)

Общая policy `scripts/router_toolchain.py` передаёт дочернему Cargo пять явных
release fields канонического Cargo.toml: lto=fat,codegen-units=1,opt-level=3,
strip=true,panic=abort. OpenWrt/Keenetic standalone helpers и Linux host gate
не наследуют для них profile overrides из окружения (включая FFI panic=unwind),
Cargo home или ancestor config. Router CI получает тот же набор через
`python3 scripts/router_toolchain.py --print-release-profile` из корня репозитория.
FFI libraries сохраняют отдельную unwind policy; SDK feed profile не изменён.

Проверены реальные GNU Cargo mini-crates и pinned Zig x86_64-musl mini-probe,
а не новая полная Qeli/cross/firmware сборка. Другие profile keys, forced child env,
source/linker/PATH/caches и clean Qeli A/B ещё не полностью изолированы.

Общий standalone/host helper также заменяет временный путь исходников на
`/usr/src/qeli` в compiled source locations (`file!()`/panic diagnostics); реальные
пути конфигов неизменны. F365 проверил две независимые полные сборки Qeli x86_64-musl
с пустыми target/Zig caches и одинаковыми offline registry-копиями: побайтно
идентичный ELF, help/version и INI metadata PASS. Прежний A/B NOT_RUN снят только
для этого target/recipe; другие targets, SDK/CI path policy и произвольное окружение
проверяются отдельно. Подробности в отчёте Q31.

### Аудит: standalone A/B и release preflight (7 октября 2026)

Q31-V006 завершил независимые полные A/B для aarch64, armv7 и mipsel; каждая пара
побайтно идентична. Вместе с sealed F365 x86_64 и проверкой совпадения inputs
подтверждены все четыре standalone-цели. Шесть новых ELF также прошли static target
admission и QEMU help/version/INI metadata. Это обновляет прежний статус other-target
A/B NOT_RUN. QEMU parser checks не подтверждают firmware, роутерную сеть или полный
SDK build/release pipeline.

Для maintainer: `python scripts/release_preflight.py <branch>` выполняет optional
32-bit lab gate 2 при заданном `QELI_LAB_PASS`. До SSH запрещены dirty source и
участвующие recipe inputs; точные байты одного committed Git-архива `qeli/`
собираются в приватном checkout общим закреплённым locked one-job рецептом.
Проверяются SHA256 скачанного файла и static target ELF; SSH закрывается при успехе
и ошибке. `QELI_LAB_SRC` устарел. Artifact не публикуется, приватный checkout
сохраняется для инспекции. Действующий toolchain helper может установить недостающие
закреплённые tools. Полный live preflight/CI dispatch, SDK bootstrap и source-pin/
mirror release-cut остаются отдельными release-проверками.


## Смена адресов OpkgTun (development0.8.2)

Pending теперь содержит snapshot интерфейса и плана, который мог быть частично
применён. Перед новыми L3-командами hook очищает устаревшие адреса из завершённого
APPLIED и предыдущего pending; только затем атомарно записывает новое намерение.
Ошибка cleanup/publication/смена плана сохраняет сведения для повторной попытки.
IPv6 удаляется конкретной `no ipv6 address <старый адрес/prefix>`;
`no ip address` для исчезнувшего IPv4 допускается только при совпадении прежнего
адреса с текущим локальным полем `address:`. Упоминание адреса в gateway/peer не
разрешает сброс. Смена IPv4 выполняется обычным setter, поскольку IPv4 статический
адрес один; IPv6 допускает несколько адресов. Другие IPv6 и заменённый администратором
IPv4 сохраняются. При смене OpkgTun hook проверяет записи прежнего интерфейса и
удаляет только его прежние адреса Qeli, а не интерфейс/политики ndm.

Пустые старые pending совместимы, но не содержат ownership. Если прежний шаблон уже
удалил записи или после reboot они потеряны, hook не угадывает прежние адреса:
проверь их вручную. Не удаляй APPLIED/pending без сверки с ndm. Это cooperative
core/init/hook protocol; root/admin replacement, смешанный старый/новый комплект
и атомарность всех ndm-команд не обещаются. На физическом KeeneticOS5 не запускалось:
проверены native process lifecycle и stateful ndmc-модель на dash/BusyBox.
Синтаксис сверён с [официальным справочником CLI](https://docs.help.keenetic.com/cli/3.1/en/cli_manual_kn-1910_tr.pdf),
команды interface ip address и interface ipv6 address; это не firmware qualification.

## Блокировка публикации и применения NetworkPlan (development0.8.2)


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

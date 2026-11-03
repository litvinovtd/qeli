# qeli-client на Keenetic (Entware) — IPv4/IPv6 деплой

Запуск qeli-VPN-клиента на роутере Keenetic как шлюза для всего LAN.
**Подробный пошаговый гайд (по шагам, с проверкой туннеля) — [docs/*/manuals/KEENETIC-DEPLOY.md](../../docs/ru/manuals/KEENETIC-DEPLOY.md).**
План и обоснование порта — [docs/*/reference/KEENETIC-PORT.md](../../docs/ru/reference/KEENETIC-PORT.md).

> **Границы проверки 0.8.2:** физические роутеры исключены из согласованного аудита.
> Прежние аппаратные результаты не подтверждают новую сборку. Текущие проверки исходников,
> ELF, SDK и изолированного lifecycle сохраняют свою область. Скрипты остаются
> **шаблонами**: проверь имена интерфейсов и firewall своей модели/прошивки.

## Предусловия на роутере
- Установлен **Entware** (opkg, `/opt`).
- Включён компонент **VPN** в KeeneticOS (чтобы был `/dev/net/tun`).
- Есть SSH-доступ.
- Бинарник занимает 8,93 МиБ (aarch64) или 10,87 МиБ (mipsel). Помимо него нужны
  место для зависимостей, старой копии и временного файла при обновлении.

## Готовый комплект из релиза (основной способ)

После публикации выбери точную версию на [GitHub Releases](https://github.com/litvinovtd/qeli/releases).
Скачай `qeli-keenetic-files.tar.gz`, `qeli-client-keenetic-aarch64` **или**
`qeli-client-keenetic-mipsel` по архитектуре роутера и `SHA256SUMS` из того же релиза.
Архив содержит интеграцию и примеры, но не бинарник. На рабочем компьютере, например
для aarch64, проверь две выбранные загрузки и собери каталог:

```sh
grep -E ' [ *](qeli-keenetic-files[.]tar[.]gz|qeli-client-keenetic-aarch64)$' SHA256SUMS > selected.sha256
test "$(wc -l < selected.sha256)" -eq 2
sha256sum -c selected.sha256
tar -xzf qeli-keenetic-files.tar.gz
cp qeli-client-keenetic-aarch64 qeli-keenetic/
scp -r qeli-keenetic <user>@<router-ip>:/opt/tmp/keenetic
```

Для mipsel замени имя бинарника в обеих командах. Затем на роутере выполни шаг
установки ниже из `/opt/tmp/keenetic`. Отдельный `install-keenetic.sh` в загрузках —
тот же installer; без `S99qeli`, `lifecycle.sh`, примеров и подходящего ELF он не заменяет архив.

## Сборка бинарей для мейнтейнера (приватная лаба .10)

Этот helper требует доступа к приватной лабе; пользователям готовых файлов он не нужен.
```sh
python scripts/build_keenetic.py --sync
# → release/keenetic/qeli-client-keenetic-aarch64 и qeli-client-keenetic-mipsel
```

## Установка (на роутере)
Для готового комплекта каталог уже скопирован по инструкции выше. После собственной
сборки скопируй `release/keenetic/` вместе с ELF. На роутере:
```sh
cd /opt/tmp/keenetic
sh install-keenetic.sh      # определит арку, поставит ip-full/iptables, разложит файлы
vi /opt/etc/qeli/client.conf
/opt/etc/init.d/S99qeli start
tail -f /opt/var/log/qeli-client.log   # ждём 'Auth OK'
```

## Режим шлюза (весь LAN через VPN)
- В `client.conf`: `gateway = true` (full-tunnel) и `dns = off` (не трогать DNS роутера).
- Рекомендуемый конфиг использует `gateway_nat = true`: само ядро qeli ставит и проверяет
  IPv4/IPv6 forwarding, MASQUERADE, FORWARD и MSS clamp, а при остановке восстанавливает
  изменённые sysctl. `S99qeli` сохраняет `GATEWAY=yes` только как fallback для старых
  конфигов без `gateway_nat`/`forward`.
- Legacy fallback ждёт до 60 секунд атомарно опубликованный после AUTH/NetworkPlan файл,
  включает firewall только для реально выданных IPv4/IPv6 и не угадывает семейство по
  `ipv6 = auto`. На RA/SLAAC WAN он сохраняет `accept_ra`, ставит `2` до IPv6 forwarding и
  восстанавливает прежнее значение при остановке.
- Для inner IPv6 оставь `ipv6 = auto`, используй `required` для fail-closed или `off` для
  принудительного IPv4. Для dual-stack router-mode нужен `ip6tables`; без него `auto`
  согласует IPv4, а `required` откажет до настройки интерфейса.
- При необходимости ограничь NAT реальными `lan_subnet` и `lan_subnet_ipv6` своего LAN.
  Имя LAN-бриджа для legacy fallback (`LAN_IF`, обычно `br0`) проверь через `ip a`.

## Очередь создаваемого клиентом TUN

В бинарнике с доработкой development 0.8.2 по умолчанию задаётся `1000` пакетов;
локальный ключ `tun.tx_queue_len` в `[qeli]` файла `/opt/etc/qeli/client.conf`
принимает `1..32767`, без auto. Можно явно выбрать `500`; после правки остановить/
запустить клиент. Старые бинарники сначала нужно обновить; новый amd64-тест не
доказывает работоспособность сборки на MIPS/ARM-роутере. В OpkgTun/attach этот ключ
не задаётся — очередью владеет `ndm`. Размер не входит в server push/ссылку/QR;
увеличение может повысить задержку, а не только сгладить всплески.
[Подробности](../../docs/ru/manuals/CONFIG.md#client-tun-tx-queue).

## Выбор режима под железо
- **MIPS** (MT7621/7628, без AES-NI): `fake-tls` / `obfs` / `plain` (ChaCha20). Потолок —
  десятки Мбит. `reality-tls` очень медленный (двойной AEAD).
- **ARM** (Cortex-A53, crypto-ext): можно `reality-tls`; скорость в разы выше.

## Удаление
```sh
/opt/etc/init.d/S99qeli stop
rm -f /opt/etc/init.d/S99qeli /opt/bin/qeli-client
rm -rf /opt/etc/qeli
```

## Ошибки установки (development0.8.2)

Установщик предпочитает canonical имена `qeli-client-keenetic-aarch64/mipsel`,
старые `qeli-client-aarch64/mipsel` поддерживает для ручных bundles. Ошибка установки
обязательных ip-full/iptables прекращает установку; отсутствие ip6tables явно
предупреждается и требует проверить IPv6 перед запуском.

Существующий INI сохраняется, доступ ограничивается0600, каталог —0700. Копии
готовятся до замены; каждый файл публикуется атомарно, но весь bundle не является
транзакцией. После отказа публикации устранить ошибку и повторить установщик.
Работающий VPN автоматически не перезапускается. Это проверено shell/filesystem
fixtures, не настоящим opkg/прошивкой/ELF. См. [Q31](../../docs/ru/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

Legacy gateway использует правила с тегом `qeli-keenetic-legacy` и forwarding
checkpoint `version=2`. Ошибка очистки сохраняет состояние и блокирует перезапуск.
Старый checkpoint без версии требует ручной сверки; он не удаляется автоматически.
Перед заменой работающего legacy-шаблона остановить его предыдущим скриптом и
проверить правила/sysctl. Подробности: [восстановление при обновлении](../../docs/ru/manuals/KEENETIC-DEPLOY.md).

PID-файл нового шаблона хранит `PID start_ticks`. До обновления остановить клиент
предыдущим установленным шаблоном и проверить завершение: установщик блокирует
существующий PID/pending record. Stop ждёт TERM перед очисткой; при timeout состояние
сохраняется, restart не запускает ещё один клиент. Старые single-PID записи требуют
сверки владельца. Status:0 running,3 stopped,4 unverified. Шаблон не удаляет TUN
напрямую. [Порядок остановки и обновления](../../docs/ru/manuals/KEENETIC-DEPLOY.md).

Gateway fallback больше не разбирает INI в shell. При GATEWAY=yes без OpkgTun
шаблон читает `qeli-client --config ... --print-gateway-owner`: core для
gateway_nat/forward/exit_node, legacy при выключенных flags. Ответ/ошибка
проверяются до запуска; старый binary без команды отказывает. Обновлять binary
и шаблон вместе; проверка и запуск используют общую приватную копию INI. Для OpkgTun или
GATEWAY=no этот compatibility query не нужен. [Подробности](../../docs/ru/manuals/KEENETIC-DEPLOY.md).

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

Maintainer builds now always upload into private0700 /var/tmp/qeli-router-keenetic-XXXXXX
checkouts, with separate target/rlib restriction and one compiler job. --sync is
compatible but optional. Retained directories require reviewed per-run cleanup.
SHA256-bound ELF admission precedes atomic local publication; it checks class,
machine, little endian and absence of interpreter/shared dependencies, not full
ISA/musl/firmware compatibility or reproducibility. Old /opt/qeli-src is unused.
See [deployment manual](../../docs/eng/manuals/KEENETIC-DEPLOY.md) for limits.

Both router helpers now share target aliases, explicit Rust1.97.0/MIPS nightly-2026-06-10,
Zig0.13.0/cargo-zigbuild0.23.0 admission and build commands. Encoded/ambient flags
cannot shadow recipe RUSTFLAGS; MIPS soft-float remains explicit. Wrong identity
stops setup; installer/target false success fails verification. Shared caches/global
Cargo config/PATH and actual cross/firmware behavior remain separately qualified.

Installation now keeps same-directory backups of the previous binary/init/helper
and a0600 /opt/etc/qeli/install-pending recovery record while publishing code.
Ordinary publication failures and a handled termination signal restore old bytes
and modes (or remove new code that was originally absent). A failed restore keeps
remaining backups and the marker. Installer retry, both updated init starts and
the updated active wan.d hook refuse it; stop remains available. Existing INI
contents are preserved. A newly published example and stricter600 config mode
may remain after a late error; package/dependency changes are not rolled back.

If install-pending remains, keep the client stopped and inspect the record and
remaining backups before any start or retry. Verify no init/hook/installer owns
the lifecycle action before repairing the complete compatible binary/init/helper
set. Empty backup fields mean the target was originally absent; a missing named
backup may already have been restored and does not authorize blind file deletion.
After verifying recovery, remove install-pending and, if SIGKILL left it, only the
empty lifecycle lock directory. Do not delete PID/plan/forwarding recovery records.
Older installed scripts may not honor this marker: manual stop/review remains
mandatory. No automatic SIGKILL/power-loss recovery or fsync-backed bundle
transaction is claimed. Symlink/nonregular publication targets and a linked
/opt/etc/qeli directory are rejected before package updates. Root/admin path
replacement during installation remains outside this cooperative protocol.

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
и router ABI/runtime ими не подтверждаются. См. [Q31](../../docs/ru/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

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

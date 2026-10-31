# Клиентский конфиг: актуальный контракт и миграция 0.7.14 → 0.7.15

Эта таблица фиксирует **актуальный контракт 84 допустимых ключей** секции `[qeli]`
для всех пяти клиентов и сохраняет историю рефакторинга. «До» означает поведение
выпущенной 0.7.14; «после» начиналось как контракт 0.7.15 и расширяется здесь вместе
с текущим кодом (включая NetworkPlan v2 и полный IPv6).

Обозначения:

- **A** — ключ читается и влияет на работу клиента;
- **C** — ключ принимается, его значение сохраняется, но на этой платформе не применяется;
- **R** — ключ распознаётся как допустимый, но данным клиентом не применяется и не
  пересохраняется (актуально для headless CLI, у которого нет редактора профилей);
- **D** — ключ принимался, но терялся при сохранении профиля; это дефект 0.7.14;
- **N** — ключа ещё не было в контракте 0.7.14; старая версия считала его неизвестным;
- `X→Y` — историческое состояние в 0.7.14 и актуальное состояние справа.

`C` и `R` не означают опечатку. Неизвестное всему qeli имя по-прежнему отклоняется
fail-closed. Текущие GUI-клиенты сохраняют любой известный ключ, даже если применить его
может только другая платформа; отдельные управляемые поля перечислены в примечаниях.
> **Контракт Reality/H2:** отдельного клиентского H2-ключа нет. `mode = reality-tls`
> автоматически выбирает настоящий H2 carrier в общем Rust-ядре, а этот путь игнорирует
> запрошенный qeli heartbeat. Установленное приложение получит поведение только после пересборки,
> упаковки и установки его native core; обновление сервера не меняет старый клиентский бинарник.

| Ключи | CLI | Windows | macOS | Android | iOS | Текущий контракт / изменение |
|---|:-:|:-:|:-:|:-:|:-:|---|
| `server` `proto` `user` `pass` `key` `bind_static` `mode` `sni` `obfs_key` `front` `reality_sid` `quic` `awg` `jc` `jmin` `jmax` `mtu` `mtu_probe` `gateway` `route_local` `include` `exclude` `dns` `ipv6` `allow_ipv6_leak` `allow_ipv4_leak` | A→A | A→A | A→A | A→A | A→A | IPv6 согласуется внутри аутентифицированных capabilities/NetworkPlan v2. Режимы `auto`, `required` и `off`, а также симметричные leak-controls едины для всех адаптеров; общий default `gateway=true`; явный `false` включает split tunnel. |
| `pull_routes` | N→A | N→A | N→A | N→A | N→A | 0.8.3: default `true`; `false` отклоняет только серверные маршруты, сохраняя локальные, независимый full tunnel и защищённый DNS. Общий INI/URI/model контракт. |
| `windows_disable_sharing` | N→R | N→A | N→C | N→C | N→C | 0.8.3: default `false`; opt-in только для созданного Windows Wintun. Владение GUID/LUID/CIM и readback bindings; не применяется к WinDivert и другим платформам. |
| `windows_persistent_adapter` | N→R | N→A | N→C | N→C | N→C | 0.8.4 экспериментально, профильный default `false`, применяется только при общем режиме «По профилям». Режим приложения default «Выключен»; «Один общий» использует Qeli-Global. SwDevice, явное удаление, durable откат L3. Не WinDivert; reboot ещё не квалифицирован. |
| `roaming` | N→A | N→A | N→A | N→A | N→A | Новый общий ключ 0.8: `off` запрещает roam, `auto` использует безопасно согласованный TCP/UDP roam с reconnect fallback, `required` отказывает без полного контракта. Явные `local`/ненулевой `lport` несовместимы с `required`. Linux `dev_attach=true` не предоставляет `ROAMING_PATH`: `auto` → reconnect; `required` недоступен. |
| `reality_compact` `reality_split` `reality_split_delay` | R→A | C→A | C→A | C→A | C→A | Единое Rust-ядро управляет размером REALITY ClientHello и split-write evasion на всех приложениях. Редакторы без отдельных контролов сохраняют точные значения. |
| `reconnect` `reconnect_retries` `reconnect_base_delay` `reconnect_max_delay` | R→A | A→A | A→A | A→A | A→A | Ключи теперь читаются также CLI и доходят до его встроенного цикла. Ядро задаёт счётчик ошибок, решение по лимиту, backoff/jitter и интервал 1,5 с между началами попыток. Адаптеры передают монотонное время установленной связи и события ОС; ожидание сети не обнуляет бюджет. `reconnect_retries=-1` означает неограниченные повторы. |
| `timeout` | R→A | A→A | A→A | A→A | A→A | Таймаут соединения перенесён в Rust и теперь действительно доходит до общего ядра. |
| `padding` `padding_min` `padding_max` `heartbeat` `heartbeat_interval` `heartbeat_size` `heartbeat_jitter` `shaping` `shaping_gap_mean` `shaping_gap_min` `shaping_gap_max` `shaping_budget` `shaping_min_size` `shaping_max_size` `shaping_stealth` `shaping_stealth_mbps` | R→A | A→A | A→A | A→A | A→A | Локальные значения теперь разбирает единое ядро; аутентифицированный push сервера, если он есть, остаётся старше локального значения. |
| `keepalive` `tcp_nodelay` `recv_buffer_size` `send_buffer_size` | A→A | C→A | C→A | C→A | C→A | Настройки сокета применяет Rust на всех нативных клиентах. TCP сохраняет autotuning. Отсутствующий `recv_buffer_size` включает bounded auto-grow UDP 4→8→16 МиБ; явное значение фиксировано, `0` оставляет ОС. Новые stats показывают kernel/internal drops, grow events и фактический размер. |
| `dns_servers` | A→A | A→A | C→A | C→A | C→A | Все клиенты используют общий DNS-план для legacy IPv4 и v2: явные резолверы перекрывают push, максимум 8 адресов активных inner families, неверный выбранный push вызывает ошибку. DNS получает защищённый host-маршрут и в split-режиме; публичный fallback не подставляется. |
| `allow_unpinned_tofu` | A→A | C→A | C→A | C→A | C→A | Дефолт везде `false`. `true` разрешает продолжить только при доказанном сбое сохранения впервые увиденного ключа; несовпадение с известным пином всегда фатально. |
| `password_file` `password_command` | A→A | C→C | C→C | C→C | C→C | Источники пароля остаются headless-функцией; GUI не выполняют команды и не читают произвольные файлы. Linux `password_command`: `/bin/sh`, deadline 30 секунд, stdout до 16 KiB; stderr отбрасывается. Общий лимит сырого секрета — 16 KiB; password_file принимает обычные файлы/symlink, допускает одну фоновую задачу чтения и бюджет 30 секунд с кооперативной отменой I/O. |
| `local` `lport` | R→A | A→A | A→A | D→C | D→C | Linux и Windows/macOS применяют привязку первичного TCP/UDP carrier. Вторичные bonded TCP-сокеты сохраняют `local`, но используют ephemeral-порт и намеренно не занимают тот же фиксированный `lport`. Ошибка bind блокирует подключение вместо скрытого продолжения с другим source address/port. Телефоны сохраняют ключи для desktop-профиля. |
| `dev` | A→A | A→A | C→C | D→C | D→C | Linux применяет `dev` как имя TUN/TAP. Windows использует явный `dev`, приоритет имеет `dev_node`; без обоих ключей сохраняется уникальное имя профиля. macOS получает `utunN` от ядра, телефоны — системный TUN. |
| `device_type` | R→A | C→C | C→C | C→C | C→C | Linux выбирает `tun` или `tap`; остальные клиенты сохраняют переносимый ключ и отклоняют TAP при подключении, потому что их системные VPN-интерфейсы работают только на L3. |
| `dev_attach` | A→A | C→C | C→C | C→C | C→C | Подключение к готовому TUN остаётся функцией CLI; остальные редакторы не теряют ключ. Требуются NO_PI без VNET_HDR и защищённый attach; см. [CONFIG](../manuals/CONFIG.md). |
| `tun.tx_queue_len` | N→A | N→C | N→C | N→C | N→C | Development 0.8.2: Linux задаёт TX-очередь собственного TUN/TAP, default `1000` пакетов, явный диапазон `1..32767`, без auto. Только локальный INI, не push/ссылка/QR; нужен обновлённый клиент. При `dev_attach=true` ключ отсутствует, иначе Linux отказывает. Другие ОС сохраняют без применения. [Полный контракт](../manuals/CONFIG.md#client-tun-tx-queue). |
| `dev_node` | R→R | A→A | A→A | D→C | D→C | Windows: имя Wintun. macOS 0.8.4: auto или фиксированный `utunN` (`0..65534`), редактор/INI и служебный снимок; занятость — ошибка без смены номера. Не постоянное устройство. |
| `metric` | R→R | A→A | C→C | D→C | D→C | Wintun-метрику применяет только Windows, остальные GUI сохраняют её. |
| `persist_tun` `route_file` | R→R | A→A | A→A | D→C | D→C | Desktop lifecycle/маршруты не применимы телефоном, но больше не исчезают после mobile round-trip. |
| `kill_switch` | A→A | A→A | A→A | C→A | D→C | Android реализует fail-closed через системный Always-on VPN + lockdown и отказывается подключаться без подтверждённой политики. iOS сохраняет ключ, но применяет отдельную системную политику VPN On Demand. |
| `gateway_nat` `exit_node` `lan_subnet` `lan_subnet_ipv6` `post_up` `post_down` | A→A | C→C | C→C | C→C | C→C | Linux/router-only dual-family политика сохраняется всеми редакторами; команды GUI не исполняют. CLI hooks получают `$1=ifname`, `$2=gateway`, versioned `QELI_*`, stop reason и временный JSON полного NetworkPlan. |
| `forward` | A→A | A→A | A→A | D→C | D→C | Site-to-site forwarding остаётся CLI/desktop-функцией; мобильный round-trip больше не удаляет настройку. |
| `allow_lan` | R→R | C→C | C→C | A→A | A→A | Мобильное исключение домашней LAN сохраняет прежнюю семантику; desktop хранит его для телефона. |
| `apps` `apps_mode` | R→R | C→A | C→A | A→A | C→C | Windows использует пути к `.exe` и WinDivert; macOS — signing identifier и transparent+DNS Network Extension; Android — имена пакетов. iOS сохраняет выбор, но без MDM `NEAppRule` применить его не может. |
| `autostart` | A→A | C→C | C→C | C→C | C→C | На headless это политика supervisor/панели; GUI используют OS lifecycle и лишь сохраняют переносимое поле. |
| `name` | R→R | A→A | A→A | D→C | D→C | Desktop хранит имя в `[qeli]`; мобильные клиенты используют собственную метаинформацию профиля и теперь не стирают desktop-ключ. |

## Найденные и закрытые разрывы рефакторинга

В промежуточном состоянии 0.7.15 адаптеры продолжали сериализовать часть параметров, но
новое ядро их не читало. Это исправлено до релиза:

- `timeout`, все padding/heartbeat/shaping и `local`/`lport` добавлены в Rust parser,
  validation и round-trip;
- `keepalive`, `tcp_nodelay` и socket buffers больше не заменяются скрытыми константами GUI;
- defaults формы и runtime берутся из общей Rust-схемы; отсутствие `recv_buffer_size`
  сохраняется, поскольку оно включает автоматический рост UDP-буфера;
- `dns_servers` стал единым wire/config-представлением, а молчаливая подстановка
  `1.1.1.1`/`8.8.8.8` удалена;
- Android/iOS перестали удалять известные ключи другой платформы;
- `allow_unpinned_tofu` унифицирован и больше не отключает проверку уже известного пина;
- Android `kill_switch` теперь означает проверяемый системный lockdown, а не неработающий
  флаг в профиле.

Секция `[logging]` добавляет **3 поля** к 84 ключам `[qeli]` и сохраняется всеми GUI.
CLI применяет `level`, `file`, `time_format`. Windows/macOS используют `level` в профиле
службы/демона; GUI может задать его из настроек приложения. `file` и `time_format` desktop
сохраняет в документе, но не применяет. Android/iOS сохраняют все три поля, используя
для журнала настройки своего приложения.

Редакторская грамматика и defaults теперь общие: [ABI 1.16 configuration core](../plans/CLIENT-CONFIG-CORE.md). Таблица выше описывает применение полей платформой, а не наличие отдельных парсеров.

## Повторная сверка с исходниками — 22 сентября 2026

Исправлены пропуски чтения `reconnect*` в CLI и применения явного `dev` в Windows.
Экспорт C# больше не теряет пустые/повторные `route_file`; пути с разным регистром
сохраняются отдельно. Неизменённые bool/int из `carriedKeys` сравниваются по типу:
дубликаты больше не исчезают при сохранении формы. Разбор имени `qeli://` на Android
также делегирован ядру. На момент этой сверки проверки моделей охватывали 84 поля,
включая `[logging]`; актуальное покрытие с `tun.tx_queue_len` приведено ниже.

Матрица описывает исходники после исправлений. Для установленного приложения нужны
новые native-библиотеки ABI 1.16; Apple/device и release A/B проверки не подменяются
локальным C#/JVM прогоном. См. [статус переноса](../plans/CLIENT-CONFIG-CORE.md).

<!-- generated-model-coverage -->
## Покрытие моделей: все 88 полей

Этот блок генерируется из `editor/schema.rs`; M — типизированное свойство модели,
S — значение сохраняется в исходном документе ядра и/или `carriedKeys`.
Это не перечень контролов формы: поле без отдельного UI остаётся доступно через INI.
Общий парсер распознаёт ключи: `[qeli]` — 85, `[logging]` — 3.

Ключей с типизированным представлением: C# 65, Kotlin 59, Swift 58; остальные поля сохраняются как S.

| Ключи схемы | C# (Windows/macOS) | Kotlin | Swift |
|---|:-:|:-:|:-:|
| `server` `proto` `user` `pass` `key` `bind_static` `allow_unpinned_tofu` `mode` `obfs_key` `front` `sni` `reality_sid` `quic` `awg` `jc` `jmin` `jmax` `mtu` `mtu_probe` `gateway` `pull_routes` `ipv6` `roaming` `route_local` `allow_ipv4_leak` `allow_ipv6_leak` `include` `exclude` `dns` `dns_servers` `apps_mode` `apps` `route_file` `reconnect` `reconnect_retries` `reconnect_base_delay` `reconnect_max_delay` `timeout` `padding` `padding_min` `padding_max` `heartbeat` `heartbeat_interval` `heartbeat_size` `heartbeat_jitter` `shaping` `shaping_gap_mean` `shaping_gap_min` `shaping_gap_max` `shaping_budget` `shaping_min_size` `shaping_max_size` `shaping_stealth` `shaping_stealth_mbps` `logging.level` | M | M | M |
| `name` `persist_tun` `windows_disable_sharing` `windows_persistent_adapter` `forward` `local` `lport` `metric` `dev_node` | M | S | S |
| `kill_switch` | M | M | S |
| `allow_lan` `logging.file` `logging.time_format` | S | M | M |
| `dev` `device_type` `dev_attach` `tun.tx_queue_len` `autostart` `exit_node` `gateway_nat` `lan_subnet` `lan_subnet_ipv6` `post_up` `post_down` `password_file` `password_command` `keepalive` `tcp_nodelay` `recv_buffer_size` `send_buffer_size` `reality_compact` `reality_split` `reality_split_delay` | S | S | S |
<!-- /generated-model-coverage -->

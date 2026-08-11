# Клиентский конфиг: 0.7.14 → 0.7.15

Эта таблица фиксирует контракт **всех 73 допустимых ключей** секции `[qeli]` для пяти
клиентов. «До» означает поведение выпущенной 0.7.14, «после» — итоговый контракт 0.7.15
после переноса транспорта в общее Rust-ядро.

Обозначения:

- **A** — ключ читается и влияет на работу клиента;
- **C** — ключ принимается и сохраняется без изменений, но на этой платформе не применяется;
- **R** — ключ распознаётся как допустимый, но данным клиентом не применяется и не
  пересохраняется (актуально для headless CLI, у которого нет редактора профилей);
- **D** — ключ принимался, но терялся при сохранении профиля; это дефект 0.7.14;
- `X→Y` — состояние в 0.7.14 и в 0.7.15.

`C` и `R` не означают опечатку. Неизвестное всему qeli имя по-прежнему отклоняется
fail-closed. GUI-клиенты 0.7.15 сохраняют любой известный ключ, даже если применить его
может только другая платформа.

| Ключи | CLI | Windows | macOS | Android | iOS | Что изменилось в 0.7.15 |
|---|:-:|:-:|:-:|:-:|:-:|---|
| `server` `proto` `user` `pass` `key` `bind_static` `mode` `sni` `obfs_key` `front` `reality_sid` `quic` `awg` `jc` `jmin` `jmax` `mtu` `mtu_probe` `gateway` `route_local` `include` `exclude` `dns` `allow_ipv6_leak` | A→A | A→A | A→A | A→A | A→A | Внешняя семантика сохранена; на границе GUI→Rust теперь явно передаются платформенные дефолты `gateway`, поэтому Rust-дефолт split не меняет телефонный/desktop full-tunnel. |
| `reconnect` `reconnect_retries` `reconnect_base_delay` `reconnect_max_delay` | R→R | A→A | A→A | A→A | A→A | Реконнект остаётся платформенным lifecycle-контуром; Rust-ядро владеет попыткой соединения, но не решением GUI о следующем запуске. В 0.7.15 iOS adapter действительно создаёт следующую generation; до аудита ключи сохранялись, но любая native/pump ошибка была terminal. |
| `timeout` | R→A | A→A | A→A | A→A | A→A | Таймаут соединения перенесён в Rust и теперь действительно доходит до общего ядра. |
| `padding` `padding_min` `padding_max` `heartbeat` `heartbeat_interval` `heartbeat_size` `heartbeat_jitter` `shaping` `shaping_gap_mean` `shaping_gap_min` `shaping_gap_max` `shaping_budget` `shaping_min_size` `shaping_max_size` `shaping_stealth` `shaping_stealth_mbps` | R→A | A→A | A→A | A→A | A→A | Локальные значения теперь разбирает единое ядро; аутентифицированный push сервера, если он есть, остаётся старше локального значения. |
| `keepalive` `tcp_nodelay` `recv_buffer_size` `send_buffer_size` | A→A | C→A | C→A | C→A | C→A | Настройки сокета применяет Rust на всех нативных клиентах. TCP сохраняет autotuning. Отсутствующий `recv_buffer_size` включает bounded auto-grow UDP 4→8→16 МиБ; явное значение фиксировано, `0` оставляет ОС. Новые stats показывают kernel/internal drops, grow events и фактический размер. |
| `dns_servers` | A→A | A→A | C→A | C→A | C→A | Все клиенты используют канонический IPv4-only список `dns_servers`; мобильные всё ещё импортируют старое `dns = IP, IP`, но сохраняют канонический вид. IPv6-резолверы явно отклоняются до появления IPv6 inner data plane; публичный fallback DNS не подставляется. |
| `allow_unpinned_tofu` | A→A | C→A | C→A | C→A | C→A | Дефолт везде `false`. `true` разрешает продолжить только при доказанном сбое сохранения впервые увиденного ключа; несовпадение с известным пином всегда фатально. |
| `password_file` `password_command` | A→A | C→C | C→C | C→C | C→C | Источники пароля остаются headless-функцией; GUI не выполняют команды и не читают произвольные файлы. |
| `local` `lport` | R→R | A→A | A→A | D→C | D→C | Windows/macOS снова передают привязку первичного TCP/UDP carrier в Rust. Вторичные bonded TCP-сокеты намеренно не занимают тот же фиксированный порт. Ошибка bind теперь блокирует подключение вместо скрытого продолжения с другим source address/port. Телефоны сохраняют ключи для desktop-профиля. |
| `dev` | A→A | A→A | C→C | D→C | D→C | Имя интерфейса применимо Linux/Windows; macOS получает `utunN` от ядра, телефоны — системный TUN. |
| `dev_attach` | A→A | C→C | C→C | C→C | C→C | Подключение к готовому TUN остаётся функцией CLI; остальные редакторы не теряют ключ. |
| `dev_node` `metric` | R→R | A→A | C→C | D→C | D→C | Wintun-ключи применяет только Windows, остальные GUI сохраняют их. |
| `persist_tun` `route_file` | R→R | A→A | A→A | D→C | D→C | Desktop lifecycle/маршруты не применимы телефоном, но больше не исчезают после mobile round-trip. |
| `kill_switch` | A→A | A→A | A→A | C→A | D→C | Android реализует fail-closed через системный Always-on VPN + lockdown и отказывается подключаться без подтверждённой политики. iOS сохраняет ключ, но применяет отдельную системную политику VPN On Demand. |
| `gateway_nat` `exit_node` `lan_subnet` `post_up` `post_down` | A→A | C→C | C→C | C→C | C→C | Linux/router-only политика сохраняется всеми редакторами; команды GUI никогда не исполняют. |
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
- `gateway` и все transport-owned значения передаются в ядро явно, поэтому разный default
  разных UI не зависит от Rust-default;
- `dns_servers` стал единым wire/config-представлением, а молчаливая подстановка
  `1.1.1.1`/`8.8.8.8` удалена;
- Android/iOS перестали удалять известные ключи другой платформы;
- `allow_unpinned_tofu` унифицирован и больше не отключает проверку уже известного пина;
- Android `kill_switch` теперь означает проверяемый системный lockdown, а не неработающий
  флаг в профиле.

Секция `[logging]` не входит в эти 73 ключа `[qeli]`: CLI её применяет; Android/iOS
переносят её при редактировании; Windows/macOS используют собственные настройки логов и эту
секцию не разбирают.

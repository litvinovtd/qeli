# Завершение UDP buffer management — 31 октября 2026

Итог: исправлены ошибки Default/readback, существующее bounded auto сохранено.
На 302 прошли **14 целевых Rust-тестов**, client-only check и сборка.
На 300/301 выполнена **одна функциональная приёмка**: пять случаев, 11 коротких
UDP-окон, Recordizer required. Все проверки режимов и readback прошли;
ВМ восстановлены. Это не новый скоростной эталон и не публикация релиза.

## Что изменено в коде

- Rust `ClientPerformanceConfig::default()` согласован с INI/serde-путём:
  receive 4 МиБ и auto, send 0. Раньше derived Default давал receive 0/auto=false.
- После увеличения буфера ошибка `getsockopt` больше не подменяется успешным
  размером запроса. В подробной диагностике неизвестный readback — `null`.
- Метаданные каждого живого сокета содержат mode, requested RX/TX, raw OS readback,
  нормализованные значения, cap, clipping flags и доступный inode. Изменения
  журналируются, одинаковое состояние не логируется каждый tick.
- Linux client status: `stats.udp_socket_buffers`; server Unix control
  `queue-stats`: `udp_socket_buffers` по профилям. При закрытии сокета его запись
  удаляется. Существующие агрегатные counters и FFI/JNI ABI не изменены.
- Автоалгоритм 4→8→16 МиБ, explicit fixed/0 и серверный RAM-бюджет уже существовали;
  они не выдаются за новую разработку этого коммита. Новых блокировок/JSON в packet
  hot path нет: readback/обновление metadata выполняются на секундном tick.

Настройки и трактовка полей: [UDP-буферы](../manuals/UDP-BUFFERS.md).

## Сборка и scope

Кандидат собран только на VM302 из `13c1dfdead0a9f8dcf833f6b5f1168529692fcea`
и изолированного UDP-overlay четырёх Rust-файлов. Соседние незавершённые
REALITY/PQ/UI-изменения не включались. Исходники выбранного overlay после rustfmt
сверены с подготавливаемым коммитом по байтам.

- SHA256: `9eaa7b3bfd3aa4a802082cc3ae650c0c54fe382ce6b851baf8914eb2f857ca41`.
- Размер: 15449784 байта, native Linux amd64, jemalloc, rustc 1.97.0.
- Build raw: `/opt/qeli-udp-buffer-ready-20261031-r01` на 302.
- UDP unit: 10 passed; client/server buffer config: 2 passed;
  server INI/structured round-trip: 2 passed; client-only check и release build: code 0.
- Первый запуск ошибочно выбрал CLI test-target и получил 0 UDP-тестов.
  Обвязка отвергла такой PASS; отказ/лог сохранены. Target исправлен на `--lib`,
  исходники кандидата не менялись. В итог засчитаны только реальные 14 тестов.

Это лабораторный native-кандидат, не переносимый release/dist и не ARM64 qualification.
Бинарные артефакты релиза не заменялись.

## Функциональная приёмка 300/301

По 2 vCPU/2 ГиБ (MemTotal 2020904 КиБ), kernel `6.12.111+deb13-amd64`,
MTU 1400, TUN queue 1000, outer IPv4. Новые бинарники — частные копии в новом raw-root.
Старые установленные/архивные бинарники не перезаписывались. В каждой сессии
проверены ping IPv4/IPv6 и фактический `PACKET_MUX_V1`.

| Случай | Явная тестовая политика ОС | Что подтверждено |
|---|---|---|
| QUIC auto, OS clamp | rmem_max/default 212992 | Запрос 4 МиБ (далее возможна попытка 8), actual normalized 212992, raw 425984; `receive_clamped=true` |
| UDP-FakeTLS auto | rmem_max 16 МиБ, default 4 МиБ | Реальный рост 4→8→16 МиБ; активные сокеты 16, idle server worker 4 МиБ; не выше cap |
| QUIC auto | та же | Реальный рост 4→8→16 МиБ, предел соблюдён |
| UDP-FakeTLS fixed | explicit receive 4194304 | 4 МиБ остаются fixed; raw 8388608 |
| UDP-FakeTLS OS-default | explicit receive 0 | Нулевой запрос не применяет setsockopt; raw остаётся default 4194304, normalized 2097152; auto выключен |

Во всех случаях `receive_os_bytes`/`send_os_bytes` совпали с `ss rb/tb` по inode
у клиента и всех серверных UDP worker-сокетов. Ошибка readback проверена unit-тестом,
а не повреждением живого сокета. Код Qeli не менял sysctl: только тестовый сборщик
временно задавал указанные значения и сохранил исходные для отката.

Auto-окна: UDP600, payload 1200, 5 с + 1 с прогрева, IPv4/IPv6 up/down, n=1.
Остальные три окна — UDP10, 2+1 с. Всего 57 с заданных traffic windows.

| Auto-профиль | IPv4 up | IPv4 down | IPv6 up | IPv6 down |
|---|---:|---:|---:|---:|
| UDP-FakeTLS, receiver Мбит/с | 599.09 | 569.87 | 598.87 | 599.99 |
| QUIC, receiver Мбит/с | 598.58 | 600.01 | 599.46 | 600.00 |

Loss и TUN TX drops во всех 11 окнах — 0; оконный CPU steal не выше 0,33%.
Окно UDP-FakeTLS IPv4 download **не заменялось**: при 569.87 Мбит/с receiver
и 600.00 sender интервалы JSON различаются (5.000650 и 5.262154 с).
Эти короткие n=1 окна не являются A/B-доказательством отсутствия регрессии скорости.
Не заявляется, что увеличение буфера устраняет CPU steal, постоянную перегрузку
или все оставшиеся потери ранее проверенных сборок.

## Raw и восстановление

Raw обеих ВМ: `/opt/qeli-release-short-udp-buffer-ready-20261031-r01`.
UTC `16:40:30.721041`–`16:49:45.439034` (включая хеширование старых архивов).
Сборка 302 завершилась до передачи тестового трафика; cargo/rustc проверены отсутствующими.
Приватные конфиги и большие raw не публикуются.

Все 16 restoration checks на каждой ВМ прошли: boot, прежние файлы, sysctl,
процессы, сеть/маршруты/правила, qdisc и iptables/ip6tables. Независимая проверка
повторно подтвердила rmem/wmem по 212992, отсутствие Qeli/iperf/IRTT/TUN/netns/lock,
inactive qeli/qeli-client и неизменный SHA кандидата. Reboot не выполнялся.

Для сборки по отдельному разрешению удалён только старый
`/opt/qeli-license-compression-20261030-r01/target/debug` на 302.
104 ELF/`libqeli*` файла проверены по SHA и сохранены в
`/opt/qeli-preserved-debug-udp-20261031-r01/legacy-debug.tar.gz`,
SHA256 `b59f2bf4e4967de1997f3397c2d682f678a9b268627282dc99cf0573d6e867de`.
Исходники, логи, release-target, прежние кандидаты и raw не удалялись.
Промежуточные файлы компилятора восстанавливаются пересборкой; бинарники — из архива.

Релиз не публиковался. Лабораторная приёмка не заменяет переносимую сборку,
проверку обеих Linux-архитектур и финальные release gates.

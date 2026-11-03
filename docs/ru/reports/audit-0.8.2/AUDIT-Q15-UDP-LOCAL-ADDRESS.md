# Q15-F002: локальный адрес ответа UDP wildcard

25 сентября 2026. База `f7f6a7a8`. D06/D09/D10, Linux server. **P1, доступность.**

## Дефект и воспроизведение

После смены адреса сервера клиент мог не получить ServerHello, хотя сервер принимал
ClientHello и отправлял ответы. При `bind.address = 0.0.0.0` пакет приходил на второй
локальный IP, но обычный `send_to` выбирал основной адрес по маршруту. Подключённый
UDP-сокет клиента отбрасывал ответ от другого endpoint. `recvmmsg` сохранял только
удалённый адрес и терял локальное назначение каждого входящего пакета.

Исходный FAIL из [Q25-F107/F108](AUDIT-Q25-FIREWALL-TASK.md) сохранён. Дополнительный
захват заголовков **реального Qeli** подтвердил: 62 пакета на `192.0.2.3`, 127 ответов
с `192.0.2.1`. Это уже проверка приложения, а не только отдельного UDP echo socket.

## Исправление

Общий `udp_source` хранит значение локального адреса. Linux server включает `IP_PKTINFO`
или `IPV6_RECVPKTINFO`; `recvmmsg` получает отдельный control buffer для каждого пакета.
Parser проверяет размер, усечение, повтор pktinfo и unicast, сохраняет IPv6 link-local
scope. При отсутствии/ошибке метаданных пакет не получает случайный или прежний источник.
Буфер имеет 64 байта и нативное выравнивание на 32/64-битных целях; после syscall все
указатели scratch сбрасываются, перед новым receive прежние адреса очищаются.

`ObfsUdp` создаёт неизменяемое представление исходного listener socket с выбранным
локальным адресом. Ограниченный кеш из 32 представлений на receive worker не создаёт
дополнительных kernel sockets; активные сессии держат свои `Arc` независимо от вытеснения.
Адрес передаётся через handshake, AUTH, данные, управляющие сообщения и roaming mailbox.
Single/try/batch send используют `sendmsg`/`sendmmsg` с тем же pktinfo. Они не меняют
общую опцию source address и не используют изменяемый кеш «последний адрес клиента».

Сравнение roaming-путей учитывает общий сокет и локальный endpoint, поэтому новое
представление после вытеснения кеша остаётся тем же путём. Другой локальный IP — другой
путь. Обратная PMTU-проба привязывает свой краткоживущий сокет к адресу активного пути,
а не к wildcard. IPv4 source задаётся через `ipi_spec_dst`; ненулевой `ipi_ifindex`
не подменяет его основным адресом интерфейса. Для IPv6 link-local сохраняется scope.

INI, wire format и C ABI не менялись. Новых параметров нет. Клиентские connected API
сохраняют обычное поведение; общие batch/obfs алгоритмы не дублировались.

## Проверки

- **6 новых Linux-регрессий + 1 privileged IPv6 PASS**: дефектные/отсутствующие/повторные
  pktinfo, link-local scope, сохранение источника после чередования адресов, plain/obfs,
  single/try/batch send, отказ без старого адреса и короткий массив peer addresses.
- Реальный сервер с **2 SO_REUSEPORT workers** и двумя активными клиентами: IPv4/IPv6 ×
  fake-tls/obfs, всего **8/8 исправленных подключений**. **256/256 UDP echo packets** внутри
  туннелей вернулись. Захват **332 ответных датаграмм** не обнаружил неверного IP.
  Наборы данных содержали короткие и 1202-байтовые пакеты; это не тест скорости.
- Baseline `f7f6a7a8` в двух IPv4 wire modes: основной адрес работает, второй не подключается;
  **96 ответов с неверным источником**. Тестовые harness завершаются 0, потому что
  явно проверяют этот дефект; secondary client выходит 1. Это не baseline PASS по доступности.
- Исходный wildcard refresh-fault recovery также повторён: client exit 1/failed сохраняет
  защиту, шесть прямых UDP-проб заблокированы, новый явный запуск достигает Running и
  завершает точную очистку. Сохранившийся heartbeat — 8/8 тиков. Клиентский driver F107
  не менялся, исправлен именно сервер. Новые capture ответы используют `192.0.2.3`.
- **38/38 network cells**, 34 crash/recovery, **1220 основных + 806 вложенных checks PASS**.
  Обе перестановки nft/legacy, вторая с private firewalld: **1088** прямых попыток под
  защитой заблокированы, **656** разрешённых получили ответы.
- Итоговый снимок: **1564 host + 71 config; 2125 Linux + 47 privileged + 8 lifecycle PASS**.
  Все 9 host/cross/feature/lint/format команд PASS; сохранено прежнее исключение Clippy
  `chunks_exact_to_as_chunks`. RU/EN docs-as-code и `git diff --check` PASS.

## Доказательства и границы

Лаба: только `10.66.116.11`, Debian/Linux 6.12.105+deb13, Rust 1.97;
локально Windows/Rust 1.98. `10.66.116.10` не использовался. Runtime запускается в private
NET/mount/PID с отдельными `/run`, `/var/lib`, `/var/log`, `/etc/qeli`, `/tmp`.

Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`.
`udp-local-phase/evidence.json` проверяет **351 исходный файл**, 22 сценарных SHA,
packet headers, client status/exit, UDP echo results, before/after rules/routes/TUN,
state markers, матрицу и архивы. Полезная нагрузка пакетов в capture не сохраняется.
`udp-local-native-v1` — два baseline и четыре fixed сценария, по два клиента;
`udp-local-baseline-v1`/`udp-local-recovery-v1` — исходный FAIL и успешный recovery с теми
же условиями и неизменным старым клиентским драйвером. `udp-local-matrix-v1` — полная
повторная матрица; `udp-local-linux-v3` — итоговые unit/privileged/build/lifecycle.

Промежуточный Linux v1 FAIL сохранён: новый тест клонировал пустой BytesMut и получил
буферы без свободной ёмкости. После исправления теста v2 прошёл. Финальный v3 заменил
размер `[usize; 8]` на 64 байта независимо от pointer width. Исполняемые файлы v2 и v3
**побайтно идентичны по SHA-256**; native-v1 использовал замороженный v2, матрица/recovery
и итоговые тесты — v3. Поэтому native evidence относится к тому же исполняемому файлу;
валидатор отдельно сверяет единственную разницу исходников и оба binary SHA.

Повтор: `scripts/audit_udp_local_address.py --qeli <fixed-worker> --baseline <F107-worker>
--artifacts <new-directory>`. Требуются root и изолированная Linux-лаба. Передаются
реальные клиент и сервер Qeli; INI/учётные записи/ключи тестовые. Для точного повторения
исходного fault-recovery сохранены `udp-local-phase/capture-baseline.py` и команды job.
| Artifact | SHA-256 |
|---|---|
| `qeli-udp-local-v2-worker / qeli-udp-local-v3-worker` | `41ee7a9b03f1c44350054683f00703f6a395fd067aa3886e58488ae876087a36` |
| `qeli-firewall-task-v1-worker (baseline)` | `584d73ff8048be5da5cb5391b462f6dfeea4447f89a0fe86317defc3c808651d` |
| `linux-source-final.tar.gz` | `9c676d6e9af5bae730f20e2341e28765a0491c66824d1ce4af703eca4f776703` |
| `udp-local-matrix-v1.tar.gz` | `02cedacbad442e719a967ded4e0a9928dd9ac28fe974f941ab7487198b864c50` |
| `udp-local-native-v1.tar.gz` | `2430cf569c13eb4a2ef90c8cc4395a5cc430740f00fc0d1a1aa13eee714e7855` |
| `udp-local-baseline-v1.tar.gz` | `69525a08935d1286e62a88943b308767417c5cb80526ae240fefc2c23016639d` |
| `udp-local-recovery-v1.tar.gz` | `0388e1ca75a739ed7dc78abcd1741f20b4181af570fa663b01bb87782aead8e7` |
| `lifecycle-udp-local-v3.tar.gz` | `0e54313a1a05e2efd2370723b93ce5f4dc62dd3729f647b5a5669ec3132bc11b` |
| `udp-local-scripts-v1.tar.gz` | `5d8fe861872e88008090544b7ee109c63ce763d4f422f7ebd5a774cb1cb58bd0` |


Wildcard UDP с двумя локальными адресами закрыт в проверенных границах. Это не закрывает
D06/D10: process-global DNS/carrier, динамический WAN/IPv6, все multiprofile/firewalld
комбинации и полная матрица roaming остаются отдельными обязанностями. Scope link-local
проверен на уровне значения/control parser; новые native IPv6 сценарии используют ULA.
Тесты не сертифицируют multicast/broadcast, IPv4-mapped UDP listener или произвольные
policy-routing/VRF сочетания. При потере локального адреса нет обещания бесшовного
переноса уже установленного пути. Измерений производительности здесь нет; D14 открыт.

D05, D11/D12/D13/D15 также открыты. Новые разделы полного аудита не открывались.
Windows VM, Mac/iOS и физический роутер — **SKIPPED по решению пользователя**, не PASS.
Техдолг: **4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO**.

Контракт Linux: [in_pktinfo](https://man7.org/linux/man-pages/man2/in_pktinfo.2type.html),
[IPv6 packet information](https://man7.org/linux/man-pages/man2/IPV6_RECVPKTINFO.2const.html).
[Реестр](../../plans/AUDIT-DEBT.md) · [Мануал](../../manuals/OPERATIONS.md).

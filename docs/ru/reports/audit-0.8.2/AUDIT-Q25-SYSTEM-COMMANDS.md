# Q25: сроки системных команд TUN и DNS

Дата: 23 сентября 2026. Исходный коммит: `29e11399`.
Разделы 14, 19, 21 и 25: **IN_PROGRESS**; полный аудит остаётся открытым.

## Замечания

**Q25-F016, P2 — команды TUN и resolvectl не имели срока выполнения и лимита вывода.**
`std::process::Command::output` синхронно ожидал завершения процесса и EOF обоих pipes.
Зависший `ip`/`resolvectl` либо потомок с унаследованным pipe мог задержать setup, shutdown
и rollback. Эти вызовы есть и в синхронных Drop guards. Обычный async timeout вокруг
ожидания blocking-задачи не прекращает её процесс. Вывод прежде накапливался без лимита.

**Q25-F017, P3 — сообщение DNS обещало успешный rollback без проверки его результата.**
После неудачного применения per-link DNS код игнорировал результат немедленного
`resolvectl revert`, но писал «partial change was reverted». Marker уже сохранялся для
повторной очистки; ошибка была в диагностике, а не в отсутствии marker.

## Исправление и охват

`qeli/src/system_command.rs` предоставляет синхронный Command для Linux setup/rollback.
На команду отводится 15 секунд и до 16 МиБ stdout плюс 16 МиБ stderr. Полный бинарный
вывод сохраняется в пределах лимита; превышение возвращает InvalidData без частичного
Output. Таймаут возвращает TimedOut, ненулевой exit code остаётся обычным Output со
статусом процесса. Stdin закрыт. Нового INI-параметра нет.

Runner использует существующий OwnedProcess из `qeli/src/hooks/process.rs`. Новый
`qeli/src/hooks/output.rs` собирает полный машинный вывод; диагностические хвосты hooks
и обработка секретов сохраняют отдельные контракты. Обе трубы читаются одновременно.
На timeout/I/O error/overflow трубы закрываются, затем процесс завершается и ожидается
его выход. На Linux используется уже существующая группа процессов: лидер не reap-ится
до EOF pipes, поэтому последующая отмена не сигналит переиспользованному PGID.

Синхронный адаптер создаёт scoped thread с собственным current-thread Tokio runtime и
ждёт его. Он работает из Drop, вне runtime и внутри любого Tokio runtime, не оставляя
отдельного spawn_blocking task. Вызов по-прежнему блокирует вызывающий поток; это не
перенос всего сетевого setup в async. Deadline начинается до запуска helper thread.

Перенесены все пять запусков `ip` в `tun/iface.rs`: address, link up/MTU, MAC, queue length,
удаление TUN/TAP. Это общий интерфейс Linux-клиента и сервера. Перенесены все вызовы
`resolvectl` из client DNS: применение, немедленный rollback и восстановление по marker.
Отдельных runner в клиентах не добавлено. INI, wire format и ABI 1.16 не изменены.

Немедленный DNS rollback теперь пишет ошибку, если команда не завершилась успешно.
Итоговая ошибка говорит о попытке отката и сохранённом marker. Логика retirement marker
перенесена без копирования в `dns_backup::revert_link_marker`: marker удаляется только
после подтверждённого revert; ошибки команды/чтения/удаления возвращаются вызывающему.
Она проверяется на host через внедряемый вызов команды и реальные временные файлы.

Timeout мутации не доказывает отсутствие уже применённых изменений. DNS marker записан
до первого изменения и остаётся для повторного revert. Ошибки TUN проходят существующие
guards владельца интерфейса и журнал ошибок очистки Linux-клиента. Полный атомарный
rollback всей сетевой конфигурации этим проходом не подтверждён.

## Проверка

17 дополнительных host-тестов (включая entry point дочернего fixture) проверяют полный
бинарный вывод обоих pipes, повторный запуск builder, отсутствие runtime, оба вида Tokio
runtime, закрытый stdin, ненулевой exit и spawn error, истёкший deadline, зависание,
бесконечный stdout/stderr, отмену async collector, точный лимит/overflow/read error и
сохранение DNS marker при ошибках с успешным повтором/ошибкой удаления.

Две регрессии отдельно запущены с прежним прямым std Command::output за адаптером новой
тестовой сигнатуры: конечная медленная команда ошибочно возвращает успех после deadline;
конечный большой вывод ошибочно доходит до parser. Оба теста падают ожидаемым образом
и проходят с исправлением. Для baseline не использовался бесконечный дочерний процесс.

**915 host unit + 52 editor/policy + 7 examples + 12 server INI = 986 Rust tests PASS.**
Два новых Linux group-теста (ожидающий shell и вышедший лидер с унаследованными pipes)
только кросс-компилированы. Linux all-targets Clippy, client-only, client без roaming,
server-only, minimal FFI, compatibility без features и rustfmt проходят. Сохраняются
23 server-only warnings, terminal_sender без roaming, 33 compatibility warnings в
неизменённых модулях и информационное сообщение MSVC linker. Исключение Clippy
chunks_exact_to_as_chunks относится к неизменённому ndp_proxy.
Девять проверок документации и git diff --check проходят.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/system-command-audit-20260923.

## Открытые границы

15 секунд — срок команды, не жёсткая верхняя граница всего shutdown. Отдельно ожидаются
завершение/reaping процесса, синхронные файловые операции и другие шаги cleanup. Вызов
spawn, процесс в непрерываемом kernel wait либо ошибка kill могут задержать возврат;
потомок, намеренно покинувший process group, не получает гарантию групповой остановки.

Server NAT, включая его firewall/probe/WAN lookup, позднее перенесён в
[Q14-F032](AUDIT-Q14-NAT-COMMANDS.md). Мутации маршрутов и firewall-команды клиентского kill-switch/gateway
ещё используют прежний запуск. Gateway WAN discovery перенесён в
[Q25-F021/F022](AUDIT-Q25-GATEWAY-WAN.md). Read-only path monitor перенесён в
[Q25-F020](AUDIT-Q25-PATH-MONITOR.md). Server preflight перенесён в
[Q05-F001](AUDIT-Q05-PREFLIGHT.md). Перенос оставшихся мутаций требует проверки ownership journal при неизвестном результате мутации
и сохранения fail-closed поведения. Не объявлять весь слой системных команд исправленным.
Серверные ошибки cleanup и общая сериализация операций также требуют отдельного прохода.

Linux runtime, реальные TUN/firewall/DNS, SSH/systemd/Actions, native release builds,
приложения на устройствах и новые бенчмарки не запускались. Новые fixtures используют
дочерние тестовые процессы, loopback witnesses и временные файлы.

Предыдущие этапы: [ошибки cleanup](AUDIT-Q25-TUN-CLEANUP.md) и
[серверный H2](AUDIT-Q14-H2-TASKS.md).

Продолжение: [Q14-F024/F025](AUDIT-Q14-NAT-CLEANUP.md) делает общий NAT sweep конечным
и добавляет диагностику. Сроки server NAT-команд добавлены в [Q14-F032](AUDIT-Q14-NAT-COMMANDS.md);
общий срок операций и полная передача ошибок teardown остаются открытыми.

Продолжение D05: [общий срок применения клиентского DNS](AUDIT-Q25-DNS-BUDGET.md). Последовательность dns/domain теперь делит один deadline; откат остаётся отдельной owned-операцией.

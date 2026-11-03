# Q25-F109: стартовое восстановление в присоединяемом worker

25 сентября 2026. База `5fbfde6e`. D05/D09, Linux.

## Дефект и изменение

После чтения credentials `run_client_inner` синхронно резервировал сетевой namespace,
восстанавливал журнал физических маршрутов и проверял DNS-маркеры. Ожидание реального
flock журнала блокировало однопоточный executor: heartbeat и обработка SIGTERM не
выполнялись до завершения recovery. Отдельные командные бюджеты этого не устраняли.

Резервирование TUN/kill-switch lease, route recovery и DNS recovery теперь выполняются
одним владеющим worker через существующий `network_task::prepared`. До допуска готовый
stop отменяет запуск. После допуска worker присоединяется до фактического результата:
сигнал не освобождает lease раньше времени и не заменяет ошибку успешной отменой.
Успешный lease передаётся вызывающему коду и сохраняет прежнее время жизни через
reconnect/cleanup. При ошибке или непринятом результате он освобождается на worker.
Контекст NET/mount наследуется и проверяется общим helper; принудительный Drop ждёт join.

Если stop получен во время успешно завершившегося recovery, клиент возвращается до
настройки hooks/firewall и нового подключения. Ошибка журнала, DNS или deadline
сохраняет `failed` и exit 1. Порядок остаётся прежним: routes → DNS. При
`dev_attach = true` route recovery пропускается, DNS-проверка выполняется.
DNS recovery по-прежнему не изменяет живой resolver по одному сохранённому маркеру.
Дубликатов алгоритмов восстановления, новых INI-полей и изменений публичного C ABI нет.

## Проверки

- 3 новые Linux-регрессии: удержание реального namespace lease после stop и передача
  вызывающему коду; сохранение поздней ошибки с освобождением lease; принудительный
  Drop присоединяется до освобождения. Существующие проверки pre-stop, namespace,
  panic и cancellation общего helper остаются в полном прогоне.
- 2 baseline + 6 fixed runtime-сценариев на настоящем клиенте с current-thread runtime.
  Удерживается реальный `client-routes.state.lock`, затем отправляется SIGTERM.
  Baseline: 0 heartbeat ticks; fixed: 7–8 за каждый интервал около 800 мс до/после
  stop. До завершения операции процесс жив, конкурентный запуск отвергается.
  Проверены как TUN claim, так и общий kill-switch claim при другом имени TUN.
  В baseline без kill-switch listener также получил 6 UDP-пакетов на адрес сервера
  после освобождения lock, хотя SIGTERM был отправлен ранее; fixed — 0.
- Fixed: обычный stop с kill-switch и без него, повреждённый route journal, отказ legacy
  DNS после остановки, 15-секундный lock deadline, attach с занятым повреждённым route
  journal. Attach доходит до DNS-отказа, не ожидая route lock. В каждом fixed-сценарии
  listener получил **0** handshake-пакетов; успешные остановки — `stopped`/0,
  отказы — `failed`/1. После выхода namespace claims свободны.
- DNS: в clean-сценариях удалён только stale-маркер исчезнувшего ifindex; live, busy,
  foreign и legacy сохранены побайтно. Повреждённое/legacy evidence не удалено.
  Маршруты, операторские IPv4/IPv6 firewall-правила, interfaces и resolver до/после совпали.
- 38/38 hostname network cells, 34 crash/recovery, 1220 основных + 806 вложенных
  checks PASS. Обе комбинации IPv4/IPv6 nft/legacy, включая private firewalld:
  1088 запрещённых UDP-попыток заблокированы, 656 разрешённых проб получены.
- Итоговый снимок: **1564 host + 71 config; 2128 Linux + 47 privileged + 8 lifecycle PASS**.
  Все 9 host/cross/feature/lint/format команд PASS. Существующее исключение Clippy
  `chunks_exact_to_as_chunks` сохранено. RU/EN docs и `git diff --check` проверены отдельно.

## Evidence и границы

Лаба только `10.66.116.11`; рабочий `10.66.116.10` не использовался. Runtime использует
отдельные NET/mount/PID и приватные `/etc`, `/var/lib`, `/run`, `/var/log`, `/tmp`.
Linux 6.12.105+deb13, Rust 1.97; host Windows/Rust 1.98. Никаких установленных
сервисов или внешней сети в новом recovery-сценарии не требуется.

Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`.
`startup-recovery-phase/evidence.json` проверяет 351 исходный файл, архив, SHA бинарников,
результаты runtime, snapshots и packet assertions матрицы. Сценарий
`audit_startup_recovery.py` сохраняет команды, INI, состояния, журналы, heartbeat и хеши
DNS evidence. В матрице повторно использованы замороженные 22 сценария
`udp-local-scripts-v1`; их fixture-хеши сверены с предыдущим запуском.
Driver source/Cargo.lock и baseline source manifest сохранены отдельно.

- Worker: `ab51edd03b9b9a4428ea2c72a2f89089bfd186bfa88ca2df55d79476f5792960`.
- Fixed heartbeat driver: `e2ecdd3e2f597f8f3059d313fa2583984818ebb6a526775c0b566eebf62c7e81`.
- Baseline heartbeat driver (`5fbfde6e`): `4ec30901b504400418a04757291806ff20aba6bcf0ad189964e46679299191ab`.
- Итоговые задания: `startup-recovery-linux-v2`, `startup-recovery-runtime-v2`,
  `startup-recovery-matrix-v1`; все exit 0. Exit 1 внутри fault-сценариев ожидается.

Первый host-прогон **FAIL**: новые проверки Linux lease были без платформенного cfg;
после ограничения `linux + client` повтор успешен. Исходный log/checks сохранён.
Linux-v1 прошёл до этой тестовой корректировки; окончательное evidence относится к v2.
Runtime-v1 **FAIL** до запуска клиентов: приватный `/etc` скрыл iptables alternatives.
Фикстура закрепляет executables до mount; исправленный runtime-v2 сохранён отдельно.

**D05 остаётся IN_PROGRESS.** Не закрыты ранние error/Drop-пути, оставшиеся синхронные
locks/I/O/диагностика и общий NetworkPlan/shutdown deadline. Отдельный route budget
не гарантирует срок произвольного зависшего syscall. Принудительный Drop может
синхронно ждать worker. DNS filesystem/kernel stalls отдельно не инъецировались.
Это не benchmark и не сертификация всей сетевой матрицы D10. Windows VM, Mac/iOS,
физический роутер — SKIPPED по решению пользователя; Android final snapshot впереди.
Техдолг: 4/15 DONE, 9 IN_PROGRESS, 2 TODO.

Сверка после Q25-F110: запуск Linux TUN pump и его ранний откат выполняются в joined worker; чистая проверка recordizer/budgets проходит перед применением плана. Остальные границы D05 сохраняются. [Отчёт](AUDIT-Q25-PUMP-START.md).

# Q25-F110: запуск TUN pump и ранний откат в присоединяемом worker

25 сентября 2026. База `667920a3`. D05/D09, Linux.

## Дефект и исправление

После применения NetworkPlan TCP и UDP вызывали `LinuxTunPump::start` на async-потоке.
Операция включает fcntl, выделение буферов и создание reader/writer. При отказе второго
потока она присоединяет первый; последующий `?` вызывал Drop платформенного TunGuard
на том же async-потоке. Ожидание команды удаления маршрута останавливало heartbeat.
Валидация recordizer/MTU и UDP-бюджетов также могла завершить функцию уже после
применения сетевого плана и запуска packet workers.

Общий `start_linux_tun_pump` теперь принимает TunGuard и оба owned fd. Существующий
network worker запускает pump, присоединяет частично созданные потоки при отказе и
выполняет откат guard до возвращения результата. Успешный результат передаётся
вызывающему коду без await после принятия. Если future потерян, непринятый результат
на исходном worker сначала останавливает/присоединяет pump, затем освобождает guard:
порядок полей возвращаемого tuple задан явно.

Внутренняя ошибка запуска и ошибка самого worker — разные результаты. Обычный отказ
fcntl/thread creation после успешной очистки не объявляется ошибкой очистки. Ошибка
контекста/создания worker или panic фиксируется в sticky `Resource::Transaction`;
ошибки DNS/routes/forwarding продолжают записывать соответствующие владельцы. Поэтому
незавершённая очистка запрещает reconnect и снятие kill-switch, включая stop по сигналу.

Чистая проверка TCP MTU/recordizer и UDP record/control budgets/recordizer перенесена
перед `prepare_tunnel`. Алгоритмы и ограничения не дублируются. Это общий TCP/UDP-код
клиентов; новая граница worker относится к Linux. Формат INI, wire protocol и публичный
C ABI не изменены. NetworkPlan ACK и `post_up` сохраняют прежний порядок перед запуском
pump; этот этап не меняет контракт полной готовности data plane.

## Проверки

- **4 baseline + 8 fixed runtime-сценариев**: TCP/UDP × ошибка fcntl/создания writer;
  fixed дополнительно проверяет отказ удаления маршрута во время отката и SIGTERM.
  Test-only LD_PRELOAD применяется только к клиентам приватного стенда. fcntl-fault
  выбирает реальный TUN по TUNGETIFF после post_up; writer-fault возвращает EAGAIN на
  втором pthread_create исходного потока запуска, сохранив созданный reader.
- Во время удержанного системного вызова и route rollback baseline давал **0** heartbeat
  ticks; fixed — **7–8** за каждый интервал около 800 мс. Перед отказом writer
  reader наблюдается в `/proc/<pid>/task`, writer отсутствует. До очистки маршрутов
  оба packet workers уже отсутствуют. При fcntl-fault ни один из них не создаётся.
- Во всех 12 сценариях конкурентный запуск получает `cannot reserve TUN` во время
  отката. Исходный интерфейс и IPv4/IPv6 DROP остаются до завершения очистки.
  Все инъецированные отказы заканчиваются `failed`/exit 1; OS error сохраняется.
- **4/4 cleanup faults** сохраняют kill-switch и исходную ошибку после SIGTERM.
  **4/4 новых явных запусков** восстанавливают оставшееся состояние и штатно останавливаются.
  Маршруты и операторские firewall-правила совпадают с исходными после успешной очистки
  или recovery; TUN отсутствует. Во время неполной очистки допускаются только маршруты,
  уже наблюдавшиеся в активном поколении; исходные операторские маршруты сохраняются.
- **38/38 network cells**, 34 crash/recovery, 1220 основных + 806 вложенных checks
  PASS. Обе комбинации IPv4/IPv6 nft/legacy, включая private firewalld:
  1088 запрещённых UDP-попыток заблокированы, 656 разрешённых проб получены.
- **1564 host + 71 config; 2128 Linux + 47 privileged + 8 lifecycle PASS**. Все 9
  host/cross/feature/lint/format команд PASS; существующее исключение Clippy
  `chunks_exact_to_as_chunks` сохранено. Проверки документации RU/EN и diff выполняются
  перед коммитом. Новая регрессия — реальный runtime-fault сценарий; проверки общего
  network worker и pump из существующего Rust-набора повторно прошли.

Полный Linux-набор и сетевая матрица относятся к v1. Итоговый v2 изменяет только короткий
текст ошибки (причина ОС теперь видна в `last_error`) и комментарий TunGuard. Это
проверяет `final-only.patch` и сравнение исходников. На v2 повторены 9 host/cross команд,
сборка, 8 lifecycle и 12 runtime-сценариев с проверкой `last_error`. Сетевые алгоритмы
после полного прогона не менялись; матрица не выдаётся за запуск другого бинарника.

## Evidence и ограничения

Использована только лаба `10.66.116.11`. Рабочий сервер `10.66.116.10` не трогался.
Каждая ячейка имеет отдельные NET/mount/PID и приватные `/run`, `/var/lib`, `/var/log`,
`/tmp`, `/etc/qeli`; клиент находится в дополнительном NET namespace с veth.
Linux 6.12.105+deb13/Rust 1.97, Windows/Rust 1.98; shim собран cc с
`-Wall -Wextra -Werror`. Он не меняет установленный Qeli или системные библиотеки.

`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/pump-start-phase/evidence.json`
сверяет 351 исходный файл, tar, исходники/бинарник shim, snapshots, errors, thread lists,
baseline/fixed hashes и packet assertions матрицы. Прогоны: `pump-start-linux-v1`,
`pump-start-linux-final-v2`, `pump-start-runtime-v1/v2`, `pump-start-matrix-v1`. Driver source
и Cargo.lock сохранены в `pump-start-driver-evidence-v1/v2`. Матрица повторно использует
замороженные 22 сценария `udp-local-scripts-v1`, fixture hashes сверены. Baseline —
замороженный heartbeat driver предыдущего коммита, его source manifest сохранён.

Matrix/v1 worker `1af48032b2bca32b1ec5924ca01f79430177c02596b1410b525ddb6ef60d3b3a`.

Final/v2 worker `3e2cd6487e380eb225bc5d8cd2829b42a169e393fadcf5d4ef8e45f8a4e5787f`.

Fixed driver `a1756289c39dbebab52bf9e9510311e615f5f2af82d9a4c41dede142b598c085`.

Baseline driver `e2ecdd3e2f597f8f3059d313fa2583984818ebb6a526775c0b566eebf62c7e81`.

Test shim `98db0518ea1cf0e9acec3521c31552123d0c2e9b76defeebe999c7e5b4889562`.

**D05 остаётся IN_PROGRESS.** Принудительный Drop и невозможность запустить cleanup
worker могут синхронно ждать откат; общий NetworkPlan/shutdown deadline не закрыт.
Оставшиеся locks/I/O/диагностика и ранние пути до этой границы требуют дальнейшей
проверки. Перенос recordizer-валидации проверен по порядку вызовов и существующим тестам;
инъекции malformed remote push здесь не было. Это не benchmark и не сертификация D10.
Windows VM, Mac/iOS и физический роутер — SKIPPED по решению пользователя;
финальный Android-прогон остаётся D12. Техдолг: 4/15 DONE, 9 IN_PROGRESS, 2 TODO.

Сверка 25 сентября 2026: блокирующая запись клиентской диагностики рассмотрена и исправлена в [Q25-F111](AUDIT-Q25-STATUS-WRITER.md). Прочие ограничения D05 сохраняются.

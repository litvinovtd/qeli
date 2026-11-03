# Q28: native socket lifetime и пределы I/O

<!-- normative-sync: audit-q28-macos-sockets-v1 -->

**5 октября 2026: Swift SOURCE REVIEW; compiler/runtime USER SKIPPED. Связанные managed регрессии PASS. Q28 IN_PROGRESS, план 27/37 (73,0%), осталось 10 разделов.**

## Изменения исходников

| ID | Проблема и изменение |
|---|---|
| F268 | DispatchSource отменялся асинхронно, но fd закрывался сразу; глобальный read callback/send мог использовать уже переиспользованный номер. Все fd/source операции relay перенесены на одну serial queue. Published fd закрывает только cancel handler; DispatchGroup/closures удерживают ответственность до release. Stop latch блокирует позднюю публикацию TCP/UDP socket, а очередная операция проверяет cancellation до I/O. Private connect/DNS sockets без source закрываются своим worker через catch/defer. |
| F269 | Блокирующие connect/send и отдельные DNS timeouts на каждый сервер не давали общего ограничения. Socket создаётся nonblocking/CLOEXEC; ошибка SO_NOSIGPIPE обязательна. Connect проверяет SO_ERROR. Единый monotonic budget: 10 секунд TCP connect вместе с DNS/кандидатами; 5 секунд TCP send и весь UDP batch; DNS query не более 2 секунд внутри внешнего бюджета. Poll slice до 100 ms, EINTR/EAGAIN не продлевают deadline. |
| F270 | Нулевая UDP датаграмма считалась EOF; zip скрывал несовпадение arrays; framework writes могли накапливаться, errno читался уже после ошибки. Empty datagram сохраняется, cardinality проверяется, входящие write сериализованы с pause/resume sources. Watchdog framework-write через 10 секунд работает вне I/O queue; атомарный ticket исключает влияние старого таймера/late completion на следующую запись. errno сохраняется в error. |

## Проверки и ограничения доказательства

Добавлено **20 Swift cases** на production RelayLifetime/RelayDeadline: stop/publication gate, повтор stop, poll slice/deadline, nested DNS budget, pending write ticket, старый timeout, late completion. RelayWork.swift включён в policy-test target. **Cases не исполнялись; Swift compiler/Xcode и Darwin/NetworkExtension runtime USER SKIPPED.** Ни simulated fd reuse, ни настоящий native baseline здесь не объявляются PASS/FAIL. Изменения SocketRelay проверены только по коду и контрактам Apple.

Свежие связанные managed проверки: per-app **39**, forwarding **58**, network **117**, control **83**, storage **54**, Windows **325**, shared **549 PASS**; всего **1225**. Они подтверждают C# regressions и ABI/DTO boundaries, **не выполняют изменённый Swift relay**. Три C# Release-сборки без warnings/errors; Shared DLL copies равны. Docs/bindings/panel/diff PASS; Rust/native digest и 14 artifact hashes неизменны. Новый Swift исходник и project.yml закреплены в proof отдельно от неизменённых Rust libraries.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-sockets-20261005-r2.
Evidence: release/certification/evidence/q28-macos-sockets-20261005.json.

## Поведение

Deadline TCP connect относится ко всем кандидатам, поэтому blackhole первого адреса может исчерпать бюджет до fallback. Таймаут send после частичной передачи закрывает relay; прежний stream не возобновляется. Framework-write watchdog отказывает текущую запись, но не обещает отмену уже принятого OS callback. Stop асинхронен: latch отказывает новому I/O, а queued cleanup/cancel handlers освобождают fd позже; возврат stop не доказывает завершённый kernel release. Поздняя completion не возрождает source. Один входящий write на relay ограничивает накопление ответов; скорость/latency на настоящем Mac не измерялись.

Бюджеты не прерывают любой системный syscall и зависят от планирования очередей. В частности, создание сокета, bind/fcntl/getaddrinfo и framework вызов могут задержаться вне poll. Не заявлены общий deadline полного relay/manager teardown или подтверждённая leak-free работа NetworkExtension. UDP DNS correlation/policy и family-specific IP_BOUND_IF сохранены. Пользовательские конфиги только INI, новых параметров нет; предыдущая схема v5/internal JSON не меняется. Реальный Mac исключён пользователем.

Остаток Q28: итоговый integration review, включая UTC identity старых DNS/PF stamps. Исторические release cases/artifacts/timestamps и physical rows сохранены. Нет новых Linux/JNI/native A/B/benchmark/soak результатов; лаба, сеть, службы и пользовательские профили не изменялись. Push/deploy не выполнялись.

Первичные контракты: [DispatchSource cancellation и fd close](https://developer.apple.com/documentation/dispatch/dispatchsourceprotocol/setcancelhandler%28handler%3A%29), [connect](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/connect.2.html), [SO_ERROR](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getsockopt.2.html), [poll](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/poll.2.html).

Финальный source review заменил отдельные delayed timers на один watchdog per relay (poll 250 ms); heap отложенных задач больше не растёт с количеством пакетов. Первая квалификация сохранена отдельно; это source refinement, не воспроизведённая runtime-регрессия.

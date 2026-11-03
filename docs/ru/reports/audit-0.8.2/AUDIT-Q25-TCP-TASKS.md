# Q25: владение TCP-задачами и остановка Linux-монитора путей

Дата: 23 сентября 2026. Исходный коммит: `9e0c4fd8`. Разделы 22–25: **IN_PROGRESS**.

## Замечания

**Q25-F010, P1 — TCP-задачи могли пережить очистку своего соединения.**
Реестр хранил JoinHandle в общем Vec. При остановке ramp, maintenance и handover получали
abort без ожидания завершения, затем реестр stream-задач опустошался с тем же abort без join.
Уже выполняемый синхронный участок producer мог зарегистрировать новый stream после drain;
его собственная копия реестра оставляла задачи живыми. Даже принятые до drain задачи не
обязательно освобождали сокеты, codecs и TUN-каналы до восстановления DNS и удаления TUN.
Ошибка core.management_event обходила штатный teardown через `?`. Отмена всей future
уничтожала JoinHandle, что само по себе не отменяет задачу.

Общий transport_core::tasks теперь содержит отдельного владельца TaskGroup и клонируемый
Spawner со слабой ссылкой. В одну группу входят reader/writer, pipeline decrypt, adaptive ramp,
maintenance, handover и Linux path monitor. Создание задачи и закрытие группы используют один
mutex: после закрытия новая future отвергается до запуска. Завершённые задачи собираются при
новом spawn, сохраняя ограничение накопления handles при долгих handover. Штатный finish
закрывает группу, отменяет и ждёт все принятые задачи до сетевой очистки. Отмена ожидания
сохраняет handles в группе, повтор finish продолжает ожидание; владелец допускает только
одного waiter через &mut self. Drop закрывает группу и запрашивает отмену без async join.
Слабые ссылки исключают цикл владения producer → registry → producer.

Ошибка управляющего события и типизированный terminal kick сохраняются как результат и
возвращаются после той же последовательности teardown. Новый порядок находится в общем
TCP loop Linux/Android/Windows/macOS/iOS; ABI и INI не меняются. Старый Vec-реестр,
register_tcp_stream_task и отдельные handles производителей удалены. Серверные ProfileTasks
с контрактом нескольких shutdown-waiters и WorkerServices с завершением текущего цикла
не заменялись этим владельцем клиентского соединения.

**Q25-F011, P1 — blocking-операция монитора могла менять путь после остановки монитора.**
Linux-монитор создавал отдельные spawn_blocking для чтения маршрутов и submit_path_update.
Abort его async-задачи не останавливает уже начатую blocking-операцию. Даже await только
монитора не гарантировал бы окончание изменения пути до очистки сетевого плана.

Монитор теперь запускается как future владельцем. Его blocking-работы регистрируются в той
же группе до запуска; результат доставляется через oneshot. Отмена async-получателя не
теряет blocking-handle. Finish ждёт уже начатую операцию, а новые операции закрытая группа
не принимает. TCP использует группу соединения; UDP — такую же группу для монитора и его
работ. Остальные UDP-задачи в этом проходе не перенесены. Изменение относится к исходникам;
ранее выпущенные native-библиотеки автоматически не обновляются.

## Проверка

Девять тестов владельца: поздний spawn работающего producer, отмена/retry finish,
Drop с живыми Spawner, ранняя ошибка/unwind, сбор завершённых handles, panic одного ребёнка,
ожидание blocking-работы после отмены её waiter, отказ blocking после закрытия и destructor
отвергнутой future, повторно использующий Spawner. Прежняя проверка очистки handles перенесена
в этот набор. Две дополнительные Windows host-проверки запускают настоящий spawn_stream
на duplex-паре и канале TUN: inline и pipeline. После finish проверяют EOF сокета,
закрытую очередь writer и отсутствие владельцев TUN-канала. Реальная сеть не используется.

**860 host unit + 52 editor/policy + 7 examples + 12 server INI = 931 Rust tests PASS.**
Linux all-targets Clippy, client-only, client без roaming, server-only, minimal FFI и rustfmt
проходят. Прежнее исключение chunks_exact_to_as_chunks относится к неизменённому ndp_proxy;
23 transport-предупреждения server-only остаются. Документация RU/EN и diff проверены.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/tcp-task-audit-20260923.
Linux проверен кросс-сборкой; Linux runtime, реальные TUN/DNS/firewall, мобильные устройства,
SSH, systemd restart, Actions, пересборка release native и новый бенчмарк не запускались.

## Что осталось

При принудительной отмене всей future, panic процесса или SIGKILL async join не гарантирован;
уже исполняемую blocking-операцию нельзя остановить через abort. Сроки TUN/DNS-команд позднее добавлены в [Q25-F016](AUDIT-Q25-SYSTEM-COMMANDS.md),
read-only команд монитора — в [Q25-F020](AUDIT-Q25-PATH-MONITOR.md).
Мутации маршрутов и клиентский firewall ещё открыты; общего срока join нет.
Вложенные задачи транспортных библиотек/connector, UDP candidate/receive/draining lifetime,
отмена TUN shutdown и Linux fault injection требуют следующих проходов. Полный аудит открыт.

Продолжение: [UDP task ownership](AUDIT-Q25-UDP-TASKS.md) переносит active/candidate/draining и candidate-connect в ту же модель, исправляет ранний выход и порядок ожидания перед rollback. Принудительная отмена и вложенные transport workers остаются открытыми.

Продолжение 23 сентября: владение клиентскими H2 driver/bridge расширено от connect до
join поколения; [Q25-F015](AUDIT-Q25-H2-TASKS.md). Остальные ограничения сохраняются.

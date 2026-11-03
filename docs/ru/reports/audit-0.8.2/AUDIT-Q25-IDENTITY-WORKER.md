# Q25-F114: TOFU worker, отмена handshake и поздние ошибки

25 сентября 2026. База `c5cd6526`. D05/D09, Linux.

## Исправление

После F112/F113 файловый TOFU оставался синхронным внутри async identity callback.
Ожидание flock, чтение и fsync останавливали current-thread runtime: heartbeat, сигнал
остановки и тайм-аут handshake не обрабатывались до возврата системного вызова.

Linux-клиент теперь владеет отдельным потоком `qeli-identity` на время запуска без
явного `key`. Worker наследует исходный OS-контекст клиента. Semaphore допускает только
одну проверку одновременно; permit удерживается до чтения результата или регистрации
ошибки отброшенного ответа. Файлового I/O под mutex очереди нет. Отменённый запрос,
ожидающий admission, не попадает в очередь и не меняет файл. Результаты доверия не кешируются:
каждая принятая проверка заново использует обычные проверки `known_hosts`.

Handshake может прекратить ожидание по stop или `timeout`. TOFU-ожидание ограничено
`connection_timeout_secs` и для TCP, и для UDP; внешний TCP handshake timeout сохраняется.
Начатая файловая операция продолжает выполняться под владельцем клиента. Перед следующим
reconnect, освобождением egress protection и завершением клиент асинхронно ждёт её результат.
Успешное сохранение может завершиться уже после timeout/stop; это допустимая запись пина,
а не разрешение отменённому handshake установить туннель.

Отброшенный response сохраняет первую непрочитанную ошибку, включая уже доставленный,
но не опрошенный oneshot. Свидетельство ограничено 2048 символами. Поздний отказ
проверки/сохранения завершает запуск ошибкой до reconnect и не превращается в успешный
SIGTERM. Сетевые ресурсы очищаются обычным путём; такая ошибка сама по себе не является
неудачной очисткой firewall. Итоговая диагностика публикуется после join worker.
Нормально прочитанная ошибка следует прежней политике reconnect и не дублируется.

Явный `key` проверяется в памяти; TOFU worker и обращение к known_hosts не создаются.
Формат INI, wire protocol, публичный C ABI и native adapters других платформ не менялись.

## Проверки

- **9 новых portable регрессий**: отсутствие admission после отмены, timeout с работающим
  runtime, сохранение позднего и доставленного-непрочитанного отказа, однократная обработка
  обычной ошибки, сериализация/отмена ожидающего запроса, повторное ожидание finish,
  stop после admission, panic и принудительный Drop с join.
- **16 native сценариев, 8 baseline + 8 fixed**: TCP/UDP × stop/timeout × успешный/ошибочный
  fsync. C shim удерживает настоящий TOFU file-fsync до явного release. До release исходный
  файл неизменен, процесс жив, post_up не выполнен. Baseline даёт 0 heartbeat тиков;
  fixed — **5 за 500 мс** и **12 за следующие 1,2 с**.
  Fixed не создаёт туннель после отмены, поздние fsync errors дают exit 1/`failed`;
  timeout-fault с `reconnect = true` завершается после единственной записи. Stop с успешным
  fsync даёт exit 0/`stopped`. После каждого случая проверены маршруты, firewall и отсутствие qnt0.
- Повторены **16 F112/F113 file cases**, включая повреждённый TOFU с обоими значениями
  allow_unpinned_tofu, device-id lock и сохранение старого файла при fsync error.
- **6 established TCP/UDP teardown cases + 2 recovery** подтверждают успешный TOFU,
  работающий туннель, stop и восстановление после cleanup fault.
- **1584 host + 71 config; 2157 Linux + 48 privileged + 8 lifecycle PASS**.
  Все 9 host/cross/feature/lint/format команд PASS; RU/EN docs и staged diff проверены.

## Evidence и границы

Только `10.66.116.11`; приватные NET/mount/PID namespaces и каталоги состояния.
Рабочий сервер `10.66.116.10` и установленные службы не изменялись. Windows/Rust 1.98,
Linux/Rust 1.97. Первый Linux job завершился до сборки: source guard обнаружил старый
манифест; FAIL сохранён, манифест исправлен. Итоговый job — `identity-worker-linux-v2`.
Первоначальный host-прогон также сохранён; после уточнения одного теста он повторён.

`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/identity-worker-phase/evidence.json`
сверяет 358 исходников, tar, hashes и все 38 native cases плюс 2 recovery.

Worker `c53dec6b253a144c6bca41e0dcde97e18527c9add13a0c7c917f90b07fa83c97`.

Fixed driver `6e97d3dbe0b85030ab7932a1f87a2c7ade292392566a24f7eb4f1cef5fb6adf8`.

Baseline driver `b6b518fe033e731832eab3bb18a62ecd37bca3f5e8da17940bdf11016d3289e7`.

**D05 остаётся IN_PROGRESS.** Timeout прекращает ожидание handshake, но не прерывает
уже начатый syscall; корректная остановка ждёт завершения операции. Принудительный Drop
владельца может синхронно ждать worker. Общий NetworkPlan/shutdown deadline и другие
startup I/O/Drop-пути остаются. Контекст путей/межпроцессное поведение остаются D06.
Packet/firewall matrix и benchmark не повторялись. Windows VM, Mac/iOS и router runtime —
SKIPPED по решению пользователя; итоговый Android-прогон остаётся D12.
Техдолг: 4/15 DONE, 9 IN_PROGRESS, 2 TODO.

# Q23: роуминг, resume и CONTROL_V2

<!-- normative-sync: audit-q23-final-v1 -->

**DONE/PASS. План: 23/37 (62,2%), осталось 14.** 4 октября 2026.
[Evidence](../../../../release/certification/evidence/q23-roaming-20261004.json).
Параметры INI, публичный ABI и формат протокола не менялись.

## Подтверждённая ошибка Q23-F001 (P2)

Одноразовый таймер очистки TCP orphaned-сессии корректно уступает подготовленному
resume. Но если исходный grace истёк во время подготовки, а resume затем отменился,
старый код возвращался в Orphaned без нового таймера. Сессия могла удерживать адрес,
locator, резерв record buffers в 4 MiB и бюджет orphaned-сессий до другой внешней
очистки: обычное истечение grace больше не освобождало ресурсы.

abort_resume теперь возвращает исходный ReapTicket для orphan fallback. Общий
серверный helper повторно планирует его во всех четырёх путях отказа: admission
stream, отправка JOINOK, подтверждение client commit и server commit. Поколение
и исходный deadline сохраняются; просроченный ticket исполняется сразу, без
нового grace. До deadline работает прежний таймер, новый будущий не создаётся. Active fallback не возвращает ticket. Устаревший/terminal abort
не создаёт таймер. Повторные таймеры не удаляют восстановленную или заменённую
сессию и не освобождают бюджет дважды.

Две регрессии падают на старых переходах состояния и проходят после исправления.
Standalone baseline содержит только адаптацию прежнего return type () в Ok(None)
для компиляции проверки ticket; это не запуск неизменённого старого server binary.
Полный unit-набор также проверяет настоящую серверную обёртку. Live-сценарии
подтверждают обычные resume и expiry, но не вводят точную гонку задержанного
JOIN-abort в работающий процесс: этот порядок детерминированно проверен unit-тестами.

## Исправление тестового стенда Q23-T001

Multinode-стенд запускал два worker в одном network namespace, что конфликтовало
с существующим exclusive owner. Второй сервер теперь имеет свой namespace и линк
к роутеру; DNAT сохраняет клиентский endpoint. Отказ чужого locator и новая AUTH
остаются обязательными. Старый отказ сохранён отдельно; исправленный сценарий
проходит все 28 проверок. Production-проверка владения не ослаблялась. В UDP supersede/commit-race probe
физического C перенесён до запуска клиента, привязан к интерфейсу; rp_filter
восстанавливается. Прежний probe по source IP конфликтовал с active bypass A.
Исправления стенда не меняют production transport и обязательные утверждения.

## Разбор слоёв

| Слой | Контракт и проверка |
|---|---|
| Negotiation | Пересечение authenticated capabilities, включение в профиле и полный platform ROAMING_PATH contract. Resume и make-before-break требуют разных разрешений. Legacy bearer JOIN запрещён для authenticated-resume сессии. |
| TCP proof/reservation | Proof связывает locator, свежий handshake transcript, epoch, logical slot и handover bit. Epoch сгорает при reservation; допускается один candidate, orphan sessions/bytes ограничены. Проверены неверный proof, stale epoch, busy/draining slot, revoke и замена поколений. |
| TCP commit/cleanup | JOINOK только подготавливает реальный non-ready stream slot. Клиент сначала подтверждает платформенный commit и отправляет JOINCOMMIT; сервер публикует новый carrier, удаляет старый и отправляет JOINCOMMITOK. Явный отказ обратим; потеря/unknown platform commit требует reconnect. Abort после пропущенного grace теперь восстанавливает исходный таймер. |
| UDP ingress/validation | AEAD/replay проверяются session codec до изменения candidate. Направленные CID/epoch, точные peer/receiving worker/token связывают validation; codec owner не меняется при переключении family/listener. До validation исходящий объём ограничен тройным authenticated ingress; также действуют лимиты bytes, количества/rate candidates и неизменяемый TTL 10 секунд. Повтор INIT не продлевает срок. |
| UDP commit/retry | Publish callback выполняется до rotation registry; отказ публикации сохраняет candidate. Точный повтор committed response возвращает прежний результат без повторной публикации. На клиенте retry 500 ms, максимум четыре отправки, двухфазный platform ACK, generation-scoped abort и одна попытка NAT recovery на active epoch с grace 15 секунд. |
| PMTU/drain | Commit создаёт новое PMTU generation и conservative payload budget; stale ticket не увеличивает его. Старый путь остаётся только receiving на ограниченный drain; прежние control/PMTU не меняют текущий путь. Evidence Q21 по PMTU/fragments сохраняет область неизменённых исходников. Свежие family/NAT проверки сохраняют process/TUN/session ownership. |
| CONTROL_V2 | Authenticated/capability-gated framing, строгие lengths/status flags и ограниченные ordered fragments. Максимум 8 inflight messages, 16 parts/64 KiB на сообщение, expiry 5 секунд и 64 completed IDs. Duplicate identity включает type, flags, parts и payload digests. Management receipt появляется после semantic acceptance; неверный payload не блокирует исправленный message ID. |
| Restart/APPLY/server boundary | Resume state локален для процесса. Независимый сервер отклоняет чужой locator; auto после потери carrier выполняет новую AUTH. Прозрачной межсерверной репликации/восстановления после restart нет. Прежние APPLY/rollback проверки сохраняют собственный scope. PUSH_CONFIG представлен framing constant/tests, live handler отсутствует; hot push не заявляется. |
| Владение и мёртвый код | TCP/UDP actors используют общие core state и task owners; platform adapters владеют sockets/routes/ACK. Рассмотренные методы имеют production, feature либо compatibility callers. Новых дублирующих реализаций и подтверждённых неиспользуемых путей не найдено. |

## Выполненные проверки

- **2405 full Linux unit PASS, 60 ignored**, с transport-core-ffi;
  strict all-target Clippy и release PASS на .10 с Rust 1.97.0,
  одним build job и dev/test debug=0. Три новые регрессии: overdue hard
  resume abort, потеря старого carrier во время prepare и серверная обёртка.
- **24 целевых TCP/CONTROL_V2 теста PASS** на копиях настоящих production-модулей.
  Production wire module включён; его full-crate-dependent tests исключены только
  из маленькой обвязки и выполняются в полном наборе. Обвязка завершилась на .11
  до инцидента; окончательный full Linux gate выполнен на .10. Два ожидаемых baseline
  failures отделены от окончательных PASS.
- **12 свежих изолированных Linux сценариев, 281 проверка PASS**: TCP handover,
  hard resume, grace expiry, independent-server rejection/full AUTH; UDP success,
  rollback, supersede, commit race, loss/replay, IPv4/IPv6 switch и NAT rebind;
  TCP soak с **100 подтверждёнными сменами пути**. Resource samples проверяют
  fd/socket/state/RSS bounds. 100 — ограниченный release gate, не новый
  endurance run на 10 000 flips и не throughput benchmark.
- Все **четыре native artifacts проходят независимые A/B**; canonical/consumer
  copies совпадают с current provenance. Их байты совпадают с Q22, поэтому
  его 22 Windows ABI, 23 Android JNI и header проверки сохраняют исходные даты
  и библиотеки. Повторные device/OS network execution не заявляются.

Все runtime gates используют новый private Linux candidate. Только строка
linux.roaming-flap-soak получает новые execution/SHA/evidence; остальные строки
матрицы сохраняют прежние фактические artifacts/dates и область evidence.
Полная транспортная/IPv6 release matrix не повторялась. Неудачная подготовка
baseline и отказ старого multinode-стенда сохранены отдельно. Android A/B выполнен
по pinned recipe на .10 после сетевых тестов, с одним build job; flags/toolchain
и обязательные A/B/export/hash проверки сохранены. Подтверждено сохранение сервиса
и active binary .10, а также двух посторонних пользовательских локальных правок.

.11 перестала выдавать SSH banner во время параллельных приватных компиляций.
Причина не подтверждена: перегрузка памяти вероятна, OOM не диагностирован. Эти
попытки не засчитываются как квалификация. Доступной консоли VM/гипервизора здесь
нет; итоговое состояние сервиса .11 не проверено. Обязательные full Linux/runtime/native gates Q23
выполнены на .10; недоступность .11 остаётся отдельным инцидентом лабы.

## Границы проверки

NAT64, физические Wi-Fi/LTE/sleep-wake и installed Android VPN app E2E здесь не
повторялись. Mac/iOS/router/Windows VM network runtime остаётся исключённым по
решению пользователя. Принятые ограничения Q25-A125 WAN replacement и ambient
legacy firewall сохраняются. Completed-ID cache ограничен, это не бесконечная
история semantic replay. CONTROL_V2 — служебный обмен; конфиги профилей остаются
INI. Deployment/push не выполнялись.

Далее: **Q24 — multipath, bonding и общий бюджет**.

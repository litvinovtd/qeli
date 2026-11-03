# Q22: transport core, FFI/JNI и память

<!-- normative-sync: audit-q22-final-v1 -->

**DONE/PASS. План: 22/37 (59,5%), осталось 15.** 4 октября 2026.
[Evidence](../../../../release/certification/evidence/q22-core-20261004.json).
ABI остаётся **1.16**; config values и wire formats не менялись.

## Подтверждённые ошибки

| ID | До исправления | Исправленный контракт |
|---|---|---|
| Q22-F001, P2 | Registry получал Arc до блокировки объекта. Уже ожидающий mutex конкурентный вызов мог прочитать частично изменённое состояние после panic другого вызова. Guard находился снаружи catch_unwind, поэтому mutex не становился poisoned; удаление публичного поколения не отзывало выданный Arc. | Guard создаётся внутри unwind boundary. При panic mutex становится poisoned до пробуждения ожидающего вызова; тот получает Panicked без выполнения операции. Retirement по-прежнему сверяет исходное поколение и не затрагивает replacement или другие handles. |
| Q22-F002, P2 | Panic управляющей операции удалял публичный ClientCore handle, но уже запущенный native runner удерживал Arc и неотменённый token. Последующие stop/free через удалённый handle уже не могли запросить отмену. | Все короткие client-операции проходят общий helper: cancellation token поколения устанавливается до resume_unwind. Затем Registry помечает mutex и удаляет handle. Платформа всё равно должна дождаться собственного IO worker перед очисткой сети. |

Оба воспроизведения намеренно вызывают внутренний Rust panic. Удалённый trigger,
Rust memory UAF и безопасность произвольных pointers не заявляются. Baseline F001:
9 controls PASS, новый тест FAIL с `Ok(77)`. Baseline F002: 16 FFI controls PASS,
assertion отмены leased runner FAIL. После исправлений реальные production-модули
проходят эти проверки.

## Разбор слоёв

| Слой | Контракт и проверка |
|---|---|
| Конфигурация и policy | Strict INI/qeli-link parser и pure configuration API остаются общими. Служебные JSON DTO отделены от формата профиля. Временные JNI inputs и secret fields ядра используют прежние wipe paths; это не доказательство очистки каждой копии allocator. |
| Handles и конкуренция | Opaque slot/generation отклоняет stale/double free. Global registry mutex не удерживается на время операции; разные объекты работают параллельно. Panic boundary теперь закрывает ожидающие короткие вызовы и отменяет leased runner поколения. |
| Lifecycle и events | Create/start/plan ACK/stop/free, queue limits, protect/trust/management events и stale correlations. Packet backend не появляется до положительного ACK. Даже при event backpressure stop запрашивает отмену, но возвращённую ошибку нужно обработать: drain/retry либо dispose. |
| Runner и callbacks | Один runner на handle, проверенные carrier inputs, общий handshake/data loop и task ownership. Cancel участвует в DNS/connect/handshake и ожидании callbacks. Завершение сверяет identity счётчиков, не давая старому поколению перезаписать новое. Events копируются в caller storage; Android сериализует двухэтапный poll монитором TransportCore. |
| Buffers и queues | Batch содержит максимум 64 packets; lengths ограничены и точно делят payload. Pools дают backpressure, возвращают allocations через Drop и не добавляют fallback slots. Events/stats сохраняют старые prefixes, caller size markers и future tails. Byte budgets pools — исходные reservations; Vec может вырасти для большего поддерживаемого record, поэтому это не универсальный жёсткий heap cap. |
| Workers и descriptors | Общие TaskGroup/TunWorkers владеют cancel/join; fd adoption дублирует descriptor вызывающего. Bridge generations, stale ACK и stop gates проверяются. Privileged TUN evidence Q21 сохраняет прежнюю дату/ELF и область совпадающих исходников. free отзывает публичный доступ, но не заменяет join worker и синхронную очистку OS routes. |
| Protocol/path seams | Session, framing, UDP receive/buffer/batch и TCP/UDP adapters сохраняют current-unit и scoped evidence Q10/Q12/Q17/Q21. PREPARE/BIND/COMMIT различают обратимый отказ и неизвестное состояние платформы; failed cleanup терминален. Подробный roaming/resume review — Q23. |
| ABI и packaging | Event=48, stats V3=144, additive minor compatibility, 64-bit handles и обязательные exports. Native cdylib требует unwind; abort/fatal fault не входит в catch_unwind recovery. Все четыре packaged artifacts проходят независимые A/B и совпадают с consumer copies. |
| Мёртвый код | Рассмотренные helpers используются общими путями, platform/feature adapters либо намеренными compatibility exports. cfg/allow(dead_code) сам по себе не доказывает отсутствие вызовов. Дополнительных самостоятельных parser/packet implementations не добавлено. |

## Выполненные проверки

- **2402 full Linux unit PASS, 60 ignored**, с включённым `transport-core-ffi`;
  strict all-target Clippy с этим feature и CLI release PASS. Внутри набора:
  213 transport_core, 17 C ABI и 10 Registry tests. Первый default-feature
  проход также дал 2384 PASS/60 ignored. Новая queued-регрессия и усиленный
  assertion отмены runner выполнены успешно.
- **22 проверки свежей packaged Windows DLL PASS**: old/future output buffers,
  owned plans, stale ACK, packet-pool backpressure, 100 slot-reuse cycles,
  восемь concurrent free и отмена настоящего localhost handshake. Второй runner
  отклоняется; concurrent free отменяет и завершает первый. Wintun и настройка
  Windows routes/DNS/firewall не запускались.
- **23 JNI проверки PASS на Android 14/API34/x86_64**: приватный app_process DEX
  загружает новую A/B libqeli.so. Проверены framing, отличие broken poll от
  пустой очереди, 100 handle reuse, cancel до регистрации UDP probe и free/join
  настоящего runner, ожидающего socket-protect ACK. APK не устанавливался,
  VpnService/TUN plan не применялся. Исходные userdata hashes read-only AVD,
  packages и link inventory сохранены.
- Публичный header компилируется и выполняется как **C11 и C++11**: offsets,
  initializers, major/minor compatibility. **Четыре native A/B PASS**:
  Windows x86_64, macOS universal2, Android arm64-v8a и x86_64. Provenance
  соответствует исходникам; все consumer copies совпадают.

CLI Linux побайтно совпадает с Q21:
`36a0e491f9437773b73b3e29f9c7ab0b7f624142e782dd78777f0c6168e6cef1`.
Его прежние сетевые execution сохраняют реальные даты/evidence; нового полного
Linux matrix или benchmark здесь не заявляется. Native libraries изменились
и получили свежую проверку.

## Границы и сохранённое состояние

C ABI требует валидных caller-owned memory и lifetimes; произвольный неверный
адрес не является защищённым input. Panic recovery относится к unwind, а не
OOM abort/process-fatal fault. Сохраняется документированная wrap-граница
32-bit slot generation; бесконечная уникальность handles не заявляется.

Mac/iOS/router/Windows VM network runtime не заявляется: исключённые пользователем
платформы сохраняют свой scope. Android — JNI lifecycle на эмуляторе, не installed
app E2E и не полноценная VPN forwarding-проверка. Config JSON не возвращён.

Оба сервиса лабы, active/working executable hashes сохранены. Прежняя принятая
ambient-разница из трёх legacy firewall rules на desktop остаётся scoped.
Android preflight сначала отказал из-за требования 8 GiB; после фиксации успешных
результатов удалены только проверенные inactive private Linux test/Clippy caches.
Подготовительные отказы отделены от итоговых PASS. Рабочие бинарники не заменялись;
push/deploy и нового benchmark нет.

Далее: **Q23 roaming, resume и CONTROL_V2**.

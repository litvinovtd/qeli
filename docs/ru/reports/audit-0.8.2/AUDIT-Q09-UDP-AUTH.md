# Q09: владение UDP AUTH и PMTU до авторизации

<!-- normative-sync: audit-q09-udp-auth-v4 -->

Дата: **3 октября 2026**. Код: `616cb54b`. Пакет исправлений проверен;
полный раздел Q09 остаётся **IN_PROGRESS**. [Evidence](../../../../release/certification/evidence/q09-udp-auth-20261003.json).

## Находки и исправления

| ID | Приоритет | До исправления | Исправление и проверка |
|---|---|---|---|
| Q09-F001 | P2 | Обе ветви carrier PMTU проверяли наличие записи адреса, хотя комментарии обещали авторизованную сессию. `AwaitingAuth`, ещё не отправленный AuthOK и revoked-сессия могли получить ACK до общей проверки состояния | Общий `pmtu_reply` проверяет Authenticated, AuthOK и revoked до отправки и расходования QUIC packet number. Старый/новый release проверены через реальные UDP/QUIC-сокеты |
| Q09-F002 | P1 | Отдельная AUTH-задача хранит адрес; reaper или pending-cap могли удалить исходный handshake во время tarpit/Argon2. Затем отложенный verifier мог удалить или настроить новую запись того же адреса | Резерв привязан к конкретному handshake через `UdpAuthLease`. Он берётся под directory lock до spawn. Reaper, capacity eviction и удаление revoked приёмником сохраняют активный резерв; один handshake не запускает две AUTH-задачи. Drop освобождает резерв при завершении, отмене или отказе запуска |

Это подтверждённая ошибка владения состоянием; успешный удалённый обход пароля
воспроизведением не заявляется. Если все 1024 half-open слота зарезервированы,
новый handshake отбрасывается для повторной попытки, без превышения лимита.

Проверка UDP AUTH, ожидание Argon2 gate и tarpit теперь используют оставшееся время
`perf.connection.handshake_timeout_secs` от создания handshake. Повторный AUTH не
получает новый бюджет. Резерв удерживается до завершения admission/отправки AuthOK;
таймаут вокруг всей транзакции с уже выделенными ресурсами не добавлялся.
Уже выполняющийся blocking Argon2 завершается со своим concurrency permit: отмена
ожидающего future не выдаёт этот permit другой задаче преждевременно.

## Проверки окончательного пакета

- **2283 Linux units PASS**, 0 failed, 60 явно ignored; четыре новые регрессии: PMTU state/order/revocation, ownership/cancel, rejected spawn и original deadline.
- Pinned full/minimal Clippy и rustfmt PASS. Linux release с jemalloc: `406cbb794521d8cbbf4bcd3929b4258c34e59bfee3dbe00a785331ac864aff48`.
- **16 реальных UDP/QUIC проверок**: proxy передаёт ClientHello настоящего Qeli, удерживает весь ServerHello и не допускает AUTH. Оба PMTU формата получают ACK от baseline Q08 и ни одного ACK от исправленного бинарника.
- **35 admission E2E checks PASS**: TCP/UDP same-device, fixed IPv4, session cap, profile scope, teardown и настоящие tunnel packets. Владение при forced live reaper race отдельно не воспроизводилось; его проверяют review и детерминированные ownership/cancellation тесты.
- Fresh **18 release cases / 327 assertions**, aggregate leak и **100 TCP + 100 QUIC / 33 soak checks PASS** того же SHA.
- Четыре native core A/B, ABI, потребляемые копии и provenance PASS. Серверные изменения исключены из этих native целей; все четыре бинарника остались побайтно прежними, metadata обновлена на текущие исходники.
- Полные снимки лабы, PID/start и рабочие исполняемые файлы сохранены. Сервисы не заменялись; push, deployment и новый benchmark не выполнялись.

Сырые журналы, source/fixture hashes и сохранённые артефакты:
`audit-debt-20260924/q09-handshake-20261003` рядом с worktree. Секреты в fixtures отсутствуют.

## Остаток Q09

TCP deadlines/saturation и полный ClientHello/JOIN проверены следующим [пакетом Q09-F003–F005](AUDIT-Q09-TCP-PARSER.md). Остались UDP anti-amplification, replay/reorder, неверные PQ/proof/password и capabilities/downgrade, а также итоговый review. Общий Q09 остаётся IN_PROGRESS; обязательные проверки этого UDP-пакета выполнены. Физические платформы и прежние оговорки Q08 сохраняются.

**Последующее состояние:** UDP publication, fragments, expiry и deadline проверены [Q09-F006–F009](AUDIT-Q09-UDP-CONTRACTS.md). Актуальный остаток и ограничения перечислены там; исходные числа этого отчёта относятся к своему пакету.

**Итог Q09:** дополнительные decrypted proof/capabilities, конкуренция и воспроизводимый TCP KICK/EOF закрыты в [финальном отчёте](AUDIT-Q09-FINAL.md). Q09 DONE; исходные результаты и ограничения этого этапа остаются историческими.

# Q25 — общий срок клиентских route-транзакций

<!-- normative-sync: audit-q25-route-budget-v1 -->

24 сентября 2026. Кодовая база `ea87fd49` (последующий `d5779b4a` меняет только
измерительные скрипты и документацию). Продолжение D05/D09.

## Q25-F092, P2 — общий mutex и последовательность маршрутов не имели срока

Владелец маршрутов, setup, prepare, COMMIT и cleanup теперь получают по 15 секунд
на допуск через process-local operation mutex и последовательность `ip` queries/mutations.
IPv4/IPv6, проверка FIB, route_local discovery и подтверждение удаления используют
общий срок текущей попытки. Поздний ответ не подтверждает успешную операцию;
после истечения срока новый child не запускается.

Route rollback после неуспешного COMMIT получает отдельные 15 секунд на всю обратную
последовательность. Срок не обновляется для каждого маршрута. Неполный откат означает
`RouteCommitStateUnknown` и прекращает допуск COMMIT этого владельца. Pending-записи
не дают права удалить маршрут с неизвестным происхождением. Cleanup закрывает допуск
до ожидания mutex, сохраняет неподтверждённые записи и допускает отдельный verified retry.

Срок передаётся thread-local RAII scope в строго синхронном коде, который держит operation
mutex. Guard имеет `!Send` и не переносится через await; unwind восстанавливает родительский
срок. Откат временно заменяет срок, а не меняет сохранённого владельца или его namespace.

## Проверки

7 новых переносимых + 1 Linux-тест: expired/busy admission; остановка допуска при
неуспевшем cleanup; поздний refresh без route I/O; неизвестный add без delete authority;
поздний FIB и отдельный общий rollback; cleanup обеих семей; RAII unwind; реальный
child `sleep 5` с deadline 120 мс (внешний допуск 2 секунды).

**1491 host unit + 71 config**, все **9 feature/cross/lint checks PASS**.
**2009 обычных Linux + 32 privileged + 8 worker lifecycle E2E PASS**.
Отключение deadline guards в приватной копии даёт **6 ожидаемых FAIL**;
после восстановления — **196 route tests PASS**, ещё 7 privileged/fixtures
явно остаются ignored в этом focused-прогоне (privileged выполнены в полном выше).
Первые две локальные регрессии считали подготовительные fixture queries частью операции;
счётчик исправлен, исходный неуспешный лог сохранён. Критерии runtime не ослаблены.

Все 322 файла снимка проверены по SHA до/после полного и контрольного прогона.
Source archive: `99eeff06b596dd2a3d287fae2dfba7ff7d54b313dba3f2a33fe3ef0ab725197a`.
Debug worker: `24f87dc8765c37014c79506492895aa7a1f48fba97471654c520681b6341230c`.
Rust Linux 1.97 / host 1.98; прежнее Clippy-исключение `chunks_exact_to_as_chunks`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/route-budget-phase/`,
`route-budget-final.log`, `route-budget-counterfactual/`, `lifecycle-route-budget/`.
Лаба `.11`, приватные namespaces; работающий сервер `.10` не изменён.

Реальная клиентская [packet-матрица](AUDIT-Q34-LINUX-MATRIX.md) повторена на этом же debug worker: **17/17 строк, 297 утверждений PASS**, включая stop с удалением TUN и возвратом прямых маршрутов. DNS packets настоящие, resolvectl остаётся stub: D-Bus context этим не подтверждён. Evidence: `packet-matrix-route-budget/` и одноимённый лог.

## Границы

15 секунд ограничивают operation admission и child-команды, а не весь NetworkPlan/shutdown.
Внутренние registry locks, filesystem/sysctl I/O и синхронный внешний refresh callback
не прерываются этим механизмом; просроченный результат отвергается при возврате.
Executor isolation остаётся D05, persistent crash recovery — D04, контекст resolver — D06,
полный fault/resource охват — D09/D10/D13. Root может изменить сеть между проверкой и
командой: process-local mutex не является kernel CAS. Новых параметров INI нет.
Windows VM/Mac/iOS/router runtime пропущен по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Мануал](../../manuals/CONFIG.md)

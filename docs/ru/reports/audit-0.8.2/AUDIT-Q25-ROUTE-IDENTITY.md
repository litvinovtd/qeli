# Q25: исходный TUN и namespace при очистке маршрутов

Дата: 23 сентября 2026. Baseline: `bac06814`.
Q25-F063–F064 исправлены в описанных пределах. Разделы 21/22/25 остаются **IN_PROGRESS**.

## Находки

**Q25-F063, P2 — сохранённое имя позволяло очистить замену исходного TUN.**
После внешнего rename/delete имя могло принадлежать новому устройству. Cleanup сначала
сопоставлял сохранённые route selectors, где `dev` тоже был именем, а затем выполнял
общий IPv4/IPv6 `route flush dev`. Ни маршрутный журнал, ни удержание старого fd сами
по себе не подтверждали, что это имя всё ещё обозначает прежний интерфейс. Точечное
удаление могло совпасть с идентичным маршрутом замены; flush затрагивал и незаписанные
маршруты нового устройства. TCP, UDP, TunGuard Drop и частичный setup rollback имели
одну и ту же достижимую цепочку.

**Q25-F064, P2 — route owner не проверял namespace выполняющего очистку потока.**
Журнал учитывал generation/имя/процессный id, но команды исполнялись в текущем network
namespace. Если владелец использовался из другого namespace, даже физический bypass
мог совпасть по всем selectors с чужим маршрутом. Также orphan recovery мог принять
отсутствие записи в чужом namespace за отсутствие остатка. Обычный клиент сам не вызывает
такой перенос; условие дефекта — внешний/in-process переход потока в другой namespace.

## Исправление

RouteOwner удерживает открытый `/proc/thread-self/ns/net`, включая оставшуюся orphan
reservation. Сравниваются device/inode удерживаемого дескриптора и текущего namespace
потока. Дескриптор удерживает сам объект namespace живым, поэтому его identity не
переиспользуется, пока существует эта reservation.
[Контракт Linux namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html).
Начало setup/roaming operation и orphan recovery также проверяет namespace.

Для managed TUN owner один раз связывается с индексом исходного устройства перед
адресами/up и другими изменениями плана. Нужны разрешённые `TUNGETIFF`/`TUNGETDEVNETNS`,
CAP_NET_ADMIN и procfs namespace metadata, даже при `dns=off`. Несовпадение фактического
имени с настроенным отклоняется до этих изменений. Повторное связывание запрещено.
`dev_attach` по-прежнему не устанавливает и не очищает managed routes.

Все production cleanup callers передают исходный TunInterface. Общий алгоритм заново
проверяет namespace перед каждой командой, включая запросы, способные освободить запись
журнала. Для TUN-записей и обеих family flush дополнительно наблюдается исходный fd:
устройство должно оставаться в нужном namespace, с исходными именем и индексом.
Прежние ioctl-проверки берутся из общего TUN backend.
[Linux TUN ioctl](https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c).

Rename, detached fd, смена index, недоступные metadata/ioctl не дают права на команду.
Записи ownership/pending и ошибка сохраняются; новое поколение не присваивает остатки.
Это консервативный отказ: отсутствие устройства по сохранённому имени само по себе
не освобождает reservation. Если доказательства восстановлены, живой guard может повторить
очистку. После потери guard при неподтверждённом flush имя остаётся зарезервированным
до завершения процесса. На диске новый маршрутный журнал не появляется.

Физические bypass/blackhole очищаются независимо при доказанном namespace; потеря TUN
не прерывает весь цикл. Borrowed physical routes не приобретают delete authority.
Pending TUN-записи тоже не освобождаются по неподтверждённому снимку чужого интерфейса.
Проверки до/после удаления и прежние selectors/обработка lost completion сохранены.

## Проверки

**8 новых регрессий: FAIL на исходной логике → PASS после исправления.**
Baseline использовал тонкий тестовый адаптер, передающий управление исходному cleanup
и игнорирующий ещё не существовавшие identity callbacks. Командная модель и тела восьми
сценариев одинаковы; host не выполняет реальные сетевые команды. Добавлены ещё пять
контролей: повтор namespace-check перед физическим delete, потеря postcheck, независимое
освобождение physical pending, блокировка orphan name и сохранение borrowed route.

**1388 host unit + 52 editor/policy + 7 examples + 12 server INI = 1459 Rust tests PASS.**
Восемь baseline регрессий входят в итоговые 13 новых host tests, не прибавляются второй раз.
Один ignored host fixture — дочерний процесс DNS-lock, явно запускаемый его parent test.
Девять команд матрицы проходят; новых warning headlines и исключений Clippy нет.
Linux проверки — cross-compile, не runtime.

Три новых ignored native-теста используют реальные TUN/ip в свежем namespace отдельного
потока: rename + замена имени с независимым physical cleanup, delete + идентичный маршрут
замены, переход namespace + физический маршрут с теми же selectors и retry после возврата.
Без успешного unshare сетевые изменения не выполняются. Эти тесты **только скомпилированы**:

```bash
cargo test --manifest-path qeli/Cargo.toml --lib identity_linux_tests -- --ignored
```

Нужны Linux, CAP_SYS_ADMIN/CAP_NET_ADMIN, `/dev/net/tun` и `ip`.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/route-identity-audit-20260923.
Мануалы RU/EN и docs gate обновлены.

## Открытые границы

Проверка fd и команда iproute2 не атомарны. Привилегированный внешний rename/delete,
move или повторное использование имени/index после последней проверки всё ещё возможны.
Для устранения этой границы нужен отдельный дизайн операций через netlink и владения
маршрутами; простая замена имени на ifindex не создаёт kernel CAS. Identity физических
интерфейсов пока представлена прежними selectors, а не исходными descriptor/namespace
leases для каждого uplink. Общий flush по доказанному собственному TUN сохраняется.

Setup и roaming проверяют namespace при входе в operation, но не получили такую же
проверку TUN перед каждой мутацией. Address/up/gateway/firewall также требуют отдельного
прохода. Согласованность parser/backend имён пока обеспечена отказом при несовпадении,
а не поддержкой шаблонов и переименований. Namespace FD unresolved owner удерживает
ресурсы до освобождения reservation/процесса; registry не имеет постоянного crash recovery.
Ошибки route cleanup остаются частью прежней политики удержания kill-switch.

Следующие работы: setup/roaming и прочие команды по имени, identity resolver-сервиса/шины,
sysfs attach, физические uplinks, общий deadline, Q14-F027 и Linux E2E.
Native certification и новый benchmark не выполнялись. План: 37 разделов,
19 IN_PROGRESS, 18 TODO, полного PASS нет.

Продолжение: [Q25-F065–F066](AUDIT-Q25-SETUP-IDENTITY.md) переносит проверки в route
setup/roaming и перед прямыми managed MAC/address/up; gateway/firewall остаются отдельной задачей.

Продолжение: [Q25-F099](AUDIT-Q25-ROUTE-ATTRIBUTES.md) отделяет borrowing от ownership и проверяет неявные route attributes; прежнее сравнение только переданных полей больше не даёт права удалить изменённый физический маршрут.

Продолжение D04: [Q25-F100](AUDIT-Q25-ROUTE-JOURNAL.md) добавляет постоянное владение физическими маршрутами и recovery после аварии. Описанный здесь process-local контракт дополнен durable intent/confirmed state; неопределённые операции по-прежнему не дают права удалить маршрут.

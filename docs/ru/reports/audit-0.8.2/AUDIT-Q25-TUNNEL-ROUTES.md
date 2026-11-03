# Q25: единая установка TUN/TAP-маршрутов и удаление старых реализаций

Дата: 23 сентября 2026. Baseline: `d6b2c079`.
Q25-F037–F039 исправлены в описанных границах. Разделы 22/23/25 остаются **IN_PROGRESS**.

## Находки

**Q25-F037, P2 — активный TUN installer не подтверждал результат и терял ownership.**
`setup_network_plan_routes` применял connected pool, full-tunnel capture, записи
`NetworkPlan.routes` и connected-prefix overrides через `add_tunnel_route`.
Успешный exit code считался достаточным без post-query. При `File exists` проверялись
device/gateway, но не metric; для L3 TUN допускался существующий маршрут с `via`.
Установленные записи не попадали в общий журнал. Потеря результата add не закрывала
admission и не резервировала неизвестный остаток. CIDR проверялся только до слеша.

**Q25-F038, P3 — неподключённые клиентские реализации дублировали shared core.**
Call graph подтвердил отсутствие callers у `apply_local_networks` и
`apply_pushed_routes` вне их собственной цепочки. Локальный `PushedRoute` и второй
парсер оставались рядом с активным NetworkPlan. Они удалены вместе с неиспользуемыми
обёртками. Настоящий planner в `transport_core/network.rs` сохранён; его одноадресный
тестовый адаптер ограничен `cfg(test)`. Старые route-query helpers нужны только
историческим Linux fixtures и теперь также исключены из production.
Служебный формат передачи pushed routes не менялся; пользовательские конфиги остаются INI.

**Q25-F039, P2 — route_local молча пропускал повреждённый список адресов.**
Lossy UTF-8 и `continue` при неверной строке превращали ошибку inventory в пустой или
неполный список подключённых сетей. Нужные более специфичные tunnel routes могли не
появиться, хотя настройка завершалась успешно и physical connected route продолжал
определять путь в локальную сеть.

## Исправление

`install_initial_route` — общий установщик для физических bypass/blackhole и TUN/TAP.
До add он проверяет чужие ownership/pending и exact-снимок destination. Совпадающий
маршрут заимствуется без add/claim, конфликт или непригодный снимок запрещает запись.
После add проверка обязательна при любом результате команды. Только success вместе
с совпадающим снимком даёт запись ownership; отсутствие означает отказ без claim;
неизвестный остаток становится pending и закрывает owner.

Проверяются destination, интерфейс, ожидаемая метрика, gateway для TAP и отсутствие
gateway для прямого TUN. CIDR и семейство gateway проверяются до мутации.
Pushed/include/DNS/RFC1918 blanket уже находятся в `NetworkPlan.routes` и проходят
этот же installer; отдельный клиентский parser/application path больше не нужен.
Общий planner продолжает фильтровать недопустимые server pushes.

Учтено отображение метрик Linux: IPv4 не передаёт нулевой `RTA_PRIORITY` в dump,
поэтому отсутствие metric допускается только для явно ожидаемого IPv4 нуля.
[Linux IPv4 fib_dump_info](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_semantics.c).
IPv6 metric 0 преобразуется Linux в 1024; Qeli явно записывает это эффективное значение
в add и undo, не меняя прежний результат выбора ядра.
[Linux IPv6 route](https://github.com/torvalds/linux/blob/master/net/ipv6/route.c),
[IP6_RT_PRIO_USER](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ipv6_route.h).
Метка `default` принимается только для ожидаемого /0 соответствующей семьи запроса.

Cleanup удаляет доказанные записи по сохранённым selectors, затем отдельно выполняет
проверяемый flush принадлежащего owner интерфейса. Pending сам по себе не даёт права
`route del`. Его отсутствие теперь проверяется после flush: неопределённый TUN add,
убранный этой независимой очисткой, не оставляет ложную reservation.
Маршрут на другом интерфейсе flush не затрагивает; если destination остаётся или query
неуспешен, pending и ошибка сохраняются. Владение всем TUN/TAP существовало до этого
этапа; даже заимствованная запись на таком интерфейсе попадает под его общий flush.
`dev_attach` не вызывает setup этого NetworkPlan; чужой интерфейс этим не присваивается.

Inventory route_local теперь требует UTF-8 и корректные основные поля каждой непустой
строки: положительный index, непустое имя, `inet` и IPv4/prefix. Непригодная строка
останавливает setup до записи маршрутов. Адреса с host bits допустимы; сеть вычисляется
из prefix. Суффикс `@peer`, несколько адресов, дубли, пустой список, пропуск своего TUN
и сетей вне RFC1918 покрыты контролями. Это не полный parser всех атрибутов iproute2.

## Проверки

**8/8 регрессий FAIL на исходном production-коде → PASS после исправления.**
Затем ещё две регрессии inventory воспроизвели дефект прежнего parser: FAIL → PASS.
Тела первых восьми тестов сохранены; последующее форматирование не меняет проверок.
Всего **23 новых теста**: десять воспроизводящих и тринадцать положительных/защитных
контролей. Они исполняют production NetworkPlan setup/cleanup через изолированную
модель команд, без изменения сети хоста.

**1186 host unit + 52 editor/policy + 7 examples + 12 server INI = 1257 Rust tests PASS.**
Все девять команд матрицы PASS: host/config, Linux all-targets Clippy, client-only,
server-only, minimal FFI, client без roaming, compatibility без features, rustfmt.
Linux проверки — cross-compile, не runtime. Rust 1.98.0 и прежнее исключение Clippy
`chunks_exact_to_as_chunks`; новых исключений нет. RU/EN docs gate проходит.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/route-tunnel-audit-20260923.

## Границы и следующий проход

Shared core задаёт политику, Linux применяет план. Этот этап не переносит реализацию
OS-команд в кроссплатформенное ядро и не пересобирает поставляемые native cores.
Удалённые Linux Rust helpers не были C ABI/API панели; INI и сетевой протокол не менялись.

Снимки не создают атомарный kernel CAS и не доказывают авторство при внешней гонке.
Несколько exact-маршрутов отклоняются как неоднозначность; произвольные policy tables,
VRF и multipath не сертифицированы. Journal остаётся в памяти. Новые pre/post queries
увеличивают работу setup/cleanup; производительность не измерялась. Deadline 15 секунд
по-прежнему относится к отдельной команде, не ко всей операции под mutex.

Далее: полный gateway rollback, частичные изменения firewall/sysctl и изоляция globals;
проверка доказательств IPv6-защиты, Q14-F027 TUN workers/FD, общий preflight deadline,
Linux E2E restart/restore/manual+NDP, native certification и новый benchmark.
Полный аудит не завершён.

Предыдущий этап: [ограничения команд и IPv4-защита](AUDIT-Q25-CLIENT-COMMANDS.md).

Продолжение gateway: [откат по scope и проверки firewall](AUDIT-Q25-GATEWAY-ROLLBACK.md).

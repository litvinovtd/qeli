# Q25 — удержание namespace на время sysctl-транзакции

<!-- normative-sync: audit-q25-namespace-pin-v1 -->

Дата: 24 сентября 2026. База: `34b3af41`. Частичное закрытие D02
[реестра техдолга](../../plans/AUDIT-DEBT.md).

## Q25-F082, P2 — сохранённые номера не удерживали исходный namespace

Guard сравнивал dev/inode network, PID и time namespaces до и после I/O, но
сохранял только строки. Если последний владелец namespace исчезает, его номер
может быть переиспользован: равенство номеров перестаёт доказывать, что это
исходный объект. Проверка смены identity сама по себе не удерживала его.

Теперь `Context` открывает `/proc/thread-self/ns/{net,pid,time}` и сохраняет
дескрипторы. Identity берётся через metadata того же открытого fd. Захват
происходит до ожидания local/flock; дескрипторы живут до конца транзакции,
включая persist и обработку отказов. Каждая повторная проверка также читает
identity через открытый fd; временные handles освобождаются сразу после сравнения.
Отсутствие time namespace остаётся допустимым, прочие ошибки запрещают операцию.

Открытый namespace fd удерживает объект живым; CLOEXEC не позволяет передать его
запущенным командам. Это стандартный контракт
[namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html).
Production-код не вызывает setns, не возвращает поток в прежний namespace и
не продолжает уже отказавшую транзакцию. INI, ABI и journal v2 не меняются;
новые kernel ioctls/socket options не требуются.

## Проверки

Новая привилегированная Linux-регрессия в отдельном потоке создаёт namespace,
открывает production pin и покидает namespace последним участником. Через
сохранённый fd удаётся вернуться к тому же объекту; новый namespace имеет другую
identity. Проверяются CLOEXEC и EBADF после Drop. Тест выполняется в изолированном
namespace, последовательно с другими privileged tests. Он проверяет владение fd;
фактическое принудительное переиспользование namespace inode не воспроизводилось.

Все 9 host/feature/cross/lint-команд PASS: **1458 host unit + 71 config integration**.
Linux: **1922 обычных + 29 привилегированных + 8 worker lifecycle E2E PASS**.
Worker SHA256: `def5577ee4174e05b3ddcd1f40bb2b865580690f56797ba7d08a0e93036bbfa9`.

Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/namespace-pin-phase/`,
`namespace-pin-final.log`, `lifecycle-namespace-pin/`.

## Оставшиеся границы

Дескрипторы удерживают identity только в живой транзакции. Между отдельными
транзакциями и после crash journal v2 всё ещё содержит только dev/inode. Durable
namespace generation и исходное поколение интерфейса остаются открытыми D02.
Нельзя считать имя или ifindex интерфейса доказательством его непрерывной жизни,
а procfs inode — устойчивым идентификатором интерфейса. Эта фаза не заявляет
автоматическое безопасное восстановление после любого rename/delete/recreate.

[Guard внутренних I/O](AUDIT-Q25-SYSCTL-CONTEXT-IO.md) ·
[Каталог состояния](AUDIT-Q25-STATE-DIRECTORY.md)

Продолжение: [Q25-F083 — v3 и исходный sysctl fd](AUDIT-Q25-SYSCTL-TARGET.md). Исторические ограничения выше относятся к снимку этого отчёта; исчезновение имени больше не разрешает забыть original.

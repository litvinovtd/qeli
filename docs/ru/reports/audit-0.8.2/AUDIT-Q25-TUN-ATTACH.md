# Q25: attach без создания TUN и сохранение формата устройства

Дата: 23 сентября 2026. База: `e93d165c`.
Q25-F057–F058 исправлены в описанных пределах; разделы 14/21/25 остаются **IN_PROGRESS**.

## Подтверждённые проблемы

**Q25-F057, P2 — attach мог создать устройство вместо исчезнувшего.**
После проверки существования и чтения `tun_flags` внешний TUN мог исчезнуть.
Неэксклюзивный `TUNSETIFF` тогда создавал новый non-persistent интерфейс, хотя
`dev_attach` обещает заимствование. Тот же переход возможен при открытии следующей
multiqueue-очереди после удаления исходного устройства другим управляющим.

Общая последовательность открытия теперь перед каждым неэксклюзивным `TUNSETIFF`
выполняет `TUNSETIFINDEX` с индексом 1. Этот ioctl задаёт индекс только для создания;
для существующего TUN он не меняет index. В Linux индекс 1 постоянно занят loopback:
это закреплено в [flow.h](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/net/flow.h)
и проверяется в [loopback_net_init](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/loopback.c).
Ветви ioctl описаны в [tun.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/tun.c),
а повторная регистрация занятого индекса отклоняется в
[register_netdevice/dev_index_reserve](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/core/dev.c).

Таким образом, при отсутствии имени попытка создания не может зарегистрировать
подменный TUN. Открытый fd удерживает свой network namespace; имя loopback не используется,
поэтому его переименование не отменяет запрет. Это намеренное использование сочетания
существующих ioctl, а не отдельный kernel-флаг attach-only.

Ошибка `TUNSETIFINDEX` останавливает операцию до `TUNSETIFF`; fallback без защиты нет.
Эксклюзивное создание первой очереди не требует этого шага. Для `dev_attach` и второй/
последующих очередей теперь необходима поддержка `TUNSETIFINDEX` и разрешение его вызова.
Неподдерживаемое ядро или запрещающий ioctl sandbox дают явный отказ.
Для номера ioctl используется архитектурная константа libc.

**Q25-F058, P2 — attach допускал несовместимый формат и сбрасывал чужие features.**
Проверялся `IFF_NO_PI`, но не `IFF_VNET_HDR`. Устройство с virtio-заголовком могло
попасть в тракт обычных IP/Ethernet-пакетов. При первой очереди драйвер также может
перезаписать features из запрошенных флагов: прежний helper передавал только тип,
NO_PI и MQ, теряя ONE_QUEUE/NAPI/NAPI_FRAGS.

Проверка и parser перенесены из platform ioctl wrapper в общую тестируемую политику.
Virtio-заголовок и неизвестные bits отклоняются до открытия fd. Поддерживаемые
ONE_QUEUE/NAPI/NAPI_FRAGS сохраняются вместе с типом, NO_PI и MQ. Read-only PERSIST
не передаётся как запрашиваемый флаг; persistence-changing ioctl не вызывается.
Тип устройства и отсутствие packet-information header по-прежнему обязательны.
INI, API и FFI ABI не изменились.

## Проверки

**18 новых host-тестов** и один прежний parser-тест, теперь также выполняемый на Windows.
Baseline adapter прежней последовательности дал **6 FAIL / 4 PASS**. Шесть тел
сценариев неизменны после rustfmt. Четыре проверяют исчезновение при attach/добавлении
очереди, VNET_HDR и потерю features; два фиксируют новые требования отказа при
ошибке защиты и неизвестных flags. Это модели kernel contract и policy, не запуск
старых Linux ioctl на Windows. Модель не проверяет точный Linux errno.

**1354 host unit + 52 editor/policy + 7 examples + 12 server INI = 1425 Rust tests PASS.**
Девять команд основной матрицы PASS, дополнительная Linux no-features test compilation
PASS. Прежнее исключение `chunks_exact_to_as_chunks` сохранено; новых warning headlines
в основной матрице нет.

Три новых Linux-only теста используют реальные ioctl на отдельном OS-потоке после
успешного `unshare(CLONE_NEWNET)`. Они проверяют отказ создания при attach, заимствование
существующего устройства и multiqueue/закрытие последнего fd. Первый сценарий сначала
проверяет способность создать контрольный TUN, чтобы отсутствие `/dev/net/tun` или прав
не давало ложного PASS. Эти тесты **скомпилированы, но не исполнены**; по умолчанию ignored.
На подготовленном Linux-хосте с CAP_SYS_ADMIN/CAP_NET_ADMIN и `/dev/net/tun`:

```bash
cargo test --manifest-path qeli/Cargo.toml --lib tun::iface::linux_tests -- --ignored
```

Тесты не меняют исходный network namespace; недоступная изоляция означает ошибку,
а не пропуск. Они не проверяют всю публичную цепочку attach через sysfs.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/tun-attach-audit-20260923.

## Границы и следующий этап

Запрет регистрации отсутствующего устройства не доказывает identity уже существующего
устройства с тем же именем. Замена/переименование между проверками, изменение features
внешним владельцем и sysfs другого namespace остаются открыты.
Внешний менеджер должен держать устройство и его формат стабильными во время attach.

Проверка cleanup выявила оставшиеся операции по имени: `TunInterface::delete` через
`ip tuntap del` вызывается клиентскими guards и серверным teardown. Она повторно
открывает имя и не доказывает identity исходного устройства. Независимые route flush
и DNS cleanup также требуют отдельной проверки. Этот проход их не меняет.
Далее: владение fd и освобождение устройства, привязка route/DNS cleanup к его lifetime,
единый контракт имён parser/backend, затем остальные namespace/journal/deadline пункты.

Полный Linux E2E, старые/минимальные ядра, OpenWrt, native certification и новый benchmark
не выполнялись. 37 разделов плана: 19 IN_PROGRESS, 18 TODO, полного PASS пока нет.

Продолжение: [Q25-F059–F060](AUDIT-Q25-TUN-LIFETIME.md) удаляет очистку TUN по имени и сохраняет исходные дескрипторы до конца cleanup. Identity DNS/маршрутов при внешней подмене и таймаут workers остаются открыты.

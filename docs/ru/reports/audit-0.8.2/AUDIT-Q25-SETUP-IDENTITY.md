# Q25: проверка владельца при setup и roaming

Дата: 23 сентября 2026. Baseline: `0157dab6`.
Q25-F065–F066 исправлены в описанных границах; разделы 21/22/25 остаются **IN_PROGRESS**.

## Находки

**Q25-F065, P2 — установка маршрутов не проверяла исходный TUN перед командами.**
После однократного bind интерфейс мог быть переименован/удалён внешним менеджером,
а сохранённое имя — занято заменой. Initial installer проверял destination/selectors,
но не связь имени с исходным fd. Это позволяло установить TUN-маршрут на замену или
продолжать физические bypass/blackhole для уже потерянного туннеля. Аналогичный разрыв
был перед MAC/address/up в managed setup. Проверки из предыдущего этапа действовали
в cleanup и сами по себе не защищали установку.

**Q25-F066, P2 — roaming не связывал команды и результат с живым исходным TUN.**
RouteOwner удерживал generation/namespace, но не давал prepared path доступ к исходному
устройству. Команды prepare/add/replace/retire/FIB продолжались при потере TUN; успешный
откат физических маршрутов сам по себе не доказывал пригодность поколения. Между входной
проверкой и route transaction также вызывался `refresh_platform`: изменение namespace
в callback не проверялось повторно. Обычный gateway callback сейчас не вызывает setns;
этот namespace-сценарий проверяет контракт внутреннего callback, а не утверждает, что
штатный reconnect сам переносит namespace.

## Исправление

Исходный TunInterface находится в Arc на прежний срок жизни setup/TunGuard. При bind
RouteOwner получает Weak на этот объект вместе с его index. Weak не держит fd открытым,
не продлевает жизнь устройства через prepared path/orphan journal и не создаёт новую
TUN-очередь. Утрата владельца исходного объекта не заменяется поиском устройства по имени.

Перед каждой активной маршрутной командой setup/prepare/commit проверяются удерживаемый
namespace, исходный fd, его имя и index. Это охватывает физический route lookup, initial
pre/add/post-query, кандидатские add/replace, retirement и FIB-проверки. Inventory для
route_local тоже получает входную проверку. Непосредственные MAC/address/up проверяются
перед каждым вызовом; финальная проверка предшествует публикации успешного managed setup.
Диагностический hook lookup и исторические IPv4 fixtures не стали мутациями сетевого плана.

Отдельные physical rollback/restore команды требуют исходный namespace, но допускают
потерянный TUN: подтверждённые собственные физические записи можно удалить/восстановить
независимо. При потере namespace такие команды не выполняются. Прежние selectors,
ownership, borrowed routes, pending reservations и проверки результата сохранены;
неопределённая установка не становится собственностью Qeli.

Потеря identity фиксируется на весь срок жизни RouteOwner и закрывает admission.
Возврат имени/namespace не разрешает продолжать установку того же поколения. Cleanup
по-прежнему может повторять допустимые действия и освобождать подтверждённые остатки.
Roaming возвращает `RouteCommitStateUnknown` при потере identity, включая отказ на входе
и случай успешного physical rollback. Проверки идут до/после platform callback и перед
успешным завершением commit. При потере доказательств в последнем FIB-query также
выполняется доступный откат вместо подтверждения commit.

Удалена ненужная обёртка удаления маршрута без явного checked executor. Пользовательский
INI, C ABI, DNS API и серверные routing modes не изменялись. Gateway/firewall внутри
callback не получили per-command identity checks этим изменением.

## Проверки

**7 регрессий: FAIL на исходной production-логике → PASS после исправления.**
Baseline добавлял только явные synthetic evidence fixtures, которые старый код не читал.
Командная модель и тела семи сценариев сохранены. Ещё шесть контролей проверяют
namespace mismatch на входе, запрет оживления поколения, восстановление прежнего
physical route после replace, потерю TUN во время последнего FIB query, успешную
установку обеих семей и сохранение borrowed carrier без claim.

**1401 host unit + 52 editor/policy + 7 examples + 12 server INI = 1472 Rust tests PASS.**
13 новых host tests входят в эту сумму. Старые командные fixtures теперь явно создают
synthetic owner; production `new` и native-тесты такого разрешения не получают.
Один ignored host fixture — DNS-lock child, явно запускаемый parent test.
Девять команд матрицы и Linux no-default-features tests compilation проходят; новых
warning headlines и исключений Clippy нет. RU/EN docs gate проходит.

Добавлены четыре ignored native-сценария: отказ route add после rename; освобождение
TUN при живом RouteOwner и отказ на замене; запрет setup для unbound owner; смена
namespace внутри roaming callback. Вместе с тремя предыдущими в модуле семь проверок:

```bash
cargo test --manifest-path qeli/Cargo.toml --lib identity_linux_tests -- --ignored
```

Нужны Linux, CAP_SYS_ADMIN/CAP_NET_ADMIN, `/dev/net/tun`, `ip`. Тесты сначала переходят
в свежий namespace отдельного потока. Здесь они **только скомпилированы**, как и прежние
семь TUN ioctl-тестов. Изменений сети Windows-хоста не выполнялось.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/route-setup-identity-audit-20260923.

## Границы и следующий проход

Проверка fd и последующая iproute2-команда не атомарны. Внешние privileged rename/delete/
move/reuse после последнего наблюдения остаются возможны. Числовой ifindex сам по себе
не даёт kernel CAS. Физические uplinks всё ещё идентифицируются прежними selectors.

Gateway/firewall/sysctl setup и rollback, внутренности refresh callback, kill-switch
refresh и внешние hooks требуют отдельного прохода ownership. Ранний route identity
отказ не делает безопасным весь чужой callback. Attach и серверный setup не переведены
на эти проверки MAC/address/up. Procfs/sysfs trust, согласованность имён parser/backend,
resolver service/bus namespace, общий deadline и постоянный crash recovery остаются
открытыми. Q14-F027 workers/FD, Linux E2E, native certification и новый benchmark
не закрыты. План: 37 разделов, 19 IN_PROGRESS, 18 TODO, полного PASS нет.

Продолжение: [Q25-F067–F068](AUDIT-Q25-GATEWAY-IDENTITY.md) добавляет собственные проверки gateway и cleanup до закрытия TUN; внутренний sysctl journal остаётся отдельной задачей.

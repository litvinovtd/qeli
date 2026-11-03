# Q25: владение gateway при setup, roaming и cleanup

Дата: 24 сентября 2026. Baseline: `ac86c442` (этап начат 23 сентября).
Q25-F067–F068 исправлены в описанных границах. Разделы 21/22/25 остаются **IN_PROGRESS**.

## Находки

**Q25-F067, P2 — gateway продолжал команды после потери исходного TUN/namespace.**
Проверки маршрутов до/после roaming callback не защищали операции внутри него.
Gateway/exit-node принимали только имя: после внешнего rename/delete или смены namespace
они могли продолжить установку правил и sysctl. В частности, потеря identity во время
best-effort MSS/rp_filter не превращала успешный ответ gateway в ошибку. Это относится
также к начальному setup обеих семей. Штатный callback не вызывает setns; fault injection
проверяет поведение при изменении окружения, а не утверждает наличие штатного setns.

**Q25-F068, P2 — cleanup gateway не был связан с поколением и сроком жизни TUN.**
Правила и sysctl жили через полный reconnect; терминальная очистка по имени выполнялась
после завершения сессии и освобождения её TUN. Она не проверяла исходный namespace,
а восстановление per-interface sysctl могло адресовать другое устройство с тем же именем.
Успешная очистка маршрутов сама по себе не удерживала поколение для оставшихся router-ресурсов.

## Исправление

Gateway регистрирует исходный RouteOwner перед первым собственным изменением. Реестр
удерживает generation/namespace до подтверждённой очистки; Weak на TUN не продлевает
жизнь fd. Новый владелец с тем же именем не допускается при незавершённой очистке.
Частичный setup и TunGuard очищают только совпадающего владельца; терминальный retry
по имени использует сохранённое владение. Без записи cleanup ничего не удаляет.

Активные gateway/exit операции проверяют исходный TUN, имя/index, удерживаемый namespace
и admission поколения перед/после каждого firewall query/mutation и WAN lookup. Sysctl
проверяется на входе/выходе вызова общего журнала, а не перед каждым его внутренним I/O.
Финальная проверка не позволяет best-effort MSS/rp_filter скрыть потерю identity.
Начало cleanup закрывает admission; возвращение окружения разрешает cleanup, но не setup.

Удаление сохранённых tagged gateway/exit правил требует исходный namespace перед/после
каждой команды и допускает потерю TUN. Неопределённые/неочищенные семейства сохраняются
для повторной проверки. При потере TUN восстановление всей sysctl scope откладывается,
включая общие forwarding/rp_filter: общий журнал содержит также per-interface значения,
и безопасно восстановить их по одному имени нельзя. Это консервативный отказ, а не
автоматическое восстановление всех настроек хоста.

TCP/UDP graceful cleanup, аварийный TunGuard и rollback частичного плана теперь очищают
router-состояние до закрытия исходного fd. Полный reconnect создаёт новое владение и
устанавливает правила заново. Roaming в рамках поколения сохраняет старые WAN-правила
до его завершения. Включённый kill-switch продолжает жить через reconnect по прежнему
контракту. Ошибки cleanup остаются sticky и препятствуют успешному завершению/reconnect.
`dev_attach=true` с router-функциями тоже связывает исходный fd; адреса/маршруты внешнего
владельца не становятся собственностью Qeli. Без router-функций attach не требует такого bind.

## Проверки

Девять регрессий на отдельной копии `ac86c442` воспроизводят ошибки (**9 FAIL**),
после изменения проходят (**9 PASS**). Адаптер baseline добавляет только fault injection,
инертную synthetic evidence и Result-обёртку прежнего void rp_filter API; он не меняет
решения firewall/sysctl. Проверены входной отказ, потери identity после query/sysctl/MSS,
WAN lookup при roaming, namespace при cleanup до/после удаления и независимая очистка
правил при потерянном TUN с сохранением sysctl.

Ещё четыре теста используют настоящий RouteOwner с явно synthetic TUN evidence:
unbound production owner отказывает; reservation переживает вызывающего и освобождается
после cleanup; неудачный cleanup удерживает поколение; остановленное поколение не
разрешает setup, но допускает cleanup. Production не получает тестового разрешения.

**1414 host unit + 52 editor/policy + 7 examples + 12 server INI = 1485 Rust tests PASS.**
13 новых host tests входят в эту сумму. Один ignored fixture — DNS-lock child, явно
запускаемый parent test. Девять команд матрицы и Linux no-default-features tests compilation
проверены отдельно; существующее исключение Clippy не расширялось. RU/EN docs gate PASS.

Linux E2E не выполнялся. Предыдущие семь native route identity и семь TUN ioctl tests
здесь только скомпилированы. Реальные firewall/sysctl/namespace сценарии и поведение
при физическом reconnect ещё требуют изолированного Linux-стенда. Benchmark не запускался.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/gateway-identity-audit-20260923.

## Пределы и следующий проход

Проверка и внешняя команда не атомарны. Rename/delete/move/reuse после последнего
наблюдения остаются возможны. Для sysctl окно включает ожидание общего journal lock
и внутренние read/prune/write: этот этап не переделывает общий sysctl backend, его
crash recovery или идентификацию физических WAN. После смерти процесса stale journal
и остатки firewall требуют отдельного анализа; не считать их защищёнными этим реестром.

Реестр gateway находится в памяти, не является durable journal и удерживает namespace
до cleanup/завершения процесса. Нельзя освобождать reservation или удалять sysctls.state
просто для обхода ошибки. Сначала нужно установить владельцев и фактическое состояние.
При потере исходного TUN оставшиеся общие sysctl могут оставаться включёнными.

Следующий проход: внутренние операции sysctl (включая stale owners, namespace и
переиспользование имён), затем самостоятельный kill-switch lifecycle. Resolver service/bus,
procfs/sysfs trust, имена parser/backend, deadlines, динамический IPv6, DNS/carrier globals,
Q14-F027 workers/FD, native certification и новый benchmark остаются открытыми.
План: 37 разделов, 19 IN_PROGRESS, 18 TODO, полного PASS нет.

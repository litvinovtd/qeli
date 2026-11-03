# Q25-F204 — ресурсный churn Linux worker

<!-- normative-sync: audit-q25-worker-resource-churn-v2 -->

Дата: 1 октября 2026. Текущий Rust-исходник, ранее синхронизированный на
лабу .11; `cargo build --offline --locked --bin qeli` с
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=1` завершился PASS.
Проверенный debug binary SHA-256:
`ae59962eebe483ad4d312bda34cb5634bf66bcd2ca372869b17b15e8c95e66d9`.
Полный `qeli/src`: 308 файлов, одинаковый digest
`64be415e454438fe2b90129168069e0be9a9caf4a7a467bca24398fd4a6250aa`
в checkout и на .11.

Существующий `scripts/audit_worker_lifecycle.py` получил ограниченный
`--resource-reloads 10`. Каждый кейс выполняется в новых network,
mount и PID namespaces с приватно примонтированным `/etc/qeli`.
После готовности worker проверяется отказ второго владельца и
отвергнутый повреждённый SIGHUP; затем выполняются 10 корректных
SIGHUP с контрольным запросом между ними. Снимки `/proc/<pid>/fd`,
socket fd, `task` и `VmRSS` сохраняются до и после каждого reload.
Заранее заданный критерий: финальный прирост fd/socket fd/tasks не
более 2, максимальный sampled RSS не более +32 МиБ. После SIGTERM
сверяются TUN, routes, firewall, sysctl, control socket и journal.

| Режимы | Результат | Δ fd/socket/tasks | Максимальный Δ RSS |
|---|---:|---:|---:|
| TCP: off/manual/route/nat66 | 4/4 PASS | 0/0/0 во всех | 15 520 КиБ |
| UDP: off/manual/route/nat66 | 4/4 PASS | 0/0/0 во всех | 15 472 КиБ |

Всего **8/8 кейсов и 80 корректных reload PASS**; все восемь
отказов второго worker и восемь повреждённых reload сохранили
действующий worker. После каждой остановки контрольный сокет,
TUN, правила Qeli и `sysctls.state` отсутствуют; полные снимки
сетевых объектов до/после совпали по установленным проверкам.
Верхняя граница RSS — sampled peak, не непрерывный пик между пробами.
`py_compile` и `git diff --check` прошли.

Raw evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/d13-resource-20261001/`
(`results.json`, 8 × `resource-samples.json`, network-before/after,
активные firewall dumps и worker logs). Identity-ключи не копировались
из изолированного стенда.

## TCP same-session churn и строгий `rp_filter`

При первом прогоне текущего Linux-клиента с настройкой стенда
`net.ipv4.conf.all.rp_filter=1` запасной путь не принимал ответы:
старый маршрут `/32` к серверу оставался на A до COMMIT, а ответ нового
carrier приходил через B. Изолированное изменение только
`net.ipv4.conf.qrm-b.rp_filter=2` подтвердило причину: handover прошёл.
Клиент теперь получает управляемый lease на интерфейс IPv4-кандидата
при PREPARE и освобождает его при COMMIT/ABORT. Исходное значение и
запись журнала восстановлены; глобальный sysctl не меняется. Preflight
стенда временно проверяет B с loose-фильтром и возвращает исходный
строгий режим **до** запуска клиента, поэтому тест не маскирует фикс.

Первый 100-кратный debug soak подтвердил все 100 COMMIT и отсутствие
orphan/sockets, но честно сохранил FAIL: клиентский fd вырос 18→26,
серверный RSS — на 54 216 КиБ. Длинный lease интерфейса создавал
лишние fd; после ограничения его срока до COMMIT/ABORT точная релизная
сборка с обязательным `jemalloc` прошла критерии. Debug RSS нельзя
подменять показателем релизного аллокатора.

Финальный `qeli/src`: **308 файлов**, совпадающий digest
`f3626d47535f5cb73286adcd2e50de7ab88f466158b291fbfc22947045cda124`.
`cargo build --offline --locked --release --features jemalloc --bin qeli` PASS;
release SHA-256 `a526c03bf0bae927828e91f11ac5d751c3a82e560a7f12ada3a6ab6b410cedb0`.
Точный бинарник дал **20/20** в single handover и **16/16** в
100-кратном TCP fake-tls soak. Сохранились одна сессия, исходные
процессы/TUN и 100 клиентских/серверных COMMIT; orphan=0,
повторного AUTH нет. Клиентские fd 18→18, socket fd 6→6,
RSS 51 712→54 104 КиБ (sampled peak +2 524 КиБ).
Серверные fd 21→21, socket fd 7→7,
RSS 52 100→56 764 КиБ (sampled peak +4 664 КиБ).
Все значения меньше фиксированного лимита +32 МиБ RSS и порогов fd.
`cargo fmt --all -- --check` PASS. Полный `cargo test --offline --locked --lib`
с исходным лабораторным soft limit 1024 fd дал 2237 PASS / 1 FAIL (`EMFILE`):
DNS capacity test одновременно держит 512 клиентских и 512 серверных
TCP-сокетов. При soft limit 4096 и `--test-threads=2` тот же набор
**2238 PASS / 0 FAIL** (59 ignored); оба полных лога сохранены.
После сценариев namespace/test listeners/processes отсутствовали;
`qeli-server.service` на .10 остался active на :443.

Raw evidence в том же каталоге: `qeli-d13-product-rpf2.log`,
`qeli-d13-product-soak100.log` (debug FAIL),
`qeli-d13-final-success.log`, `qeli-d13-final-soak100.log`,
`qeli-d13-fmt.log`, `qeli-d13-unit.log` и `qeli-d13-unit-fd4096.log`.

## UDP same-session и многопрофильный stop/fault

На том же release binary `a526c03b` UDP QUIC выполнил **100/100**
COMMIT одной сессии: **17/17** проверок PASS. Исходные клиентский и
серверный процессы/TUN остались теми же, AUTH не повторился, кандидаты
и CID не накапливались. Клиентские fd 18→19, socket fd 6→7,
RSS 51 532→60 660 КиБ (sampled peak +13 048 КиБ); серверные fd 21→21,
socket fd 7→7, RSS 59 792→74 728 КиБ (sampled peak +14 936 КиБ).
Оба пика ниже заранее заданного лимита +32 МиБ. После COMMIT оба
`rp_filter` вернулись к исходному строгому значению 1, а lease исчез
из журнала. Первый прогон сохранился как **FAIL 14/15** только из-за
ошибочной проверки пути B: она использовала исходный адрес B при
действующем default на A и строгом reverse-path filter. Исправленный
preflight временно использует совместимый фильтр и `ping -I qru-b`,
возвращает исходный фильтр **до** запуска Qeli. Продукт не менялся.

Новый `scripts/audit_worker_multiprofile_resource.py` изолирует
network/mount/PID namespaces и проверяет два одновременно работающих
профиля: TCP `alpha` и UDP `beta`. **14/14** утверждений PASS:
повреждённый SIGHUP сохранил оба профиля, 10 корректных reload
сохранили fd/socket/tasks 26/11/7→26/11/7 и sampled peak RSS
54 224→54 352 КиБ (+128 КиБ). Штатная остановка выполнила оба
`post_down` ровно по одному разу и восстановила исходные firewall,
routes, links, forwarding, control socket и journal. После SIGKILL
журнал и правила обоих профилей остались для recovery; запуск только
`alpha` удалил осиротевшие правила/устройство удалённого `beta`, а
следующая штатная остановка снова восстановила исходный снимок.
Первый вариант этого нового теста ложно определял готовность второго
запуска по старому файлу hook; исправлено ожиданием новой записи `up`.

Три других UDP wire mode на том же бинарнике проверены по 20 переходов:
`fake-tls`, `obfs` и `obfs-awg` — каждый **17/17 PASS**. Во всех
случаях одна сессия и исходные процессы/TUN сохранились, счётчики
COMMIT совпали с 20, fd/socket не накапливались, `rp_filter` и sysctl
lease восстановились. Максимальный sampled RSS прирост среди этих
трёх прогонов — +12 428 КиБ на сервере и +5 660 КиБ на клиенте.
Это ограниченные 20-переходные проверки адаптеров, а не 100-переходный
endurance для каждого из них.

D13 **DONE** в доступном Linux-объёме: bounded worker reload/stop,
TCP и UDP same-session churn, двухпрофильный SIGKILL/recovery и
восстановление сетевых объектов уложились в записанные критерии.
Непрерывный пик RSS между пробами и недоступные платформенные runtime
этим результатом не утверждаются.

Raw evidence: `udp-quic-100.log` (первый стендовый FAIL),
`udp-quic-100-fixed.log`, `multi-profile.log` (ранний false-ready FAIL),
`multi-profile-02.log` и `multi-profile-02/` (14 результатов, снимки,
ресурсные измерения и журналы). Ранее выполненные 100 release handover
на `ea87fd49` сохранены отдельно и не подменяют текущий результат.

[Реестр техдолга](../../plans/AUDIT-DEBT.md) ·
[Прежний release soak](AUDIT-Q34-RELEASE-SOAK.md)

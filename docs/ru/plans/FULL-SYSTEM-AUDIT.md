# Полный аудит Qeli: история проверок и пошаговый тестовый план

> Ранее снятые с публикации замеры разработки 0.8.2 и их сравнения сохраняются локально для аудита и не возвращаются в качестве бенчмарка релиза. Новые датированные [снимки Linux](../reports/LINUX-LAB-0.8.2-2026-10-17.md) и [результаты N04](../reports/TUN-N04-0.8.2-2026-10-19.md) включены в документацию отдельно: каждый сохраняет идентификатор проверенного ELF, методику и границы применимости. Они не описывают все платформы или любой последующий бинарник; статусы инженерных проверок сами по себе не являются бенчмарком.

**Текущий итог, 15 октября: 37/37 разделов аудита завершено в согласованном объёме (100%). Q29 закрыт после явного принятия пользователем generic/null DnsResolver ENONET на проверенном API34-образе как документированного ограничения; этот FAIL не исправлен и не переименован в PASS. [Решение Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md), [критерии](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md). Q31/Q34 закрыты по ранее подтверждённым критериям. Secure VPN, системный kill switch, D06 и границы физических платформ сохранены. Исторические checkpoint-записи ниже не являются текущим остатком.**


**Исторический снимок на 3 октября:** [реестр техдолга](AUDIT-DEBT.md) завершён: 14 DONE
и D06 ACCEPTED_LIMITATION по решению пользователя. Полный аудит возобновляется;
статусы 37 разделов ниже сверяются по критериям, без автоматического PASS.

**Режим завершения с 25 сентября:** [четыре пакета и правила выбора проверок](AUDIT-DEBT.md)
заменяют повтор полного набора на каждую правку. Уровни ниже остаются критериями
покрытия раздела; отдельный отчёт на каждый небольшой шаг не обязателен. Новые
некритичные гипотезы ждут полного аудита, текущие обязательства сохраняются.

<!-- normative-sync: full-system-audit-v278 -->

**15 октября, политика Android:** отдельный DNS bypass-режим отклонён пользователем; сохраняются secure VpnService и системный kill switch. [Решение и границы DNS](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md). Generic/null ENONET на проверенном API34 не объявлен исправленным. Отменённый режим не является новым техдолгом; общий итог — 37/37 (100%).

**Исторический checkpoint Q34, 14 октября, iOS:** finite-number MDM source fix, исправлен тест export/validate roaming и подготовлен signed simulator CI с проверкой effective Keychain entitlements.17 portable methods,32 native DTO requests и5 shell fixtures PASS; свежие Swift/Keychain/Apple CI НЕ запускались. См. [отчёт](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md).

**Исторический checkpoint Q34, 14 октября:** гонка Unix helper сервисного ключа исправлена и воспроизведена старым кодом;28 Windows/Linux checks PASS, daemon/self-test используют общий Mac RENAME_EXCL. Apple/current hosted runtime не подтверждён; iOS failures и public source pin остаются открыты. См. [отчёт](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md).


Дата инвентаризации: **22 сентября 2026**. База: ветка `dev`, commit
`fc6f4a5dc8df7f119f2d99a6b72b08916ae7a268`, разработка **0.8.2**.
Рабочее дерево до этой документации было чистым. Предыдущие исправления панели и
`manual + NDP` уже находятся в истории Git. Код продукта в этом этапе не изменялся.

Цель — последовательно проверить все системы Qeli на функциональные ошибки,
небезопасные границы доверия, гонки, утечки ресурсов/трафика, несогласованность
платформ, мёртвый код и расхождения документации. Это исполнимый план нового цикла,
а не заявление, что все системы уже прошли аудит.

## 1. Что удалось восстановить по памяти

Использованы история этой задачи, релевантные задачи «аудит» и «ipv6», локальная
память Qeli, сохранённые отчёты, Git и текущая структура исходников. Старые записи
могут относиться к удалённым реализациям; отметка «исправлено» в памяти не закрывает
регрессию на текущем commit. Независимый внешний криптоаудит этим не подтверждается.

| Источник | Период и восстановленное покрытие | Доказательство и предел |
|---|---|---|
| H01 | 10–12 июня: crypto/KDF/replay, handshake/framing, auth/Argon2, users/sessions, Win storage, DNS/kill switch и INI | [Аудит 10 июня](../archive/audits/AUDIT-2026-06-10.md), [11 июня](../archive/audits/AUDIT-2026-06-11.md), [12 июня](../archive/audits/AUDIT-2026-06-12.md); исторические версии |
| H02 | 18 июня — 5 июля: панель/CSRF, SSRF notify, DNS/DHCP, supervisor/control, NAT cleanup, obfs/WS/AWG и serializers | Память Qeli и [сводка 5 июля](../../archive/audits/AUDIT-FIXES-2026-07-05.md); отдельные старые подозрения были опровергнуты |
| H03 | 11–12 июля: trust boundary hooks/restore/client-save, session teardown, quota/iroute, clients и backup | Запись `project_qeli_audit_2026-07-11.md`; исторические fixes/build gates, не свежий E2E |
| H04 | 23–27 июля: core/data plane, UDP auth/HOL, pool races, max_clients, NAT tags, routes, парсеры, все клиенты и supply chain | Память core/client audits 24/25 июля и [сводка 27 июля](../../archive/audits/AUDIT-2026-07-27-FIXES.md); часть платформенных проверок была compile-only |
| H05 | 4 августа: общий аудит core, клиентов, панели и scripts | Запись `project_qeli_audit_2026-08-04.md`; перечень исторических кандидатов, не реестр текущих дефектов |
| H06 | Август–сентябрь: IPv6/TAP/NetworkPlan/PMTU/DATA_FRAG, roaming/CONTROL_V2, native/core parity | [План IPv6](IPV6-IMPLEMENTATION-PLAN.md), [роуминг](ROAMING.md), [transport core](../reference/TRANSPORT-CORE.md), `docs/data/validation/ipv6_lab_matrix_dev.json`; применимость evidence к текущему SHA перепроверяется |
| H07 | 26 августа — 1 сентября: REALITY/H2 PCAP, обнаружимость и throughput/CPU/RSS | [DPI](../reports/DPI-AUDIT.md), [сравнительный бенчмарк](../reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md); измерения 0.8.0, не 0.8.2 |
| H08 | 16 сентября: общий многослойный аудит A01–A14 и fixes | Локальные `audit-vpn-20260916/AUDIT.md` и `FIX-VERIFICATION.md`; Rust/managed builds, probes и Linux tests; не физические платформенные E2E |
| H09 | 16–17 сентября: углублённый аудит панели/парсеров A01–A14 | Локальные `audit-panel-20260916/AUDIT.md`, `panel-fixes-20260917/RESULT.md`; Rust/JS probes, сохранение, ACL-поля, секреты, черновики и INI roundtrip |
| H10 | 22 сентября: продолжение панели A15–A22 | Локальные `audit-panel-20260922/AUDIT.md`, `panel-fixes-20260922/RESULT.md`; restart/preflight, staged restore, share transaction, quotes/dev, notify INI; commit `a8c5050b` |
| H11 | 22 сентября: IPv6 manual/NDP и документация | Локальный `ipv6-manual-20260922/RESULT.md`; commit `fc6f4a5d`; 632 portable Rust tests, 25 JS groups, 16 isolated runtime probes; без настоящего Linux NDP/firewall E2E |

Локальные отчёты H08–H11 лежат вне репозитория; их имена оставлены для поиска в
рабочем архиве. Секреты и адреса лабораторных/рабочих серверов сюда не переносятся.
Номера **A01–A14 повторно использованы в двух разных аудитах**: ссылка на находку
обязана включать H08 или H09. Числа тестов разных feature/OS-наборов не складываются
и не сравниваются как показатель роста или уменьшения покрытия.

## 2. Правила нового прохода

У каждого раздела две независимые оценки: **историческое покрытие** и **новый прогон**.
Состояния нового прогона: `TODO`, `IN_PROGRESS`, `PASS`, `FAIL`, `BLOCKED`, `N/A`.
`BLOCKED` требует причины и нужного стенда; `N/A` — подтверждённой неприменимости.
Отсутствующий runtime не превращает проверку в `PASS`. Исправленная находка закрывается
после проверки исправления; нерешённая находка остаётся в очереди независимо от других PASS.

Каждый раздел проходит одни и те же уровни:

1. **Структура:** входы/выходы, владелец состояния, зависимости, trust boundaries и все
   callers; OS/feature gates, FFI/reflection/generated code и потенциально мёртвые ветви.
2. **Контракт:** штатные сценарии, границы, malformed input, defaults и сохранение смысла;
   differential/roundtrip проверки независимыми реализациями.
3. **Отказы:** failure injection при acquire/apply/save, partial I/O, concurrent actions,
   timeout/cancel/crash/restart и корректное восстановление владельцем ресурса.
4. **Интеграция:** настоящий процесс/API/browser/TUN/firewall/OS adapter, затем реальные
   устройства, если поведение зависит от драйвера, ОС или мобильной сети.
5. **Регрессия:** воспроизводитель на исходном дефекте, исправление, повтор затронутых
   проверок, документация и фиксация результата с точным SHA/feature/target.

Для каждого шага нужен отчёт: ID, дата, commit + dirty diff/hash, версии инструментов,
OS/arch/features, команда, fixtures/seed, ожидаемый/фактический результат, stdout/stderr,
exit code, PCAP/host-state при необходимости, finding ID/severity и ограничения.
Гипотеза отделяется от воспроизведённого бага; accepted risk имеет обоснование.
Долгие тесты получают timeout и план остановки; утечки измеряются, а не оцениваются по UI.

До запуска старого lab/E2E-скрипта проверить target, hardcoded endpoints, cleanup,
credentials handling и destructive defaults. Наличие файла теста ниже означает
**точку входа для проверки обвязки**, а не готовый безопасный набор или доказанное
покрытие всех перечисленных сценариев. Результат теста самого harness не равен E2E.
Сетевые/разрушительные сценарии выполняются на отдельном стенде со снимком, не на prod.

## 3. Стенды и обязательная матрица

| Стенд | Назначение |
|---|---|
| Локальный portable | Parser/crypto/protocol/KAT, JS state, Python harness, docs; не Linux server runtime |
| Изолированный Linux | Server/CLI/API/backup/systemd/TUN/routes/DNS/NAT/NDP; iptables и nft/firewalld, multiprofile, crash recovery |
| Windows VM | GUI/LocalSystem/Wintun/WinDivert/ACL/DPAPI, реальные DNS/routes/firewall и восстановление |
| macOS Intel + ARM | launchd/utun/pf/Keychain/Network Extension/per-app; build отдельно от runtime |
| Android устройство | Release APK/JNI/VpnService, Wi-Fi/LTE/Doze/always-on/lockdown, sleep/wake |
| iOS устройство | Signed IPA/PacketTunnel/On Demand/NAT64/per-app/MDM; simulator отдельно |
| OpenWrt/Keenetic | MIPS/ARM и 32-bit ABI, init/UCI/LuCI, реальная сеть и ограниченная память |
| Нагрузочный стенд | Контролируемые bandwidth/RTT/jitter/loss/reorder/MTU, отдельные генератор и наблюдатель |

Сначала составить список **реально поддерживаемых** transport × obfuscation сочетаний
из кода: Quick Start не является полным списком protocol capabilities. Неподдерживаемые
сочетания проверять на понятный отказ, не записывать как недостающий PASS.
Для каждого поддерживаемого режима: соединение/auth, трафик вверх/вниз, DNS,
reconnect и stop/cleanup. Дополнительные оси:

- outer IPv4/IPv6 × inner IPv4/IPv6/dual; IPv6-only uplink/NAT64;
- full/split, TUN/TAP, client-to-client/site-to-site/per-app;
- IPv6 egress `off/manual/route/nat66` × NDP `off/auto/required`, все переходы;
- старый/новый сервер и клиент, несовместимые ABI/capabilities, off/prefer/required;
- single/multiprofile, single/multisession/multipath и пустой/исчерпанный pool;
- clean stop, timeout, revoke, crash, reload/restart, suspend/resume и network change.

Обязательные сочетания безопасности выполняются полностью. Для остальных взаимодействий
допустим pairwise-набор с явной таблицей покрытых комбинаций, а не обещание полного
декартова произведения. Для leak-проверок нужны packet capture на tunnel и physical
интерфейсах; для cleanup — before/after routes/DNS/firewall/sysctl/fd/tasks.

## 4. Этап 00 — исходная точка

**DONE: инвентаризация и ограниченные локальные проверки.** Это не завершение аудита
продукта. Следующий рабочий раздел — **01: серверный INI**, затем 02–07. Linux E2E
для последних административных и IPv6-изменений остаётся обязательным.

| Проверка на `fc6f4a5d` | Результат | Граница |
|---|---|---|
| `check_panel.py` | PASS: 11 шаблонов, 1142 RU строки | Статика |
| `test_panel_editors.cjs` | PASS: 25 групп | Реальные JS-компоненты в Node, не browser E2E |
| `unittest discover -s scripts -p 'test_native_*.py'` | PASS: 67 тестов | Проверяет инструменты/контракты, не пересобирает все native cores |
| `sync_version.py` | PASS: dev/planned 0.8.2, released 0.8.1 | Согласованность версии |
| `native-libs/provenance.py --check` | **FAIL: STALE NATIVE CORES** | Digest исходников отличается от recorded native digest |
| `release_certification.py --quiet` | **FAIL: manifest missing** | Нет `release/certification/0.8.2.json` |

**B00-01:** native digest recorded `85f2f17ed9f58e7ad8d0368b936542f2391961bf0a739c7985a93208d6a1cb80`,
actual `3deb3da9d8306e0eaf4fd3d3505a7ad8f4e822b7bd502e8e748f632a852baa52`.
Не выдавать packaged-библиотеки за проверку текущего Rust. Закрывается в 22/34
пересборкой и проверкой происхождения; простое обновление записи digest не подходит.

**B00-02:** отсутствие manifest не доказывает поломку runtime, но означает отсутствие
полного подтверждения готовности 0.8.2 к выпуску. Закрывается в 34 реальными evidence
из матрицы; создавать формальный файл с `passed` без прогонов нельзя.

## 5. Реестр модулей: что уже аудировали и что повторяем

Ниже полный восстановленный перечень в порядке нового прохода. H-коды ссылаются
на раздел 1; это история review/test, не текущий PASS. Кросс-системные работы 35–37
также применяются к каждому из разделов 01–34.

| ID | Модуль | Предыдущие проверки | Новый проход |
|---|---|---|---|
| 01 | Серверный INI и схема | H01, H04, H08–H10 | PASS |
| 02 | Клиентские парсеры и qeli:// | H04, H06, H08–H10 | PASS |
| 03 | Панель: UI и состояние | H02, H09–H11 | PASS |
| 04 | Web auth и защита API | H01–H03, H08–H09 | PASS |
| 05 | Транзакции конфигурации и restart | H08–H10 | PASS |
| 06 | Пользователи, группы и выдача доступа | H01, H04, H09–H10 | PASS |
| 07 | Backup, restore и history | H03–H04, H08, H10 | PASS |
| 08 | Криптография, identity и ключи | H01, H04, H08 | DONE |
| 09 | Handshake и pre-auth TCP/UDP | H01, H04, H08 | DONE |
| 10 | PacketCodec, replay и control framing | H01, H04, H08 | DONE |
| 11 | REALITY, TLS 1.3 и HTTP/2 | H07–H08 | DONE |
| 12 | Транспорты и wire-маскировка | H02, H07–H08 | PASS |
| 13 | Recordizer, padding и shaping | H02, H07–H08 | PASS |
| 14 | Supervisor, workers и профили | H02–H03, H08 | PASS |
| 15 | Сессии, IP-пулы и лимиты | H01, H03–H04, H08 | PASS |
| 16 | ACL, push routes и site-to-site | H03–H04, H06 | PASS |
| 17 | IPv4 NAT, forwarding и sysctl | H02, H04, H08 | PASS |
| 18 | IPv6 off/manual/route/nat66 и NDP | H06, H11 | PASS |
| 19 | DNS сервера и клиентов | H01–H02, H05–H06 | PASS |
| 20 | DHCP и lease lifecycle | H02, H05 | PASS |
| 21 | TUN/TAP, IP, MTU/PMTU и фрагментация | H06, H08 | DONE/PASS |
| 22 | Transport core, FFI/JNI и память | H06, H08 | DONE/PASS |
| 23 | Роуминг, resume и CONTROL_V2 | H06, H08 | DONE/PASS |
| 24 | Multipath, bonding и общий бюджет | H04, H06, H08 | DONE/PASS |
| 25 | Linux CLI и восстановление сети | H01, H04, H08 | DONE / PASS |
| 26 | Общий C# и managed/native граница | H04, H06, H08 | DONE/PASS |
| 27 | Windows: GUI, служба и драйверы | H01, H04, H08 | DONE / PASS |
| 28 | macOS: daemon, utun, pf и Network Extension | H04, H08 | DONE/PASS |
| 29 | Android: VpnService, JNI и lifecycle | H04, H06, H08 | DONE / ACCEPTED_LIMITATION |
| 30 | iOS: PacketTunnel, Swift и MDM | H04, H06, H08 | DONE: SOURCE REVIEW; Apple USER_SKIPPED |
| 31 | OpenWrt, LuCI и Keenetic | H04, H06, H08 | DONE/PASS |
| 32 | Метрики, usage, логи и уведомления | H02–H03, H08, H10 | DONE |
| 33 | Установка, обновление, файловые права и hooks | H01, H04, H08 | DONE |
| 34 | CI, зависимости, native provenance и релиз | H04, H06, H08 | DONE/PASS |
| 35 | Fuzzing, concurrency, DoS и soak | H04, H06, H08 | DONE/PASS |
| 36 | Бенчмарки и методика измерения | H07 | DONE |
| 37 | Документация, тестовая обвязка и мёртвый код | H06, H08–H09, H11 | DONE |

Таблица сверена с итоговыми статусами разделов21–23,26,28 и открытыми29–31,35–36
11октября. Старые checkpoint-числа далее остаются историческими.

## 6. Сценарии по каждому разделу

Порядок — 01 → 37. Если проверка требует другого стенда, фиксируется BLOCKED только
для этой части; независимый анализ следующего раздела продолжается, а блокер остаётся
в очереди. Итоговый PASS раздела требует всех обязательных уровней из раздела 2.

### 01. Серверный INI и схема

**Код:** `qeli/src/config`.

Каждый ключ: parse → validate → runtime → serialize; defaults, диапазоны, дубли секций/ключей, unknown keys, кавычки/TAB/Unicode. Неверный ввод отклоняется до записи. INI — единственный формат конфигов; JSON остаётся служебным API.

**Имеющаяся обвязка/fixtures:** `qeli/tests/config_examples.rs`.

- [x] Review и мёртвый код: строгие entry points, serde/function-pointer/OS consumers, документированные неактивные поля; 3 октября.
- [x] Штатные, граничные и негативные сценарии парсера: 12 новых регрессий и существующий набор.
- [x] Отказы и конкуренция: D07/Q25-F209, 201 unit, 4 privileged и 44 runtime checks.
- [x] Linux-интеграция: check-config/startup/SIGHUP/HTTP save/Quick Start, Q25-F209; итоговый D15-кандидат.
- [x] Исправления первого прохода, повторная проверка и evidence (Q01-F001–F007).

**Статус: PASS.**

**Первый проход, 2026-09-22:** [отчёт Q01](../reports/audit-0.8.2/AUDIT-Q01-SERVER-INI.md).
Исправлены 6 дефектов обработки INI и пробел покрытия fixture. 651 переносимый Rust-тест
и 25 JS-групп прошли; Linux all-targets check прошёл. Контроль fixture: 163 имени ключей
и 3 динамических семейства. Проверена изоляция 32 параллельных разборов.

**Сверка 3 октября:** trace полей закрыт матрицами [глобальных ключей](../reports/audit-0.8.2/AUDIT-Q25-SERVER-GLOBAL-FIELDS.md),
[основы профиля](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PROFILE-FOUNDATION.md) и [obf](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PROFILE-OBF.md).
D07/Q25-F209 проверил отказы, конкуренцию и Linux save/reload/import; D15 подтвердил
одинаковые SHA всех 288 Rust-файлов и проверил итоговый release. Старое ограничение
«нет Linux» снято. [Evidence применимости](../../../release/certification/evidence/q01-reconciliation-20261003.json)
сохраняет первоначальный debug SHA и границы, не приписывает новый запуск этим 44 checks.
**Завершение 3 октября:** адресный review закрыт без новых подтверждённых дефектов; fixture check повторён. Все пять критериев раздела 01 закрыты. PASS относится к серверной схеме и путям конфигурации, а не к сетевым реализациям следующих разделов.

### 02. Клиентские парсеры и qeli://

**Код:** `qeli/src/config/client.rs`, `qeli/src/config/share.rs`, `conformance`.

Сверить текущий контракт 81 ключа в Rust/C#/Kotlin/Swift; INI ↔ формы ↔ URI, сохранение чужих полей и секретов. Проверить malformed pin/port/IPv6/MTU и запрет незаметного перехода в TOFU.

**Имеющаяся обвязка/fixtures:** `scripts/test_native_config_keys.py`.

- [x] Review и мёртвый код: INI/editor/URI callers, проекции, C ABI/JNI; 3 октября.
- [x] Штатные, граничные и негативные сценарии: 81 ключ / 84 поля, общий URI/INI корпус, прежние регрессии и свежий DLL audit.
- [x] Отказы и конкуренция: лимиты, сохранение ошибок, 1000 черновиков, 128 параллельных сценариев; D08 storage coordination.
- [x] Доступная интеграция: действующий C ABI, D08 C#/JVM/Android emulator, D15 native A/B; Apple/physical SKIP по решению пользователя.
- [x] Q02-F001–F019, D08/D15 и сверка неизменённых входов; evidence с исходными границами.

**Статус: PASS в согласованном объёме; Apple/physical SKIP.**

**Проход URI, 2026-09-22:** [отчёт Q02](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md).
Закрыты Q02-F001–F006: неоднозначные query-параметры, scalar/UTF-8/defaults и пропуск
JVM-перепроверки корпуса. 651 Rust-тест, 438 C# checks и 137 JVM-тестов прошли.
Общий корпус: 21 valid + 29 reject; контракт 81 имени ключей сохраняется.

**Текущее состояние, 3 октября:** адресный INI/редакторский review завершён без новых подтверждённых дефектов. D08 уже проверил доступные модели/хранилища и Android-эмулятор; D15 обновил release native A/B и provenance. Apple и недоступные физические стенды исключены по решению пользователя, не получили runtime PASS. [Сверка](../../../release/certification/evidence/q02-reconciliation-20261003.json): 81 ключ, 84 поля редактора, 164 adapter + 288 Rust SHA совпали; шесть статических тестов и генератор проекций прошли. Старые runtime результаты не объявляются новыми.
**Архитектурное предложение пользователя:** [единый конфигурационный модуль](CLIENT-CONFIG-CORE.md)
в существующем Rust core реализован в исходниках (ABI 1.16). Местные парсеры удалены; проекции/defaults генерируются из Rust. Объединены политики маршрутов/reconnect/версий и парсер route_file. Release A/B закрыты D15; Apple runtime исключён пользователем.

**Продолжение 22 сентября — границы конфигурации:** в общем ядре исправлены Q02-F007–F014 — восемь
воспроизведённых сценариев INI/URI: потеря символов и ошибок DNS, недопустимые имена
полей, обход проверки через BOM, маскирование секретов и неверная секция `logging.*`.
Регрессии проверяют сохранение через модели клиентов; подробности и результаты —
в [отчёте общего конфигурационного модуля](CLIENT-CONFIG-CORE.md#аудит-границ-конфигурации--22-сентября-2026).
Это не закрывает весь раздел: Linux E2E и проверки на целевых устройствах остаются открыты.

**Параметры перед runtime, 2026-09-22:** закрыты Q02-F015–F019 — неверный нулевой PIN,
некорректный host, исправление порта без его изменения, старый валидатор панели и ошибки автозаписи dev.
Регрессии и сохранение положительных случаев описаны в [реестре Q02](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md).

**Продолжение runtime-аудита, 2026-09-22:** в том же плане зафиксированы общий бюджет/задержка
повторов, монотонное время установленной сессии, исправления конечных лимитов и возврата сети,
прерывание Linux-backoff по сигналу. Регрессии Rust/C ABI/JNI и Linux cross-Clippy пройдены.
Проверки реальных устройств/смены сети, Apple runtime и релизных библиотек этим не закрыты.

**Завершение 3 октября:** свежий audit упакованной DLL (`653522e6…`), восемь групп:
84 явных значения полей в runtime-документе, 21 valid + 29 reject URI, 15 INI boundary,
1000 seeded черновиков, сохранение ошибок при unrelated edit, лимиты и 128 параллельных
сценариев изоляции/маскирования. C#/JVM/Android проверки D08 переиспользованы только после
сверки 164 adapter + 288 Rust SHA; это не новые платформенные прогоны. [Результат](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md#завершение-раздела--3-октября-2026).
PASS относится к конфигурационному контракту; эффекты OS-параметров и настоящая сеть
проверяются в соответствующих платформенных разделах. Apple build/runtime не заявлены.

### 03. Панель: UI и состояние

**Код:** `qeli/src/web/templates`, `qeli/src/web/assets`, `qeli/src/web/pages`.

Загрузка/error/retry, dirty-state, поздние ответы, concurrent edits, Form/INI, удаление полей, маски секретов, даты и квоты. Настоящий браузер: все страницы, RU/EN, клавиатура, мобильный экран; ошибки не превращаются в сохранение defaults.

**Имеющаяся обвязка/fixtures:** `scripts/check_panel.py`, `scripts/test_panel_editors.cjs`.

- [x] Review и мёртвый код: все 11 шаблонов / 10 page wrappers; общий Form/INI lifecycle, Rust defaults/Quick Start.
- [x] Штатные, граничные и негативные сценарии: 116 групп реальных JS-компонентов; секреты, даты, квоты, ревизии и Form/INI.
- [x] Отказы и конкуренция: error/retry всех страниц, старые ответы, владельцы модальных окон и черновиков, повторные отправки, destroy и отмена.
- [x] Доступная интеграция: все страницы в Edge RU/EN, desktop/mobile и клавиатура; общий фокус и настоящий beforeunload. API fixtures подтверждают UI, а не backend protection/persistence.
- [x] Q03-F001–F015 исправлены и проверены; baseline-воспроизведения, raw logs/captures, свежая release-матрица и soak того же артефакта.

**Статус: PASS в области UI/state панели.**

**Завершение 3 октября:** [Подробный отчёт](../reports/audit-0.8.2/AUDIT-Q03-PANEL-STATE.md) и [итоговое evidence](../../../release/certification/evidence/q03-config-20261003.json). Итоговый пакет: 26 новых JS-групп (всего 116), четыре Config Edge-сценария, черновик/ревизия, одна запись, владельцы identity/hash/history/remove, Cancel/Tab/Shift+Tab/Escape/возврат фокуса и переход с правками. Свежий release: 18 изолированных сценариев / 327 checks, aggregate leak и 100 TCP + 100 QUIC / 33 checks PASS. Неизменные Rust/native/budget результаты явно используются как reuse. Пользовательский live-users WIP сохранён отдельно; physical qualification и новые benchmarks не заявляются. Backend auth, транзакции и восстановление остаются обязательствами Q04/Q05/Q07.

### 04. Web auth и защита API

**Код:** `qeli/src/web/auth.rs`, `qeli/src/web/mod.rs`, `qeli/src/web/api`.

Инвентаризировать routes/guards, Basic/cookie/TOTP, logout/expiry, CSRF, reverse proxy, base_path, allowed_ips. Argon2 budget/rate limit под конкуренцией. Запрос без прав не раскрывает секреты и не имеет побочных эффектов.

**Имеющаяся обвязка/fixtures:** `scripts/check_panel.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: PASS.**

**3 октября, завершение:** все пять критериев Q04 закрыты в области авторизации и границ API. 2261 Linux units, 116 JS-групп, 293 реальных HTTP checks, pinned full/minimal Clippy PASS. Release-матрица 18/327 и soak 100 TCP + 100 QUIC/33 PASS; HTTP/matrix повторно используются только по побайтному совпадению release SHA. Свежие desktop/Android native A/B и provenance PASS. Web TOTP отсутствует; положительные транзакции и restore остаются Q05/Q07. [Report](../reports/audit-0.8.2/AUDIT-Q04-WEB-AUTH.md), [evidence](../../../release/certification/evidence/q04-web-auth-20261003.json).

### 05. Транзакции конфигурации и restart

**Код:** `qeli/src/web/api/config.rs`, `qeli/src/web/api/control.rs`, `qeli/src/server/preflight.rs`, `qeli/src/util.rs`.

Общий validator/preflight для Form/INI/API/history/Quick Start/worker/full restart. Stale revision, concurrent writers, ENOSPC/EACCES и crash между snapshot/rename/restart. Failed preflight не останавливает рабочий сервис и не публикует плохой конфиг.

**Имеющаяся обвязка/fixtures:** `scripts/test_web_reload.py`, `scripts/test_panel_editors.cjs`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: PASS.**

**3 октября, завершение:** 6 пакетов / 352 реальных HTTP/systemd checks PASS: Form/INI/history, 8 concurrent writers, все 10 Quick Start modes, live password/allowlist, worker replacement, detached restart failures, ENOSPC/read-only/EACCES, SIGKILL до/после rename и fsync uncertainty; настоящий full restart собственного transient unit. Q05-F009: старый live-service тест заменён изолированным launcher. Unchanged Linux 2261 / Clippy / native / matrix / soak явно reused; все 322 compilation inputs совпадают. Power loss и несогласованные внешние root writes не сертифицированы; backup/restore остаётся Q07. [Report](../reports/audit-0.8.2/AUDIT-Q05-HTTP-TRANSACTIONS.md), [evidence](../../../release/certification/evidence/q05-transactions-20261003.json).

### 06. Пользователи, группы и выдача доступа

**Код:** `qeli/src/config/users.rs`, `qeli/src/web/api/users.rs`, `qeli/src/web/api/share.rs`, `qeli/src/web/api/identity.rs`.

Inline + users_file, duplicates/precedence, missing group, неверные типы versus снятие ограничений, static addresses, quota/expiry. Ошибка identity не меняет пароль при выдаче ссылки. Revoke применяется к уже открытым TCP/UDP-сессиям.

**Имеющаяся обвязка/fixtures:** `scripts/test_user_reload.py`, `scripts/test_l3_user_limits.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: PASS.**

**3 октября, первый пакет:** исправлены пять подтверждённых проблем API, inline override, routes, live revoke и bandwidth writers. 119 API + 57 TCP/UDP checks PASS; свежие Linux units/lint и 293/75 HTTP regressions PASS. Q06 остаётся открытым для filesystem/concurrency и дополнительных политик. [Отчёт](../reports/audit-0.8.2/AUDIT-Q06-USERS-ACCESS.md).

**3 октября, второй пакет:** Q06-F006 устраняет стартовые inline users/groups в контрольных командах после SIGHUP. 23 новых storage/control checks, повторные 119 API + 57 live, 2264 Linux units и свежая release/native квалификация PASS. Конкуренция и read-only/rename/corrupt INI проверены; crash/lock/final-fsync, ACL и устройства ещё открыты. [Отчёт](../reports/audit-0.8.2/AUDIT-Q06-USERS-ACCESS.md#второй-пакет-ini-хранилище-и-inline-auth-после-sighup).

**3 октября, третий пакет:** исправлены live ACL/group, делегированные источники,
уменьшение лимита устройств, неограниченное ожидание lock и ложный отказ после
публикации INI. 315 checks Q06 (72 storage/durability, 67 policy, 119 API, 57 live)
и 2265 Linux units PASS. Реальные ENOSPC/EACCES, crash до/после rename и все API/control
writers проверены. Опасные legacy drivers заменены изолированными пакетами.
Файловые отказы и конкурентные писатели закрыты; Q06 остаётся IN_PROGRESS для
измерения bandwidth и оставшихся сценариев admission/выдачи доступа.
[Отчёт](../reports/audit-0.8.2/AUDIT-Q06-USERS-ACCESS.md#третий-пакет-live-права-и-отказы-публикации-ini).

**3 октября, завершение:** Q06-F012–F014 исправлены; общий TCP/UDP admission, терминальная замена сессий, effective bandwidth/legacy burst и recovery share-reset. 387 Q06 checks, 2265 Linux units / 60 ignored, 118 JS-групп, свежие matrix 18/327 и soak 100 TCP + 100 QUIC/33 PASS. Native A/B побайтно совпадает; .11 сохранён, .10 SDK PASS с явно сохранённым ограничением firewall snapshots. Physical qualification не заявляется. [Итоговый отчёт](../reports/audit-0.8.2/AUDIT-Q06-USERS-ACCESS.md), [evidence](../../../release/certification/evidence/q06-users-access-complete-20261003.json).

### 07. Backup, restore и history

**Код:** `qeli/src/web/api/backup.rs`, `qeli/src/web/api/backup_listing.rs`, `qeli/src/web/api/config.rs` (history), `qeli/src/web/tls.rs`.

Fresh restore с custom paths, inline+external users, identity и panel-secret. Tar bombs, traversal, links, missing files, overlay/exact, совместимость staged-файлов, concurrent restore. Snapshots не архивируют себя; interrupted publish проверяется восстановлением.

**Имеющаяся обвязка/fixtures:** `scripts/audit_web_auth_lab.py --audit q07 --scenario archives --fixture scripts/audit_web_transactions.py`; общий Q05 `basic` для history/config regression.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: PASS в согласованном доступном Linux/runtime scope.**

**История, 3 октября, первый пакет:** HTTP-воспроизведение выявило отказ exact при вложенных lock-файлах, отсутствие проверки identity/TLS и сохранение чужого UID из tar. Исправления и текущая квалификация описаны в [отчёте Q07](../reports/audit-0.8.2/AUDIT-Q07-BACKUP-RESTORE.md). Полный Q07 остаётся открытым: crash/partial publication и recovery, файловые отказы, cross-process users/identity writers, mixed users и panel-secret, операционные файлы/rotation и дополнительные INI trust boundaries (исторический список до второго пакета).

**История, 3 октября, второй пакет:** Q07-F005–F013: strict exact, INI command trust, operational snapshots/rotation, old/new users/identity FileLocks, absent-directory lock inode, partial-publication metadata и отказ вместо ложного exact success. 17 baseline checks FAIL; текущие 176 HTTP/system checks PASS. SIGKILL до/после первого rename и manual tar recovery проверены. Остаются mixed inline/external users, panel-secret и прямые prepare ENOSPC/read-only/HTTP cancellation для архивного restore. Общий Q07 ещё IN_PROGRESS.

**3 октября, закрытие Q07:** Q07-F014–F015 исправлены: extraction ENOSPC → HTTP 500; только реальный FileLock timeout → 409. Mixed users/groups, real restored VPN clients, same/new-host panel-secret, legacy migration, real archive prepare ENOSPC/read-only и HTTP cancellation проверены. Финальные 226 HTTP/system checks, 2266 units, matrix 18/327, soak 33 и native A/B PASS. Review всех семи слоёв завершён; приватный staging при read-only и per-file publication описаны как принятые ограничения. [Финальный отчёт](../reports/audit-0.8.2/AUDIT-Q07-BACKUP-RESTORE.md). Следующий раздел: Q08.

### 08. Криптография, identity и ключи

**Код:** `qeli/src/crypto`, `qeli/src/server/reality.rs`, `qeli/src/web/api/identity.rs`.

X25519/ML-KEM/HKDF/AEAD KAT и negative vectors; static binding, proof до credentials, pin/TOFU, RNG, nonce exhaustion, rotation и zeroization. Owner/mode/link/atomic-write ключей. Unit tests не заменяют независимый криптоаудит.

**Имеющаяся обвязка/fixtures:** `conformance/hkdf.json`, `conformance/prp-nonce.json`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE.**

**Первый пакет Q08:** Q08-F001–F003, shared bounded key reads, serialized legacy migration, low-order proof refusal. Прежний release воспроизводит шесть файловых отказов; первый пакет и его квалификация сохранены в [отчёте](../reports/audit-0.8.2/AUDIT-Q08-CRYPTO-KEYS.md).

**3 октября, завершение Q08:** Q08-F004–F007, независимые NIST/RFC/AEAD/HKDF vectors, полный review семи направлений, 31 key/rotation + 25 restore/state checks с настоящими pinned-клиентами, 2279 units, matrix18/327, soak33 и native A/B PASS. Все обязательные проверки fixes закрыты. Принятые ограничения и корректная conditional REALITY TLS PQ-защита описаны в [финальном отчёте](../reports/audit-0.8.2/AUDIT-Q08-CRYPTO-KEYS.md). Далее Q09.

### 09. Handshake и pre-auth TCP/UDP

**Код:** `qeli/src/server/handler.rs`, `qeli/src/server/udp_handler.rs`, `qeli/src/protocol/capabilities.rs`, `qeli/src/client/mod.rs`.

Truncation/replay/reorder/slow peer и неверный PQ/proof/password. Permits до spawn, pending caps, anti-amplification, tarpit, deadlines/cancel. Один login не блокирует UDP recv-loop; каждый отказ освобождает ресурсы, downgrade только по контракту.

**Имеющаяся обвязка/fixtures:** `qeli/fuzz/fuzz_targets/clienthello.rs`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE.**

**Серверный H2 и pre-auth, 23 сентября 2026:**
[Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md): профиль ждёт вложенные H2-задачи перед
teardown; flush отказа сохраняет pre-auth slot до освобождения I/O. 13 новых регрессий,
969 Rust tests PASS. H2/ProfileTasks/semaphore проверены на host, production Linux только
кросс-компилирован. Остальные сценарии раздела и live Linux E2E остаются открытыми.

**3 октября, UDP AUTH/PMTU:** [Q09-F001/F002](../reports/audit-0.8.2/AUDIT-Q09-UDP-AUTH.md) исправлены и проверены: handshake reservation/cancel/deadline, PMTU только после AuthOK без revoked. 2283 units, 16 old/new UDP/QUIC + 35 admission checks, fresh matrix/soak/native PASS; общий Q09 остаётся IN_PROGRESS.

**3 октября, TCP/parser:** [Q09-F003–F005](../reports/audit-0.8.2/AUDIT-Q09-TCP-PARSER.md): исходный AUTH-дедлайн, откат AUTH OK, строгий полный ClientHello и JOIN. 2290 units, 8 TCP checks с реальным baseline/fixed и насыщением 256 слотов, bounded ASan/libFuzzer, fresh matrix/soak/native PASS. Остались UDP anti-amplification/replay/reorder и негативные auth/capabilities контракты; общий Q09 IN_PROGRESS.

**3 октября, UDP contracts:** [Q09-F006–F009](../reports/audit-0.8.2/AUDIT-Q09-UDP-CONTRACTS.md): publication/revocation, direction/bounds, reaper revalidation и admission/AuthOK deadline+rollback. 2294 units, 74 live UDP/QUIC +16 PMTU +35 admission, fresh matrix/soak/native PASS. Исходные failures и ограничения лабы сохранены. Остаток: final review, forged client-proof/capabilities/contention и уточнение первого TCP terminal-loss; Q09 IN_PROGRESS.

**3 октября, завершение Q09:** [Q09-F010/F011 и итоговый review](../reports/audit-0.8.2/AUDIT-Q09-FINAL.md): KICK сохраняется при EOF, pipeline drain и ошибке platform delivery. 2301 units;8 live baseline/fixed +66 decrypted proof/capabilities/concurrent +35 admission checks; fresh18/327 matrix,100 TCP+100 QUIC/33 soak и четыре native A/B PASS. Все обязательные проверки исправлений Q09 закрыты; ограничения evidence явно сохранены. Следующий раздел — Q10.

### 10. PacketCodec, replay и control framing

**Код:** `qeli/src/protocol/packet.rs`, `qeli/src/protocol/ctrl.rs`, `qeli/src/protocol/control_v2.rs`.

Lengths 0/min/max/overflow, AEAD tags, sequence около 2^63/2^64, replay-window, unknown types/generation. Malformed пакет не вызывает panic/abort/unbounded allocation; после отказа корректный пакет обрабатывается.

**Имеющаяся обвязка/fixtures:** `conformance/packet-decode.json`, `conformance/replay-window.json`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE.**

**3 октября, Q10 завершён:** [PacketCodec/replay/CONTROL_V2](../reports/audit-0.8.2/AUDIT-Q10-CODEC-CONTROL.md): Q10-F001–F003,2307 units,два bounded ASan fuzz runs,свежая matrix/terminal/soak/native qualification PASS. Общий план:10/37 DONE/PASS (27,0%). Следующий раздел — Q11.

### 11. REALITY, TLS 1.3 и HTTP/2

**Код:** `qeli/src/protocol/realtls`, `qeli/src/protocol/h2_carrier.rs`, `qeli/src/protocol/h2_carrier`.

Transcript/replay/decoy, TLS key budget. H2 zero/small window, SETTINGS/WINDOW_UPDATE/GOAWAY/RST, partial I/O, backpressure. Stop/timeout освобождает task/socket/permit. PCAP/active probing отдельно от работоспособности туннеля.

**Имеющаяся обвязка/fixtures:** `qeli/src/protocol/h2_carrier/hardening_tests.rs`, `scripts/roaming_netns_e2e.sh`, `scripts/audit_realtls_wire.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE.**

**Серверный H2 и pre-auth, 23 сентября 2026:**
[Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md): профиль ждёт вложенные H2-задачи перед
teardown; flush отказа сохраняет pre-auth slot до освобождения I/O. 13 новых регрессий,
969 Rust tests PASS. H2/ProfileTasks/semaphore проверены на host, production Linux только
кросс-компилирован. Остальные сценарии раздела и live Linux E2E остаются открытыми.

**3 октября, завершение Q11:** [REALITY/TLS/H2](../reports/audit-0.8.2/AUDIT-Q11-REALITY-TLS-H2.md): пять исправлений общего TLS,2317 Linux units,73 REALITY-TLS/H2 checks,3 PCAP/6 wire-probe результатов,два bounded ASan fuzz,свежие matrix/soak/четыре native A/B PASS. Общий план:11/37 DONE/PASS (29,7%). Следующий раздел — Q12.

### 12. Транспорты и wire-маскировка

**4 октября, Q12 DONE/PASS:** Close/control и wire-матрица завершены; 8 baseline FAIL,17 новых тестов,2352 Linux PASS,13 fresh wire cases,64 probes,два frame/QUIC ASan прогона,свежие matrix/soak/четыре native A/B PASS. [Evidence и границы](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md). Общий план **12/37 (32,4%)**; далее Q13.

**4 октября, WS writer batch PASS:** [Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md): четыре исправления общего writer/read,5 baseline FAIL,7 new tests,2325 Linux PASS,10prior +3fresh wire-mode cases,свежие matrix/soak/native A/B PASS. На момент того пакета HTTP/inbound frame/fuzz оставались впереди; тогда Q12 IN_PROGRESS,план11/37 (29,7%).

**Код:** `qeli/src/protocol/tls.rs`, `qeli/src/protocol/obfs.rs`, `qeli/src/protocol/quic.rs`, `qeli/src/transport`.

Получить все допустимые сочетания из runtime/Quick Start: plain/fake-tls/reality/reality-tls/WS/obfs/UDP-QUIC/AWG. WS masking/control caps, junk counters, fallback и запрет несовместимых комбинаций. Protocol compliance и DPI detection не смешивать с goodput.

**Имеющаяся обвязка/fixtures:** `conformance/quic.json`, `qeli/fuzz/fuzz_targets/websocket_head.rs`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

### 13. Recordizer, padding и shaping

**4 октября, Q13 DONE/PASS:** удалены две выключенные UDP stealth-ветви, сохранена действующая политика TCP. Прошли 2365 Linux-тестов, 7 сетевых сценариев, матрица 18/18, 33 проверки длительного прогона и четыре независимые сборки библиотек A/B. Общий план **13/37 (35,1%)**, осталось 24 раздела; далее Q14. [Итог и границы](../reports/audit-0.8.2/AUDIT-Q13-MORPHOLOGY.md).

**4 октября, morphology batch PASS:** ещё четыре исправления padding/normalization/mux,2365 Linux PASS,6 combined TCP/UDP cases,свежие matrix/soak/native A/B. [Evidence и оставшиеся две UDP ветви](../reports/audit-0.8.2/AUDIT-Q13-MORPHOLOGY.md).

**4 октября, shaping batch PASS:** [пять исправлений и замеры](../reports/audit-0.8.2/AUDIT-Q13-MORPHOLOGY.md):5 baseline FAIL,7 новых тестов,2359 Linux PASS,10 network cases/102 assertions,recordizer campaign,свежие matrix/soak/native A/B. Review recordizer/padding/normalization продолжается;общий итог остаётся12/37 (32,4%).

**Код:** `qeli/src/protocol/recordizer.rs`, `qeli/src/protocol/shaper.rs`, `qeli/src/protocol/obfuscate.rs`.

Off/prefer/required и legacy peer; batch/reassembly caps, flush deadlines, cancellation и общий budget. Junk/heartbeat не вытесняют payload. Сравнить on/off на одинаковом workload; bounded memory, jitter и периодические сигналы в PCAP.

**Имеющаяся обвязка/fixtures:** `scripts/validate_shaping.py`, `scripts/bench_stealth.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

### 14. Supervisor, workers и профили

**4 октября, Q14 DONE/PASS:** исправлен Q14-F039 — supervisor владеет фоновыми задачами и останавливает HTTP/HTTPS-панель. 2368 Linux-тестов, 38 process checks, 4 panel stop/cancel cases, 5 privileged-прогонов, stop во время backoff, матрица 18/18 и native A/B PASS. [Итог и границы](../reports/audit-0.8.2/AUDIT-Q14-CURRENT-LIFECYCLE.md).

**Предыдущий пакет 4 октября, lifecycle PASS:** 8/8 сценариев worker, 80 reload, 22 проверки восстановления и 14 проверок нескольких профилей на текущем release. Состояние лабы и рабочий сервис сохранены. [Разбор и остаток Q14](../reports/audit-0.8.2/AUDIT-Q14-CURRENT-LIFECYCLE.md). Q14 IN_PROGRESS.

**Код:** `qeli/src/server/mod.rs`, `qeli/src/server/tasks.rs`, `qeli/src/server/supervisor.rs`, `qeli/src/server/control.rs`, `qeli/src/server/control_io.rs`, `qeli/src/server/control_socket.rs`, `qeli/src/main.rs`, `qeli/src/hooks.rs`, `qeli/src/hooks/process.rs`.

Start/stop/reload/crash/respawn, занятый bind/TUN, удаление/rename профиля, hook failure и умерший control client. Lock order, backoff, watchdog и tasks. Cleanup идемпотентен, ошибка одного профиля не затрагивает соседний.

**Имеющаяся обвязка/fixtures:** `scripts/test_web_reload.py`, `scripts/test_tun_reclaim.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**Владение задачами, 23 сентября 2026:**
[проход Q14/Q19](../reports/audit-0.8.2/AUDIT-Q14-Q19-LIFECYCLE.md) исправляет Q14-F001–F002:
ожидание служб после ранней ошибки запуска и барьер конкурентного/отменённого
shutdown. 7 task-ownership тестов, включая гонку 1024 ресурсов; DNS-слушатели
проверены через loopback. Linux E2E TUN/firewall, forced wrapper cancellation,
watch/control, hooks и restart/reload ещё открыты.

**Supervisor и управляющие события, 23 сентября 2026:**
[продолжение Q14](../reports/audit-0.8.2/AUDIT-Q14-SUPERVISOR.md) исправляет Q14-F003–F007:
stop во время ошибок spawn, владение Child/PID, 60-секундный grace deadline,
очередь Restart/Reload и раннюю установку обработчиков сигналов. 13 поведенческих
тестов и дочерний fixture; 812 Rust-тестов суммарно — PASS. Проверены реальные
изолированные host-процессы, не Linux worker с TUN. Control socket, hooks,
Unix-сигналы и rollback на Linux остаются открытыми.

**Control socket и hooks, 23 сентября 2026:**
[проход Q14-F008–F013](../reports/audit-0.8.2/AUDIT-Q14-CONTROL.md): владение Unix-сокетом,
безопасные права runtime-каталога, границы сообщений, deadlines и drain handlers
до teardown профилей, post_down только для готового поколения. 819 host Rust tests
PASS; 12 новых Unix tests только скомпилированы. Linux runtime/systemd/hooks и
forced cancellation остаются открытыми; далее — hook processes/output и startup rollback.

**Процессы hooks, 23 сентября 2026:**
[Q14-F014–F015](../reports/audit-0.8.2/AUDIT-Q14-HOOKS.md): общий server/client runner удерживает
по 8 KiB stdout/stderr и завершает Linux process group при timeout/cancellation,
сохраняя штатные фоновые службы с перенаправленным выводом. 828 host Rust tests PASS;
4 новых Linux group tests только скомпилированы. Следующие участки: startup rollback,
фоновые worker services и связь trusted config с parsed contents. Linux E2E ещё открыт.

**Службы worker и учёт трафика, 23 сентября 2026:**
[Q14-F016–F017 / Q15-F001](../reports/audit-0.8.2/AUDIT-Q14-Q15-WORKER-USAGE.md): владение и контроль
периодических задач, их завершение до очистки профилей, writable accounting только после
захвата права worker, финальное сохранение на обоих путях остановки. Короткие сессии и
последние байты учитываются после удаления из реестра. 848 host Rust tests PASS;
Linux только cross-check. Уведомления, forced outer cancellation и Linux E2E ещё открыты.

**Владение уведомлениями, 23 сентября 2026:**
[Q14-F018 / Q32-F001](../reports/audit-0.8.2/AUDIT-Q14-Q32-NOTIFICATIONS.md): до 128 принятых отправок,
8 активных запросов на процесс, общий лимит проб панели, ограниченные payloads и drain
до 10 секунд после завершения производителей. Detached-обёртки уведомлений удалены.
864 host Rust tests PASS; Linux только all-targets cross-check. Владение panel/metrics/
autostart supervisor, доверие конфигу и Linux E2E ещё открыты.

**Доверие прочитанному конфигу, 23 сентября 2026:**
[Q14-F019 / Q33-F001](../reports/audit-0.8.2/AUDIT-Q14-Q33-CONFIG-TRUST.md): владелец/права и данные
для парсера получаются из одного дескриптора; исходное разрешение не меняется при
повторах профиля и не перепроверяет путь. Очистка готового поколения сохраняет команду
и окружение после удаления/замены конфига. 874 host Rust tests PASS; четыре новых Unix/
Linux-теста только cross-checked. Лимиты password_command, владение startup-задачами,
installer/update/restore и Linux runtime integration ещё открыты.

**Поставщик пароля и изоляция features, 23 сентября 2026:**
[Q25-F001 / Q33-F002 / Q14-F020 / Q34-F001](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md):
асинхронный password_command, deadline 30 секунд, полный stdout до 16 KiB, отброшенный
stderr и ошибки без секретов. Ранний SIGINT/SIGTERM отменяет и собирает поставщика;
watchers/sampler клиента имеют владельца. Исправлен server-only TUN gate, обе изолированные
features проверяются в CI. 883 host Rust tests PASS; четыре Linux-теста только cross-check.
Server-only check имеет 23 прежних transport dead-code warnings. Лимиты password_file,
финальный drain клиента и Linux runtime/release checks ещё открыты.

**Файловый пароль и финальный статус, 23 сентября 2026:**
[Q25-F002 / Q14-F021](../reports/audit-0.8.2/AUDIT-Q25-PASSWORD-FILES.md): общий zeroizing-буфер 16 KiB
для файла/команды, одна управляемая blocking-задача чтения обычного файла, поддержка symlink,
отказ FIFO и ожидание активного I/O при штатном stop/deadline. Final пишется после join
watchers/sampler, включая ошибки после инициализации reporter. 895 host Rust tests PASS;
два Unix-теста только cross-check. Неотменяемый I/O может превышать бюджет 30 секунд.
Startup/network rollback, мониторинг фоновых ошибок и Linux E2E ещё открыты.

**Fail-closed очистка сети, 23 сентября 2026:**
[Q25-F003](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-CLEANUP.md): forwarding/NAT cleanup должен
завершиться успешно до снятия включённого kill-switch; ошибка сохраняет защиту и её причину.
899 host Rust tests PASS, включая четыре переносимых fault-injection сценария. Linux
пока только cross-check. Разбор begin_connection записан ниже; live firewall/E2E ещё открыты.

**Ошибки жизненного цикла ядра, 23 сентября 2026:**
[Q25-F004/F005](../reports/audit-0.8.2/AUDIT-Q25-CORE-LIFECYCLE.md): ошибка запуска ядра проходит через
cleanup/post_down; ошибка остановки завершается отказом и сохраняет включённый kill-switch,
при этом очистка forwarding выполняется. Шесть новых host-регрессий, включая реальный отказ
ClientCore при полной очереди. 905 host Rust tests PASS; Linux только cross-check.
Live Linux lifecycle/firewall и полный rollback маршрутов/DNS ещё открыты.

**Передача ошибок очистки TUN/маршрутов/DNS, 23 сентября 2026:**
[Q25-F007–F009](../reports/audit-0.8.2/AUDIT-Q25-TUN-CLEANUP.md): явная очистка и guards отката передают
ошибки в Linux retry loop через общий ограниченный журнал. Ошибка не становится успешной
остановкой по сигналу и не снимает включённый kill-switch. TunnelSetup владеет guard до ACK
ядра; тип terminal kick сохраняется при сопутствующих ошибках. Восемь новых host-тестов
проходят, два Linux adapter-теста только cross-check. 921 host Rust tests PASS. Live Linux
E2E, сроки выполнения команд и полное ожидание задач поколения ещё открыты.

**Серверный H2 и pre-auth, 23 сентября 2026:**
[Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md): профиль ждёт вложенные H2-задачи перед
teardown; flush отказа сохраняет pre-auth slot до освобождения I/O. 13 новых регрессий,
969 Rust tests PASS. H2/ProfileTasks/semaphore проверены на host, production Linux только
кросс-компилирован. Остальные сценарии раздела и live Linux E2E остаются открытыми.

**Системные команды TUN/DNS, 23 сентября 2026:**
[Q25-F016/F017](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md): 15 секунд на команду, полный
вывод с лимитом 16 МиБ на поток, завершение дочернего процесса и сохранение DNS marker
при отказе. Диагностика больше не обещает неподтверждённый rollback. 986 host Rust tests
PASS; два новых Linux process-group теста только cross-check. Маршруты/firewall, live
Linux и общий deadline shutdown остаются открытыми; статус раздела IN_PROGRESS.

**Очистка NAT, 23 сентября 2026:**
[Q14-F024/F025](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md): конечный проход по снимку правил,
проверка после удаления и диагностика ошибок с продолжением остальных правил/цепочек.
13 новых host-тестов, 999 Rust tests PASS; production Linux только cross-check.
Q14-F026 исправлена [следующим проходом](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Q14-F027 (передача ошибок teardown), сроки firewall-команд и live Linux остаются открытыми.

**Общие firewall-проверки, 23 сентября 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): сервер и Linux
kill-switch используют общий разбор presence/absence/errors; точечная очистка DNS
проверяет границу 1024 и продолжает TCP после отказа UDP. 17 новых host-тестов,
1016 Rust tests PASS; два новых Unix/Linux сценария только cross-check.
Q14-F027, сроки команд и реальные backend/runtime проверки остаются открытыми.

**Владение DNS firewall, 23 сентября 2026:**
[Q14-F028](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md): реестр worker сохраняет точные правила
при ошибке Drop/rollback; cleanup и новая установка повторяют очистку. Tokens защищают
новое поколение от старого lease; активные записи не участвуют в точечном retry.
12 новых host-тестов, 1028 Rust tests PASS; три adapter-регрессии отдельно сравнивают
baseline/fix. Q14-F027, persistent journal, deadlines и live Linux остаются открытыми.

**Итог остановки worker, 23 сентября 2026:**
[Q14-F027, частичное исправление](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md): окончательный
retry известных DNS/IPv6 sysctl leases влияет на Result и код выхода worker. Flush
статистики выполняется после ошибки сети; активные DNS leases обнаруживаются без удаления.
14 новых host-тестов, 1042 Rust tests PASS; восемь отдельных process-exit сценариев PASS.
Дополнительный проход передаёт ошибку worker через внешний supervisor при финальной
остановке: nonzero exit и принудительный kill больше не возвращают Ok. Ещё пять
host-тестов, итог этого этапа 1047 Rust tests PASS; три отдельные supervisor-регрессии PASS.
Следующий проход: [задачи профиля и TUN teardown](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).
Ошибки shutdown JoinSet, TUN queue timeout/panic и удаления устройства теперь входят в
итог worker; 13 новых host-тестов, матрица этого этапа 1060 Rust tests PASS.
[Q14-F029/F030](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md): исправлены ложный успех
sysctl recovery и потеря существующего owner при неудачном повторном acquire;
1060 Rust tests и 7 отдельных fixture checks PASS.
[Q14-F031](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md): частичный IPv6 acquire теперь
регистрируется до первой попытки; любой отказ вызывает rollback, неуспешный откат
сохраняет scope для итоговой очистки. 11 новых регрессий и перенос одного Linux-only
теста: матрица этого этапа 1072 Rust tests PASS; пять отдельных adapter checks PASS.
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): все пять запусков команд server NAT
переведены на общий runner (15 с; 16 МиБ на каждый поток вывода). Timeout не теряет
DNS ownership; матрица этого этапа 1073 Rust tests и шесть отдельных adapter checks PASS.
Открыты generic NAT outcome, старые поколения/retry backoff, restart policy, persistent
journal, общий срок всей операции, остальные системные команды и live Linux.

**Preflight, 23 сентября 2026:** [Q05-F001](../reports/audit-0.8.2/AUDIT-Q05-PREFLIGHT.md):
четыре host-state probe используют общий runner (15 секунд, по 16 МиБ stdout/stderr).
Fail-open IPv4 и независимый частичный IPv6 snapshot сохранены. 4 новых теста и
20 существующих preflight-тестов включены в host-прогон; 1097 Rust tests и 21
production-adapter сценарий PASS. Linux HTTP/restart/restore, общий срок транзакции
и синхронное ожидание в async handlers остаются открытыми.

[Q25-F050–F051](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md): неизвестные владельцы sysctl сохраняются,
acquire/recovery сообщают ошибку; недостоверное наблюдение sysctl не теряет original
для retry. Восемь baseline-регрессий исправлены, 1362 Rust tests PASS. Namespace
identity журнала, реальный Linux runtime и полный PASS раздела остаются открыты.

[Q25-F052–F053](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md): sysctl journal v2 разделяет network namespaces,
проверяет PID/time контекст и procfs до prune; непустой v1 текущего boot-id сохраняется
с явной ошибкой миграции. 24 новых теста, 1386 Rust tests PASS. Реальный Linux,
устойчивость namespace identity после уничтожения объекта и полный PASS остаются открыты.

[Q25-F054–F056](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md): удалено разрушающее восстановление TUN
по неполному списку PID. Клиент пассивно ждёт освобождения имени и отказывает при
ошибке lookup/смене ifindex; клиент и сервер создают первую очередь эксклюзивно.
Остальные очереди используют её фактическое имя. 20 новых тестов, 7 baseline FAIL,
1406 Rust tests PASS. Исправлена сборка Linux-тестов без server feature.
Attach/teardown races и реальный Linux остаются открыты.

[Q25-F057–F058](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md): attach и дополнительные очереди
не регистрируют замену исчезнувшего TUN; ошибка TUNSETIFINDEX останавливает открытие.
VNET_HDR/неизвестные features отклоняются, поддерживаемые флаги сохраняются.
18 новых host-тестов + прежний parser-тест, 1425 Rust PASS; три новых Linux ioctl
теста только скомпилированы. Следующий проход владения зафиксирован ниже.

[Q25-F059–F060](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md): удаление TUN по имени устранено.
Guards клиента/сервера сохраняют исходные fd до очистки сети; setup rollback заимствует
устройство. 12 сценариев с извлечённым кодом PASS (baseline 7 FAIL / 5 PASS), 1425 Rust PASS.
Три новых native Linux-теста только скомпилированы. Внешние rename/delete,
identity DNS-маркеров/маршрутов и Q14-F027 остаются открытыми.

[Q25-F061–F062](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md): DNS сбрасывает только владеющее им
поколение. Namespace/index journal и неблокирующий lock заменяют маркеры по имени;
перед числовыми resolver-командами проверяется исходный fd. Startup не сбрасывает живой
link только по сохранённому маркеру. 24 новых host-теста, 1446 Rust PASS; guard harness
baseline 3 FAIL / 3 PASS, fixed 6 PASS. Native namespace-тест только скомпилирован.
Identity маршрутов, namespace resolver-сервиса и reuse индекса после проверки остаются открыты.

### 15. Сессии, IP-пулы и лимиты

**4 октября, Q15 DONE/PASS:** Q15-F003 ограничивает историю освобождённых IPv4/IPv6.
2370 unit-тестов, 148 проверок сессий, 54 проверки доставки через TUN, bonding,
матрица 18/18 и native A/B — PASS. [Отчёт и границы](../reports/audit-0.8.2/AUDIT-Q15-CURRENT-SESSIONS.md).

**Код:** `qeli/src/server/pool.rs`, `qeli/src/server/handler.rs`, `qeli/src/server/udp_handler.rs`, `qeli/src/server/usage.rs`.

Allocate/auth/reconnect/evict/reap/revoke/quota под конкуренцией, atomic v4+v6, static/reservations/excludes, pool exhaustion. Общие caps TCP/UDP/bonding. Нет duplicate IP, leaked lease/token/task/client_subnet после каждого выхода.

**Имеющаяся обвязка/fixtures:** `scripts/test_udp_reap.py`, `scripts/test_maxsessions.py`, `scripts/test_multidevice.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**Проход учёта трафика:** [Q15-F001](../reports/audit-0.8.2/AUDIT-Q14-Q15-WORKER-USAGE.md) закрывает
короткие TCP/UDP-сессии, последние байты writer, baseline при reset и удаление счётчиков.
14 переносимых тестов учёта проходят. Финальный пакет выше дополняет этот
исторический проход IP-пулами, конкурентными подключениями и фактическим
отключением по quota/expiry/revoke на Linux.

### 16. ACL, push routes и site-to-site

**4 октября, Q16 DONE/PASS:** Q16-F001 закрывает подмену источника через чужой или
незарегистрированный client_subnet; exact/LPM/current-session проверяются в общем ingress.
Q16-F002 сохраняет локальную доставку к TUN-адресу сервера при exit-default /0.
2374 unit-теста, реальные TCP/UDP/QUIC с IPv4/IPv6, матрица и native A/B — PASS.
[Отчёт и границы](../reports/audit-0.8.2/AUDIT-Q16-ACL-ROUTES.md).

**Код:** `qeli/src/server/acl.rs`, `qeli/src/config/users.rs`, `qeli/src/transport_core/network.rs`.

User/group/profile precedence, longest prefix, client_to_client, spoofed source, overlap, /0 и client_subnet return path. Проверить TCP/UDP, v4/v6. Enforcement на сервере; revoke/смена владельца маршрута не сохраняет доступ старой сессии.

**Имеющаяся обвязка/fixtures:** `scripts/test_push_matrix.py`, `scripts/test_route_push.py`, `scripts/test_l3_user_limits.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

### 17. IPv4 NAT, forwarding и sysctl

**4 октября, Q17 DONE/PASS:** 228 свежих packet/gateway checks на текущем кандидате;
319 адресных unit из Q16 и source/hash-qualified прежние backend/recovery проверки.
Q17-F001: старый gateway runner заменён безопасным изолированным. Исторические
открытые статусы ниже относятся к прежним снимкам; текущие результаты и принятые
границы — в [отчёте](../reports/audit-0.8.2/AUDIT-Q17-IPV4-NETWORK.md).

**Код:** `qeli/src/server/nat.rs`, `qeli/src/client/sysctl.rs`, `qeli/src/client/gateway.rs`.

NAT44/forward_private/gateway_nat/MSS и iptables/nft backend errors. Before/after rules/routes/sysctl при нескольких профилях. Точный tag вместо substring, ownership, crash journal/boot-id; чужие правила и значения сохраняются.

**Имеющаяся обвязка/fixtures:** `scripts/test_gateway_nat.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**Очистка NAT, 23 сентября 2026:**
[Q14-F024/F025](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md): конечный проход по снимку правил,
проверка после удаления и диагностика ошибок с продолжением остальных правил/цепочек.
13 новых host-тестов, 999 Rust tests PASS; production Linux только cross-check.
Q14-F026 исправлена [следующим проходом](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Q14-F027 (передача ошибок teardown), сроки firewall-команд и live Linux остаются открытыми.

**Общие firewall-проверки, 23 сентября 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): сервер и Linux
kill-switch используют общий разбор presence/absence/errors; точечная очистка DNS
проверяет границу 1024 и продолжает TCP после отказа UDP. 17 новых host-тестов,
1016 Rust tests PASS; два новых Unix/Linux сценария только cross-check.
Q14-F027, сроки команд и реальные backend/runtime проверки остаются открытыми.

**Владение DNS firewall, 23 сентября 2026:**
[Q14-F028](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md): реестр worker сохраняет точные правила
при ошибке Drop/rollback; cleanup и новая установка повторяют очистку. Tokens защищают
новое поколение от старого lease; активные записи не участвуют в точечном retry.
12 новых host-тестов, 1028 Rust tests PASS; три adapter-регрессии отдельно сравнивают
baseline/fix. Q14-F027, persistent journal, deadlines и live Linux остаются открытыми.

**Итог остановки worker, 23 сентября 2026:**
[Q14-F027, частичное исправление](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md): окончательный
retry известных DNS/IPv6 sysctl leases влияет на Result и код выхода worker. Flush
статистики выполняется после ошибки сети; активные DNS leases обнаруживаются без удаления.
14 новых host-тестов, 1042 Rust tests PASS; восемь отдельных process-exit сценариев PASS.
Дополнительный проход передаёт ошибку worker через внешний supervisor при финальной
остановке: nonzero exit и принудительный kill больше не возвращают Ok. Ещё пять
host-тестов, итог этого этапа 1047 Rust tests PASS; три отдельные supervisor-регрессии PASS.
Следующий проход: [задачи профиля и TUN teardown](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).
Ошибки shutdown JoinSet, TUN queue timeout/panic и удаления устройства теперь входят в
итог worker; 13 новых host-тестов, матрица этого этапа 1060 Rust tests PASS.
[Q14-F029/F030](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md): исправлены ложный успех
sysctl recovery и потеря существующего owner при неудачном повторном acquire;
1060 Rust tests и 7 отдельных fixture checks PASS.
[Q14-F031](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md): частичный IPv6 acquire теперь
регистрируется до первой попытки; любой отказ вызывает rollback, неуспешный откат
сохраняет scope для итоговой очистки. 11 новых регрессий и перенос одного Linux-only
теста: матрица этого этапа 1072 Rust tests PASS; пять отдельных adapter checks PASS.
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): все пять запусков команд server NAT
переведены на общий runner (15 с; 16 МиБ на каждый поток вывода). Timeout не теряет
DNS ownership; матрица этого этапа 1073 Rust tests и шесть отдельных adapter checks PASS.
Открыты generic NAT outcome, старые поколения/retry backoff, restart policy, persistent
journal, общий срок всей операции, остальные системные команды и live Linux.

**Откат gateway и защита, 23 сентября 2026:**
[Q25-F040–F042](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md): записи TUN/семья/подсеть
заменяют общие флаги и undo по текущему конфигу. Ошибка семьи сохраняет состояние
для повтора; ошибка проверки firewall запрещает вставку, повторно используемый
permit тоже проверяет порядок kill-switch. Router-операции удерживают общую
блокировку процесса до release sysctl. Восемь исходных FAIL → PASS; 25 новых теста
и пять существующих, впервые включённых на host; 1287 Rust tests и девять команд
матрицы PASS. Общий WAN/NAT exit-node, несколько kill-switch chains, межпроцессные
гонки, общий deadline и Linux runtime остаются открытыми.

**Exit NAT и допуск kill-switch, 23 сентября 2026:**
[Q25-F043–F045](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md): NAT-комментарии различают
правила TUN/WAN; cleanup больше не обнаруживает цели без записанного владения.
Запуск kill-switch проверяет обе семьи до изменений и отвергает чужую/старую Qeli
chain. Carrier первого остаётся доступен; конкурентные запуски одного процесса
принимают одну политику. 13 исходных FAIL → PASS; 30 новых тестов, два устаревших
helper-теста удалены. 1315 Rust tests и девять команд матрицы PASS. Межпроцессные
гонки, stale TUN identity, обнаружение IPv6-защиты и Linux runtime остаются открыты.
Продолжение: [Q25-F046–F047](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-LIFETIME.md) —
межпроцессное владение защищённой сессией и отказ при неизвестном IPv6.
Linux runtime новых lease-тестов остаётся открытым; статус раздела не меняется.

[Q25-F048–F049](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md): положительное доказательство
ipv6.disable=1 разрешает пропустить IPv6 firewall; общий lease резервирует TUN всех
Linux-клиентов, включая gateway/exit без kill-switch и dev_attach. 17 новых host-тестов,
3 исходных FAIL → PASS. Runtime Linux и полный PASS раздела остаются открыты.

[Q25-F050–F051](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md): неизвестные владельцы sysctl сохраняются,
acquire/recovery сообщают ошибку; недостоверное наблюдение sysctl не теряет original
для retry. Восемь baseline-регрессий исправлены, 1362 Rust tests PASS. Namespace
identity журнала, реальный Linux runtime и полный PASS раздела остаются открыты.

[Q25-F052–F053](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md): sysctl journal v2 разделяет network namespaces,
проверяет PID/time контекст и procfs до prune; непустой v1 текущего boot-id сохраняется
с явной ошибкой миграции. 24 новых теста, 1386 Rust tests PASS. Реальный Linux,
устойчивость namespace identity после уничтожения объекта и полный PASS остаются открыты.

### 18. IPv6 off/manual/route/nat66 и NDP

**4 октября, Q18 DONE/PASS:** Q18-F001/F002 исправлены; baseline → fix на настоящих NS/NA. 184 новых NDP checks и 446 checks матрицы/переходов; 2376 unit PASS, Clippy и четыре native A/B target PASS. [Итог и границы](../reports/audit-0.8.2/AUDIT-Q18-IPV6-NDP.md). Исторические открытые статусы ниже относятся к прежним снимкам.

**Код:** `qeli/src/server/nat.rs`, `qeli/src/server/ndp_proxy.rs`, `qeli/src/config/server.rs`.

Все 4×3 egress/NDP комбинации для ipv4/dual/ipv6; все 16 переходов через stop/restart на dual, отдельная квалификация IPv6-only сохраняет исходную область. Linux E2E: off блокирует transit; manual не добавляет IPv6 firewall/DNS/sysctl; route сохраняет source; nat66 маскирует. RA, exact cleanup, NS validation, live-session ownership/revoke, required failure, DNS 53/5353, независимый IPv4.

**Имеющаяся обвязка/fixtures:** `scripts/test_panel_ipv6_e2e.py`, `scripts/run_ipv6_release_matrix.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**Очистка NAT, 23 сентября 2026:**
[Q14-F024/F025](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md): конечный проход по снимку правил,
проверка после удаления и диагностика ошибок с продолжением остальных правил/цепочек.
13 новых host-тестов, 999 Rust tests PASS; production Linux только cross-check.
Q14-F026 исправлена [следующим проходом](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Q14-F027 (передача ошибок teardown), сроки firewall-команд и live Linux остаются открытыми.

**Общие firewall-проверки, 23 сентября 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): сервер и Linux
kill-switch используют общий разбор presence/absence/errors; точечная очистка DNS
проверяет границу 1024 и продолжает TCP после отказа UDP. 17 новых host-тестов,
1016 Rust tests PASS; два новых Unix/Linux сценария только cross-check.
Q14-F027, сроки команд и реальные backend/runtime проверки остаются открытыми.

**Владение DNS firewall, 23 сентября 2026:**
[Q14-F028](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md): реестр worker сохраняет точные правила
при ошибке Drop/rollback; cleanup и новая установка повторяют очистку. Tokens защищают
новое поколение от старого lease; активные записи не участвуют в точечном retry.
12 новых host-тестов, 1028 Rust tests PASS; три adapter-регрессии отдельно сравнивают
baseline/fix. Q14-F027, persistent journal, deadlines и live Linux остаются открытыми.

**Итог остановки worker, 23 сентября 2026:**
[Q14-F027, частичное исправление](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md): окончательный
retry известных DNS/IPv6 sysctl leases влияет на Result и код выхода worker. Flush
статистики выполняется после ошибки сети; активные DNS leases обнаруживаются без удаления.
14 новых host-тестов, 1042 Rust tests PASS; восемь отдельных process-exit сценариев PASS.
Дополнительный проход передаёт ошибку worker через внешний supervisor при финальной
остановке: nonzero exit и принудительный kill больше не возвращают Ok. Ещё пять
host-тестов, итог этого этапа 1047 Rust tests PASS; три отдельные supervisor-регрессии PASS.
Следующий проход: [задачи профиля и TUN teardown](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).
Ошибки shutdown JoinSet, TUN queue timeout/panic и удаления устройства теперь входят в
итог worker; 13 новых host-тестов, матрица этого этапа 1060 Rust tests PASS.
[Q14-F029/F030](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md): исправлены ложный успех
sysctl recovery и потеря существующего owner при неудачном повторном acquire;
1060 Rust tests и 7 отдельных fixture checks PASS.
[Q14-F031](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md): частичный IPv6 acquire теперь
регистрируется до первой попытки; любой отказ вызывает rollback, неуспешный откат
сохраняет scope для итоговой очистки. 11 новых регрессий и перенос одного Linux-only
теста: матрица этого этапа 1072 Rust tests PASS; пять отдельных adapter checks PASS.
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): все пять запусков команд server NAT
переведены на общий runner (15 с; 16 МиБ на каждый поток вывода). Timeout не теряет
DNS ownership; матрица этого этапа 1073 Rust tests и шесть отдельных adapter checks PASS.
Открыты generic NAT outcome, старые поколения/retry backoff, restart policy, persistent
journal, общий срок всей операции, остальные системные команды и live Linux.

**Откат gateway и защита, 23 сентября 2026:**
[Q25-F040–F042](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md): записи TUN/семья/подсеть
заменяют общие флаги и undo по текущему конфигу. Ошибка семьи сохраняет состояние
для повтора; ошибка проверки firewall запрещает вставку, повторно используемый
permit тоже проверяет порядок kill-switch. Router-операции удерживают общую
блокировку процесса до release sysctl. Восемь исходных FAIL → PASS; 25 новых теста
и пять существующих, впервые включённых на host; 1287 Rust tests и девять команд
матрицы PASS. Общий WAN/NAT exit-node, несколько kill-switch chains, межпроцессные
гонки, общий deadline и Linux runtime остаются открытыми.

**Exit NAT и допуск kill-switch, 23 сентября 2026:**
[Q25-F043–F045](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md): NAT-комментарии различают
правила TUN/WAN; cleanup больше не обнаруживает цели без записанного владения.
Запуск kill-switch проверяет обе семьи до изменений и отвергает чужую/старую Qeli
chain. Carrier первого остаётся доступен; конкурентные запуски одного процесса
принимают одну политику. 13 исходных FAIL → PASS; 30 новых тестов, два устаревших
helper-теста удалены. 1315 Rust tests и девять команд матрицы PASS. Межпроцессные
гонки, stale TUN identity, обнаружение IPv6-защиты и Linux runtime остаются открыты.
Продолжение: [Q25-F046–F047](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-LIFETIME.md) —
межпроцессное владение защищённой сессией и отказ при неизвестном IPv6.
Linux runtime новых lease-тестов остаётся открытым; статус раздела не меняется.

[Q25-F048–F049](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md): положительное доказательство
ipv6.disable=1 разрешает пропустить IPv6 firewall; общий lease резервирует TUN всех
Linux-клиентов, включая gateway/exit без kill-switch и dev_attach. 17 новых host-тестов,
3 исходных FAIL → PASS. Runtime Linux и полный PASS раздела остаются открыты.

[Q25-F050–F051](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md): неизвестные владельцы sysctl сохраняются,
acquire/recovery сообщают ошибку; недостоверное наблюдение sysctl не теряет original
для retry. Восемь baseline-регрессий исправлены, 1362 Rust tests PASS. Namespace
identity журнала, реальный Linux runtime и полный PASS раздела остаются открыты.

[Q25-F052–F053](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md): sysctl journal v2 разделяет network namespaces,
проверяет PID/time контекст и procfs до prune; непустой v1 текущего boot-id сохраняется
с явной ошибкой миграции. 24 новых теста, 1386 Rust tests PASS. Реальный Linux,
устойчивость namespace identity после уничтожения объекта и полный PASS остаются открыты.

### 19. DNS сервера и клиентов

**4 октября, Q19 DONE/PASS:** 105 свежих real DNS/tunnel/resolved/crash checks; Q19-V001 закрывает TCP/TC runtime gap. Новых production-багов не найдено; 32 релевантных source hashes, 61 raw file и 9 архивов сверены; неизменённый Q18 Linux/native reuse. [Итог и границы](../reports/audit-0.8.2/AUDIT-Q19-DNS-FINAL.md). Исторические открытые статусы ниже относятся к прежним снимкам.

**Код:** `qeli/src/server/dns.rs`, `qeli/src/server/dns/resolver.rs`, `qeli/src/client/dns.rs`, `qeli/src/transport_core/network.rs`.

UDP/TCP upstream, truncation fallback, timeouts, malformed packets, cache/eviction/blocklist. Full/split, resolved/resolv.conf и OS resolvers, leak v4/v6, failed apply до Connected, crash restore. Custom port/manual IPv6; DoT не объявляется реализованным при отказе валидатора.

**Имеющаяся обвязка/fixtures:** `scripts/test_dns_test_server.py`, `scripts/test_panel_route_dns.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**Проход общего сетевого плана, 22–23 сентября 2026:**
[отчёт Q19/Q22](../reports/audit-0.8.2/AUDIT-Q19-Q22-NETWORK-PLAN.md). Исправлены различия legacy/v2 DNS
и зависимость лимита маршрутов от порядка исключений; убрана устаревшая тестовая
реализация Linux DNS. Это проверка общего планировщика, не завершение всего модуля.
DNS proxy/cache, реальные OS apply/rollback и конкурентный lifecycle остаются открыты.

**Серверный DNS, 23 сентября 2026:** [отчёт Q19](../reports/audit-0.8.2/AUDIT-Q19-DNS-PROXY.md).
Исправлены Q19-F004–F006: TTL NODATA после CNAME, проверка сжатых имён и failover
после TCP TC. Один production engine тестируется локально; 22 DNS-теста с UDP/TCP,
754 Rust-теста суммарно — PASS. Linux lifecycle, расширенные DNS-типы и нагрузочные
проверки остаются открытыми; общий статус раздела не закрыт.

**Кеш и подписанные обмены, 23 сентября 2026:**
[Продолжение Q19](../reports/audit-0.8.2/AUDIT-Q19-DNS-CACHE.md) закрывает Q19-F007–F010:
лимит пакетов кеша 16 МиБ на профиль, пересылка TSIG/SIG(0) без изменения байтов
и кеширования, проверка заголовка/opcode запросов. У старого сценария панели
устранён запуск SSH при импорте. 36 DNS-тестов, 768 Rust-тестов
суммарно — PASS. Реальный Linux lifecycle, длительная конкурентная нагрузка/RSS,
расширенные EDNS/RDATA и внешний стенд подписанных обменов остаются открытыми;
раздел 19 сохраняет статус **IN_PROGRESS**.

**EDNS/RDATA, 23 сентября 2026:**
[Следующий проход Q19](../reports/audit-0.8.2/AUDIT-Q19-DNS-EDNS.md) закрывает Q19-F011–F015:
TTL всех возвращаемых секций, структуру распространённых RDATA, проверку OPT/TLV
и BADVERS, сохранение расширенного RCODE при усечении, обход кеша для EDNS-опций
и новый OPT при обычном cache hit. 51 DNS-тест, включая IPv6 loopback UDP/TCP;
783 Rust-теста суммарно — PASS. Linux lifecycle, длительная нагрузка/RSS,
семантика DNSSEC/RRset, внешняя совместимость и OS DNS apply/rollback остаются открытыми.

**DNS-слушатели и cleanup, 23 сентября 2026:**
[проход Q14/Q19](../reports/audit-0.8.2/AUDIT-Q14-Q19-LIFECYCLE.md): production UDP/TCP listeners
доступны host-тестам; удалён неиспользуемый ServerState. 7 listener + 52 resolver
теста: IPv4/IPv6, persistent/pipelined TCP, deadline, предел 512 соединений,
отмена запросов и повторное занятие портов. 798 Rust-тестов суммарно — PASS.
Общий lifecycle исправлен в Q14-F001–F002; реальный Linux runtime и длительная
нагрузка остаются открытыми.

**Восстановление старого resolver, 23 сентября 2026:**
[Q25-F006](../reports/audit-0.8.2/AUDIT-Q25-DNS-RECOVERY.md): ошибки unlink/chmod и некорректный снимок
больше не считаются успешным восстановлением и не приводят к удалению записи восстановления.
Восемь новых Windows host-тестов проходят; три Unix-сценария только cross-check.
913 host Rust tests PASS. Live Linux DNS и передача ошибок нижележащей очистки ещё открыты.

**Передача ошибок очистки TUN/маршрутов/DNS, 23 сентября 2026:**
[Q25-F007–F009](../reports/audit-0.8.2/AUDIT-Q25-TUN-CLEANUP.md): явная очистка и guards отката передают
ошибки в Linux retry loop через общий ограниченный журнал. Ошибка не становится успешной
остановкой по сигналу и не снимает включённый kill-switch. TunnelSetup владеет guard до ACK
ядра; тип terminal kick сохраняется при сопутствующих ошибках. Восемь новых host-тестов
проходят, два Linux adapter-теста только cross-check. 921 host Rust tests PASS. Live Linux
E2E, сроки выполнения команд и полное ожидание задач поколения ещё открыты.

**Системные команды TUN/DNS, 23 сентября 2026:**
[Q25-F016/F017](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md): 15 секунд на команду, полный
вывод с лимитом 16 МиБ на поток, завершение дочернего процесса и сохранение DNS marker
при отказе. Диагностика больше не обещает неподтверждённый rollback. 986 host Rust tests
PASS; два новых Linux process-group теста только cross-check. Маршруты/firewall, live
Linux и общий deadline shutdown остаются открытыми; статус раздела IN_PROGRESS.

**Очистка NAT, 23 сентября 2026:**
[Q14-F024/F025](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md): конечный проход по снимку правил,
проверка после удаления и диагностика ошибок с продолжением остальных правил/цепочек.
13 новых host-тестов, 999 Rust tests PASS; production Linux только cross-check.
Q14-F026 исправлена [следующим проходом](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Q14-F027 (передача ошибок teardown), сроки firewall-команд и live Linux остаются открытыми.

**Общие firewall-проверки, 23 сентября 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): сервер и Linux
kill-switch используют общий разбор presence/absence/errors; точечная очистка DNS
проверяет границу 1024 и продолжает TCP после отказа UDP. 17 новых host-тестов,
1016 Rust tests PASS; два новых Unix/Linux сценария только cross-check.
Q14-F027, сроки команд и реальные backend/runtime проверки остаются открытыми.

**Владение DNS firewall, 23 сентября 2026:**
[Q14-F028](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md): реестр worker сохраняет точные правила
при ошибке Drop/rollback; cleanup и новая установка повторяют очистку. Tokens защищают
новое поколение от старого lease; активные записи не участвуют в точечном retry.
12 новых host-тестов, 1028 Rust tests PASS; три adapter-регрессии отдельно сравнивают
baseline/fix. Q14-F027, persistent journal, deadlines и live Linux остаются открытыми.

**Итог остановки worker, 23 сентября 2026:**
[Q14-F027, частичное исправление](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md): окончательный
retry известных DNS/IPv6 sysctl leases влияет на Result и код выхода worker. Flush
статистики выполняется после ошибки сети; активные DNS leases обнаруживаются без удаления.
14 новых host-тестов, 1042 Rust tests PASS; восемь отдельных process-exit сценариев PASS.
Дополнительный проход передаёт ошибку worker через внешний supervisor при финальной
остановке: nonzero exit и принудительный kill больше не возвращают Ok. Ещё пять
host-тестов, итог этого этапа 1047 Rust tests PASS; три отдельные supervisor-регрессии PASS.
Следующий проход: [задачи профиля и TUN teardown](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).
Ошибки shutdown JoinSet, TUN queue timeout/panic и удаления устройства теперь входят в
итог worker; 13 новых host-тестов, матрица этого этапа 1060 Rust tests PASS.
[Q14-F029/F030](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md): исправлены ложный успех
sysctl recovery и потеря существующего owner при неудачном повторном acquire;
1060 Rust tests и 7 отдельных fixture checks PASS.
[Q14-F031](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md): частичный IPv6 acquire теперь
регистрируется до первой попытки; любой отказ вызывает rollback, неуспешный откат
сохраняет scope для итоговой очистки. 11 новых регрессий и перенос одного Linux-only
теста: матрица этого этапа 1072 Rust tests PASS; пять отдельных adapter checks PASS.
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): все пять запусков команд server NAT
переведены на общий runner (15 с; 16 МиБ на каждый поток вывода). Timeout не теряет
DNS ownership; матрица этого этапа 1073 Rust tests и шесть отдельных adapter checks PASS.
Открыты generic NAT outcome, старые поколения/retry backoff, restart policy, persistent
journal, общий срок всей операции, остальные системные команды и live Linux.

### 20. DHCP и lease lifecycle

**Код:** `qeli/src/server/dhcp.rs`, `qeli/src/config/server.rs`.

DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE, bad requested_ip, duplicate xid/MAC, expiry и malformed options. NAK не расходует lease, пустой пул не underflow. Только поддерживаемая TAP/IPv4 конфигурация; проверить сохранение через панель.

**Имеющаяся обвязка/fixtures:** `qeli/tests/config_examples.rs`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**4 октября, Q20 завершён:** [отчёт DHCP](../reports/audit-0.8.2/AUDIT-Q20-DHCP-FINAL.md). Пять исправлений;2383 Linux unit PASS/60 ignored;35 смысловых DHCP-проверок и60 запросов заполнения лимита,13 свежих VPN smoke checks;четыре native A/B target. TAP injection проверяет настоящий worker DHCP, а не VPN AUTH/device E2E. Воспроизведены старые malformed OFFER и64-DNS admission;INI-границы описаны.

### 21. TUN/TAP, IP, MTU/PMTU и фрагментация

**4 октября, Q21 завершён:** [TUN/TAP, IP и MTU/PMTU](../reports/audit-0.8.2/AUDIT-Q21-PACKETS-FINAL.md). Новых production-ошибок не подтверждено; семь новых свойств,61 actual-module test,70 сетевых проверок,3 portable checks и два независимо разобранных carrier PCAP PASS. Текущие full unit/Clippy/release/native Q20 и прежний privileged TUN runtime сверены в пределах реального scope. Итого: 21/37 (56,8%), осталось 16; далее Q22.

[Q25-F067–F068](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md): gateway привязан к RouteOwner;
firewall проверяет namespace/TUN внутри операций, cleanup выполняется до закрытия TUN.
При потере TUN правила очищаются в исходном namespace, sysctl scope сохраняется.
13 новых host tests, 1485 Rust PASS; 9 baseline регрессий воспроизведены. Внутренний
sysctl journal/stale recovery и самостоятельные kill-switch операции ещё открыты.

[Q25-F065–F066](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md): setup/roaming route commands
проверяют исходный TUN через Weak и удерживаемый namespace; physical rollback независим.
Потеря identity терминальна, включая callback и последний FIB query. 13 новых host tests,
1472 Rust PASS; четыре новых native tests только скомпилированы. Gateway/firewall/sysctl
внутри callback, physical uplinks и гонка после проверки остаются открыты.

[Q25-F063–F064](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md): route cleanup проверяет
удерживаемый namespace и исходный TUN перед каждой командой; rename/delete/unknown
сохраняет reservations, physical bypass очищается независимо. 13 новых host tests,
1459 Rust PASS; три native route tests только скомпилированы. Гонка после последней
проверки, setup/roaming TUN identity и физические uplinks остаются открыты.

**Код:** `qeli/src/tun`, `qeli/src/protocol/ip.rs`, `qeli/src/protocol/icmp.rs`, `qeli/src/protocol/data_frag.rs`, `qeli/src/protocol/udp_frag.rs`.

TUN host prefixes, TAP ARP/NDP/RA/DAD, unsupported EtherType/VLAN/multicast. MTU 1280/малый outer PMTU, spoofed PTB и смена пути. Reassembly duplicate/overlap/gap/order/expiry/ID reuse, memory cap; PCAP без непредусмотренной внешней фрагментации.

**Имеющаяся обвязка/fixtures:** `scripts/test_tap_ipv6_control_probe.py`, `qeli/fuzz/fuzz_targets/data_frag.rs`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**Отмена shutdown TUN, 23 сентября 2026:** [Q25-F014](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
Общий TunWorkers сохраняет владение Unix TUN/Wintun потоками до join, включая отмену
начатого shutdown и занятый blocking pool. Семь новых host-регрессий; 947 Rust tests PASS.
Unix-тест дескрипторов только кросс-компилирован. Реальные устройства/драйверы и остальные
сценарии раздела не проверены; полный аудит остаётся открытым.

**Системные команды TUN/DNS, 23 сентября 2026:**
[Q25-F016/F017](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md): 15 секунд на команду, полный
вывод с лимитом 16 МиБ на поток, завершение дочернего процесса и сохранение DNS marker
при отказе. Диагностика больше не обещает неподтверждённый rollback. 986 host Rust tests
PASS; два новых Linux process-group теста только cross-check. Маршруты/firewall, live
Linux и общий deadline shutdown остаются открытыми; статус раздела IN_PROGRESS.

[Q25-F054–F056](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md): удалено разрушающее восстановление TUN
по неполному списку PID. Клиент пассивно ждёт освобождения имени и отказывает при
ошибке lookup/смене ifindex; клиент и сервер создают первую очередь эксклюзивно.
Остальные очереди используют её фактическое имя. 20 новых тестов, 7 baseline FAIL,
1406 Rust tests PASS. Исправлена сборка Linux-тестов без server feature.
Attach/teardown races и реальный Linux остаются открыты.

[Q25-F057–F058](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md): attach и дополнительные очереди
не регистрируют замену исчезнувшего TUN; ошибка TUNSETIFINDEX останавливает открытие.
VNET_HDR/неизвестные features отклоняются, поддерживаемые флаги сохраняются.
18 новых host-тестов + прежний parser-тест, 1425 Rust PASS; три новых Linux ioctl
теста только скомпилированы. Следующий проход владения зафиксирован ниже.

[Q25-F059–F060](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md): удаление TUN по имени устранено.
Guards клиента/сервера сохраняют исходные fd до очистки сети; setup rollback заимствует
устройство. 12 сценариев с извлечённым кодом PASS (baseline 7 FAIL / 5 PASS), 1425 Rust PASS.
Три новых native Linux-теста только скомпилированы. Внешние rename/delete,
identity DNS-маркеров/маршрутов и Q14-F027 остаются открытыми.

[Q25-F061–F062](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md): DNS сбрасывает только владеющее им
поколение. Namespace/index journal и неблокирующий lock заменяют маркеры по имени;
перед числовыми resolver-командами проверяется исходный fd. Startup не сбрасывает живой
link только по сохранённому маркеру. 24 новых host-теста, 1446 Rust PASS; guard harness
baseline 3 FAIL / 3 PASS, fixed 6 PASS. Native namespace-тест только скомпилирован.
Identity маршрутов, namespace resolver-сервиса и reuse индекса после проверки остаются открыты.

### 22. Transport core, FFI/JNI и память

**4 октября, Q22 завершён:** [transport core, FFI/JNI и память](../reports/audit-0.8.2/AUDIT-Q22-CORE-FFI-FINAL.md). Q22-F001/F002 закрывают queued access после panic и отменяют leased runner до удаления handle. Два baseline-отказа воспроизведены; 2402 full-feature units, strict Clippy, 22 Windows C ABI, 23 actual Android JNI, C11/C++11 headers и четыре native A/B PASS. CLI Linux побайтно прежний, сетевые execution сохраняют свой scope. Итого: 22/37 (59,5%), осталось 15; далее Q23.

[Q25-F067–F068](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md): gateway привязан к RouteOwner;
firewall проверяет namespace/TUN внутри операций, cleanup выполняется до закрытия TUN.
При потере TUN правила очищаются в исходном namespace, sysctl scope сохраняется.
13 новых host tests, 1485 Rust PASS; 9 baseline регрессий воспроизведены. Внутренний
sysctl journal/stale recovery и самостоятельные kill-switch операции ещё открыты.

[Q25-F065–F066](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md): setup/roaming route commands
проверяют исходный TUN через Weak и удерживаемый namespace; physical rollback независим.
Потеря identity терминальна, включая callback и последний FIB query. 13 новых host tests,
1472 Rust PASS; четыре новых native tests только скомпилированы. Gateway/firewall/sysctl
внутри callback, physical uplinks и гонка после проверки остаются открыты.

[Q25-F063–F064](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md): route cleanup проверяет
удерживаемый namespace и исходный TUN перед каждой командой; rename/delete/unknown
сохраняет reservations, physical bypass очищается независимо. 13 новых host tests,
1459 Rust PASS; три native route tests только скомпилированы. Гонка после последней
проверки, setup/roaming TUN identity и физические uplinks остаются открыты.

**Код:** `qeli/src/transport_core`, `qeli/include/qeli_transport_core.h`, `native-libs`.

Create/start/PREPARE/APPLY/COMMIT/stop/free, callbacks, buffers, queues, cancellation/generation. Stale handle, double-free, callback после dispose, partial failure, ABI/feature mismatch. Packaged cores должны соответствовать исходникам, а не только успешно загружаться.

**Имеющаяся обвязка/fixtures:** `scripts/test_native_repro.py`, `native-libs/provenance.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**Проход общего сетевого плана, 22–23 сентября 2026:**
[отчёт Q19/Q22](../reports/audit-0.8.2/AUDIT-Q19-Q22-NETWORK-PLAN.md). Исправлены различия legacy/v2 DNS
и зависимость лимита маршрутов от порядка исключений; убрана устаревшая тестовая
реализация Linux DNS. Это проверка общего планировщика, не завершение всего модуля.
DNS proxy/cache, реальные OS apply/rollback и конкурентный lifecycle остаются открыты.

**Владение задачами TCP и Linux path monitor, 23 сентября 2026:**
[Q25-F010/F011](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md): общий владелец закрывает создание задач
до abort/join. TCP reader/writer/pipeline и producers завершаются до сетевой очистки;
ошибка управляющего события также проходит teardown. Linux blocking-работы монитора
учитываются для TCP и UDP. 931 host Rust tests PASS; Linux только cross-check. Остальные
UDP-задачи, вложенные transport workers, полная отмена и сроки команд остаются открытыми.

**Владение UDP-задачами и порядок отката, 23 сентября 2026:**
[Q25-F012/F013](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md): active/candidate/draining receive,
candidate-connect и Linux-монитор принадлежат одной группе. Ошибка управляющего события
проходит штатную очистку; группа завершается до проверки/отката платформенного кандидата.
TaskHandle сохраняет обязанность join при отмене ожидания или переносе пути. Девять новых
регрессий; 940 host Rust tests PASS, Linux только cross-check. Открыты вложенные transport
workers, принудительная отмена, сроки команд и платформенные fault-injection сценарии.

**Отмена shutdown TUN, 23 сентября 2026:** [Q25-F014](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
Общий TunWorkers сохраняет владение Unix TUN/Wintun потоками до join, включая отмену
начатого shutdown и занятый blocking pool. Семь новых host-регрессий; 947 Rust tests PASS.
Unix-тест дескрипторов только кросс-компилирован. Реальные устройства/драйверы и остальные
сценарии раздела не проверены; полный аудит остаётся открытым.

**Вложенные H2-задачи, 23 сентября 2026:** [Q25-F015](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
TCP-группа создаётся до connect и ждёт driver/bridge; native runner сохраняет её при
отмене попытки. Девять новых регрессий, 956 Rust tests PASS; Linux только cross-check.
Серверный H2 проверен далее в [Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).
Standalone H2, ранний platform rollback, UDP cancellation и deadlines остаются открытыми.

**Серверный H2 и pre-auth, 23 сентября 2026:**
[Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md): профиль ждёт вложенные H2-задачи перед
teardown; flush отказа сохраняет pre-auth slot до освобождения I/O. 13 новых регрессий,
969 Rust tests PASS. H2/ProfileTasks/semaphore проверены на host, production Linux только
кросс-компилирован. Остальные сценарии раздела и live Linux E2E остаются открытыми.

**Команды Linux-монитора, 23 сентября 2026:** [Q25-F020](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md):
три read-only запроса маршрутов/адресов используют общий runner со сроком 15 секунд
и лимитами вывода. TaskGroup сохраняет владение blocking-командой при остановке;
ошибка sample не публикует PathUpdate. 1098 Rust tests и 23 production-adapter сценария PASS.
Мутации маршрутов, общий срок остановки и реальный Linux handover остаются открытыми.

**Gateway WAN, 23 сентября 2026:** [Q25-F021/F022](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-WAN.md):
IPv4/IPv6 default-route и fallback используют общий runner с ограничениями; cleanup
ищет WAN только при отсутствии сохранённых целей семейства. Семь новых переносимых
регрессий, 1105 Rust tests и 33 отдельных adapter-сценария PASS. Реальный Linux firewall
и ownership при неизвестном результате мутации остаются открытыми.

**Неуспешные мутации маршрутов, 23 сентября 2026:**
[Q25-F023/F024](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md): failed add/replace/retirement
считается обратимым только после подтверждения неизменности destination; недоступный,
изменённый или многострочный снимок даёт unknown state. 15 новых регрессий и восемь
существующих route-тестов теперь исполняются на host; 1128 Rust tests PASS.
Baseline: 10 ожидаемых отказов и 5 controls. Pending ownership/recovery неопределённого
маршрута, сроки команд и реальный Linux остаются открытыми.

**Владение маршрутами и cleanup, 23 сентября 2026:**
[Q25-F025/F026](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md): журнал сохраняет переданные
параметры удаления; устаревшая identity не разрешает replace/retirement/rollback.
Очистка подтверждает отсутствие и сохраняет неудачные записи для retry.
16 новых регрессий; 1144 Rust tests PASS. Те же adapter-тесты воспроизводят 15 отказов
baseline и один control. Общий для процесса ownership, неизвестные pending мутации,
атомарная identity, сроки команд и реальный Linux остаются открытыми.

**Изоляция маршрутов, 23 сентября 2026:**
[Q25-F027/F028](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md): уникальный owner передаётся setup,
guards и roaming; cleanup закрывает приём и обрабатывает только его записи.
Другой Qeli owner не может заимствовать маршрут; повтор имени TUN заблокирован до
завершения прежнего lease. 17 новых регрессий, 1161 Rust tests PASS; baseline — два
целевых отказа. Attach-mode не объявляет managed roaming. Межпроцессная изоляция,
осиротевшие/pending операции, TUN workers, deadlines и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — результаты retirement/restore:**
[Q25-F029/F030](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md): удаление требует
подтверждённого отсутствия, восстановление — полного прежнего снимка. Потерянный
результат не отменяет подтверждённое действие, ложный успех не подтверждает откат.
16 новых baseline failures → 16 PASS; общий набор 1177 Rust tests, девять команд
матрицы PASS. Linux runtime не запускался. Pending unknown/orphan recovery,
межпроцессные гонки и сроки команд остаются открытыми; статус раздела не изменён.

**Дополнение 2026-09-23 — pending и orphan:**
[Q25-F031/F032](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md): неопределённая roaming-операция
сохраняет reservation без права delete; любой неизвестный commit закрывает admission.
Cleanup/reconnect освобождает pending/orphan только после подтверждения отсутствия,
с отдельными условиями для финального lease и interface flush. 17 новых регрессий/
controls; 1194 Rust tests и девять команд матрицы PASS. Initial setup mutations,
flush postconditions, постоянный crash recovery, deadlines и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — initial setup и flush:**
[Q25-F033/F034](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md): carrier/exclude/blackhole используют
общие exact pre/post checks и pending при неизвестном результате. Обе семьи interface
flush требуют подтверждения пустого состояния либо отсутствующего интерфейса через
link inventory. 8 baseline failures → PASS, ещё 13 controls; 1214 Rust tests и девять
команд матрицы PASS. Linux runtime, command deadlines, остальные route paths,
постоянный crash recovery и Q14-F027 workers/FD остаются открытыми.

**Дополнение 2026-09-23 — ограниченные route/firewall-команды:**
[Q25-F035/F036](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md): route и kill-switch используют
общий runner: 15 секунд на команду, по 16 МиБ stdout/stderr. Gateway наследует пределы
через iptables-helper. Unknown outcome сохраняет pending/проверки; неизвестный IPv4
default route требует защиты при отсутствии явного allow_ipv4_leak.
20 новых тестов; 1234 Rust tests и девять команд матрицы PASS. Общий deadline транзакции,
прочие route ownership paths, gateway rollback и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — TUN/TAP, pushed и local routes:**
[Q25-F037–F039](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md): активный NetworkPlan installer
использует общие exact pre/post checks, проверку метрик и ownership/pending.
Старые невызываемые pushed/local implementations и второй parser удалены.
Повреждённый inventory route_local запрещает мутации. Pending сверяется после
независимого flush принадлежащего Qeli интерфейса. 10 воспроизводящих регрессий и
13 controls; 1257 Rust tests и девять команд матрицы PASS. Gateway rollback, globals,
общий deadline, crash recovery и Linux runtime остаются открытыми.

### 23. Роуминг, resume и CONTROL_V2

**4 октября, Q23 завершён:** [роуминг, resume и CONTROL_V2](../reports/audit-0.8.2/AUDIT-Q23-ROAMING-FINAL.md). Q23-F001 восстанавливает таймер исходного grace после abort подготовленного resume. 2405 units, strict Clippy, 24 целевых теста, 12 свежих Linux сценариев/281 проверок и четыре native A/B PASS. Итого: 23/37 (62,2%), осталось 14; далее Q24.

**Код:** `qeli/src/protocol/roaming.rs`, `qeli/src/protocol/control_v2.rs`, `qeli/src/transport_core`.

TCP make-before-break/UDP migration: proof/path validation, anti-amplification, grace expiry, replay/revoke и candidate races. NAT rebinding, family switch, Wi-Fi/LTE, sleep/wake, server restart/APPLY rollback, PMTU reset. Проверить межсерверные границы; одна константа PUSH_CONFIG не доказывает реализацию.

**Имеющаяся обвязка/fixtures:** `scripts/roaming_tcp_all_modes_netns_e2e.sh`, `scripts/roaming_udp_all_modes_netns_e2e.sh`, `scripts/roaming_mixed_version_netns_e2e.sh`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**Владение задачами TCP и Linux path monitor, 23 сентября 2026:**
[Q25-F010/F011](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md): общий владелец закрывает создание задач
до abort/join. TCP reader/writer/pipeline и producers завершаются до сетевой очистки;
ошибка управляющего события также проходит teardown. Linux blocking-работы монитора
учитываются для TCP и UDP. 931 host Rust tests PASS; Linux только cross-check. Остальные
UDP-задачи, вложенные transport workers, полная отмена и сроки команд остаются открытыми.

**Владение UDP-задачами и порядок отката, 23 сентября 2026:**
[Q25-F012/F013](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md): active/candidate/draining receive,
candidate-connect и Linux-монитор принадлежат одной группе. Ошибка управляющего события
проходит штатную очистку; группа завершается до проверки/отката платформенного кандидата.
TaskHandle сохраняет обязанность join при отмене ожидания или переносе пути. Девять новых
регрессий; 940 host Rust tests PASS, Linux только cross-check. Открыты вложенные transport
workers, принудительная отмена, сроки команд и платформенные fault-injection сценарии.

**Вложенные H2-задачи, 23 сентября 2026:** [Q25-F015](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
TCP-группа создаётся до connect и ждёт driver/bridge; native runner сохраняет её при
отмене попытки. Девять новых регрессий, 956 Rust tests PASS; Linux только cross-check.
Серверный H2 проверен далее в [Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).
Standalone H2, ранний platform rollback, UDP cancellation и deadlines остаются открытыми.

**Команды Linux-монитора, 23 сентября 2026:** [Q25-F020](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md):
три read-only запроса маршрутов/адресов используют общий runner со сроком 15 секунд
и лимитами вывода. TaskGroup сохраняет владение blocking-командой при остановке;
ошибка sample не публикует PathUpdate. 1098 Rust tests и 23 production-adapter сценария PASS.
Мутации маршрутов, общий срок остановки и реальный Linux handover остаются открытыми.

**Неуспешные мутации маршрутов, 23 сентября 2026:**
[Q25-F023/F024](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md): failed add/replace/retirement
считается обратимым только после подтверждения неизменности destination; недоступный,
изменённый или многострочный снимок даёт unknown state. 15 новых регрессий и восемь
существующих route-тестов теперь исполняются на host; 1128 Rust tests PASS.
Baseline: 10 ожидаемых отказов и 5 controls. Pending ownership/recovery неопределённого
маршрута, сроки команд и реальный Linux остаются открытыми.

**Владение маршрутами и cleanup, 23 сентября 2026:**
[Q25-F025/F026](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md): журнал сохраняет переданные
параметры удаления; устаревшая identity не разрешает replace/retirement/rollback.
Очистка подтверждает отсутствие и сохраняет неудачные записи для retry.
16 новых регрессий; 1144 Rust tests PASS. Те же adapter-тесты воспроизводят 15 отказов
baseline и один control. Общий для процесса ownership, неизвестные pending мутации,
атомарная identity, сроки команд и реальный Linux остаются открытыми.

**Изоляция маршрутов, 23 сентября 2026:**
[Q25-F027/F028](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md): уникальный owner передаётся setup,
guards и roaming; cleanup закрывает приём и обрабатывает только его записи.
Другой Qeli owner не может заимствовать маршрут; повтор имени TUN заблокирован до
завершения прежнего lease. 17 новых регрессий, 1161 Rust tests PASS; baseline — два
целевых отказа. Attach-mode не объявляет managed roaming. Межпроцессная изоляция,
осиротевшие/pending операции, TUN workers, deadlines и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — результаты retirement/restore:**
[Q25-F029/F030](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md): удаление требует
подтверждённого отсутствия, восстановление — полного прежнего снимка. Потерянный
результат не отменяет подтверждённое действие, ложный успех не подтверждает откат.
16 новых baseline failures → 16 PASS; общий набор 1177 Rust tests, девять команд
матрицы PASS. Linux runtime не запускался. Pending unknown/orphan recovery,
межпроцессные гонки и сроки команд остаются открытыми; статус раздела не изменён.

**Дополнение 2026-09-23 — pending и orphan:**
[Q25-F031/F032](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md): неопределённая roaming-операция
сохраняет reservation без права delete; любой неизвестный commit закрывает admission.
Cleanup/reconnect освобождает pending/orphan только после подтверждения отсутствия,
с отдельными условиями для финального lease и interface flush. 17 новых регрессий/
controls; 1194 Rust tests и девять команд матрицы PASS. Initial setup mutations,
flush postconditions, постоянный crash recovery, deadlines и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — initial setup и flush:**
[Q25-F033/F034](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md): carrier/exclude/blackhole используют
общие exact pre/post checks и pending при неизвестном результате. Обе семьи interface
flush требуют подтверждения пустого состояния либо отсутствующего интерфейса через
link inventory. 8 baseline failures → PASS, ещё 13 controls; 1214 Rust tests и девять
команд матрицы PASS. Linux runtime, command deadlines, остальные route paths,
постоянный crash recovery и Q14-F027 workers/FD остаются открытыми.

**Дополнение 2026-09-23 — ограниченные route/firewall-команды:**
[Q25-F035/F036](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md): route и kill-switch используют
общий runner: 15 секунд на команду, по 16 МиБ stdout/stderr. Gateway наследует пределы
через iptables-helper. Unknown outcome сохраняет pending/проверки; неизвестный IPv4
default route требует защиты при отсутствии явного allow_ipv4_leak.
20 новых тестов; 1234 Rust tests и девять команд матрицы PASS. Общий deadline транзакции,
прочие route ownership paths, gateway rollback и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — TUN/TAP, pushed и local routes:**
[Q25-F037–F039](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md): активный NetworkPlan installer
использует общие exact pre/post checks, проверку метрик и ownership/pending.
Старые невызываемые pushed/local implementations и второй parser удалены.
Повреждённый inventory route_local запрещает мутации. Pending сверяется после
независимого flush принадлежащего Qeli интерфейса. 10 воспроизводящих регрессий и
13 controls; 1257 Rust tests и девять команд матрицы PASS. Gateway rollback, globals,
общий deadline, crash recovery и Linux runtime остаются открытыми.

### 24. Multipath, bonding и общий бюджет

**Код:** `qeli/src/client/mod.rs`, `qeli/src/transport_core/buffer_pool.rs`, `qeli/src/transport_core/carrier.rs`, `qeli/src/transport_core/session.rs`, `qeli/src/server/handler.rs`.

JOIN proof, stream caps, asymmetric RTT/loss, отказ одного/всех путей, ordering/starvation. Bandwidth/quota/buffer cap не умножается на streams. Resume/reconnect/stream close сохраняют корректную сессию и освобождают лишние carriers.

**Имеющаяся обвязка/fixtures:** `scripts/roaming_netns_e2e.sh`, `scripts/roaming_tcp_bonding_netns_case.sh`, `scripts/roaming_tcp_starvation_netns_case.sh`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS.**

**4 октября — Q24 завершён:** [отчёт](../reports/audit-0.8.2/AUDIT-Q24-BONDING.md). Q24-F001
устраняет starvation общего пула с обеих сторон. 2407 units/60 ignored, строгий
Clippy, release, 12 Linux сценариев/283 проверки, 4 native A/B, 22 Windows ABI
и 23 JNI проверки PASS. Исторический throughput не повторялся. Итог: 24/37 (64,9%); далее Q25.

**Владение задачами TCP и Linux path monitor, 23 сентября 2026:**
[Q25-F010/F011](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md): общий владелец закрывает создание задач
до abort/join. TCP reader/writer/pipeline и producers завершаются до сетевой очистки;
ошибка управляющего события также проходит teardown. Linux blocking-работы монитора
учитываются для TCP и UDP. 931 host Rust tests PASS; Linux только cross-check. Остальные
UDP-задачи, вложенные transport workers, полная отмена и сроки команд остаются открытыми.

**Владение UDP-задачами и порядок отката, 23 сентября 2026:**
[Q25-F012/F013](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md): active/candidate/draining receive,
candidate-connect и Linux-монитор принадлежат одной группе. Ошибка управляющего события
проходит штатную очистку; группа завершается до проверки/отката платформенного кандидата.
TaskHandle сохраняет обязанность join при отмене ожидания или переносе пути. Девять новых
регрессий; 940 host Rust tests PASS, Linux только cross-check. Открыты вложенные transport
workers, принудительная отмена, сроки команд и платформенные fault-injection сценарии.

**Вложенные H2-задачи, 23 сентября 2026:** [Q25-F015](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
TCP-группа создаётся до connect и ждёт driver/bridge; native runner сохраняет её при
отмене попытки. Девять новых регрессий, 956 Rust tests PASS; Linux только cross-check.
Серверный H2 проверен далее в [Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).
Standalone H2, ранний platform rollback, UDP cancellation и deadlines остаются открытыми.

### 25. Linux CLI и восстановление сети

**Сверка 4 октября:** [итог Q25](../reports/audit-0.8.2/AUDIT-Q25-LINUX-CLI-FINAL.md). F216/F217 исправлены; 2414 unit, 26 CLI/68 checks, 2 connected/32 checks и четыре fresh A/B пары PASS. Неизменённые сетевые реализации сверены по SHA/точному shared prefix; прежние recovery/soak scopes и D06 accepted limitation сохранены. Исторические открытые формулировки ниже относятся к прежним снимкам.

[Q25-F067–F068](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md): gateway привязан к RouteOwner;
firewall проверяет namespace/TUN внутри операций, cleanup выполняется до закрытия TUN.
При потере TUN правила очищаются в исходном namespace, sysctl scope сохраняется.
13 новых host tests, 1485 Rust PASS; 9 baseline регрессий воспроизведены. Внутренний
sysctl journal/stale recovery и самостоятельные kill-switch операции ещё открыты.

[Q25-F065–F066](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md): setup/roaming route commands
проверяют исходный TUN через Weak и удерживаемый namespace; physical rollback независим.
Потеря identity терминальна, включая callback и последний FIB query. 13 новых host tests,
1472 Rust PASS; четыре новых native tests только скомпилированы. Gateway/firewall/sysctl
внутри callback, physical uplinks и гонка после проверки остаются открыты.

[Q25-F063–F064](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md): route cleanup проверяет
удерживаемый namespace и исходный TUN перед каждой командой; rename/delete/unknown
сохраняет reservations, physical bypass очищается независимо. 13 новых host tests,
1459 Rust PASS; три native route tests только скомпилированы. Гонка после последней
проверки, setup/roaming TUN identity и физические uplinks остаются открыты.

**Код:** `qeli/src/client`, `qeli/src/client_main.rs`, `qeli/src/hooks.rs`.

Endpoint route pin/same-LAN, full/split, include/exclude, leak policy/kill switch. Stop/SIGTERM/SIGKILL/reconnect/failed setup: before/after routes/DNS/firewall без удаления чужого состояния. Trusted hooks/password_command, subprocess deadlines, честный cleanup status.

**Имеющаяся обвязка/fixtures:** `scripts/test_gateway_nat.py`, `scripts/test_tun_reclaim.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE / PASS.**

**Поставщик пароля и изоляция features, 23 сентября 2026:**
[Q25-F001 / Q33-F002 / Q14-F020 / Q34-F001](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md):
асинхронный password_command, deadline 30 секунд, полный stdout до 16 KiB, отброшенный
stderr и ошибки без секретов. Ранний SIGINT/SIGTERM отменяет и собирает поставщика;
watchers/sampler клиента имеют владельца. Исправлен server-only TUN gate, обе изолированные
features проверяются в CI. 883 host Rust tests PASS; четыре Linux-теста только cross-check.
Server-only check имеет 23 прежних transport dead-code warnings. Лимиты password_file,
финальный drain клиента и Linux runtime/release checks ещё открыты.

**Файловый пароль и финальный статус, 23 сентября 2026:**
[Q25-F002 / Q14-F021](../reports/audit-0.8.2/AUDIT-Q25-PASSWORD-FILES.md): общий zeroizing-буфер 16 KiB
для файла/команды, одна управляемая blocking-задача чтения обычного файла, поддержка symlink,
отказ FIFO и ожидание активного I/O при штатном stop/deadline. Final пишется после join
watchers/sampler, включая ошибки после инициализации reporter. 895 host Rust tests PASS;
два Unix-теста только cross-check. Неотменяемый I/O может превышать бюджет 30 секунд.
Startup/network rollback, мониторинг фоновых ошибок и Linux E2E ещё открыты.

**Fail-closed очистка сети, 23 сентября 2026:**
[Q25-F003](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-CLEANUP.md): forwarding/NAT cleanup должен
завершиться успешно до снятия включённого kill-switch; ошибка сохраняет защиту и её причину.
899 host Rust tests PASS, включая четыре переносимых fault-injection сценария. Linux
пока только cross-check. Разбор begin_connection записан ниже; live firewall/E2E ещё открыты.

**Ошибки жизненного цикла ядра, 23 сентября 2026:**
[Q25-F004/F005](../reports/audit-0.8.2/AUDIT-Q25-CORE-LIFECYCLE.md): ошибка запуска ядра проходит через
cleanup/post_down; ошибка остановки завершается отказом и сохраняет включённый kill-switch,
при этом очистка forwarding выполняется. Шесть новых host-регрессий, включая реальный отказ
ClientCore при полной очереди. 905 host Rust tests PASS; Linux только cross-check.
Live Linux lifecycle/firewall и полный rollback маршрутов/DNS ещё открыты.

**Восстановление старого resolver, 23 сентября 2026:**
[Q25-F006](../reports/audit-0.8.2/AUDIT-Q25-DNS-RECOVERY.md): ошибки unlink/chmod и некорректный снимок
больше не считаются успешным восстановлением и не приводят к удалению записи восстановления.
Восемь новых Windows host-тестов проходят; три Unix-сценария только cross-check.
913 host Rust tests PASS. Live Linux DNS и передача ошибок нижележащей очистки ещё открыты.

**Передача ошибок очистки TUN/маршрутов/DNS, 23 сентября 2026:**
[Q25-F007–F009](../reports/audit-0.8.2/AUDIT-Q25-TUN-CLEANUP.md): явная очистка и guards отката передают
ошибки в Linux retry loop через общий ограниченный журнал. Ошибка не становится успешной
остановкой по сигналу и не снимает включённый kill-switch. TunnelSetup владеет guard до ACK
ядра; тип terminal kick сохраняется при сопутствующих ошибках. Восемь новых host-тестов
проходят, два Linux adapter-теста только cross-check. 921 host Rust tests PASS. Live Linux
E2E, сроки выполнения команд и полное ожидание задач поколения ещё открыты.

**Владение задачами TCP и Linux path monitor, 23 сентября 2026:**
[Q25-F010/F011](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md): общий владелец закрывает создание задач
до abort/join. TCP reader/writer/pipeline и producers завершаются до сетевой очистки;
ошибка управляющего события также проходит teardown. Linux blocking-работы монитора
учитываются для TCP и UDP. 931 host Rust tests PASS; Linux только cross-check. Остальные
UDP-задачи, вложенные transport workers, полная отмена и сроки команд остаются открытыми.

**Владение UDP-задачами и порядок отката, 23 сентября 2026:**
[Q25-F012/F013](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md): active/candidate/draining receive,
candidate-connect и Linux-монитор принадлежат одной группе. Ошибка управляющего события
проходит штатную очистку; группа завершается до проверки/отката платформенного кандидата.
TaskHandle сохраняет обязанность join при отмене ожидания или переносе пути. Девять новых
регрессий; 940 host Rust tests PASS, Linux только cross-check. Открыты вложенные transport
workers, принудительная отмена, сроки команд и платформенные fault-injection сценарии.

**Отмена shutdown TUN, 23 сентября 2026:** [Q25-F014](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
Общий TunWorkers сохраняет владение Unix TUN/Wintun потоками до join, включая отмену
начатого shutdown и занятый blocking pool. Семь новых host-регрессий; 947 Rust tests PASS.
Unix-тест дескрипторов только кросс-компилирован. Реальные устройства/драйверы и остальные
сценарии раздела не проверены; полный аудит остаётся открытым.

**Вложенные H2-задачи, 23 сентября 2026:** [Q25-F015](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
TCP-группа создаётся до connect и ждёт driver/bridge; native runner сохраняет её при
отмене попытки. Девять новых регрессий, 956 Rust tests PASS; Linux только cross-check.
Серверный H2 проверен далее в [Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).
Standalone H2, ранний platform rollback, UDP cancellation и deadlines остаются открытыми.

**Системные команды TUN/DNS, 23 сентября 2026:**
[Q25-F016/F017](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md): 15 секунд на команду, полный
вывод с лимитом 16 МиБ на поток, завершение дочернего процесса и сохранение DNS marker
при отказе. Диагностика больше не обещает неподтверждённый rollback. 986 host Rust tests
PASS; два новых Linux process-group теста только cross-check. Маршруты/firewall, live
Linux и общий deadline shutdown остаются открытыми; статус раздела IN_PROGRESS.

**Общие firewall-проверки, 23 сентября 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): сервер и Linux
kill-switch используют общий разбор presence/absence/errors; точечная очистка DNS
проверяет границу 1024 и продолжает TCP после отказа UDP. 17 новых host-тестов,
1016 Rust tests PASS; два новых Unix/Linux сценария только cross-check.
Q14-F027, сроки команд и реальные backend/runtime проверки остаются открытыми.

**Продолжение серверного слоя:**
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): все пять запусков команд server NAT
переведены на общий runner (15 с; 16 МиБ на каждый поток вывода). Timeout не теряет
DNS ownership; матрица этого этапа 1073 Rust tests и шесть отдельных adapter checks PASS.
Открыты generic NAT outcome, старые поколения/retry backoff, restart policy, persistent
journal, общий срок всей операции, остальные системные команды и live Linux.

**Команды Linux-монитора, 23 сентября 2026:** [Q25-F020](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md):
три read-only запроса маршрутов/адресов используют общий runner со сроком 15 секунд
и лимитами вывода. TaskGroup сохраняет владение blocking-командой при остановке;
ошибка sample не публикует PathUpdate. 1098 Rust tests и 23 production-adapter сценария PASS.
Мутации маршрутов, общий срок остановки и реальный Linux handover остаются открытыми.

**Gateway WAN, 23 сентября 2026:** [Q25-F021/F022](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-WAN.md):
IPv4/IPv6 default-route и fallback используют общий runner с ограничениями; cleanup
ищет WAN только при отсутствии сохранённых целей семейства. Семь новых переносимых
регрессий, 1105 Rust tests и 33 отдельных adapter-сценария PASS. Реальный Linux firewall
и ownership при неизвестном результате мутации остаются открытыми.

**Неуспешные мутации маршрутов, 23 сентября 2026:**
[Q25-F023/F024](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md): failed add/replace/retirement
считается обратимым только после подтверждения неизменности destination; недоступный,
изменённый или многострочный снимок даёт unknown state. 15 новых регрессий и восемь
существующих route-тестов теперь исполняются на host; 1128 Rust tests PASS.
Baseline: 10 ожидаемых отказов и 5 controls. Pending ownership/recovery неопределённого
маршрута, сроки команд и реальный Linux остаются открытыми.

**Владение маршрутами и cleanup, 23 сентября 2026:**
[Q25-F025/F026](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md): журнал сохраняет переданные
параметры удаления; устаревшая identity не разрешает replace/retirement/rollback.
Очистка подтверждает отсутствие и сохраняет неудачные записи для retry.
16 новых регрессий; 1144 Rust tests PASS. Те же adapter-тесты воспроизводят 15 отказов
baseline и один control. Общий для процесса ownership, неизвестные pending мутации,
атомарная identity, сроки команд и реальный Linux остаются открытыми.

**Изоляция маршрутов, 23 сентября 2026:**
[Q25-F027/F028](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md): уникальный owner передаётся setup,
guards и roaming; cleanup закрывает приём и обрабатывает только его записи.
Другой Qeli owner не может заимствовать маршрут; повтор имени TUN заблокирован до
завершения прежнего lease. 17 новых регрессий, 1161 Rust tests PASS; baseline — два
целевых отказа. Attach-mode не объявляет managed roaming. Межпроцессная изоляция,
осиротевшие/pending операции, TUN workers, deadlines и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — результаты retirement/restore:**
[Q25-F029/F030](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md): удаление требует
подтверждённого отсутствия, восстановление — полного прежнего снимка. Потерянный
результат не отменяет подтверждённое действие, ложный успех не подтверждает откат.
16 новых baseline failures → 16 PASS; общий набор 1177 Rust tests, девять команд
матрицы PASS. Linux runtime не запускался. Pending unknown/orphan recovery,
межпроцессные гонки и сроки команд остаются открытыми; статус раздела не изменён.

**Дополнение 2026-09-23 — pending и orphan:**
[Q25-F031/F032](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md): неопределённая roaming-операция
сохраняет reservation без права delete; любой неизвестный commit закрывает admission.
Cleanup/reconnect освобождает pending/orphan только после подтверждения отсутствия,
с отдельными условиями для финального lease и interface flush. 17 новых регрессий/
controls; 1194 Rust tests и девять команд матрицы PASS. Initial setup mutations,
flush postconditions, постоянный crash recovery, deadlines и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — initial setup и flush:**
[Q25-F033/F034](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md): carrier/exclude/blackhole используют
общие exact pre/post checks и pending при неизвестном результате. Обе семьи interface
flush требуют подтверждения пустого состояния либо отсутствующего интерфейса через
link inventory. 8 baseline failures → PASS, ещё 13 controls; 1214 Rust tests и девять
команд матрицы PASS. Linux runtime, command deadlines, остальные route paths,
постоянный crash recovery и Q14-F027 workers/FD остаются открытыми.

**Дополнение 2026-09-23 — ограниченные route/firewall-команды:**
[Q25-F035/F036](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md): route и kill-switch используют
общий runner: 15 секунд на команду, по 16 МиБ stdout/stderr. Gateway наследует пределы
через iptables-helper. Unknown outcome сохраняет pending/проверки; неизвестный IPv4
default route требует защиты при отсутствии явного allow_ipv4_leak.
20 новых тестов; 1234 Rust tests и девять команд матрицы PASS. Общий deadline транзакции,
прочие route ownership paths, gateway rollback и Linux runtime остаются открытыми.

**Дополнение 2026-09-23 — TUN/TAP, pushed и local routes:**
[Q25-F037–F039](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md): активный NetworkPlan installer
использует общие exact pre/post checks, проверку метрик и ownership/pending.
Старые невызываемые pushed/local implementations и второй parser удалены.
Повреждённый inventory route_local запрещает мутации. Pending сверяется после
независимого flush принадлежащего Qeli интерфейса. 10 воспроизводящих регрессий и
13 controls; 1257 Rust tests и девять команд матрицы PASS. Gateway rollback, globals,
общий deadline, crash recovery и Linux runtime остаются открытыми.

**Откат gateway и защита, 23 сентября 2026:**
[Q25-F040–F042](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md): записи TUN/семья/подсеть
заменяют общие флаги и undo по текущему конфигу. Ошибка семьи сохраняет состояние
для повтора; ошибка проверки firewall запрещает вставку, повторно используемый
permit тоже проверяет порядок kill-switch. Router-операции удерживают общую
блокировку процесса до release sysctl. Восемь исходных FAIL → PASS; 25 новых теста
и пять существующих, впервые включённых на host; 1287 Rust tests и девять команд
матрицы PASS. Общий WAN/NAT exit-node, несколько kill-switch chains, межпроцессные
гонки, общий deadline и Linux runtime остаются открытыми.

**Exit NAT и допуск kill-switch, 23 сентября 2026:**
[Q25-F043–F045](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md): NAT-комментарии различают
правила TUN/WAN; cleanup больше не обнаруживает цели без записанного владения.
Запуск kill-switch проверяет обе семьи до изменений и отвергает чужую/старую Qeli
chain. Carrier первого остаётся доступен; конкурентные запуски одного процесса
принимают одну политику. 13 исходных FAIL → PASS; 30 новых тестов, два устаревших
helper-теста удалены. 1315 Rust tests и девять команд матрицы PASS. Межпроцессные
гонки, stale TUN identity, обнаружение IPv6-защиты и Linux runtime остаются открыты.
Продолжение: [Q25-F046–F047](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-LIFETIME.md) —
межпроцессное владение защищённой сессией и отказ при неизвестном IPv6.
Linux runtime новых lease-тестов остаётся открытым; статус раздела не меняется.

[Q25-F048–F049](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md): положительное доказательство
ipv6.disable=1 разрешает пропустить IPv6 firewall; общий lease резервирует TUN всех
Linux-клиентов, включая gateway/exit без kill-switch и dev_attach. 17 новых host-тестов,
3 исходных FAIL → PASS. Runtime Linux и полный PASS раздела остаются открыты.

[Q25-F050–F051](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md): неизвестные владельцы sysctl сохраняются,
acquire/recovery сообщают ошибку; недостоверное наблюдение sysctl не теряет original
для retry. Восемь baseline-регрессий исправлены, 1362 Rust tests PASS. Namespace
identity журнала, реальный Linux runtime и полный PASS раздела остаются открыты.

[Q25-F052–F053](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md): sysctl journal v2 разделяет network namespaces,
проверяет PID/time контекст и procfs до prune; непустой v1 текущего boot-id сохраняется
с явной ошибкой миграции. 24 новых теста, 1386 Rust tests PASS. Реальный Linux,
устойчивость namespace identity после уничтожения объекта и полный PASS остаются открыты.

[Q25-F054–F056](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md): удалено разрушающее восстановление TUN
по неполному списку PID. Клиент пассивно ждёт освобождения имени и отказывает при
ошибке lookup/смене ifindex; клиент и сервер создают первую очередь эксклюзивно.
Остальные очереди используют её фактическое имя. 20 новых тестов, 7 baseline FAIL,
1406 Rust tests PASS. Исправлена сборка Linux-тестов без server feature.
Attach/teardown races и реальный Linux остаются открыты.

[Q25-F057–F058](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md): attach и дополнительные очереди
не регистрируют замену исчезнувшего TUN; ошибка TUNSETIFINDEX останавливает открытие.
VNET_HDR/неизвестные features отклоняются, поддерживаемые флаги сохраняются.
18 новых host-тестов + прежний parser-тест, 1425 Rust PASS; три новых Linux ioctl
теста только скомпилированы. Следующий проход владения зафиксирован ниже.

[Q25-F059–F060](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md): удаление TUN по имени устранено.
Guards клиента/сервера сохраняют исходные fd до очистки сети; setup rollback заимствует
устройство. 12 сценариев с извлечённым кодом PASS (baseline 7 FAIL / 5 PASS), 1425 Rust PASS.
Три новых native Linux-теста только скомпилированы. Внешние rename/delete,
identity DNS-маркеров/маршрутов и Q14-F027 остаются открытыми.

[Q25-F061–F062](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md): DNS сбрасывает только владеющее им
поколение. Namespace/index journal и неблокирующий lock заменяют маркеры по имени;
перед числовыми resolver-командами проверяется исходный fd. Startup не сбрасывает живой
link только по сохранённому маркеру. 24 новых host-теста, 1446 Rust PASS; guard harness
baseline 3 FAIL / 3 PASS, fixed 6 PASS. Native namespace-тест только скомпилирован.
Identity маршрутов, namespace resolver-сервиса и reuse индекса после проверки остаются открыты.

### 26. Общий C# и managed/native граница

**Код:** `qeli-shared/QeliShared`, `qeli-shared/QeliConformance`.

Rust validation parity, import/export/storage, lifetime handles/callbacks. Conformance с обязательными fixtures и platform selftests. Мёртвые managed codecs проверять по OS/features/reflection до удаления; build/selftest не заменяет подключение клиента.

**Имеющаяся обвязка/fixtures:** `conformance/README.md`, `.github/workflows/ci.yml`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS** в доступном объёме; исключённые пользователем platform runtime — SKIPPED.

[Итог Q26](../reports/audit-0.8.2/AUDIT-Q26-MANAGED-FINAL.md): четыре исправления observer/pump ownership/update body/route reader; 543 shared conformance, 143 Windows selftest, Release builds и три negative fixture gates. Настоящая DLL: 32 handle generations; реальный Stop timeout/cleanup retry с fake TUN. Native/Rust inputs неизменны. Desktop VPN connection с настоящими TUN/firewall и Mac runtime не выдаются за selftest; пользовательские исключения сохранены.

### 27. Windows: GUI, служба и драйверы

**Код:** `qeli-win/QeliWin`, `qeli/src/transport_core/wintun.rs`.

LocalSystem IPC/ACL/SID, DPAPI, protected directories, atomic service profile и DLL loading. В Windows VM: Wintun/WinDivert/per-app, routes/DNS/firewall, stop во время connect, sleep/wake, boot service. Cleanup failures не маскируются; UAF/double-close отсутствуют.

**Имеющаяся обвязка/fixtures:** `scripts/e2e_windows_native.py`, `scripts/verify_windows_drivers.ps1`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE / PASS в согласованном объёме; VM runtime SKIPPED пользователем.**

**Отмена shutdown TUN, 23 сентября 2026:** [Q25-F014](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
Общий TunWorkers сохраняет владение Unix TUN/Wintun потоками до join, включая отмену
начатого shutdown и занятый blocking pool. Семь новых host-регрессий; 947 Rust tests PASS.
Unix-тест дескрипторов только кросс-компилирован. Реальные устройства/драйверы и остальные
сценарии раздела не проверены; полный аудит остаётся открытым.

**5 октября, storage этап:** [Q27-F222–F224](../reports/audit-0.8.2/AUDIT-Q27-WINDOWS-STORAGE.md):
DPAPI `.bak` recovery, согласованные bounded service files, strict UTF-8 и required-null
validation. 41 новая Windows проверка; 184/184 platform + 543/543 shared PASS;
5 старых production FAIL воспроизведены, Wintun signatures/hash/licenses PASS.
Q27 остаётся IN_PROGRESS: GUI/SCM/autostart и остальные adapters далее;
Windows VM network/sleep/boot runtime — пользовательский SKIPPED.

**5 октября, GUI/control этап:** [Q27-F225–F228](../reports/audit-0.8.2/AUDIT-Q27-WINDOWS-CONTROL.md):
profile stop/publish/restart с сохранением intent, SCM pending-state refusal,
scheduler exit/deadline/pipe drains и settings snapshot. 40 новых assertions,
224 Windows + свежие543 shared PASS; baseline 8 FAIL. Shared/native inputs unchanged;
managed metadata поменялись с Git SHA, поэтому текущая DLL проверена заново. Q27 IN_PROGRESS: existing registration
trust и recovery/status/log/driver adapters далее; user runtime SKIPPED сохранён.

**5 октября, наблюдение службы:** [Q27-F229–F232](../reports/audit-0.8.2/AUDIT-Q27-WINDOWS-OBSERVATION.md): Регистрация command/account/type/owner/DACL и filesystem recheck перед изменениями; stale/unknown status и terminal cleanup Error, bounded trusted log snapshot/atomic rotation. 273 Windows + 543 shared PASS, 49 новых assertions, 7 baseline FAIL. Q27 IN_PROGRESS; далее native loader/driver adapters и итоговая сверка. План 26/37 (70,3%).

**5 октября, Q27 завершён:** [итог Windows](../reports/audit-0.8.2/AUDIT-Q27-WINDOWS-FINAL.md): F233–F239, 325 Windows + 549 shared PASS, 52+6 новых проверок, 12 baseline FAIL. Реальные VM driver/network/LocalSystem boot/sleep/service reload исключены пользователем; не PASS. Остальные доступные критерии сверены с тремя предыдущими этапами. План 27/37 (73,0%); далее Q28.

### 28. macOS: daemon, utun, pf и Network Extension

**Код:** `qeli-mac/QeliMac`, `qeli-mac/per-app`.

Daemon IPC/owner/mode, Keychain, selected profile, Intel/ARM ABI и DNS journal. Реальный Mac: чужие pf/nat/rdr anchors, per-app entitlements, DNS leaks, reconnect, crash и sleep/wake. GUI/daemon/Network Extension проверяются отдельно.

**Имеющаяся обвязка/fixtures:** `qeli-mac/README.md`, `.github/workflows/ci.yml`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE — доступный объём PASS; Mac/Xcode/runtime USER SKIPPED.**

**5 октября: этап хранения PASS.** [F240–F242](../reports/audit-0.8.2/AUDIT-Q28-MACOS-STORAGE.md): 54 storage PASS, 5 baseline FAIL; Keychain errors/duplicate/key creation concurrency, strict key files/growth limits, no quarantine on key-provider failures. Реальный Mac USER SKIPPED. Далее daemon/helper/selected profile/utun/pf/Swift; полный раздел не закрыт. План 27/37 (73,0%).

**5 октября: этап daemon/control PASS.** [F243–F248](../reports/audit-0.8.2/AUDIT-Q28-MACOS-CONTROL.md):83 control +54 storage +325 Windows +549 shared PASS;5 ожидаемых baseline FAIL. Реальный Mac USER SKIPPED. Далее utun/pf/DNS/Swift. План27/37(73,0%).

**5 октября: этап сетевой очистки PASS.** [F249–F255](../reports/audit-0.8.2/AUDIT-Q28-MACOS-NETWORK.md):117 network +83 control +54 storage +325 Windows +549 shared PASS;10 ожидаемых baseline FAIL. Реальный Mac USER SKIPPED. Остаток: Swift/per-app/build contracts, forwarding ownership/crash recovery и финальный обзор интеграции. Q28 IN_PROGRESS;27/37.

**5 октября, итог:** [интеграция F271/F272](../reports/audit-0.8.2/AUDIT-Q28-MACOS-INTEGRATION.md):1248 managed PASS,23 новых network checks,4 baseline FAIL;8 новых Swift cases не исполнены. Все доступные критерии сверены с предыдущими этапами; реальные Mac/Swift исключения не стали PASS. План28/37(75,7%),9 осталось;далее Q29.

### 29. Android: VpnService, JNI и lifecycle

**5 октября, Q29 lifecycle:** [F277 и проверки](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-LIFECYCLE.md). Установка TUN и остановка сериализованы; join вне монитора. Q29 остаётся IN_PROGRESS, полный VPN/lifecycle ещё не подтверждён. Общий итог 28/37 (75,7%). **167 JVM +23 Android PASS;2 ожидаемых baseline FAIL.**

**5 октября, Q29 framework service:** [F278 и проверки](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SERVICE.md): отклонённый конфиг сохраняет текущий статус; пять настоящих lifecycle-сценариев до Auth. 167 JVM +28 Android PASS;1 baseline FAIL. Q29 IN_PROGRESS, план28/37(75,7%).

**5 октября, Q29 data plane:** [три режима и dual-stack](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-DATA.md):3 свежих integration PASS,48 ответов через TUN;1 F278 baseline FAIL после Auth. Product APK/JNI неизменны;167 JVM/28 Android/1248.NET повторно используются, не свежие. Явный VPN Network + kernel source preflight; обычный default-network выбор остаётся открыт. Q29 IN_PROGRESS,28/37(75,7%).

**Код:** `qeli-android/app`.

Protect/TUN retention/generation при reconnect/cancel/stop. Keystore, INI migration, encrypted backup/lost-key recovery; manifest exports/deep links/boot. Устройство: Wi-Fi/LTE, always-on/lockdown, Doze, process kill, IPv6-only/NAT64, Release/R8.

**Имеющаяся обвязка/fixtures:** `scripts/roaming_android_sleep_wake_gate.py`, `scripts/roaming_android_udp_grace_expiry_gate.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE в согласованном объёме; scoped API34 DNS — ACCEPTED_LIMITATION.**

**5 октября, store/package:** [F273–F276](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md):167 JVM и18 debug instrumentation PASS;2 baseline ошибки;Release/R8 build иlint(0 errors,55 warnings),API28 exactness/legacy recovery/backup exclusions. Временный read-only AVD,host/service/userdata сохранены. R8 production UI smoke отдельно;debug-test APK наminified target не квалифицирован. Q29 IN_PROGRESS;план28/37(75,7%).

### Таблица завершения Q29 — 6 октября

Эта таблица определяет остаток: прежние выполненные матрицы не требуют повторения без
относящихся к ним изменений. Результаты ограничены точными inputs и проверенным fixture.
Checklist раздела не утверждает, что каждый сценарий ниже прошёл.

| Слой | Доступные доказательства | Состояние |
| --- | --- | --- |
| INI, Keystore, migration, lost-key/backup, редактор профиля/экспорт и manifest/package | [F273–F276, F284–F285](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md) | Scoped PASS; physical OEM/D2D и старшие/младшие API не исполнялись |
| Владельцы TUN/plan/protect/observer | [F277](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-LIFECYCLE.md), [F282–F283](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONTROLLER.md) | Adapter boundaries подтверждены; универсальный порядок событий OS не заявлен |
| Настоящие команды службы и владелец Activity permission request | [F278](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SERVICE.md), [F280](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-PERMISSIONS.md) | Scoped PASS; инъекция ожидания/ответа permissions отличается от автоматизации OS-диалога |
| Data, ordinary UID, dual stack, handover, NAT64, per-app/DoT, bounded Doze/flapping и блокировка после stop | [Release](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md), [NAT64](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-NAT64.md), [per-app](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-APP-POLICY.md), [power/flapping](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-ENDURANCE.md), [trusted DoT](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-DOT.md) | Scoped PASS; публикация готовности исправлена [F279](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONNECTED-GATE.md); physical long sessions не подтверждены |
| R8 instrumentation | [matching runner](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNNER.md) | Opt-in matching runner PASS; обычный production UI smoke подтверждён отдельно; прежний runner FAIL сохранён |
| Внешняя смерть процесса | [актуальное восстановление Qeli](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md), [исторический независимый control](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md) | Реальный обычный R8 Qeli после SIGKILL восстановил authenticated NetworkPlan за 2,985s в прогоне13 октября; blocking/manual recovery PASS. Прежний automatic recovery FAIL сохранён как история; это не новый runtime текущего APK |
| Generic auto/null DnsResolver | [API diagnostic](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) | Принято пользователем как документированное ограничение данного API34-образа. Исходный ENONET остаётся FAIL; independent VPN воспроизводит его, typed A/AAAA и explicit VPN работают. Q29 завершён в согласованном объёме. |
| Итоговая сверка source/dead-code и lifetime всего раздела | [F286–F288](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SOURCE.md),31 Kotlin files, Manifest/resources/R8/22 JNI | Review завершён; [F289 исправлен](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SETTINGS.md), scoped pre-auth/UI and fresh Release checks. Reference screen сам по себе не доказывает liveness. |

Q29 завершён в согласованном объёме после явного принятия пользователем описанного API34 DNS-ограничения. Исходные FAIL и пределы платформенного покрытия сохранены; известный ENONET не объявлен исправленным. Прежние пропуски платформ и D06 не изменены.

### 30. iOS: PacketTunnel, Swift и MDM

**Код:** `qeli-ios/QeliCore`, `qeli-ios/QeliPacketTunnel`, `qeli-ios/QeliIOS`, `qeli-ios/MDM`, `qeli-ios/QeliIOSTests`.

Exactly-once start/stop completion, generation/cancel, Keychain/app groups, extension memory. Устройство: On Demand, sleep/wake, captive portal, NAT64/DNS, per-app/MDM и rollback settings. Simulator build, signed IPA и physical evidence — разные статусы.

**Имеющаяся обвязка/fixtures:** `docs/ru/reference/IOS-ANDROID-PARITY.md`, `scripts/test_verify_ios_ipa.py`.

- [x] Review и мёртвый код.
- [ ] Штатные, граничные и негативные сценарии. — USER_SKIPPED (Swift/Xcode/Apple runtime).
- [ ] Отказы и конкуренция. — USER_SKIPPED (Swift/Xcode/Apple runtime).
- [ ] Интеграция и целевая платформа. — USER_SKIPPED (Swift/Xcode/Apple runtime).
- [ ] Исправления, повторная проверка и evidence. — USER_SKIPPED (Swift/Xcode/Apple runtime).

**Статус: DONE в согласованном объёме: SOURCE REVIEW и переносимые проверки. Swift/Xcode/Apple runtime USER_SKIPPED; результаты XCTest, signed IPA, callbacks, RSS/leaks и сетевых сценариев остаются NOT_RUN.**
**Сверка 12 октября:** текущие92 Swift inputs охвачены исходным review;91 побайтно прежний. Изменён только test fixture `exit_node` с обязательным `gateway=false`; project.yml добавляет resources для LICENSE/notices. Production Swift/MDM/header inputs неизменны. Свежие6 Python IPA fixtures,10 plist parses и bindings PASS. Четыре оставшихся платформенных критерия исключены прямым решением пользователя о Mac/iOS-стенде. Ранние IN_PROGRESS/NOT_RUN ниже являются историческими checkpoints; фактическое исполнение Swift ими не подтверждается. [Текущая сверка](../reports/audit-0.8.2/AUDIT-Q30-IOS-SOURCE-MEMORY.md).

[Source fixes F290/F291](../reports/audit-0.8.2/AUDIT-Q30-IOS-POLICY-SNAPSHOT.md):
точные MDM-числа и владение устаревшими ответами расширения. Шесть IPA-verifier
fixture-регрессий PASS; шесть новых Swift XCTest и Xcode/runtime NOT_RUN
(Apple runtime исключён пользователем). Review всего раздела открыт, пункты пока
не закрыты. Наблюдения Q29 сохранены; всего28/37(75.7%),осталось9.

[Storage source fixes F292/F293](../reports/audit-0.8.2/AUDIT-Q30-IOS-KEYCHAIN.md): первый
Keychain writer для ID/TOFU, без тихой rotation, явные размеры ключей и удаление
неиспользуемого update API. Семь новых Keychain XCTest NOT_RUN; шесть IPA fixture
регрессий/docs/bindings PASS. Engine/provider shutdown, read/settings callback
lifetime и platform qualification открыты.

Неверный/удалённый explicit profile option теперь не запускает configured profile
(F294); четыре selector XCTest NOT_RUN,11 новых XCTest в пакете.

[Lifecycle source fixes F295–F297](../reports/audit-0.8.2/AUDIT-Q30-IOS-LIFECYCLE.md): terminal
monitor Stop, current-engine effects и provider-wide OS leases; общий15s settings
budget, cache invalidation и исходный completion result.13 новых XCTest NOT_RUN;
callback drain/lifetime/native joins без runtime qualification. App/UI/settings
source review остаётся.6 IPA fixture/docs/bindings PASS; прошлые runtime results
только для неизменных реализаций. Q30 IN_PROGRESS,28/37; checklist не закрывается.

[Source fixes F298/F299 настроек приложения](../reports/audit-0.8.2/AUDIT-Q30-IOS-APP-PREFERENCES.md):
убраны пять обходов сброса эпохи статуса, сериализована полная сверка MDM;
свежие настройки читаются после допуска, устаревшие/отменённые шаги отклоняются.
Три gate XCTest NOT_RUN;6 IPA fixture/docs/bindings PASS. Остаются provider-message,
backup UI и итоговая source-сверка памяти/мёртвого кода. Q30 IN_PROGRESS,28/37.

[Source fixes F300–F302 сообщений/backup](../reports/audit-0.8.2/AUDIT-Q30-IOS-MESSAGES-BACKUP.md):
отменяемое ожидание settings-message20s с проверкой session/поколения/эпохи;
один snapshot poll на эпоху, фиксированный пароль backup и имя по готовым байтам.
11 XCTest NOT_RUN;6 IPA fixture/docs/bindings PASS. Реальные OS операции по-прежнему
принадлежат callback; остаётся итоговая сверка памяти/мёртвого кода. Q30IN_PROGRESS.

Очистка membership wire-crypto F302 исключает Swift cipher/HKDF из production
и включает в XCTest; неиспользуемые X25519/auth-helper удалены. Membership проверен
по исходникам, Xcode NOT_RUN; поведение native-бинарников не изменялось.

### Итог source review Q30 — 6 октября

[Текущая сверка F303–F306 исходников/памяти](../reports/audit-0.8.2/AUDIT-Q30-IOS-SOURCE-MEMORY.md)
закрывает Review/dead-code: классифицированы92 Swift inputs,12 single-reference
framework entry points сохранены; дублирующие probe-owner удалены. Ограничены/
защищены start/completion probe, владение ping, log1МиБ/message4КиБ и update collector1МиБ.
11 XCTest NOT_RUN;6 IPA fixtures/docs/bindings PASS. Эта актуальная source-классификация
заменяет прежние замечания об открытой source review; исходные execution evidence
сохранены. Реальные Swift/Apple runtime/RSS/leaks/callback/native joins не подтверждены;
остальные четыре критерия остаются открыты. Q30 IN_PROGRESS,итог28/37(75.7%).
Платформенные наблюдения не переименованы в PASS.

### 31. OpenWrt, LuCI и Keenetic

**Код:** `qeli-openwrt`, `scripts/build_keenetic.py`.

UCI → INI escaping/shell injection, LuCI ACL, secrets на flash, init/procd, upgrade/rollback. ARM/MIPS/mipsel, endian/32-bit ABI, client-only features. Реальный router: WAN renewal/reboot, DNS/firewall/hooks, memory/throughput; cross-build не device test.

**Имеющаяся обвязка/fixtures:** `scripts/keenetic_verify.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE в согласованном объёме.**

**6 октября, F307–F310:** [пакет control/render/firewall](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md):7 Node и10 shell fixtures в каждом BusyBox/dash PASS;37 проверок рецептов PASS после сверки устаревшего Android assertion. Применённое UCI-намерение, очередь кнопок, атомарный0600 INI, проверяемый повтор firewall. Только scoped fixtures; полный review/install/upgrade/build открыт; реальный router runtime USER_EXCLUDED. Всего28/37(75.7%) без изменений.

**Продолжение F311–F313, 6 октября:** тот же [отчёт Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md),14 router-helper fault tests,10 JS caller/adapter fixtures и11 shell fixtures на interpreter PASS. Ошибки toolchain, ложный artifact PASS и утечки соединений исправлены; init-visible статус обходит кэш формы. Настоящие ucode/rpcd/rc.common и cross-build NOT_RUN; установка/upgrade/полный review OPEN. Статус целого раздела не повышен.

**Продолжение F314–F315, 6 октября:** [отчёт Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): восстанавливаемые собственные install defaults и start guard; общий managed-source sync с запретом сборки после обрыва. Baseline ignored failures/stale inputs воспроизведены.21 shell test на BusyBox/dash,7 filesystem source-sync tests,14 router-helper,12 shared lab,37 native recipes и10 JS fixtures PASS. Настоящие libuci/fw4/procd/package/cross-build NOT_RUN,router USER_EXCLUDED; полные upgrade/concurrency/provenance/review OPEN. Q31 IN_PROGRESS,28/37 без изменений.

**Продолжение F316–F319, 6 октября:** [отчёт Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): проверяемое удаление секретов, повтор legacy scrub, UCI/duplicate-zone admission, callback status через стандартные hooks rc.common. Baseline/изолированный pre-hooks dispatcher false success воспроизведён.37 shell/saved-dispatcher cases на BusyBox/dash,11 JS fixtures/37 recipes/docs/bindings PASS. Saved rc.common с подставными lib/UCI/procd; настоящий daemon/ubus/opkg/flock lifecycle не квалифицирован. Q31 IN_PROGRESS,28/37 без изменений; полный upgrade/concurrency/build review OPEN.

**Продолжение F320–F321, 6 октября:** [отчёт Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): canonical Keenetic bundle names, checked required dependencies, подготовка per-file publication и сохранение INI; checked ndm mutations, strict OpkgTun suffix и единый snapshot плана.20 shell cases на BusyBox/dash,37 recipes/docs/bindings PASS; old names/dependency/false-up/mixed-plan воспроизведены. Настоящие opkg/ndm/ELF/cross-build NOT_RUN,router USER_EXCLUDED. Template process/legacy state/idempotence/concurrency и широкий review OPEN; Q31 IN_PROGRESS,28/37 без изменений.

**Продолжение F322–F323, 6 октября:** [отчёт Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): проверяемые атомарные forwarding snapshots, checkpoints семейств/интерфейсов, tagged legacy firewall ownership и failure/retry gates в обоих шаблонах Keenetic.64 shell model tests на BusyBox/dash (44 новых),37 recipes/docs/bindings PASS. Воспроизведены старый плохой снимок, забытое восстановление, удаление совпадающих admin rules, скрытые firewall failures, смена режима и restart gating. Старые нетегированные checkpoints требуют ручной сверки; настоящие router/kernel/comment capability/cross-build NOT_RUN,router USER_EXCLUDED. PID/join/launch/INI parity/OpkgTun concurrency/широкий review OPEN; Q31 IN_PROGRESS,28/37 без изменений.

**Продолжение F324–F325, 6 октября:** [отчёт Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): проверка PID/start ticks/executable, атомарный приватный process record, ожидание TERM до wrapper cleanup, сохранение timeout/error state и проверка startup/upgrade admission.108 BusyBox/dash cases (43 настоящих native helper process checks,44 state models,21 installer/hook) и37 recipes/docs/bindings PASS. Безопасное old/new сравнение воспроизводит foreign/group PID, раннюю очистку, игнорируемый TERM и ложный успех запуска. Atomic pidfd/interprocess и настоящий router/core network не квалифицированы; сокращённый polling/сверка old PID при обновлении описаны. INI parity/OpkgTun generations/concurrency/packaging/широкий source/build review OPEN; Q31 IN_PROGRESS,28/37 без изменений.

**7 октября, Q31-V003:** настоящая SDK упаковка retained musl binary и offline opkg:7PASS без skips; подписанные release feeds, nft/legacy resolver, install/upgrade/remove и conffile0600. Полный SDK Rust compile/source release-cut OPEN; живой router USER_EXCLUDED. [Отчёт Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).28/37(75.7%) без изменений.

**7 октября, F358/Q31-V004:** Rust1.89 client-bin GNU check и полный musl compile/link actual SDK macro + GCC13.3 PASS. Убраны неиспользуемые SDK FFI outputs; baseline1FAIL/fixed5real-Cargo methods PASS, SDK3 и18 executable smoke cases PASS. Prebuilt Rust/std, без полного SDK bootstrap/release pipeline/router. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).28/37(75.7%) без изменений.

**7 октября, F359–F360:** настоящий procd воспроизвёл stale repeated start и остановку работающего клиента при отказе подготовки. File comparison INI/password и отказ пустого set/add исправлены; baseline 5 failures в 3 методах, fixed 11 native methods и 55 shell methods на ash/dash без skips PASS. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md). Inert adapter, без VPN/fw/firmware; core generation/ABA/rollback OPEN. 28/37 (75.7%) без изменений.

**7 октября, F361:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): runtime NetworkPlan содержит существующее authenticated generation; одинаковые адреса нового поколения и ABA внутри адаптера различаются. Derived baseline 2 assertion FAIL/1 PASS; fixed11 Rust units/GNU check/production Clippy/fmt PASS;194 Keenetic methods на каждом ash/dash без skips (2 новых),37 recipes/14 LuCI/docs9/bindings PASS. Writer/lock, counter reset и атомарность ndm OPEN; свежие SDK/FFI/cross/firmware не заявлены. Q31 IN_PROGRESS,28/37(75.7%),9 осталось; Q29/Q30/D06 сохранены.

**7 октября, F362–F363:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): повторная проверка plan/marker после show, mv receipt и rm pending; fresh OpkgTun init launch очищает receipt прежнего процесса, repeated live start сохраняет его. Baseline8 failures в4 из5 новых methods на каждом ash/dash; fixed199 methods/interpreter без skips,37 recipes/14 LuCI/docs9/bindings PASS. Process настоящий, ndmc/plan publication models; Rust/FFI/SDK/cross unchanged. Writer/lock/after-final-check/atomic ndm/direct launch OPEN. Q31 IN_PROGRESS,28/37(75.7%); Q29/Q30/D06 сохранены.

**7 октября,F364:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): общий router/host/CI exporter закрепляет пять release fields из Cargo.toml против ambient FFI/environment/home/ancestor overrides. Real-Cargo baseline9assertion FAIL в12cells;fixed8methods/12cells и72Linux helper/gate methods без skips PASS. Настоящий pinned Zig/cargo-zigbuild x86_64-musl mini baseline unwind|0/fixed abort|3;staticELF validator/execution PASS.37recipes/14LuCI/docs9/bindings PASS. Не current Qeli/clean A-B/4targets/SDK/FFI/CI run; full hermetic/pipeline OPEN. Q31 IN_PROGRESS28/37(75.7%);Q29/Q30/D06 сохранены.

**7 октября,F365/Q31-V005:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): полный independent x86_64-musl baseline A/B различался; общий helper remaps временные пути исходников. Две новые полные исправленные сборки Qeli побайтно идентичны;9actual-Cargo/72Linux model методов и48INI metadata cases PASS без skips. Проверенная offline registry-копия, без сети/VPN и замены опубликованных binaries. Другие ISA A/B/full hermetic/SDK pipeline OPEN;Q31 IN_PROGRESS28/37(75.7%);Q29/Q30/D06 сохранены.

**7 октября, Q31-V006/F366–F367:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): шесть новых полных AArch64/ARMv7/MIPS сборок дали три побайтно идентичные пары. С SHA-сверенным sealed F365 x86_64 evidence подтверждены все четыре standalone A/B цели. 72 настоящих QEMU INI cases/12 CLI-вызовов;15 новых release-gate/72 связанных Linux методов PASS без skips. Gate 2 использует приватный точный committed Git-архив и общие pins/locked recipe/SHA/ELF admission, запрещает dirty inputs, проваливает configured errors и закрывает SSH; tests добавлены в CI. Полный live preflight/CI dispatch,SDK bootstrap/source release-cut,full hermetic policy и оставшийся Q31 source review OPEN;firmware USER_EXCLUDED. Q31 IN_PROGRESS,28/37(75.7%),9осталось;Q29/Q30/D06 сохранены. Без push/deploy.

**7 октября, F368–F369/Q31-V007:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): завершён source review28файлов; первый критерий закрыт. Общий SSH helper устраняет воспроизведённый четырьмя callers stderr receive-window timeout; connection/probe failure close и installed-pin diagnostics исправлены.16настоящих SSH checks,8actual probe commands,125Linux methods без skips,78local native contract/docs/bindings PASS. Native provenance был STALE до изменений и остаётся release-blocking Q34; digest/artifacts не подменялись. SDK/pipeline/concurrency ограничения сохранены. Q31 IN_PROGRESS,28/37(75.7%),9осталось;Q29/Q30/D06 сохранены.

**7 октября, F372:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): exact-commit CI admission запрещает допуск при неизвестном Git/CI SHA, ошибке запросов и устаревшем workflow.77router+18CI Linux methods без пропусков; настоящий read-only preflight дошёл до общего отказа. Критерий штатных/граничных/негативных сценариев закрыт,2/5критериев; Q31 IN_PROGRESS28/37(75.7%),9остаются. Native current/долг14/15+D06 принят без изменений; SDK/release-cut/ndm и firmware exclusions сохранены. Без push/release.

**7 октября,F373–F375:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): очистка saved/partial адресов OpkgTun, ownership после stop/start и ошибки смены плана, локальный IPv4 для cached no-op/сброса.218methods на dash/ash без пропусков;14nonroot CI methods и baseline-отказы старых hook/init. Критерий cooperative отказов/конкуренции закрыт;3/5критериев,Q31IN_PROGRESS,28/37всего. Межкомпонентная/SDK/release интеграция и exclusions сохранены; без push/deploy.
**7 октября,F376–F378:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): immutable/однозначные source metadata, версия из committed TOML и сверка фактического SDK mirror SHA256.25 Linux source methods без root,18CI/15router gates PASS;4 точных старых fail-open воспроизведены. CI24+1 явный baseline skip. SDK bootstrap/release-cut/Actions не квалифицированы; Q31 остаётся3/5 criteria IN_PROGRESS,28/37overall.

**7 октября,F379/Q31-V008:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual SDK source archive/check-FIXUP/prepare PASS на exact candidate crate; старый bad mirror download/prepare0 воспроизведён. Shared prepare/compile verifier останавливает bad hash до unpack/Cargo;9dash/9ash+25source methods uid65534 PASS,7integration stages с inert Cargo boundary. Full SDK Rust/bootstrap/release-cut/CI отдельно;3/5criteria IN_PROGRESS,28/37overall.

**7 октября,Q31-V009:** [live release gate](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): реальные ARMv7/MIPS release builds через текущий Gate2 helper, SHA/static ELF PASS;32actual QEMU CLI/INI executions uid65534 PASS,317 exact compile inputs. Named tools/defaults и qeli745/901 сохранены,own roots очищены. Без нового product fix/native refresh/firmware/full preflight/Actions;SDK bootstrap/release-cut/writer-lock/atomic ndm остаются. Q31 IN_PROGRESS3/5,28/37overall.

**14 октября: холодный Rust Host/Compile теперь выполнен.** Prepare/configure и реальная компиляция bootstrap79с PASS; скачивание закреплённого LLVM CI artifact получило4HTTP404. Host/Compile FAIL сохранён, Host/Install/stage2/dist не выполнены; лимиты не сработали. Все6226200078байт собственного каталога удалены, host/аккаунты/staged сохранены. Полный compiler/cold graph остаётся OPEN, prebuilt SDK/IPK scope прежний.33/37,NO_PUSH_DEPLOY_RELEASE.

**14 октября: обход LLVM CI404 выполнен.** Один flag в частном feed, prepare/configure/bootstrap и реальная source LLVM C++ compilation проверены; последний Ninja indicator548/3710. Собственный guard остановил частичный прогон (time); full compiler/SDK graph не закрыт. Root/cache/archive/unit очищены, host сохранён; original404 прежний.33/37,NO_PUSH_DEPLOY_RELEASE.

**14 октября: длительный source compiler остановлен OOM.** LLVM1690/3710; kernel CONSTRAINT_MEMCG/llvm-tblgen, cgroup1152МиБ RAM/512МиБ swap. Архив и cleanup квалифицированы, host сохранён; SDK не запускался. Q31 остаётся IN_PROGRESS; одинаковый ресурсный retry не выполняется.33/37,NO_PUSH_DEPLOY_RELEASE.

**14 октября: Q36 socket-buffer causal tests.** Две серии по6sessions/12windows без kernel trace: tiny send buffer ухудшил unlimited ACK во всех3парах; отдельно проверен stock/auto receive при held stock send. Actual tb/rb, единичный INI delta, workload/ACK/topology/host/SHA cleanup квалифицированы; CONFIG RU/EN уточняет0 против отсутствующего ключа. Defaults продукта неизменны. Q36 IN_PROGRESS;33/37 (89,2%), NO_PUSH_DEPLOY_RELEASE.

**14 октября: Q36 client writer priority.** Fresh6sessions/12windows,nice0/-10 only own writer; actual TID/weight/policy/affinity/config/PID/ACK/host/SHA cleanup qualified. No consistent delay removal; no production adoption. Next direct per-packet stage timing with separate diagnostic build/observer controls.33/37 (89.2%),Q36 IN_PROGRESS,NO_PUSH_DEPLOY_RELEASE.

**14 октября: Q36 direct ACK stage pilot.** Private diagnostic build and2 isolated selector tests,3sessions/6windows stock/OFF/ON, unique exact-header seven-stage identity/cleanup qualified. Distinct ThinLTO artifact and one ordered observer pilot; original shipping cause and observer neutrality still open.33/37 (89.2%),Q36 IN_PROGRESS,NO_PUSH_DEPLOY_RELEASE.

**14 октября: Q36 sampled server handoffs.** Nine exact-header stages, three reversed same-artifact OFF/ON pairs /12windows, deterministic1/16 subset and actual cleanup qualified. Server TUN/forwarding/stream queue times separated; observer ratios and sampling limitations retained.33/37 (89.2%),Q36 IN_PROGRESS,NO_PUSH_DEPLOY_RELEASE.

**14 октября: Q36 recordizer FIFO control.** Three same-diagnostic-artifact policy off/required pairs/12windows; probes ON both, actual one-carrier negotiation and six common exact-header stage identities/cleanup qualified. MUX per-ACK crypto stamps unavailable; observer/batching/deadline/morphology limits explicit.33/37(89.2%),Q36 IN_PROGRESS,NO_PUSH_DEPLOY_RELEASE.

### 32. Метрики, usage, логи и уведомления

**Код:** `qeli/src/server/metrics.rs`, `qeli/src/server/usage.rs`, `qeli/src/server/notify.rs`, `qeli/src/server/roaming_metrics.rs`, `qeli/src/trace.rs`, `qeli/src/web/api/logs.rs`.

Counters/quota/session accounting при reconnect/reap/crash, corrupt store, bounded log/SSE/backpressure. Notify INI/token/load races, SSRF/DNS rebinding/redirect/timeout/rate limit. Логи не раскрывают credentials, disabled trace не меняет hot path.

**Имеющаяся обвязка/fixtures:** `scripts/test_roaming_control_stats.py`, `scripts/test_blocked_settings.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE/PASS в документированной области.**

**Владение уведомлениями, 23 сентября 2026:**
[Q14-F018 / Q32-F001](../reports/audit-0.8.2/AUDIT-Q14-Q32-NOTIFICATIONS.md): до 128 принятых отправок,
8 активных запросов на процесс, общий лимит проб панели, ограниченные payloads и drain
до 10 секунд после завершения производителей. Detached-обёртки уведомлений удалены.
864 host Rust tests PASS; Linux только all-targets cross-check. Владение panel/metrics/
autostart supervisor, доверие конфигу и Linux E2E ещё открыты.

**8 октября, F380–F383:** [метрики Q32](../reports/audit-0.8.2/AUDIT-Q32-METRICS.md): missing-RPC baseline, guest/CPU reset и PID/starttime исправлены; три старых ошибки метрик и PID42 collision воспроизведены;8metrics/36namespace при PID42 и2424library PASS (60ignored),Clippy/daemon PASS. Native/ABI в evidence отчёта. Usage/logs/notify остаются открыты; Q32 IN_PROGRESS,28/37 overall.

**8 октября, F384:** [usage Q32](../reports/audit-0.8.2/AUDIT-Q32-USAGE.md): ошибка fsync после rename воспроизведена; память больше не откатывает опубликованный сброс, тип ошибки сохранён, control API сообщает о неподтверждённой сохранности. 16 harness/2426 Linux tests PASS (60ignored), strictClippy/daemon,A-B four cores,WindowsABI22/AndroidJNI23 PASS; evidence отчёта. Store, registration/quota/shutdown reviewed; logs/trace/roaming/notify остаются открыты. Q32 IN_PROGRESS,28/37 overall.

**8 октября, F385–F388:** [Q32: логи и trace](../reports/audit-0.8.2/AUDIT-Q32-LOGS-TRACE.md): чтение через закреплённые fd отклоняет подменённые симлинки/FIFO, четыре I/O-слота удерживаются после отмены HTTP, tail сохраняет полные граничные строки, trace атомарно публикуется с0600 вне потоков Tokio с одним допуском. Три baseline-ошибки воспроизведены; harness11/UID65534, два настоящих SIGUSR1 с65536 упорядоченными строками,2434 library-теста (60ignored), строгийClippy/daemon и118 групп Node VM PASS. Четыре актуальных nativeA/B, WindowsABI22/AndroidJNI23 и финальные пороги — в evidence отчёта. Неудачная подготовка/прежний legacy firewall drift сохранены; неизменность всего host первоначального .10 baseline не заявляется. Ограничения покрытия/HTTP/диска/платформ сохранены. Q32IN_PROGRESS; roaming, доверие/маскирование секретов уведомлений и полная интеграция открыты. Общий план28/37(75,7%), остаётся девять.

**8 октября, F389–F394:** [INI уведомлений и доставка](../reports/audit-0.8.2/AUDIT-Q32-NOTIFICATIONS.md): доверие перед чтением/сохранением, полная ограниченная HTTP-строка и успех только 2xx, query/fragment, консервативная проверка специальных адресов, сброс кеша после записи и проверка записи симлинка. Воспроизведены три старых helper-ошибки и две ошибки кеша настоящей библиотеки; шесть helper tests, 12 изолированных HTTP-проверок и cache trust/recovery проверяют исправления. Финальные library/native результаты и guards — в machine evidence. Q32 и Q29/Q30/Q31 открыты; всего 28/37, осталось девять; старый долг14 DONE плюс принятое D06.

**8 октября, Q32 завершён:** пять критериев сверены для metrics/usage/logs/trace/notifications и неизменных roaming observations; финальные2439 library, strictClippy/daemon, реальные HTTP12/cache, native A/B/ABI22/JNI23 и docs/provenance PASS. Сравнения16 сохраняют область прежнего выполнения; границы physical/TLS/Telegram/browser документированы. План29/37(78,4%),осталось восемь;Q29/Q30/Q31 и D06 сохранены.

### 33. Установка, обновление, файловые права и hooks

**Код:** `qeli/debian`, `qeli/src/server/update.rs`, `qeli/src/util.rs`, `qeli/src/hooks.rs`, `qeli/src/config_source.rs`, `release/docker`.

Fresh install/upgrade/downgrade/remove, systemd sandbox, identity/users preservation, checksums/attestation, atomic replace. Docker digest/recreate/health/rollback. File locks/symlinks/hardlinks/owners/ENOSPC, PATH hijack, panel/restore command injection и SSH timeouts.

**Имеющаяся обвязка/fixtures:** `scripts/test_ssh_run.ps1`, `scripts/release_preflight.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE.**

**Доверие прочитанному конфигу, 23 сентября 2026:**
[Q14-F019 / Q33-F001](../reports/audit-0.8.2/AUDIT-Q14-Q33-CONFIG-TRUST.md): владелец/права и данные
для парсера получаются из одного дескриптора; исходное разрешение не меняется при
повторах профиля и не перепроверяет путь. Очистка готового поколения сохраняет команду
и окружение после удаления/замены конфига. 874 host Rust tests PASS; четыре новых Unix/
Linux-теста только cross-checked. Лимиты password_command, владение startup-задачами,
installer/update/restore и Linux runtime integration ещё открыты.

**Поставщик пароля и изоляция features, 23 сентября 2026:**
[Q25-F001 / Q33-F002 / Q14-F020 / Q34-F001](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md):
асинхронный password_command, deadline 30 секунд, полный stdout до 16 KiB, отброшенный
stderr и ошибки без секретов. Ранний SIGINT/SIGTERM отменяет и собирает поставщика;
watchers/sampler клиента имеют владельца. Исправлен server-only TUN gate, обе изолированные
features проверяются в CI. 883 host Rust tests PASS; четыре Linux-теста только cross-check.
Server-only check имеет 23 прежних transport dead-code warnings. Лимиты password_file,
финальный drain клиента и Linux runtime/release checks ещё открыты.

**8 октября,F400–F403:** [Q33 Docker entrypoint](../reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md): четыре старые ошибки воспроизведены на dash/ash; исправлены пустой argv, явный CLI-config и новые файлы0600 без перезаписи.34 сценария/46 chroot-запусков PASS без skips; проверены конкурентные creators и copy/link failures. Docker image/daemon, Debian updater/install и полный Q33 OPEN. Bootstrap Rust SDK Q31 отложен: измерены2GB RAM/~9GB диска, ниже рекомендации upstream8GB/30GB; compiler FAIL/PASS не заявляется.29/37(78.4%),осталось восемь; exclusions сохранены.

**8 октября,F404–F411:** [Q33 updater](../reports/audit-0.8.2/AUDIT-Q33-SERVER-UPDATER.md): исправлены invalid local input, admission пакета, CRLF/cleanup, блокировка транзакции, точная install/downgrade identity, restart/PID health и legacy-кэш.14 старых регрессионных сценариев FAIL;21 итоговый метод/24 запуска updater+1 installer PASS с настоящим dpkg. Точная команда CI, ShellCheck и guarded cleanup PASS; production maintainer scripts/systemd/VPN/Docker OPEN. Q33 IN_PROGRESS;29/37(78.4%),осталось восемь; старый долг14DONE+D06accepted, Q29/Q30/Q31/exclusions сохранены. Без push/deploy/release.

**8 октября,F412–F416:** [Q33 Debian lifecycle](../reports/audit-0.8.2/AUDIT-Q33-DEBIAN-LIFECYCLE.md): исправлены private no-replace users creation, pre-unpack state guards, service-user/debconf failures, отказ удаления при stop failure и adduser dependency.10 baseline methods/12 ожидаемых ошибок;16 итоговых методов/24 настоящих lifecycle dpkg-вызова PASS, точная команда CI/lint PASS. Production make/scripts с инертным бинарником/зависимостями и account/debconf/systemctl seams; полный installer/daemon/Docker OPEN. Собственный каталог SHA-backed-up/guarded-cleaned; service777/845 сохранён. Q33IN_PROGRESS,29/37(78.4%),осталось восемь; старый долг14DONE+D06accepted,Q29/Q30/Q31/exclusions сохранены. Без push/deploy/release.

**8 октября,F417–F421:** [Q33 from-binary](../reports/audit-0.8.2/AUDIT-Q33-BINARY-INSTALLER.md): исправлены copy-failure propagation, exclusive source/full staging, state/users, signal exit и remote architecture/metadata/required attestation.14 baseline methods19 ожидаемых ошибок;18 итоговых методов23 запуска(21prefix+2earlywhole) PASS, точная CI-команда/updater21 regressions/lint PASS. HTTP/account/systemctl/qeli/gh seams явные; full installation/VPN/OIDC PASS не заявлен. Полный installer dependencies/publication/tuning/health и Docker OPEN. Собственный каталог backed-up/guarded-cleaned; service777/845 сохранён. Q33IN_PROGRESS,29/37(78.4%),осталось8; старый долг14DONE+D06accepted,Q29/Q30/Q31/exclusions сохранены. Без push/deploy/release.

**8 октября,F422–F426:** [Q33 допуск installer](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-ADMISSION.md): conditional/rechecked зависимости, qeli/arch/version metadata, exact installed state, required gh и удаление мёртвой URL-ветки QELI_DEB.12 baseline methods14 ошибок;18 final methods22 calls(20helpers+2earlywhole) PASS; точная CI/binary18/updater21 regressions/lint PASS. Recipe38/native14 SHA+provenance PASS. Full positive installer/publication/tuning/health/disconnected host/Docker OPEN. Собственный root backed-up/guarded-cleaned;777/845 сохранены. Q33IN_PROGRESS;29/37DONE78.4%,осталось8; Q31 3/5 и все historical open/excluded/accepted пункты сохранены. Без push/deploy/release.

**8 октября,F427–F431:** [Q33 секреты/web-config](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-SECRETS.md): исправлены unsafe secret targets, private rename/kept-link copy, staged summary/pending-password recovery, atomic web rewrite/owner600, unique backups и retained-user notice.14 baseline methods15 ожидаемых assertions; итог21 methods22 запуска(20helpers+1earlywhole+1positivewhole с seams) PASS. Точная CI/admission18/binary18/updater21 regressions/lint/recipes38/native14 PASS. Настоящие CLI/parser/identity/users/panel/kernel/service/VPN/Docker и initial config transaction OPEN; automatic rollback/durability/race-pinned-dir не заявлены. Оба root backed-up/guarded-cleaned;777/845 сохранены. Q33IN_PROGRESS,29/37DONE78.4%,осталось8; Q31 3/5 и historical open/excluded/accepted пункты сохранены. Без push/deploy/release.

**8 октября,F432–F436:** [Q33 preflight/подготовленный INI](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CONFIG.md): explicit host/panel/boolean до изменений; auto-host до config/identity; ровно один profile header/явные awk errors; полный private INI stage через CLI/web/final validation, root helper после проверки, backup/rename publication. Baseline17methods22expected assertions; исправлено21method28whole(3positive/25refusals), точная CI21/28,78regressions/lint/recipes38/native14/docs9(676Markdown) PASS. Filesystem настоящий; CLI/systemctl/kernel seams, actual parser/auth/daemon/VPN/Docker OPEN. Config сохранён до commit; users/identity/links/tuning/bin/deps/drop-in могут измениться, restart-after-publish не откатывается, прежний root override OPEN. Собственный .11 root backed-up/cleaned;777/845 сохранены. Q33IN_PROGRESS,Q31 3/5,29/37DONE78.4%,осталось8,historical OPEN/USER_EXCLUDED/D06ACCEPTED сохранены. Без push/deploy/release.

**8 октября,F437–F438:** [Настоящий CLI/version](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CLI.md): --version для старого binary, строгие fixture argv и unique stage-lock cleanup. Version baseline2fail→2PASS; realCLI initial4lockfail→5PASS, повторCI2+5;99regressions/lint/recipes38/native14/docs9(678Markdown)PASS. Genuine debug artifact85ea/SHA37a6 reused для неизменённых CLI/parser/trust paths;4laterclient/notify различия — не fullcurrentRust/releaseABI qualification. Настоящие три profile keys/Argon2/users/panel/INI/link/custom-dropin flows;systemctl/daemon/kernel/preflight-ip seams,VPN/Docker/default-unit-rootrevertOPEN. Package CI добавлен,Actions не исполнялся. Own root backed-up/cleaned,777/845 сохранены. Raw334files41695825bytesSEALED. Q33IN_PROGRESS,Q31 3/5,29/37DONE78.4%осталось8,history/exclusions/D06accepted сохранены;без push/deploy/release.

**8 октября,F439–F441:** [Пользователь службы/ownership](../reports/audit-0.8.2/AUDIT-Q33-SERVICE-USER.md): сохранены права client-links/backups, каталог квитанций root0700; real state validation и сохранение existing override при ошибке исправления; installer явно применяет default qeli после проверки. Baseline ownership2/CLI3 failures;fixed2+10 и117regressions PASS;CI2+10+2,lint3scripts,Rustbin5/Clippy/fmt PASS. Current CLI пересобран0e01;native A/B evidence обновлено. Real systemd/startup/kernel/VPN/Docker остаются OPEN;Q33 IN_PROGRESS,29/37DONE78.4%,осталось8. Исторический долг/exclusions сохранены;только локальный dev.

**8 октября, F442–F444 / Q33-F045–F047:** [Systemd](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md): стабильный снимок nft без смешивания diagnostics; управляемый SIGHUP supervisor с сохранением panel lockouts; ограниченные filesystem capabilities root. Current CLI a36d/SHA6161 собран Rust1.97 offline/locked; bin5 + SIGHUP4 + supervisor23 + Clippy PASS; installer/CLI129 + точная локальная CI14 + lint PASS. Настоящий manager257 sandbox/reload/restart/root-qeli/invalid-INI recovery проверен в собственном network namespace; запрет root config trust сохранён. Native A/B/ABI и sealed evidence — в отчёте. Закрыт этот manager gate, а не весь Q33: настоящий package/update rollback pipeline, VPN traffic и Docker image runtime остаются OPEN. Q33 IN_PROGRESS,29/37 DONE(78.4%),осталось8; история/exclusions/deferred пункты сохранены; без push/deploy/release.

**8 октября:** [DEB/update/remove](../reports/audit-0.8.2/AUDIT-Q33-PACKAGE-MANAGER.md): настоящий portable release/jemalloc и production package; реальные apt/dpkg/debconf/CLI/systemd с частной DB и явным unit mapping, финальные 24 PASS. Успешное обновление, package rollback после неисправного unit и повреждённого ELF, exact configured DB, сохранение bytes/UID/mode config/users/identity/receipts/backups, remove/purge. Три fixture FAIL сохранены; audit helpers исправлены, продукт не изменён. Закрыт этот scoped gate; whole binary/kernel installer, release VPN roundtrip, Docker и Actions OPEN. Q33 IN_PROGRESS; 29/37 DONE (78.4%), осталось 8; предыдущие статусы/исключения сохранены.

**8 октября:** release VPN и package→systemd→VPN: [Q33 DEB](../reports/audit-0.8.2/AUDIT-Q33-PACKAGE-MANAGER.md). Матрица extracted production release ELF:18 сценариев/376 PASS (TCP/UDP, outer/inner4/6, split, leak, TAP, DNS, MTU, legacy0.7.16). Реальный pinned H-1 client через пакетную службу:36 PASS, fresh/upgrade/оба rollback, exact TUN route и clean stop. Исходный fixture trust FAIL сохранён, show-identity выполняется от qeli. Продукт/native не менялись; стенд восстановлен, roots SHA-archived/guard-cleaned. Release data-plane и package/service/VPN gate закрыты; full binary/kernel installer и Docker/Actions остаются OPEN. Q33 IN_PROGRESS;29/37 DONE78.4%,осталось8; прежние ограничения сохранены.

**8 октября,F445 / Q33-F048:** [Полный installer/kernel](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CONFIG.md): подтверждён и исправлен ложный sysctl success; private per-run snapshots/prior files/restore instructions, readback и early tuning path guards. Full QELI_BIN+QELI_SRC и production QELI_DEB: по24 PASS с actual manager/CLI/Argon2/MSS/pinned VPN; probing0→1→0 и persistent files restoration. Linux136 regressions без skips/lint PASS, CI tuning добавлен. Первые FAIL сохранены; root777/845/network/kernel не менялись. Full positive installer и partial kernel recovery gate закрыты, глобальная запись10keys/BBR load/reboot/пустой OS bootstrap не заявлены; Docker/Actions и прежние ограничения остаются OPEN. Q33IN_PROGRESS29/37DONE78.4%,осталось8; без push/deploy/release.

**Q33 завершён 8 октября:** [итоговая сверка](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md) связывает все пять критериев с evidence. F450 закрывает retained hook и exact deletion; source/runtime ограничения сохранены.

### 34. CI, зависимости, native provenance и релиз

**Код:** `qeli/Cargo.toml`, `qeli/Cargo.lock`, `.github/workflows`, `native-libs`, `release/certification`.

Feature/debug/release/jemalloc matrix, lockfiles, актуальные CVE/licenses и pinned Actions/SDK. Независимая A/B rebuild cores, hashes/ABI/provenance и signatures драйверов/APK/IPA. Certification опирается на реальные evidence текущего SHA, не на ручную замену digest/status.

**Имеющаяся обвязка/fixtures:** `scripts/test_native_recipes.py`, `scripts/test_native_repro.py`, `scripts/test_release_certification.py`, `scripts/release_certification.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE в согласованном объёме.**

**Поставщик пароля и изоляция features, 23 сентября 2026:**
[Q25-F001 / Q33-F002 / Q14-F020 / Q34-F001](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md):
асинхронный password_command, deadline 30 секунд, полный stdout до 16 KiB, отброшенный
stderr и ошибки без секретов. Ранний SIGINT/SIGTERM отменяет и собирает поставщика;
watchers/sampler клиента имеют владельца. Исправлен server-only TUN gate, обе изолированные
features проверяются в CI. 883 host Rust tests PASS; четыре Linux-теста только cross-check.
Server-only check имеет 23 прежних transport dead-code warnings. Лимиты password_file,
финальный drain клиента и Linux runtime/release checks ещё открыты.

### 35. Fuzzing, concurrency, DoS и soak

**Код:** `qeli/fuzz`, `scripts/stability_gate.py`.

Fuzz INI/hello/packet/WS/realtls/QUIC/IP/fragments/roaming с сохранением corpus. Failure injection каждой acquire/apply/save, гонки stop/auth/reload/reap. Soak 30–60 мин, перед release ≥8 ч: RSS/fd/tasks/leases/rules с churn; пороги роста задать заранее.

**Имеющаяся обвязка/fixtures:** `qeli/fuzz/README.md`, `scripts/roaming_udp_resource_soak_netns_gate.sh`, `scripts/linux_roaming_release_soak.sh`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: DONE в проверенном конечном объёме.**

**10 октября, F504–F505:** [Stability gate](../reports/BENCHMARK.md): исправлены ложный PASS по неполным/округлённым/некорректным замерам и host-wide cleanup. 89Windows/19Linux methods,4workflow lint и real read-only .11 refusal PASS; service777/845/CLI75bc сохранены. Нет нового throughput/soak или завершения Q34/Q35/Q36. 30/37DONE81,1%,7остается. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,Q35-V001:** [Реальный bounded soak](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
текущие изолированные runner выполнили100TCP+100QUIC за440,95с;33утверждения
PASS, одна сессия/исходные workers/TUN, fd стабильны, sampled RSS<32МиБ.
Реально собранный ELF повторно использован после побайтной сверки318 compiler
inputs; новая компиляция не нужна. Журналы сохранены, собственный root очищен,
служба и настройки лабы сохранены. Короткая интеграционная проверка выполнена;
30–60мин/8ч,10k, tasks churn и остальные уровни Q35 открыты. Полный статус
IN_PROGRESS, общий итог30/37(81,1%),7остаётся.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F509/Q35-F006:** [Короткие control sockets и матрица отказов](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
реальный SUN_LEN при длинном TMPDIR исправлен private /run path; все consumers
TCP/UDP/bonding/secondary перенесены.14case executions/320assertions,
7liveconcurrent snapshots,35Linuxscript+7kernelmethods PASS; первый family
FAIL и ошибка TCP-only наблюдателя сохранены. Общий Q35 IN_PROGRESS,
30/37DONE81,1%,7остаётся.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**13 октября, итог Q35:** [матрица пяти критериев](../reports/audit-0.8.2/AUDIT-Q35-FINAL.md) объединяет фактический fuzz, owning-module fault/limits audits, concurrency и полный актуальный endurance; прежние даты, FAIL и ограничения сохранены. Q36 stage-наблюдение выполнено отдельно и не квалифицирует исходную причину. Итог33/37 (89,2%), четыре раздела открыты.

### 36. Бенчмарки и методика измерения

**Код:** `scripts/benchmark.py`, `qeli/src/packet_bench_main.rs`, `test`, `docs/data/benchmarks/benchmark_results.json`.

Зафиксировать SHA/binaries, CPU/governor/affinity/VM contention, MTU/mode и background load. P=1/P=4, up/down/bidir, inner/outer v4/v6, TCP/UDP goodput, p50/p95/p99, loss/jitter, CPU/RSS/auth rate. ≥3 независимых повтора, median+spread/raw results; dev не подменяется числами 0.8.0.

**Имеющаяся обвязка/fixtures:** `scripts/bench_bonding.py` (исторический, с явным guard).

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**Статус: IN_PROGRESS.**

### 37. Документация, тестовая обвязка и мёртвый код

**Код:** `docs`, `qeli/config`, `scripts`, `conformance`, `site`.

Keys/defaults/errors против runtime, полные examples через check-config, RU/EN, stable/dev, ABI/benchmark dates. Legacy JSON config, unused dependencies/helpers/routes/flags и неподключённые тесты. Dead code подтвердить по всем OS/features/FFI/reflection/generators; регрессия должна падать на старом дефекте.

**Имеющаяся обвязка/fixtures:** `scripts/check_docs.py`, `scripts/check_panel.py`, `scripts/test_site_docs.js`, `scripts/sync_version.py`.

- [x] Review и мёртвый код.
- [x] Штатные, граничные и негативные сценарии.
- [x] Отказы и конкуренция.
- [x] Интеграция и целевая платформа.
- [x] Исправления, повторная проверка и evidence.

**11 октября, Q37-F001/F002:** [исходная точка и исправления](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md): версия RU/EN attestation examples восстановлена; private site передаётся явно через `--site-root PATH`, отсутствие входов остаётся отказом. Реальный сайт, пять отрицательных site-сценариев, пять RU/EN version methods, 97 native harness/18 certification gate tests PASS. Native provenance STALE и release certification 21 problems остаются OPEN; нужны реальные текущие сборки и финальная Linux-матрица. Полный Q37 не закрыт, общий итог 30/37 DONE81,1%.

**11 октября, Q37-F003:** убраны6320 недостижимых строк из41 retired Python/shell файла и неиспользуемый legacy JSON config. Refusal stubs сохранены;42 реальные Python отказы/3 shell guards, generated bindings и38 recipe methods PASS. Усиленный существующий regression test отказал на оригинальном dead body. [Evidence](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md). Runtime/native/benchmark inputs сохранены; полный Q37 IN_PROGRESS, итог30/37 DONE81,1%.

**11 октября,Q37-F004:** [client config parity](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md):84 defaults/81 profile keys+3 logging, REALITY/AWG/shaping/gateway/TOFU/Android docs исправлены;8 contract methods/4 old-source negatives/9docs PASS. Factory CLI39 actual admissions:37 accepted+2 expected original refusals. Первый harness FAIL и full host firewall delta FAIL сохранены; own fixture SHA/inactive cleanup выполнен. Native inputs unchanged/Q35 RUNNING; full Q37 и30/37 DONE81,1% неизменны.

**11 октября,Q37-F005:** серверные134 скалярных defaults /268 RU+EN сравнений;68 исправленных+66 исходных INI,126admission+8отказов. Исправлены inline-комментарии/смешение секций/пересечение слушателей;11methods/исходные doc negatives/docs/workflows PASS. Первый/третий/четвёртый host FAIL сохранены; повторено только девять затронутых случаев, owned SHA/inactive cleanup завершён. Native inputs прежние/Q35 RUNNING; полный Q37 IN_PROGRESS,30/37 DONE81.1%.

**11 октября,Q37-F006:** все176 читаемых INI-ключей сверены с документацией:134+41 defaults,1 obsolete. Исправлены списки/options/группы/listen/REALITY;82 реальных решения допуска (30accepted/52refused),11 прежних diagnostic FAIL сохранены. Общий вывод ошибки users.conf сохраняет причину; source Rust probe0/3 before→3/3 after, полный CLI rebuild ещё нужен. Host gates PASS/FAIL/FAIL, архив и очистка собственных roots проверены. [Отчёт](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md). Native digest317e722b stale, Q35 frozen/RUNNING; Q37 IN_PROGRESS,30/37 DONE81.1%.

**11 октября, Q37-F007:** проверены 297 Rust-файлов и 306 связей; OS/features/FFI API сохранён. Удалены прямой mio и production tower; проверены настоящие Cargo locks, 4 Linux graphs и 235 legal packages. В CI подключены 24 Python-модуля и 14 LuCI-сценариев; portable 104 на Windows, Linux 149 и изменённые import methods PASS без skips. Добавлен admission guard; 23 ручных сценария безопасны при импорте с сохранением AST тела и строк. Router tests используют временный output. Main/fuzz fmt проверен. Три host FAIL сохранены; собственные каталоги SHA-архивированы и удалены. [Отчёт](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md). Native 3538e06c STALE, Q35 frozen RUNNING; Q37 IN_PROGRESS, 30/37 DONE (81,1%).

**11 октября, Q37-F008:** локальный ci-check использует общий Rust pin и явный +toolchain, locked tests/Clippy и минимальные server/client/FFI checks. Пять настоящих Linux shell fixtures PASS, старый runner отказал; это не компиляция Rust. Два own roots SHA-архивированы/удалены; host PASS/FAIL сохранены. [Отчёт](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md). Native 3538e06c STALE, Q35 TCP5300 RUNNING; Q37 IN_PROGRESS, 30/37 DONE (81,1%).

**Q37 DONE: 12 October; agreed scope.**
## 7. Команды исходной точки и последующих прогонов

Команды ниже выполняются из корня checkout. Использовать toolchain проекта и писать
вывод каждого запуска в отдельный лог. Они не разрешают автоматически запускать
произвольные сетевые/deploy-скрипты из предыдущих разделов.

```text
python scripts/check_docs.py
python scripts/check_panel.py
node scripts/test_panel_editors.cjs
python -m unittest discover -s scripts -p "test_native_*.py"
python scripts/sync_version.py
python native-libs/provenance.py --check
python scripts/release_certification.py --quiet
```

`site/` намеренно не входит в Git. При доступном private-каталоге отдельно выполнить `node scripts/test_site_docs.js --site-root PATH`, сохранить SHA пяти проверяемых входов и лог. Если входов нет, site-проверка остаётся OPEN; остальные baseline checks выполняются независимо.

Полный серверный набор — **на Linux**; запуск той же команды на Windows имеет другое
cfg-покрытие. Зафиксировать точный target и features:

```text
cargo test --locked --manifest-path qeli/Cargo.toml --workspace -- --test-threads=1
cargo clippy --locked --manifest-path qeli/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path qeli/Cargo.toml --features transport-core-ffi transport_core -- --test-threads=1
cargo run --locked --manifest-path qeli/Cargo.toml --features conformance-gen --bin gen-conformance -- --check
```

Команды Windows/macOS/Android/iOS builds/selftests брать из текущего
[CI](../../../.github/workflows/ci.yml), сохраняя environment/fixture guards. Старое
исключение Clippy в отчётах не переносить автоматически: указать toolchain и отдельную
причину для каждого исключения. Не называть cross-check выполнением Linux runtime.

## 8. Закрытие раздела и всего цикла

Находки нового цикла именуются `Q<раздел>-F<номер>`, например `Q01-F001`, чтобы не
смешивать их с повторяющимися A-номерами старых аудитов. Для каждой — impact,
предусловия, reachable path, воспроизведение, fix и regression evidence. P0/P1 —
блокеры затронутого выпуска до исправления либо явно зафиксированного решения;
P2/P3 сохраняются как конкретные задачи, не исчезают из-за зелёных сборок.

В конце каждого раздела обновить строку в реестре, приложить результат и назвать
следующий раздел. Изменение зависимого контракта открывает регрессию у его consumers.
Перед итоговым PASS: все обязательные разделы закрыты, блокеры разрешены, все
неприменимые случаи обоснованы, native/source SHA согласованы, физические сценарии
подтверждены, benchmark воспроизводим и docs отражают пределы поддержки.

**Текущая очередь, 11 октября:** завершать Q36 по оставшимся ячейкам и проверкам
[методики](../reports/BENCHMARK.md); отдельные обязательства Q35 soak и финальная
сверка Q37 остаются открытыми. Разделы29–31 и34 закрываются по своим оставшимся
критериям; исключённые пользователем платформы не возвращаются в очередь.

**Историческая очередь на 24 сентября:** [реестр техдолга](AUDIT-DEBT.md) ниже
завершён 3 октября:14 DONE,D06 ACCEPTED_LIMITATION. Следующий абзац сохраняет
исходные обязательства того checkpoint, а не текущую очередь.

В D02 остаётся durable namespace identity глобальных записей после crash;
затем D04 crash recovery и оставшиеся D05/D06 network budgets/resource context.
Проверки lock/I/O, доверия к каталогу, отдельного kill-switch и Linux route/TUN
уже выполнены в описанных ниже границах. Runtime-контракты, полная интеграционная
матрица, другие платформы, release A/B, soak и новый benchmark остаются открытыми.
Статусы полных разделов не изменены.

**24 сентября, D05:** [Q05-F002–F004](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md): async preflight до config lock, общий бюджет проб, отказ устаревшего snapshot, owned guard для отменяемого backup/restore, bounded restart dispatch. Разделы остаются IN_PROGRESS; архивные операции и полный HTTP/systemd E2E не закрыты.

**D05/D09, backup/restore:** [Q05-F005–F007](../reports/audit-0.8.2/AUDIT-Q05-ARCHIVE-BUDGET.md): общий бюджет подготовки, bounded stdin/output, полный pre-restore snapshot, немедленный отказ дубликата и приватный API-handler roundtrip. Crash/ENOSPC/systemd и остальные сетевые бюджеты остаются открытыми.

**D02, Q25-F077:** [контекст внутри sysctl transaction](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-CONTEXT-IO.md) проверяется вокруг PID/sysctl I/O и persistence; после потери контекста транзакция не может продолжить запись. Остальные критерии D02 остаются открытыми.

D02/D05/D09: [атомарная запись состояния](../reports/audit-0.8.2/AUDIT-Q25-ATOMIC-STATE.md) очищает частичные временные файлы и синхронизирует каталог на Unix; реальные partial-write/fsync fault probes PASS. Остальные критерии этих групп остаются открыты.

D02/D05/D09: [каталог состояния и целостность lock](../reports/audit-0.8.2/AUDIT-Q25-STATE-DIRECTORY.md). Parent trust закрыт в описанных границах; durable namespace identity и исходное поколение интерфейса остаются D02. Группы целиком ещё не закрыты.

D08/D11/D12: [Android JNI и emulator runtime](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-RUNTIME.md): исправлены cwd/API flag cargo-ndk, удалён устаревший JSON-config harness; 154 JVM + 6 instrumentation PASS. Свежий dev x86_64 APK проверен по SHA. Release A/B, полный конфигурационный/runtime контракт и остальные платформы открыты.

D02: [удержание namespace](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-PIN.md) открытыми fd действует от admission до конца транзакции; 1922 Linux + 29 privileged + 8 worker E2E PASS. Между транзакциями и после crash durable generation остаётся открытым, как и исходное поколение интерфейса.

D02: [Q25-F083 — исходный sysctl интерфейса](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md): journal v3 удерживает fd и отказывает при потере свидетельства; 3 дефекта baseline воспроизведены, 5 дополнительных worker E2E PASS. Опасное восстановление по имени и потеря original закрыты. Для global journal durable namespace generation после crash остаётся открытым; автоматическое per-interface crash recovery не обещается.

D05: [Q25-F084 — общий срок DNS](../reports/audit-0.8.2/AUDIT-Q25-DNS-BUDGET.md): dns/domain делят 15 секунд от admission, частичный lease сохраняется для отдельного rollback. 3 новые Linux-регрессии PASS. NAT/routes/kill-switch и остальные lock waits остаются открытыми.

D05/D09: [Q05-F008 — async health probes](../reports/audit-0.8.2/AUDIT-Q05-HEALTH-PROBES.md): Status/Transport health не блокируют executor ожиданием `--version`; четыре общих async-слота, deadline включает очередь. 8 новых обычных + 1 privileged HTTP-router тест PASS; 2 контрольных возврата старого поведения дают ожидаемый FAIL. Общие сроки сетевых мутаций и полный HTTP/systemd/fault охват остаются открытыми.

D05/D09: [Q25-F085 — общий срок очистки kill-switch](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-BUDGET.md): 15 секунд включают operation mutex и обе семьи; частичный результат сохраняет owner для нового verified retry. 5 регрессий PASS, 2 контрольных FAIL старого поведения. Engage/refresh рассмотрены следующими фазами ниже; NAT/routes/gateway и прочие lock waits ещё открыты.

D05/D09: [Q25-F086/F087 — refresh kill-switch](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REFRESH.md): общий срок admission/команд учитывает resolver; unknown не разрешает вставку. 6 новых регрессий и 5 повторных cleanup PASS; 3 контрольных FAIL прежнего поведения. DNS/NSS остаётся синхронным; engage закрыт следующей фазой ниже в части командного срока, NAT/routes/gateway и прочие ожидания открыты.

D05/D09: [Q25-F088/F089 — установка и откат kill-switch](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-SETUP.md): общий срок установки 15 секунд и отдельный общий срок отката 15 секунд; неполный откат нельзя принять флагами разрешения утечки. 8 новых регрессий PASS; 2 контрольных FAIL, затем 8 setup + 6 refresh + 5 cleanup PASS. Полный снимок: 1962 Linux + 30 privileged + 8 worker E2E PASS. Командные сроки engage/refresh/disengage закрыты в описанных границах; синхронный DNS/NSS, NAT/routes/gateway, прочие ожидания и полные D04/D05/D09 остаются открытыми.

D05/D09: [Q14-F034 — общий срок очистки NAT](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP-BUDGET.md): profile/startup/final cleanup делят по 15 секунд между очередью, IPv4/IPv6, точными правилами и retired DNS UDP/TCP. Поздние ответы не дают успеха, неподтверждённые записи сохраняются. 8 новых Linux-регрессий PASS; 4 контрольных FAIL, затем 8 регрессий + 1 privileged exact-rule PASS. Полный снимок: 1970 Linux + 30 privileged + 8 worker E2E PASS. Открыты NAT setup/rollback, admission DNS lease в Drop/setup, routes/gateway, внутренние sysctl/I/O и полные D04/D05/D09.

D05/D09: [Q14-F035 — сроки и retirement DNS INPUT lease](../reports/audit-0.8.2/AUDIT-Q14-DNS-INPUT-BUDGET.md): setup и cleanup получают по 15 секунд с очередью/UDP/TCP; отдельный откат после setup, неблокирующая отметка завершения и сохранение pending evidence. 4 новые переносимые + 7 Linux + 1 privileged регрессии PASS; 5 контрольных отказов, затем 20 domain + 7 DNS + 8 NAT + 2 native PASS. Полный снимок: 1981 Linux + 31 privileged + 8 worker E2E PASS. NAT setup/rollback, DNS REDIRECT, routes/gateway, внутренние sysctl/I/O и полные D04/D05/D09 остаются открытыми.

D05/D09: [Q14-F036 — установка NAT/forwarding и DNS REDIRECT](../reports/audit-0.8.2/AUDIT-Q14-NAT-SETUP-BUDGET.md): общие сроки setup и точного rollback; 10 новых регрессий, 7 контрольных отказов, 1991 Linux + 31 privileged + 8 E2E PASS. Client routes/gateway, scheduler isolation и полный D05 остаются открытыми.

D02 закрыт: [Q25-F090 — поколение namespace и журнал v4](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-GENERATION.md). D04/D05 и остальные критерии сохраняются. Проверки Windows VM, Mac/iOS и роутера исключены из текущего объёма по решению пользователя; они не объявляются PASS.

D09/D10: [17/17 Linux packet matrix PASS](../reports/audit-0.8.2/AUDIT-Q34-LINUX-MATRIX.md). D13: 100 TCP handover сохранили сессию/fd, но RSS превысил критерий; FAIL сохранён, долг открыт.

D05/D09: [Q25-F091 — общий срок gateway/exit-node](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-BUDGET.md): 6 регрессий, 6 контрольных FAIL, 107 restored gateway и полный Linux 2001 + 32 privileged + 8 E2E PASS. Route-последовательности, внутренние locks/I/O и scheduler isolation остаются открыты.

D13: [release TCP/UDP по 100 handover](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md): 30/30 утверждений PASS, прирост RSS в прежнем лимите 32 MiB; debug FAIL сохранён. Полный ресурсный/fault охват и итоговый снимок ещё открыты.

D05/D09: [Q25-F092 — общий срок route-транзакций](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-BUDGET.md): 8 регрессий, 6 контрольных FAIL, 196 восстановленных route tests и полный Linux 2009 + 32 privileged + 8 E2E PASS. Executor isolation и внутренний I/O остаются открыты.

D06/D09: [Q25-F093 — строгая проверка resolver-конфига](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONFIG.md): 3 новых теста, 2 контрольных FAIL, 18 восстановленных DNS, полный Linux 2012 + 32 privileged + 8 E2E PASS. Отдельно подтверждена cross-netns мутация через общую D-Bus-шину; bus/service identity ещё требует исправления.

D06/D09/D10: [Q25-F094/F095 — контекст resolved/D-Bus и DNS-порт](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONTEXT.md): direct unique-owner вызовы с AUTH GUID, 2023 Linux + 33 privileged + 8 E2E, 17/17 packet matrix (301 assertion), 4 контрольных FAIL и restored 29 DNS + 1 privileged PASS. Реальные resolved/custom port/чужие netns и PID namespace проверены. Предыдущий пункт о незакрытом bus/service identity закрыт в описанных границах; остальные критерии D06 и D10 открыты.

D04/D06/D09: [Q14-F037 — worker network lease](../reports/audit-0.8.2/AUDIT-Q14-WORKER-NETWORK-LEASE.md): исправлен обход через разные control/state пути; baseline удалял 9 правил работающего worker. 2027 Linux + 34 privileged + 8 lifecycle и 22 crash/admission/recovery проверки PASS. D04 IN_PROGRESS: persistent exact firewall/routes и mixed nft остаются открытыми.

D04/D09/D10: [Q14-F038 — persistent server firewall](../reports/audit-0.8.2/AUDIT-Q14-FIREWALL-JOURNAL.md): точные NAT/routing/DNS INPUT/REDIRECT спецификации записываются до изменения, восстанавливаются после SIGKILL и удаления профиля без listing. Backend/namespace/file errors останавливают startup, evidence сохраняется. 2044 Linux + 35 privileged + 8 lifecycle; 27 recovery checks; 17/17 cases, 301 assertions PASS. D04 остаётся IN_PROGRESS: клиентские route/DNS/kill-switch и полная mixed nft/firewalld матрица открыты.

D04/D06/D09: [Q25-F096/F097 — DNS state v2](../reports/audit-0.8.2/AUDIT-Q25-DNS-MARKER-STORAGE.md): доверенный закреплённый каталог, проверка файлов и SO_NETNS_COOKIE; v1 сохраняется без автоматической миграции. 3 файловых дефекта воспроизведены на baseline. 2055 Linux + 37 privileged + 8 lifecycle; 17/17 cases, 323 assertions PASS. Остаются client route/kill-switch recovery, legacy global DNS, live persistent TUN, mixed nft/firewalld и накопление sidecar-файлов; D04 IN_PROGRESS.

D04/D09/D10: [Q25-F098 — kill-switch после crash](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REBUILD.md): временные точные DROP guards сохраняют прежний барьер при setup/rollback и повторном SIGKILL. Baseline реального клиента пропускал 14 IPv4 + 13 IPv6 UDP-проб; fixed — 0. 2057 Linux + 39 privileged + 8 lifecycle; 14 runtime checks; 17/17 cases, 339 assertions PASS. D04 IN_PROGRESS: routes, legacy global DNS/persistent TUN и полная mixed firewall матрица открыты.

D04/D09: [Q25-F099 — атрибуты владения маршрутом](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-ATTRIBUTES.md): пригодность чужого маршрута отделена от delete/replace authority; неявные protocol/metric/source и дополнительные атрибуты проверяются. Baseline удалял 10 операторских замен на ядре и static bypass настоящего клиента. 2068 Linux + 40 privileged + 8 lifecycle; 17/17 cases, 384 assertions PASS. На этом этапе persistent client route journal ещё не был реализован; продолжение Q25-F100 ниже. D04 IN_PROGRESS.

D04/D09: [Q25-F100 — постоянный журнал физических маршрутов](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-JOURNAL.md): durable intent/confirmed ownership, boot/cookie/TUN scope, общая блокировка и terminal roaming при I/O ошибке. Baseline оставлял bypass/blackhole после SIGKILL → reconnect → stop (3 FAIL). 2087 Linux + 43 privileged + 8 lifecycle; 17/17 cases, 489 assertions PASS. Client physical route recovery закрыт в описанных пределах; legacy global DNS, live persistent TUN и mixed firewall остаются D04 IN_PROGRESS.

D04/D05/D09: [Q25-F101 — legacy global DNS](../reports/audit-0.8.2/AUDIT-Q25-LEGACY-DNS.md): unsafe автоматический replay и PID refcount удалены; снимок/holders требуют ручного восстановления без чтения содержимого и ожидания lock. Baseline изменял resolver в 4 сценариях; новый контракт 47/47 PASS. 2078 Linux + 43 privileged + 8 lifecycle; 17/17 cases, 489 assertions PASS. Старое глобальное восстановление закрыто безопасным отказом; D04 IN_PROGRESS — live persistent TUN и mixed firewall остаются.

D04/D09: [persistent TUN/TAP после SIGKILL](../reports/audit-0.8.2/AUDIT-Q25-PERSISTENT-TUN.md): подтверждён безопасный отказ без изменения интерфейса/routes/DNS/firewall и восстановление после ручного удаления проверенного остатка. 17/17 строк, 506 основных утверждений; 17 persistent-сценариев с 199 подробными проверками PASS. Новый дефект не обнаружен, Rust не изменён. Эта часть D04 закрыта в описанных пределах; D04 IN_PROGRESS — полная mixed firewall матрица остаётся.

D04/D09/D10: [серверный mixed nft/legacy/firewalld recovery](../reports/audit-0.8.2/AUDIT-Q14-MIXED-FIREWALL.md): 16/16 сценариев, 476 проверок PASS. Реальная смена backend каждого семейства, native nft parse errors, firewalld reload, partial cleanup и ручное восстановление проверены. Неопределённое отсутствие сохраняет журнал; потерянный WAN sysctl witness остаётся ручной границей D02. Rust не изменён. D04 IN_PROGRESS: mixed firewall packet/recovery для клиентского kill-switch/DNS/routes ещё требуется.

D04 закрыт: [Q25-F102 и клиентская mixed firewall матрица](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-MIXED-FIREWALL.md): 152/152 сетевые ячейки, 136 SIGKILL/recovery, 4880 основных утверждений и 3224 вложенных проверок PASS. Все 4352 прямых UDP-попыток при защите заблокированы; 2624 разрешённых проб получили ответ. Общий распознаватель исправлен для точного legacy advisory; серверные 16/16, 476 checks повторно PASS. Ручные границы persistent TUN/sysctl/legacy DNS сохранены. **Итого техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.** Это не завершение разделов полного аудита; D05/D06 и D09/D10/D13 остаются открытыми.

D05/D09: [Q25-F103 — общий DNS/NSS и остановка](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-RESOLVER.md): четыре незавершённых вызова, deadline с очередью, сохранение слота после отмены и отсутствие ожидания blocking pool при shutdown. 4 baseline отказа и 4 fixed PASS; 38/38 hostname cells, 34 crash/recovery, 1220 основных и 806 вложенных checks PASS. 1537 host + 71 config; 2089 Linux + 44 privileged + 8 lifecycle PASS. D05 остаётся IN_PROGRESS: scheduler isolation сетевых мутаций, внутренние locks/I/O и цельный NetworkPlan/shutdown. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F104 — resolver-файлы до firewall](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-FILES.md): один ограниченный снимок, общий reader/parser со stub, точный keyword, комментарии и сохранение scope. 7 baseline/fixed пар; 2 старых зависания, все 7 fixed очищены. 38/38 cells, 34 crash/recovery, 1220 основных и 806 вложенных checks PASS. 1544 host + 71 config; 2098 Linux + 44 privileged + 8 lifecycle PASS. D05 остаётся IN_PROGRESS: сетевые мутации, внутренние locks/I/O и общий NetworkPlan/shutdown. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F105 — применение NetworkPlan вне async-потока](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-TASK.md): отдельный поток сохраняет ownership и исходный NET/mount-контекст до принятия результата или завершения отката; native ACK использует async sleep. 7 новых переносимых + 1 Linux + 1 privileged регрессия; контрольный синхронный helper FAIL, исправленный PASS. Реальные TCP/UDP × TUN-create/ip-up: 4/4 PASS с отзывчивым однопоточным runtime, ожиданием отката и точным восстановлением сети. 38/38 cells, 34 crash/recovery, 1220 основных и 806 вложенных checks; 1551 host + 71 config; 2106 Linux + 45 privileged + 8 lifecycle PASS. D05 остаётся IN_PROGRESS: штатная очистка активного туннеля, kill-switch mutations, locks/I/O/диагностика и общий NetworkPlan/shutdown deadline. Принудительный Drop может блокировать поток до join. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F106 — штатная очистка установленного туннеля](../reports/audit-0.8.2/AUDIT-Q25-TUN-TEARDOWN.md): общий TCP/UDP TunGuard shutdown сохраняет DNS → pump join → routes/forwarding и выполняет сетевую очистку в одном присоединяемом потоке. Worker failures входят в sticky Failures. 5 новых переносимых + 1 privileged тест; baseline TCP/UDP дали 0 heartbeat тиков при задержке cleanup, fixed — 7–8. 4/4 fixed сценария и 2/2 повторных явных запуска после отказа PASS; kill-switch при ошибке сохранён. 38/38 cells, 34 crash/recovery, 1220 основных и 806 вложенных checks; 1556 host + 71 config; 2111 Linux + 46 privileged + 8 lifecycle PASS. D05 остаётся IN_PROGRESS: ранние error/Drop-пути, kill-switch mutations, locks/I/O/диагностика и общий NetworkPlan/shutdown deadline. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F107/F108 — firewall workers и сохранение DROP](../reports/audit-0.8.2/AUDIT-Q25-FIREWALL-TASK.md): setup/refresh и все шесть терминальных cleanup-путей ждут владеющий worker; неподтверждённый unhook запрещает очистку цепочки. 8 новых регрессий, 8 baseline + 12 fixed runtime-сценариев; baseline пропустил 6 UDP-проб после отказа cleanup, fixed — 0. 38/38 cells, 34 crash/recovery, 1220 основных + 806 вложенных checks; 1564 host + 71 config; 2119 Linux + 46 privileged + 8 lifecycle PASS. Исходный wildcard UDP recovery FAIL сохранён: повтор с явным bind прошёл, multi-IP wildcard остаётся D06/D10. D05 открыт: startup recovery, ранний Drop, locks/I/O/диагностика, общий срок. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D06/D09/D10: [Q15-F002 — адрес ответа UDP wildcard](../reports/audit-0.8.2/AUDIT-Q15-UDP-LOCAL-ADDRESS.md): pktinfo сохраняется от receive до immutable reply/roaming/PMTU path. Baseline — второй IPv4 адрес не подключается, 96 wrong-source replies; fixed — 8/8 подключений IPv4/IPv6 × plain/obfs, 256/256 inner UDP echoes и исходный refresh-fault recovery PASS. 6 новых Linux + 1 privileged регрессия; 1564 host + 71 config; 2125 Linux + 47 privileged + 8 lifecycle; 38/38 cells, 34 crash/recovery, 1220 + 806 checks PASS. Wildcard defect закрыт в границах отчёта, полные D06/D10 и D05 открыты. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F109 — startup recovery в joined worker](../reports/audit-0.8.2/AUDIT-Q25-STARTUP-RECOVERY-TASK.md): lease → routes → DNS, stop ждёт результат и сохраняет ошибку; успешный stop не начинает подключение. 3 новые Linux-регрессии, 2 baseline + 6 fixed runtime; baseline heartbeat 0, fixed 7–8, конкурентные claims исключены; stale DNS marker удалён, live/busy/foreign/legacy сохранены. 1564 host + 71 config; 2128 Linux + 47 privileged + 8 lifecycle; 38/38 cells, 34 crash/recovery, 1220 + 806 checks PASS. D05 открыт: ранние error/Drop, locks/I/O/диагностика, общий deadline. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F110 — запуск pump и ранний откат](../reports/audit-0.8.2/AUDIT-Q25-PUMP-START.md): общий Linux worker владеет guard/fd при fcntl/thread failure, partial reader join предшествует освобождению TUN; recordizer/budget checks перенесены до platform apply. 4 baseline + 8 fixed runtime, 4 cleanup faults + 4 recovery PASS; heartbeat 0 → 7–8. 1564 host + 71 config; 2128 Linux + 47 privileged + 8 lifecycle; 38/38 cells, 34 crash/recovery, 1220 + 806 checks PASS. D05 открыт: оставшиеся ранние пути, Drop fallback, locks/I/O/диагностика и общий deadline. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F111 — последовательный writer диагностики](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md): один поток, один ожидающий снимок, join итоговой записи; файловый I/O вне async-потока. 5 новых portable + 1 privileged тест; 2 baseline + 4 fixed fsync-сценария, 2 baseline + 4 fixed TCP/UDP teardown и 2 recovery PASS. 1569 host + 71 config; 2133 Linux + 48 privileged + 8 lifecycle PASS. D05 открыт: остальные locks/I/O, ранний Drop и общий deadline. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F112/F113 — файлы идентичности](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-FILES.md): ID загружается один раз в joined worker, временный ID стабилен при reconnect; TOFU ограничен 1 MiB, повреждение/конфликт пинов запрещает новое доверие, запись атомарна. 15 новых тестов; 8 baseline + 8 fixed identity cases, 6 teardown cases и 2 recovery PASS. 1575 host + 71 config; 2148 Linux + 48 privileged + 8 lifecycle PASS. D05 открыт: синхронный TOFU, другие startup I/O/Drop и общий deadline. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F114 — TOFU worker](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md): файлы доверия обрабатываются в одном присоединяемом потоке; отмена и timeout не оставляют запись без владельца, поздний отказ сохраняется до terminal result. 9 portable regressions; 16 worker cases + 16 файловых + 6 teardown и 2 recovery PASS. 1584 host + 71 config; 2157 Linux + 48 privileged + 8 lifecycle PASS. Общий deadline и другие startup I/O/Drop остаются D05. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

**4 октября, HTTP/WS read batch PASS:** [Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md): 6 исправлений,9 baseline FAIL,11 новых тестов,2335 Linux PASS,40 live probes+63 transport assertions,request-head ASan/libFuzzer,свежие matrix/soak/четыре native A/B PASS. На момент read-пакета Close/control lifecycle и wire-матрица оставались открытыми; тогда Q12 IN_PROGRESS,план11/37 (29,7%).

**5 октября, Q28 per-app:** [bridge, Swift и build paths](../reports/audit-0.8.2/AUDIT-Q28-MACOS-PERAPP.md): F256–F261; 22 managed +10 shell PASS,6 old bridge failures и5 old shell failures. Swift source review,10 новых native cases USER SKIPPED. Q28 IN_PROGRESS; forwarding/guardian/native socket lifetime остаются. План 27/37.

**5 октября, Q28 forwarding:** [владение и recovery](../reports/audit-0.8.2/AUDIT-Q28-MACOS-FORWARDING.md): F262–F264;58 новых проверок,1208 managed PASS,6 ожидаемых baseline FAIL. Один Qeli-владелец на Mac, durable snapshot до sysctl, независимые restore/checkpoint/retry. Реальный Mac USER SKIPPED. Q28 IN_PROGRESS;guardian/native socket lifetime и интеграция остаются. План27/37.

**5 октября, Q28 guardian:** [готовность и generation ownership](../reports/audit-0.8.2/AUDIT-Q28-MACOS-GUARDIAN.md): F265–F267;39 per-app (17 новых),1225 managed PASS,9 ожидаемых old C# FAIL. Swift ownership/10 новых cases SOURCE REVIEW / USER SKIPPED. Схема v5, bundle upgrade после stop старых guardian; legacy state не перехватывается. Q28 IN_PROGRESS;native sockets и integration остаются. План27/37.

**5 октября, Q28 sockets:** [fd lifetime и I/O бюджеты](../reports/audit-0.8.2/AUDIT-Q28-MACOS-SOCKETS.md): F268–F270,20 новых Swift cases SOURCE REVIEW / USER SKIPPED. Serial queue + cancel-handler release,nonblocking deadlines,atomic framework-write watchdog,zero UDP datagrams.1225 связанных managed PASS не выполняют Swift. Q28 IN_PROGRESS;финальная интеграция/DNS-PF owner stamps остаются. План27/37.

**5 октября, обычные Android sockets:** [split/full × три транспорта](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-DATA.md):6 свежих PASS,72 ответа. В5/6 запусков первый IPv4source физический после наблюдаемогоCONNECTED;TUN готов через1–111ms,до payload есть preflight. Немедленный первый пакет и внешние/default маршруты не квалифицированы;DNS/kill-switch/lifecycle далее. ProductAPK/JNI неизменны,Q29IN_PROGRESS,28/37(75,7%).

**5 октября, Q29 off-pool/DNS:** [семь сценариев](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-DATA.md):7 новых PASS,72 ответа вне пула и12 системных DNS A/AAAA ответов;full без includeRoutes,split без default routes. Валидный full kill-switch отказал без OS lockdown. Первый wildcard UDP sink дал6 timeout;pcap подтверждает wrong-source стенда,исправленный sinkPASS. ProductAPK/JNI неизменны;положительный lockdown/system lifecycle ещё открыт,Q29IN_PROGRESS,28/37(75,7%).

**5 октября,Q29 системный lifecycle (частично):** [Always-on/lockdown и внешнее завершение процесса](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md):настоящая OS-политика,независимый UID,блокировка после SIGKILL/force-stop, ручное восстановление и системный revoke подтверждены. Автоматическая redelivery после SIGKILL FAIL (вопрос открыт) несмотря на startCommandResult=3;полный system gate не PASS. Q29 IN_PROGRESS,28/37(75,7%).

**5 октября,Q29 независимый Android-контроль:** [минимальный Java VpnService](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md):без TUN перезапущен за17,40s с flags=1;с TUN нет нового PID за45s как при lockdown=0,так и при lockdown=1. Отказ воспроизведён без JNI/ядра Qeli;при одинаковом lockdown=0 отличается только создание TUN. Точная framework реализация/другие устройства не квалифицированы;продуктовый recovery gate остаётся FAIL,Q29 IN_PROGRESS,28/37(75,7%).

**5 октября, Q29 power/TCP recovery:** [три свежих сценария](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-POWER.md): экран5s, forced IDLE20s и TCP reset/reconnect PASS с тем же PID/TUN; оба пробуждения без новой Auth/NetworkPlan. Один bootstrap PASS, 10 receipts включая отложенный fault UDP через TUN после recovery Auth (+0,207s), а не вечное отбрасывание. Revoke/cleanup, host/service/userdata/power восстановление PASS. APK/JNI неизменны; из296 source inputs изменён только README,295 идентичны. Длительный/реальный Doze, handover, UDP/QUIC остаются; SIGKILL recovery по-прежнему FAIL. Q29 IN_PROGRESS,28/37(75,7%).

**5 октября,Q29 UDP/QUIC recovery:** [четыре свежих сценария](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-UDP-RECOVERY.md):2bootstrap PASS,UDP/QUIC×soft/grace-expiry4/4PASS. Soft:новый внешний порт/epoch1 без новой Auth/plan;full:строгий fallback и ровно1 новая Auth/plan;PID/TUN/адреса сохранены.18receipts включая2отложенных fault UDP через TUN после recovery Auth,0receipts в отрицательных окнах. Revoke/очистка/host/service/userdata PASS.1test source изменён,295inputs/productAPK/JNI/managed идентичны;новый testAPK. Same-network не закрывает carrier handover;SIGKILLFAIL остаётся.Q29IN_PROGRESS,28/37(75,7%).

**5 октября,Q29 carrier handover:** [реальная смена Network в AVD](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-HANDOVER.md):UDP/QUIC×Wi-Fi↔Cellular4/4целевых PASS,2bootstrap в успешных runs,16receipts. Новый systemhandle/outerport/epoch,Auth/plan2/2,TUN сохранён. Первый UDPFAIL сохранён:ошибочный exact-one-commit predicate при LinkProperties update;исправленный gate проверяет всеtargethandles,UDPповторPASS,QUICстрогийпервыйPASS не повторён.3readonlyattempts,host/service/userdata/cleanup unchanged.296inputs/2APK/JNI/managed идентичны. Это AVD/private backend;TCPhandover,post-switchIPv6/TCP,NAT64/Release остаются,SIGKILLFAIL открыт.Q29IN_PROGRESS,28/37(75,7%).

**5 октября,Q29 TCP handover:** [Wi-Fi↔Cellular](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TCP-HANDOVER.md):2/2PASS,1bootstrap/8receipts. Новая Auth/NetworkPlan и внешние порты,PID/TUN/адреса сохранены,ordinary UID payload после recovery;UDPpathcommit0. Revoke/settings/host/service/userdata/cleanup PASS;296inputs/2APK/JNI/managed идентичны. Только harness,без пересборки. Post-switchIPv6/TCP,NAT64/Release,longpower/flapping,SIGKILLFAIL остаются.Q29IN_PROGRESS,28/37(75,7%).

**5 октября,Q29 post-switch payload:** [полная dual-stack матрица](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-HANDOVER-PAYLOAD.md):TCP/UDP/QUIC×Wi-Fi↔Cellular×IPv4/IPv6TCP/UDP24/24PASS,6transitions,3bootstrap/42receipts. IndependentUID,все replybytes/SHA,sink+TUNpcap;TCPfreshAuth/plan,TUNretained;UDPsoftcommits/Authunchanged. Revoke/settings/host/service/userdata/cleanupPASS.295inputs/productAPK/JNI/managed identical,1testreceiverchange,newtestAPK. ДоступныйAVD post-switchpayloadзакрыт;IPv6only/NAT64,Release,longpower/flapping,SIGKILLFAIL остаются,Q29IN_PROGRESS,28/37(75,7%).

**5 октября, Q29 Release runtime:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md): 24/24 payload-проб, шесть переходов Wi-Fi ↔ Cellular, три UI-импорта INI, 30 receipts. TCP/UDP/QUIC × IPv4/IPv6 TCP/UDP, независимый UID, полные ответы/SHA и TUN pcap. PID/TUN сохранены; revoke/cleanup и состояние стенда PASS. Release/testRelease R8, недебажный клиент, лабораторная подпись; production правила не ослаблены. Matching instrumentation Trace FAIL и четыре неуспешные попытки сохранены; успех UI их не закрывает. IPv6-only/NAT64, полный Release fault suite, leak-матрица, долгий power/flapping и SIGKILL FAIL остаются. Q29 IN_PROGRESS; 28/37 (75,7%).

**5 октября, Q29 Release faults:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-FAULTS.md): семь сценариев PASS (screen-off, forced Doze, TCP reset, UDP/QUIC × soft/grace-expiry), три UI-импорта, 12 стартовых dual-stack payload-проб. PID/TUN сохранены, wake без новой Auth/plan, full recovery с новой Auth/plan; revoke/cleanup и состояние стенда PASS. Та же Release-пара и все 296 inputs без пересборки. Две ошибки обвязки сохранены; DEX объясняет исходные Trace references без определения, runner FAIL не назван PASS. NAT64, leak-матрица, долгий power/flapping, остальные lifecycle и SIGKILL FAIL остаются. Q29 IN_PROGRESS; 28/37 (75,7%).

**5 октября, Q29 IPv6-only/NAT64:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-NAT64.md): TCP/UDP/QUIC masking, три Release UI-импорта, 12 dual-stack TCP/UDP payload-проб и 18 receipts PASS. SLAAC/RDNSS WLAN без IPv4, A-only сервер, DNS64 и реальная двусторонняя трансляция подтверждены pcap; revoke/cleanup и состояние стенда PASS. Все 296 inputs и APK/JNI/managed неизменны. Три ошибки стенда сохранены, NAT64 handover на fixed-IPv4 Cellular не квалифицирован. Leak-матрица, долгий power/flapping, остальные lifecycle и SIGKILL FAIL остаются. Q29 IN_PROGRESS; 28/37 (75,7%).

**5 октября, Q29 переходы/stop leak probes:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-LEAK-BURSTS.md): четыре Release runs, 1 056 проб, шесть handover и четыре force-stop. Все четыре физических исходящих пути положительно калиброваны sink/pcap; timeout короткого baseline не назван блокировкой. Нет новых физических SYN/data/UDP в проверенном окне; post-baseline маркированные запросы только через TUN, 192 post-stop пробы без ответа/receipt/capture. Ручное восстановление 16 payload-проб и revoke/cleanup PASS. Product APK/native/managed прежние; один test receiver изменён, свежий test R8 build. DNS/cold-start/split/per-app, долгие сценарии и SIGKILL FAIL остаются. Q29 IN_PROGRESS; 28/37 (75,7%).

**5 октября, Q29 DNS/cold start:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STARTUP-DNS.md): TCP/UDP/QUIC, 864 socket samples, 21 DNS operations с уникальными именами, A/AAAA через TUN; шесть DNS operations и 144 socket samples без VPN заблокированы. 12 manual recovery payloads/revoke/cleanup PASS, восемь попыток/538 echo receipts. Немедленная доставка после APPLIED FAIL на всех трёх транспортах (27–247 ms); следующее 48/48 не закрывает readiness. Generic DnsResolver ENONET и пять неуспешных попыток сохранены; QUIC test-only journal устраняет зависимость доказательств от потери logcat, TCP/UDP не повторялись. Product APK/native/managed прежние, свежие test APK; источник/пара каждого прогона закреплены. Cold publication, split/per-app/Private DNS, долгие сценарии и SIGKILL FAIL остаются. Q29 IN_PROGRESS; 28/37 (75,7%).

**5 октября,Q29 DNS API:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md):7диагностических вариантов,8no-payload socket checks,288socket samples/48blocked,4manual recovery/revoke/cleanupPASS. Ошибки и4failed attempts сохранены;productAPK/JNI/managed прежние,testAPKновый. ENONET/rootcause и прежние readiness/SIGKILL/runnerFAIL остаются;Q29IN_PROGRESS,28/37(75,7%).

**5 октября,Q29 startup state:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STARTUP-STATE.md):336socket samples/96network snapshots,callback timeline;послеAPPLIED56,activeVPN/tun0/dual48,ошибоквэтойгруппе4. ТочныйCONNECTEDнеизмерен,историческиеFAILсохранены. UI dumpперенесёнв/data/local/tmpпослеabsent-sdcard-XMLFAIL,тотжеAPK,cleanupPASSобеихпопыток;48blocked/4manualrecovery/revokePASS. Q29IN_PROGRESS,28/37(75,7%).

**5 октября,Q29 F279:** [CONNECTED gate](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONNECTED-GATE.md):172 unit/5 новых PASS,lint0errors;3 финальных Release-прогона,960samples,80freshpostCONNECTED/0errors,TCPinclude retainedTUN2transitions. ACK немедленный,UI ждёт Android callback;исторические APPLIED/SIGKILL/runnerFAIL сохранены.Q29IN_PROGRESS28/37(75,7%).

**5 октября, Q29 Release runner:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNNER.md):7/7 instrumentation PASS,TCP/UDP/QUIC×split/full,72receipts/12DNS. Opt-in R8 ABI rules выведены из pre-R8 references;default production rules неизменны. Trace/LazyKt и Kotlin access FAIL сохранены;3attempts cleanup/host/userdata PASS. PrivateDNS/per-app/longlifecycle/SIGKILL остаются;Q29IN_PROGRESS28/37(75,7%).

**5 октября, Q29 per-app/Private DNS:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-APP-POLICY.md):include/TCP иexclude/QUIC наproductionR8,112socket/80reply/32expectedblocked,52DNSops/48answers,7states×2UID. Нетphysical DNS выбранногоUID/fallback после strict-negative;2PCAP/drop0,cleanup/settings/host/userdata PASS. Strict trustedDoT/longpower/flapping/SIGKILL/ENONET остаются;Q29IN_PROGRESS28/37(75,7%).

**5 октября, Q29 ограниченный Doze/flapping:** [отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-ENDURANCE.md):TCP/UDP/QUIC,9power phases(30s+2×120s),18WiFiCellulartransitions,36wake/72posthandover payloads,1440burst samples/144poststopblocked,45DNSops/72answers;3PCAP/protectedphysical0/drop0. PID/TUN сохранены;settings/host/userdata/recovery/revoke PASS. Исправлен исторический commit false-positive в обвязке,5regression tests. Bounded AVD матрица закрыта;physical/OEM longsoak,strict trustedDoT/SIGKILLFAIL/ENONET остаются,Q29IN_PROGRESS28/37(75,7%).

**5 октября, Q29 trusted DoT:** [Report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-DOT.md): TCP/UDP/QUIC strict untrusted/trusted/mismatch/recovery PASS;39DNS/12authenticated answers,36payloads,576bursts/144poststopblocked;3PCAP physicalleaks0/drop0. Temporary labCA/settings/host/userdata cleanup5attempts PASS;2harnessFAIL preserved;dynamicUID fixed/12helper3CLI fresh,product/native/managed unchanged. SIGKILLFAIL/ENONET/otherAPI-OEM-arm64 open;Q29 IN_PROGRESS28/37(75.7%).

**6 октября, Q29 F280:** [владение запросом разрешений](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-PERMISSIONS.md): один корректный профиль/набор адаптерных тестов, старый3FAIL/новый3PASS; исправлены отмена/снимок профиля/пересоздание Activity. Свежие179JVM(7новых), lint0ошибок55предупреждений; defaultR8 TCP обычная UI-кнопка,16payload/192burst/13DNS/strictDoT/capturephysical0drop0 PASS. Стадия разрешения и ответ инъецированы; Release instrumentation NOT RUN; четыре предварительных запуска не засчитаны, все семь cleanupPASS. Native/server/managed неизменны; SIGKILL/ENONET/другиеAPI-OEM-arm64 остаются,Q29IN_PROGRESS28/37(75.7%).

**6 октября, Q29 доверенный Wi-Fi:** [runtime сервиса](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-WIFI.md):3новых instrumented PASS,реальныйSSID/фон1,2s/WiFiCellularцикл/livepause/отменаresume250ms/отказkill-switch,16полных IPv4IPv6TCPUDP payload receipts. Product/native/managed неизменны;JVM/lint/R8 сохраняют прежнюю область. 2harnessFAIL сохранены,3runtime cleanup/host/userdata PASS;свежие4helper/4CLI. Active-lockdown trustedSSID handover/оставшиесяlifecycle/SIGKILL/ENONET/другиеAPI-OEM-arm64 открыты,Q29IN_PROGRESS28/37(75,7%).

**6 октября, Q29 F281:** [доверенный Wi-Fi и lockdown](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-LOCKDOWN.md): старый Release пропускает активный reconnect на возврате и восстанавливается после ошибки транспорта; исправлены четыре callback predicates. Свежие182JVM(3новых)/lint0errors55warnings/defaultR8; TCP/UDP/QUIC6handover transitions,36полных payload отдельного UID,864bursts/144poststopblocked,3capture physical0/drop0 PASS. Свежиеdebug3normal-pause tests/16payloads PASS;15helper4CLI/docs/bindings. Три preliminary harnessFAIL и один pre-runtime SFTP обрыв сохранены;8runtime cleanup/host/userdata PASS. Native/server/managed неизменны;Release instrumentationNOT_RUN. SIGKILL/ENONET/remaining lifecycle/protect/otherAPI-OEM-arm64 открыты;Q29IN_PROGRESS28/37(75,7%).

**6 октября, Q29 F282:** [владелец защиты сокета и отказы доверенного Wi-Fi](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONTROLLER.md): устаревший взятый из очереди запрос отклоняется до carrier/bind/protect под монитором службы; задержки/JNI ACK снаружи. Тот же свежий test APK: старый8/3ожидаемых FAIL, исправленный8PASS (пять новых сценариев),28полных debug ответов. Свежие182JVM/lint0ошибок55warnings/defaultR8; TCP/UDP/QUIC6переходов/36полных ответов отдельному UID,864пробы/144poststopblocked,независимый capture physical0/drop0 PASS. Все пять попыток cleanup/host/service/userdata/address PASS;15helper4CLI/docs/bindings. Три protect проверки — Context-attached adapter fixtures с настоящими JNI sockets; location-switch redaction и queued disconnect используют framework, без утверждения о permission revoke или барьере native join. Native/server/managed неизменны;Release instrumentationNOT_RUN. SIGKILLFAIL/auto-nullENONET и непроверенное платформенное/lifecycle покрытие сохранены;Q29IN_PROGRESS28/37(75,7%).

**6 октября, Q29 F283:** [владелец снятого сетевого наблюдателя](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONTROLLER.md): callbacks проверяют owner/stopping под lifecycle monitor, регистрация/снятие сериализованы; намеренная trusted-пауза сохраняет наблюдателя. Настоящая Android registration/real carrier с управляемой поздней доставкой на Context-attached adapter службы: тот же свежий test APK старый13/5ожидаемых FAIL, исправленный13PASS; настоящая framework trusted suite сохраняет28полных ответов. Свежие182JVM/lint0ошибок55warnings/defaultR8 UDP2перехода/12полных ответов отдельному UID/288проб/48poststopblocked;независимый capture physical0/drop0 PASS. Три runtime cleanup/host/service/userdata/address PASS;15helper4CLI/docs/bindings. Первые module-style import failures сохранены, прямые вызовы scripts PASS; устаревшие комментарии удалённых реализаций исправлены. Native/server/managed неизменны,Release instrumentationNOT_RUN; прежняя TCP/QUIC матрица сохраняет старую область. Добавлена таблица завершения; SIGKILLFAIL/auto-nullENONET сохранены;Q29IN_PROGRESS28/37(75,7%).

**6 октября, Q29 F284–F285:** [редактор профиля/экспорт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md): исправлены ранний Save и потеря отсутствующего пакета/состояния режима; ошибка чтения store отображается, encryption/write/close перенесены на IO, отказ sink не считается успехом. Один исправленный test APK старый5/4ожидаемых FAIL, исправленный5PASS; первые3FAIL/диагностика раннего чтения listener сохранены. Свежие188JVM(6новых),lint0errors54warnings/defaultR8 TCP2handover/12полных ответов/288socket samples/48poststopblocked,capturephysical0/drop0;5attempts host/userdata/address/server cleanupPASS;15helper6CLI. Private file exports подтверждены, сторонние SAF/cloud providers не исполнялись. Q29IN_PROGRESS28/37(75,7%);SIGKILLFAIL/ENONET/skips/D06 неизменны.

**Продолжение F326–F327, 6 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): exact saved-plan receipt for OpkgTun no-op/MTU changes, literal address matching; matching-zombie recheck after failed exe lookup.120 cases each BusyBox/dash (47 owned native-process,44 state,29 installer/hook),12 new;37 recipes/docs/bindings PASS. Old/current hook and deterministic zombie failures reproduced; initial dash FAIL and orphan NOT_REPRODUCED retained. No actual router/core network or generation/concurrency qualification; INI parity/package/build/source review OPEN. Q31 IN_PROGRESS,28/37 unchanged.

**F328–F329, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): isolated per-run verification checkout/target; shared source sync, no service operations; checked locked single-job host gate, forward normal/build graph, mandatory ELF/hash and meaningful exit/SSH-finally.19 gate tests Windows/Linux,7 real temp-file shared-sync,37 recipes/docs/bindings PASS; actual offline Cargo local-fixture positive/negative graphs PASS. Original forced-service calls, stale sync, false PASS/exit0 and connection leak reproduced with models/temp files. No Qeli build/router qualification; INI parity/OpkgTun concurrency/package/build provenance OPEN.Q31 IN_PROGRESS,28/37 unchanged.

**F330–F331, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): removed both shell INI parsers; client-bin-only core metadata inspection uses bounded loader/strict common parser. Quoted/case/BOM/on parity and exit_node ownership; cached validated preflight, unknown/error reply fails before launch. Fresh Rust1.97 client-bin host debug build/8unit/Clippy/fmt PASS;155cases each BusyBox/dash,16new owners with22actual inspector subcases;16old/current records each shell.37recipes/docs/bindings PASS. Default core outside gated addition unchanged; no FFI/release/cross rebuild or real router networking. Binary/template upgrade together; configuration path is reloaded, generation/concurrency not closed. Q29/Q30/D06 retained,Q31 IN_PROGRESS28/37.

**F332–F334, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): shared lifecycle.sh for both init variants, wan.d and installer; atomic mkdir exclusion across whole restart/internal cleanup, under-lock marker recheck, shared library delivery0600. Observed core plan replacement stops L3/save/receipt and retains retry; directory publication targets rejected.165cases per BusyBox/dash,8new concurrent lifecycle and2installer; three old hook/stop/save assertions and old directory publication reproduced.37recipes/docs/bindings PASS. Network/ndm/opkg modeled; owned shell/native helpers real; core/native inputs/artifacts unchanged. Busy events require retry; SIGKILL stale lock needs manual owner review, no auto deletion. Atomic core/config generations/ABA/firmware/build provenance remain OPEN. Q29/Q30/D06 retained,Q31 IN_PROGRESS28/37.

**F335–F337, 6 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): приватные source/target0700 на запуск, обязательный upload, без общего restore manifest; --sync совместим, каталоги сохраняются. Общий SHA-bound ELF gate до atomic publication, ARM EABI5 hard-float; SDK lockfile/metadata guard, один compiler job.45 Linux router методов,20 old/current записей,5 реальных offline tiny-crate make/Cargo случаев,real static ELF positive/GNU debug negative,37recipes/docs/bindings PASS. Начальные harness FAIL сохранены. Новая Qeli cross/firmware сборка, полный ABI/musl/ISA/pinning/reproducibility не заявлены; native/core/binaries неизменны. Generation/ABA/rollback/firmware OPEN; Q29/Q30/D06 сохранены.Q31 IN_PROGRESS28/37(75.7%),9осталось.

**F338–F339, 6 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): общая target/setup/build policy, Rust1.97.0/MIPS nightly-2026-06-10/Zig0.13.0/cargo-zigbuild0.23.0, проверенные identities/std/rust-src/installer result. Encoded/ambient compiler flags изолированы; dead helper definitions/duplicate build_std удалены.52Linux tests/12old-current models/реальный offline host Rust1.96ambient→1.97recipe fixture/37recipes/docs/bindings PASS. Начальные CLI probe и временный BIN FAIL сохранены/исправлены,итоговый source перепроверен. .10 read-only inventory,.11 owned execution,global tools/services неизменны. Qeli/cross/firmware/SDK/A-B build не заявлены;hermeticity/config/PATH/sharedcache/uploadrace/fullABI/generation/rollback OPEN. Q29/Q30/D06 сохранены,Q31 IN_PROGRESS28/37(75.7%).

**F340–F341, 6 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): backup binary/init/helper,old bytes/modes recovery при ordinary rename failure/TERM,pending/backups сохраняются при failed restore; updated init/hook/retry admission guarded. Symlink/FIFO targets и linked config directory отвергаются до package updates.176tests на ash/dash(11new),10old/current записей на каждом,37recipes/docs/bindings PASS. Начальный read-only arch call assertion FAIL сохранён/исправлен/fullrerun. Native/core/recipes/artifacts неизменны,reused inspector/helper hashes проверены. Existing INI сохранён;late example/mode600/opkg не откатываются. Старый init может игнорировать guard;SIGKILL/powerloss/root-admin races требуют manual recovery,full-bundle transaction/generation/firmware/cross OPEN. Q29/Q30/D06 сохранены,Q31 IN_PROGRESS28/37(75.7%).

**F342, 6 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): общий shell writer корректно сериализует literal quotes/backslashes/крайние пробелы/Unicode для общего Rust INI parser; user/volatile obfs_key больше не меняются при render.4 новых проверки/40 round-trip операций,старый13несовпадений на каждом shell;41полный OpenWrt test на ash/dash,11Node/37recipes/docs/bindings PASS. Actual exact-source GNU parser +owned files;UCI/procd/fw models,realrouter USER_EXCLUDED,VPN handshake/cross/FFI build не заявлены. Начальный compile без log dependency сохранён,qualified inspector использует существующий GNU rlib. Core/native/recipes/artifacts неизменны;generation/ABA/firmware/cross и Q29/Q30/D06 остатки сохранены.Q31 IN_PROGRESS28/37(75.7%),9осталось.

**F343, 6 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): общий bounded/strict core inspector сверяет template TUN с dev/device_type=tun/dev_attach даже при GATEWAY=no; OpkgTun требует external gateway owner.20 baseline false-admission mismatches на каждом interpreter,8новых shell methods/34actual cells;184tests на ash/dash,свежий GNU client-bin build/12units/strictClippy/fmt,37recipes/docs/bindings PASS. Initial old C-helper arity timeout сохранён,новый metadata-only adapter исправлен,own process/temp cleanup выполнены;не product failure.317compile/17fixture Git inputs checked,private manifest rlib-only. Linux client-bin metadata-only change;FFI/release/cross/firmware/runtime не заявлены. Config preflight→launch race/generation/ABA OPEN;Q29/Q30/D06 сохранены.Q31 IN_PROGRESS28/37(75.7%),9осталось.

**F344–F346, 6 октября:** [Q31 actual cross-matrix](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): все4baseline musl compile FAIL; fixed4real release builds/ELF PASS. Исправлены signed statfs magic comparison и MIPS stdAtomicU64 lease counter; CI named pins/jobs1/flag isolation/commonELF. GNU build/strictClippy/fmt,79sysctl+1private native descriptor,52Linux helpers без skips,24static gateway tests на ash/dash,37recipes/docs/bindings;CI YAML/16shell/8actualELF cells PASS. Initial cast/harness missing conformance/zero filters сохранены. .10owned builds/namedtool additions,services/defaults unchanged;.11owned GNU/netns,repo artifacts не обновлены. SDK/ucode/rpcd/configgeneration/ABA/firmware/A-B остаются;актуальная таблица остатка в отчёте.Q29/Q30/D06 сохранены,Q31IN_PROGRESS28/37(75.7%),9осталось.

**F347–F349, 6 October:** [Q31 actual ucode/fs](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): pinned OpenWrt24.10/25.12 native interpreters reproduce regex/array-popen failures; literal stdin commands/byte checks now work. Directory false-success and linked runtime write/delete/status admission fixed.14 new methods PASS in all4version/shell combinations; full55OpenWrt tests on ash/dash with24.10,11Node/37recipes/docs/bindings PASS. Initial loader/cleanup harness errors retained separately; old status/link gives7independent failures per version. Private dependency extraction/single-job builds only,.10 unchanged,no services/firewall/network changed. Rust/native inputs/artifacts unchanged. ucode/fs scoped PASS; actual rpcd/UCI/procd/SDK/firmware,configgeneration/ABA and cleanA/B still OPEN. Q29/Q30/D06 preserved,Q31IN_PROGRESS28/37(75.7%),9remain.

**F350–F351, 6 October:** [Q31 native RPC/UCI/ACL](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): explicit luci-base/ucode-mod-fs deps; actual missing-fs registration failure reproduced. Shared LuCI validator rejects C0/DEL/oversize/invalid Unicode before ubus NUL truncation; direct callers must exclude unsupported NUL.7 actual chroot rpcd/ubusd/libuci/session ACL tests no skips,11 real UCI→render→common INI values,14 Node tests(3new)/37recipes/docs/bindings PASS. Immutable24.10 stack/private DESTDIR/singlejob,source/artifact/template/Git hashes saved. Setup/nodev/header/global-CLI-vs-session assumptions retained separately; no host services/network/.10 changes or residual owned processes. Rust/native/router inputs unchanged; no new Qeli/FFI/cross build. Real native API scope updates older NOT_RUN; procd/SDK/HTTP/firmware,configgeneration/ABA/A-B remain. Q29/Q30/D06 preserved,Q31IN_PROGRESS28/37(75.7%),9remain.

**F352, 6 October:** [Q31 actual procd](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): real official OpenWrt24.10.4 x86 rootfs/non-PID1 procd/ubus/UCI/rc.common supervision; init now preserves service set/add/delete exit status and failed-stop restart gate.7new integration methods PASS,8old false-success failures for missing supervisor/socket reproduced. Full69OpenWrt tests PASS on ash/dash without skips;14Node/37recipes/docs/bindings PASS. Client is inert receipt/sleep, TUN existence marker only, no actual firewall/VPN/host services/network/.10 mutation; owned cleanup verified. SDK remains OPEN (1.7GB free .11); firmware USER_EXCLUDED, HTTP/configgeneration/coreABA/A-B separate. Qeli Rust/native artifacts unchanged; Q29/Q30/D06 preserved,Q31IN_PROGRESS28/37(75.7%),9remain.

**F353–F354, 7 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): настоящий SDK24.10.4 выявил recursive ip6tables dependency и неверные owner/URL LuCI IPK; conditional +IPV6:ip6tables и LUCI_MAINTAINER/LUCI_URL исправлены.3 SDK/3 actual IPK methods без skips,14 packaged minified JS/14 source JS/37recipes/docs/bindings PASS. Stock IPv6=y и private default-n Kconfig profile проверены; firmware IPv4-only не заявлен. Offline opkg в пустой root FAIL из-за отсутствующих зависимостей; полный install/Rust build/source release-cut/MSRV compatibility/clean A/B OPEN. SDK/feed/IPK/raw сохранены; только свой completed compiler cache обратимо архивирован.41historic cases/acceptance/core/ABI/binaries unchanged,.10 untouched,no push. Q31 IN_PROGRESS28/37(75.7%),9осталось;Q29/Q30/D06 сохранены.

**Q31-V002, 7 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): настоящий official musl uhttpd24.10.4→native GNU rpcd/ucode/fs/UCI через private socket, mount/net namespaces.6 HTTP methods без skips: login/reader-writer/denials/secrets/5service verbs/UCI apply-confirm/embedded-session refusal/revoke-idle-expiry/packaged JS/malformed recovery PASS. Service process inert, browser/TLS/firmware/VPN не заявлены.959 official rootfs files/215links,28rpcd files/19links,7Git inputs verified,cleanup PASS;14JS/37recipes/docs/bindings PASS. Initial fixture FAIL retained; Qeli permissions/code/core/ABI/binaries unchanged. SDK build/install/compiler compatibility,preflight/core generation/ABA,clean A/B OPEN;41historic cases/acceptance preserved.Q31 IN_PROGRESS28/37(75.7%),9осталось,Q29/Q30/D06 сохранены.

**F355, 7 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): Keenetic проверяет и запускает одну приватную INI-копию с сохранением owner/mode; изменения оригинала применяются при restart. Installer проверяет root-owned каталог/tools; links/unsafe paths/copy failures запрещают запуск, failed join сохраняет recovery. Настоящий core/native fixture воспроизвёл baseline atomic replacement в обоих вариантах;8new methods, все192 на dash и ash без skips PASS;37recipes/14LuCI/docs9/bindings PASS. Начальные ошибки fixture с глобальным mv fault сохранены, fault ограничен PID publication. Product core/ABI/binaries неизменны;315/317 exact compile inputs, два известных portability-only diff и retained inspector проверены, fresh Rust/cross build не заявляется. Только свои .11 files/processes, cleanup проверен,.10 не затронут.41historic cases/acceptance сохранены. Root/admin replacement,core plan/ABA,OpenWrt config generation,SDK build/install/compiler/source release-cut,clean A/B OPEN;firmware USER_EXCLUDED. Q31 IN_PROGRESS28/37(75.7%),9remain;Q29/Q30/D06 сохранены. Без push/deploy.

**F356–F357, 7 октября:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): реальный Cargo воспроизвёл compiler-config и intermediate-directory overrides (тот же baseline4methods/9expected subtestFAIL). Общая политика pinned rustc lookup/output охватывает оба router helpers, host verification с Rust1.97.0/Clippy и router CI.59router methods(7real-Cargo)/19hostgate model methods без skips PASS; tiny test/Clippy/graph,16rendered bash-n steps,37recipes/14LuCI/docs9/bindings PASS.17Git/lab inputs,cleanup проверены; только private home,.10/host services/network неизменны. Full Qeli/Zig/cross/SDK/GitHub Actions не квалифицированы; project core/ABI/artifacts неизменны. Full hermetic config/profile/source/PATH/cache/A-B и прежний остаток Q31 OPEN.41historic cases/acceptance сохранены;Q31 IN_PROGRESS28/37(75.7%),9remain,Q29/Q30/D06 сохранены. Без push/deploy.

**7 октября,F370–F371:** [native preflight](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual low-space baseline удаляет контрольную A/B пару, fixed сохраняет;36Linux/80local PASS. Source roots изолированы, Cargo jobs1, installed pins inventory PASS. Native refresh заблокирован диском; два локальных архива проверены, удаление отклонено auto-review и не выполнялось. Native provenance STALE/Q34 OPEN;28/37(75.7%),9осталось,Q31/Q29/Q30/D06 scopes сохранены.

**7 октября, native/D11/D15:** [сверка текущего пакета](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md): четыре независимых A/B,14 SHA/provenance,22 Windows ABI/325 platform/549 .NET/201 JVM/23 Android JNI,2417 Linux library и12 CLI tests/Clippy/debug builds PASS. Ошибки подготовки сохранены; peak benchmark/VPN-матрица/soak не повторялись. Долг14/15 DONE+D06 ACCEPTED;полный аудит28/37(75,7%),9 впереди;Q29/Q30/Q31 и exclusions сохранены.

**8октября,F395:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): отдельный core/hook publication-lock закрывает гонку между проверкой и командой без deadlock lifecycle/startup. Три ожидаемых FAIL старого hook; четыре Rust/shell случая и196 прежних methods на каждой dash/ash без skips,2444 Linux(60прежних ignored),strictClippy/client PASS. Native refresh/ABI и raw guards записаны в scoped packet evidence. Смешанный комплект/admin writes, последовательный NDM/power loss, исключённая прошивка и полный SDK/release pipeline вне закрытия;Q31 остаётся3/5IN_PROGRESS. Общий29/37(78.4%),8осталось;старый долг14DONE+D06ACCEPTED;Q29/Q30 сохранены.

**8 October,F396:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): whole preflight requires one clean commit between gates; three old mixed-commit false-PASS cases reproduced.12 whole-program methods,56 Linux related methods uid65534 without skips PASS; Windows78PASS/3pre-existing skips. Snapshot/report identity and120-second certification timeout qualified; optional lab build and production pin/hash unchanged. Current native inputs/artifacts unchanged, SHA/provenance retained; owned Python fixture removed after verified backup. Full SDK/bootstrap/release-cut/successful Actions/preflight remain OPEN; Q31 remains3/5,full29/37(78.4%),8remain;old debt14DONE+D06ACCEPTED,Q29/Q30/exclusions retained.

**8 October,F397–F398:** [Q31 CI diagnostics](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): macOS CI output matches guarded per-app-arm64 leaf; old command fails,11 Windows/12 Linux path cases PASS (Windows symlink unavailable). iOS exit-node known-key fixture now uses valid gateway=false shared split mode; seven actual configuration-ABI checks PASS. Swift XCTest/Keychain status(-34018) runtime remains OPEN; old native CI failure reconciled to current PASS provenance, not new Actions success. Source/runtime exclusions and all plan/debt counts retained.

**8 October,F399/Q31-V010:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual SDK nested make broke sed before Cargo; exact admission plus dollar-free substitution fixes it. Official24.10.4 x86/64 Git download/hash/prepare, Rust1.89 prebuilt client compile/link, SDK install/dependency/strip/IPK PASS.6 real-Cargo,7 offline opkg and9 fresh SDK-client OpenWrt userspace cases PASS without skips. Stock toolchain tables repaired a fixture packaging prerequisite; no dependency bypass. Initial rootfs prep/autoremove backup-selection failures retained. SHA-verified backup and guarded own-root cleanup; service unchanged, native14SHA/provenance PASS. Upstream Rust bootstrap/cold-hermetic build, production source-cut and successful current Actions/preflight remain OPEN; firmware USER_EXCLUDED. Q31 remains3/5, full29/37(78.4%),8remain; old debt14DONE+D06accepted,Q29/Q30 retained. No push/deploy/release.

**8 October,Q31-V011:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): previous32-bit builds predated F395; current6c2225cd ARMv7/MIPS full client builds/SHA/static ELF PASS,318exact transferred inputs.32QEMU CLI/INI and14exact production PublicationLock/budget release behavior checks PASS on cortex-a7/24Kc uid65534. No new product regression/ABI/source change;14nativeSHA/provenance PASS. .11 rustup inventory auto-installed a missing named nightly; only that own addition removed with guards/default preserved,probe compiled sequentially on .10. Verified backups,three own roots cleaned,unrelated old root/services retained. Old four-target A/B keeps original source/date;no cfg(test)/firmware/fullVPN/SDK bootstrap/source-cut/current CI success claim. Q31 remains3/5;29/37(78.4%),8remain;Q29/Q30/D06/exclusions retained. No push/deploy/release.

**8 октября,F446–F448:** [Docker runtime](../reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md): branch latest publication исправлена, Cargo --locked, четыре destructive/status-ignoring legacy harness удалены. Настоящий Docker image/runtime26PASS: pinned H1 VPN fresh/recreate/known-image rollback, root0600/readonly volumes, protected-login readiness, сохранение bytes/UID/mode, шесть exit0 без OOM/SIGKILL. Harness FAIL сохранены; host snapshots/профили AppArmor/PID777-845 восстановлены, own root SHA-backed-up/guard-cleaned. Runtime gate закрыт; compiler multiarch/registry/currentActions и итоговая command/hook сверка Q33 OPEN.29/37DONE78.4%,осталось8; исторический долг14DONE+D06accepted/exclusions сохранены; локальный dev без push/deploy/release.

**8 октября,F449/Q33-F052:** [Итоговая сверка Q33](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md): исправлен обход защиты hook-файла при restore через `..`, кавычки и symlink aliases; literal variables/globs в неизвестном top-level managed entry отклоняются. Точный старый collector на Linux ожидаемо FAIL;14 targeted production helper/gate checks PASS. Полная серверная/native квалификация PASS:CLI5/backup49/IO2/Clippy, freshA-B/14SHA/provenance/WindowsABI22. Retained hook snapshot SOURCE REVIEW OPEN;Q33IN_PROGRESS; общий29/37DONE78.4%,8осталось. Прежние runtime gates переиспользуются только в неизменённой части; Q29/Q30/Q31/USER_EXCLUDED/D06ACCEPTED сохраняются. Без push/deploy/release.

**8 октября,F450/Q33-F053:** [Q33 завершён](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md): actual baseline два HTTP restore исполняют заменённый harmless marker; фикс хранит hooks startup/последующих worker до завершения supervisor и запрещает exact deletion. Fixed8+later10 runtime, CLI5/backup50/lifecycle1/post_down3/privateIO2/Clippy PASS; свежая native/ABI квалификация и raw seal приведены в отчёте. Q33 5/5 DONE;30/37(81,1%),7осталось. Исторические ограничения Q29/Q30/Q31/Q34/D06 сохраняются; без push/deploy/release.

**8 октября, F451–F454 / Q34-F005–F008:** [Rust dependency policy и TLS](../reports/audit-0.8.2/AUDIT-Q34-DEPENDENCY-POLICY.md): удалён archived PEM wrapper, der0.8.0 заменён на0.8.1; лицензии/all-features/locked и audit warnings теперь hard gates, tools/toolchain pinned. Свежая RustSec DB5701a6d2: baseline0CVE+2warnings/current0CVE0warnings; реальные license rejects сохранены. TLS10/unit2445+60ignored/CLI5/14HTTPS/feature+release-checks/Clippy/fmt и Wintun file signatures PASS. Первые fmt/FD/harness failures сохранены, процессный fd budget4096; host services сохранены. Свежая native квалификация и raw seal в отчёте. Q34 IN_PROGRESS,30/37DONE81.1%,7осталось; текущий exact-SHA Actions/package/platform/release охват не подменён локальными проверками. Без push/deploy/release.

**8 October, F455–F459 / Q34-F009–F013:** [Client supply chain](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): two npm advisories fixed with byte-identical CSS; official Gradle checksum qualified by real positive/corrupt-wrapper checks; NuGet all/transitive/low audit errors and explicit advisory source, actual vulnerable/unavailable-source refusals; WinDivert official archive match/signature/hash/notices positive+4negative PASS. Three Release managed builds, required conformance, Windows selftest and local codec benchmark PASS. braces advisory remains OPEN (no published patch); SDK/locks/other graphs/currentCI/release coverage pending. Native inputs/copies14SHA unchanged; no lab changes. Q34 IN_PROGRESS,30/37DONE81.1%,7remain; established Q29/Q30/Q31/D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F460–F462/Q34-F014–F016:** [SDK/locks](../reports/audit-0.8.2/AUDIT-Q34-SDK-LOCKS.md): exact official SHA512-qualifiedSDK10.0.401/runtime10.0.12;CIglobal-json-file/build_appcwd corrected;35reviewed perRID/config/tools/Linux/singlefile locks with root/referenced missinglock guard.18Windowsgenerate-lockedpairs/7builds/conformance/adapters/codec and exact2Windows+2MacpublishPASS;realoldSDK/drift/hash/missingrefusalsPASS;Linux12graphs24restore/builds2MacpublishPASS,ownedSHAarchive/proc-mountguardcleanup/service745901preserved. Native/CSS/protectedfiles unchanged;standaloneinvokerselftest only,normalrequireAdministrator740 retained. Android locks/remainingpackages/currentCI/sourcecut and bracesOPEN remain;Q34IN_PROGRESS30-37DONE81.1percent7remain;historical debt/Q29Q30Q31D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F463–F465/Q34-F017–F019:** [Android dependencies](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-DEPENDENCIES.md): strict transitive project/early-plugin locks, three real lockfiles, SHA256 artifacts+metadata and missing-policy guards. 747 independent HTTPS files match; Windows/macOS AAPT2 checksum admission only. Actual debug/defaultR8/debug-release instrumentation assemblies, locked/offline/lint and fresh201productionJNI JVM PASS; five real default-mode refusals PASS. Initial partial-lock, harness Metaspace and alias404 trials retained; separate lint/in-process Kotlin/oneworker privateVM overrides. SHA-backup/proc-mountguard owned cleanup,777845 preserved; nativee3fb/14SHA/protected unchanged. No device VPN/currentJava17CI/otherOS builds claimed. Q34IN_PROGRESS30-37DONE81.1percent7remain;braces/packages-licenses/currentCI/sourcecut-release and historicalQ29Q30Q31D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 октября,F466–F468/Q34-F020–F022:** [Maven security](../reports/audit-0.8.2/AUDIT-Q34-MAVEN-SECURITY.md): shared early-plugin/project security versions, KGP2.4.21/Netty4.1.137/BC1.85 and remaining targeted fixes; all318 locked package/version records freshOSV0affected (initial326/19affected/50distinctadvisories). CI Maven fail-closed gate8fixtures/actualJDOMnegative-positive PASS; wrong-password test now AEADBadTagException, nullable reflection checked. Java17 officialSHA private qualification: debug/defaultR8/debug-release instrumentation assemblies/201JVMproductionJNI/lint0errors53warnings/offline-strict PASS;2actualoffline policy/driftrefusals+restoredpositive.104freshHTTPS checksums/626exactinheritedsealed records,obsolete admission removed. First unit compileFAIL and harness/API diagnostics preserved. SHA32720631byte backup/proc-mountguardcleanup777845 preserved; nativee3fb/14SHA/protectedfiles unchanged. License metadata318 obtained, actualNOTICE/native copyleft/source-cut/device runtime/currentActions remain OPEN; freshestCI37765333335 is anotherSHAf84a78d9. Q34IN_PROGRESS30-37DONE81.1percent7remain;F459braces/Q29SIGKILLFAIL-ENONET/Q30/Q31/D06accepted/exclusions unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 октября,F469/Q34-F023:** [Android licenses/NOTICE packaging](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-NOTICES.md): per-variant canonical project AGPL/MPL,Apache2,Maven runtime inventory,original archive identities and preserved JAR/AAR/nested notices; dedicated original-archive ArtifactView,identical variant visit deduplication. Independent extraction current-checksum-admitted63archives/44AAR/24resources PASS;76license declarations inherited sealed review. CI APK index/hash/coordinate/origin gate12negative fixtures. APK qualification/evidence in linked report; native dependency/upstream-source notices,matching source publication/signatures/currentActions/fullrelease remain OPEN. Native e3fb/protected files unchanged; no new nativeAB/JVM/deviceVPN claim. Q34IN_PROGRESS30/37DONE81.1percent7remain; historical Q29/Q30/Q31/F459/D06/exclusions unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October, F470/Q34-F024:** [Common Cargo legal resources](../reports/audit-0.8.2/AUDIT-Q34-NATIVE-NOTICES.md): 235 checksum-locked packages,458 upstream resources, six exact-VCS supplements; one common bundle and packaging/CI checks. Actual qualification and limitations in linked report. Rust std/toolchain/.NET/upstream-source notices, source publication, OpenWrt immutable source cut and current Actions remain OPEN. Q34 IN_PROGRESS;30/37 DONE81.1percent7remain;historical Q29/Q30/Q31/F459/D06/USER_EXCLUDED unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F471–F472/Q34-F025–F026:** [Managed notices and Inter font](../reports/audit-0.8.2/AUDIT-Q34-MANAGED-NOTICES.md):67 actual SDK-content-hash/official-catalog checked NuGet/runtime packages,187 shared resources; original upstream bytes and separate SIL OFL1.1/copyright for6 exact embedded fonts.35-lock/globalSDK/runtime binding,offline generator/checker,desktop/CI/app gates.19fixtures/final-source regeneration/four actual publishes/published negative/restored and shell gates PASS; scope and raw qualification in report. Toolchain notices,MicroCom exact source binding/sourcepublication/OpenWrt cut/finalActions/release OPEN. Nativee3fb/14SHA/protected unchanged,labs untouched;no new nativeAB/JVM/device claim. Q34 IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F473/Q34-F027:** [Toolchain runtime/stdlib notices](../reports/audit-0.8.2/AUDIT-Q34-TOOLCHAIN-NOTICES.md):65 original reviewed Rust/Zig/NDK/GCC-MinGW resources,69 embedded files;533 common native files. Offline policy/version/SHA binding,Gradle source InputFile,common CI and all packaging paths. Qualification and exact scope in report. Source publication,old GCC minor linkage/NDK whole archive/OpenWrt immutable source cut/final Actions-signatures-release remain OPEN. Nativee3fb/14SHA/protected preserved;Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED retained. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F474–F477/Q34-F028–F031:** [Release publication gates](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md):actual tag/clean-source/exact-commit CI admission beforebuild,shared Rust pin,Docker reviewed base digests/common notices,extractedDEB notices gate,allworkflow CI filters.86methods/baselineactualGit/CLI/YAMLparse PASS;official metadata and401/currentCIabsence limits in report. Fullsourcepublication/OpenWrt immutablecut/wholeDockerbuild/currentActions/signatures/release OPEN;nativee3fb/14SHA/protected unchanged,labs untouched. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F478–F479/Q34-F032–F033:** [Attestation/checksums](../reports/audit-0.8.2/AUDIT-Q34-ATTESTATION-CHECKSUMS.md): removed unsupported build provenance for downloaded foreign assets; only actual CI-built DEB remains a subject. Atomic SHA256SUMS publication with consumer-compatible filename/regular-file admission and retained old manifest on failure. Linux11 no-skips/real GNU verify/baseline defect PASS;Windows7+4POSIXskips,release18,recipes38,YAML parse PASS (67distinct methods). SHA-backed-up/guard-cleaned own Python fixture;777845/service/network/native14SHA/protected unchanged. No Docker/native rebuild or hosted signing. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F480/Q34-F034:** [Full Docker build](../reports/audit-0.8.2/AUDIT-Q34-DOCKER-BUILD.md): tag/Cargo/exact-commitCI gate before publication tools/login,fullref/history/actionsread;actual classifier mismatch baseline/refusal and64focusedmethods/YAML PASS. Full fresh amd64 defaultfatLTO/jemalloc pinnedRust/Debian build826.546s/no binaryoverride,exact533image notices/CLI/dependencies and26pinnedVPN/recreation/invalidimage rollback checks PASS. Originalhost restored,own image/source/fixtures archiveSHA-qualified before guarded cleanup;public cache/tools exclusion explicit. Harness refusals/profile restoration retained;explicitunconfined runtime is not defaultAppArmor qualification. Multiarch/currentActions/signatures/sourcepublication remainOPEN;Q34IN_PROGRESS30/37DONE81.1percent7remain;native14SHA/protected/historicalQ29Q30Q31F459D06exclusions preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F481/Q34-F035:** [Immutable Docker inputs](../reports/audit-0.8.2/AUDIT-Q34-DOCKER-INPUTS.md): reviewed frontend digest matches previous whole build;fresh registry index/manifest/config SHA checked. Single signed Debian/security snapshot20261008T000000Z,live sources removed,source-scoped expiry only,archive authentication preserved. Actual SHA-pinned amd64 Debian rootfs APT3signatures/62new150total packages/13commands/check/repeat and4signature negatives PASS;66focused methods/2priorrecipe refusals. SHA-backed-up full installedrootfs/guardedcleanup/original777845/network/profiles preserved;initial harness failures retained. No fresh wholeimage/compiler/ARM/hostedActions/release;remaining Q34/historical limits preserved. Q34IN_PROGRESS30/37DONE81.1percent7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F482/Q34-F036:** [OpenWrt source Git flags](../reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-FLAGS.md): actualGit10hidden-input false-PASS reproduced on exactprior gate;scoped ls-files refuses assume-unchanged/skip-worktree on5inputs before pin/hash. Unrelatedflags keep existingboundary.37methodsPASS(25source/12preflight),3existingPOSIX-oldbaseline skips unchanged;sourcecut actualpin/tree mismatch OPEN,pin/hash/SDK untouched. Docs/native14/protected unchanged scope,no lab/network/newcompiler/runtime. Q34IN_PROGRESS30/37DONE81.1percent7remain;historical Q29/Q30/Q31/F459/D06/exclusions preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F483/Q34-F037:** [OpenWrt exact local source cut](../reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-CUT.md): stalepin/actual qelitree baseline refused;exact full local dev f4b80a9 pinned,actualSDK24.10.4 download+prepare and second emptyDL/differentURL samearchiveSHA PASS. All 3131 trackedfiles match originalcommit incllicenses/notices;no syntheticcommit. PublicURL unchanged,actualGitHubHTTP422 means publication prerequisite OPEN. Sourcegate/native14/protected/doc checks and scoped evidence in report;no newcompiler/bootstrap/IPK/router/nativeAB/hostedCI claims. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29SIGKILLFAIL-ENONET/Q30/Q31/F459braces/D06accepted/USER_EXCLUDED preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F484/Q34-F038:** [Fuzz CI inventory](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-INVENTORY.md): actualCargo15targets butoldsmoke/nightly11 omitcontrol_v2/quic_envelope/realtls_client/websocket_frame. Sharedmanifesthelper drives bothconsumers,earlymetadatafailure blocks instead ofemptysmoke;nightlydynamicneeds/output matrix.69localmethodsPASS+10repeatLinuxunits+10actualCI Bash scenarios with controlledcargo receipts inclbaselinegap,15calls/early23failure/malformed/missing/outputpreservation/new16thtarget/externalsymlink refusal. ActualRust/libFuzzer/hostedActions and pinnedfuzztools remainseparate OPEN;no core/native/tree changes,previousOpenWrtcut retainsqelitree. SHA-backed-up fullownedfixture/procmountguards/service777845 preserved. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q35TODO andhistoricalQ29/Q30/Q31/F459/D06/exclusions retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F485–F486/Q34-F039–F040:** [Воспроизводимый fuzz CI](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-TOOLCHAIN.md): фиксированы nightly/cargo-fuzz и отдельный146-package lock; locked-fetch/offline/SHA и отдельный strict audit. Все15 настоящих ASan targets:85 930 590 выполнений,без crash artifacts;72 Windows+13 Linux regression methods и реальные missing/stale/drift отказы PASS. Exact SDK source recut/prepare3140files/second emptyDL identicalSHA PASS;pin/hash обновлены. Scope и сохранённые ошибки обвязки в отчёте. Q34 IN_PROGRESS30/37DONE81,1%,7осталось;Q35 TODO и прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F487/Q34-F041:** [Fuzz Actions context correction](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-TOOLCHAIN.md): official SHA-qualified actionlint1.7.12 reproduces two invalid job-env references introduced in previous patch;export single pinned RUSTUP_TOOLCHAIN through GITHUB_ENV instead. Final semantic lint13 regressions/exact Bash export PASS. Previous real85,930,590-case ASan smoke recipe/environment unchanged,not rerun;sealed history preserved. Q34IN_PROGRESS30/37DONE81.1%,7remain;Q35TODO/hostedCI/historical limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F488/Q34-F042:** [Постоянный Actions lint](../reports/audit-0.8.2/AUDIT-Q34-WORKFLOW-LINT.md): новый CI gate проверяет все .yml/.yaml официальным SHA-закреплённым actionlint1.7.12. Все четыре baseline workflow уже корректны; закрыт пробел постоянного контроля. На каждой из Windows/Linux:11 unit+8 реальных сценариев PASS, включая отказ ошибочного env/нового yaml/подменённого бинарника. Временная .11 сохранена и удалена,777/845 сохранены. Ядро/native/source cut неизменны; hosted CI и остальные границы в отчёте. Q34 IN_PROGRESS;30/37 DONE81.1%,7 остаются. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F489/Q34-F043:** [MicroCom source binding](../reports/audit-0.8.2/AUDIT-Q34-SOURCE-BINDING.md): совместимый pin0.11.2 сохраняет52 API и указывает тот же exact commit в DLL/nuspec; full76-file upstream SHA проверен, publisher-only исключение удалено.24 настоящих Windows/Linux graph pairs, baseline/fixed COM consumer12 assertions,187-file bundle regeneration, builds/publishes/conformance PASS. Более новые API-несовместимые кандидаты не применены. Границы и cleanup evidence в отчёте; native/qeli tree неизменны. Q34IN_PROGRESS30/37DONE81.1%,7remain. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F490/Q34-F044:** [Docker latest](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): воспроизведён откат latest старым стабильным тегом; отдельный числовой допуск максимальной версии и общая concurrency group. 16 Windows +16 Linux методов, 59 связанных Windows методов и официальный lint четырёх workflow PASS. Входы/логи восстановлены, собственный Linux-каталог удалён, служба777/845 сохранена. Границы Git-tag inventory/очереди/старых refs и прочие обязательства в отчёте. Q34 IN_PROGRESS;30/37 DONE81,1%,7 остаются. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F491/Q34-F045:** [APK-builder](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): убраны глобальный SIGKILL GradleDaemon и удаление общего cache-журнала; import-safe main и finally закрывают SSH/SFTP при отказах.63 Windows/Linux метода и официальный lint4workflow PASS; отдельный PID/mount probe воспроизводит baseline SIGKILL, исправленная оркестрация сохраняет чужой процесс/cache. Evidence восстановлен, own root удалён, служба777/845 сохранена. Нового APK нет; общий source workspace/ожидаемый release-signer и прежние ограничения остаются открытыми. Q34 IN_PROGRESS;30/37 DONE81,1%,7 остаются.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F492/Q34-F046:** [Приватная APK-сборка](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): полный committed snapshot вместо общих source directories/фильтра расширений; locks/legal/Java/conformance сохранены, собственные Cargo/Gradle/output paths. Реальный APK/JVM и SHA-отказ мутации отдельного root PASS;71 Windows+22 Linux методов,lint/docs PASS. APK/исходники восстановлены,2 own roots удалены,служба777/845 сохранена. Offline/SDK/ENOSPC отказы и границы release/runtime в отчёте;Q34IN_PROGRESS30/37DONE81,1%,7remain; прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F493/Q34-F047:** [Явный APK для E2E](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): четыре installer-сценария требуют source/size/SHA/native-bound BUILD.json; приватная передача,remoteSHA/ADB status и ранний отказ перед canonical server restoration.89Windows+18Linux методов,5real transfer/refusal cases с контролируемымADB,lint/docs PASS; own inputs восстановлены/очищены,служба777/845 сохранена. Настоящий emulator/VPN/release runtime не запускался. Q34IN_PROGRESS30/37DONE81,1%,7remain; прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F494/Q34-F048:** [Единый release source admission](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): preflight/certification/tag запрещают скрывающие Git-флаги; certification закрепляет commit и повторно проверяет источник. Совместимость новых certification evidence сохранена.165Windows+33Linux методов PASS,own fixture удалён,служба .11 сохранена;без CI dispatch/Rust/APK rebuild. Q34IN_PROGRESS30/37DONE81,1%,7remain;прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F495/Q34-F049:** [Certification actual publisher](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): confirmed PASS при failed обязательном кейсе; оба release workflows теперь требуют --require-certification до DEB build/Docker login.132Windows+41Linux методов и semantic workflow lint PASS; own SHA fixture очищён,служба .11 сохранена. Без current Actions/OIDC/publication/Rust/APK rebuild.Q34IN_PROGRESS30/37DONE81,1%,7remain; historical limits сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F496/Q34-F050:** [Отказ упаковки без подписанта](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): подтверждённый unsigned archive/Done; build_app.sh теперь отказывает до native/publish и сохраняет прежние outputs. 57 Windows +8 Linux методов, Bash syntax и workflow lint PASS. Подписанты контролируемые; actual Mac signature/runtime не проверены. Own Linux fixture очищён, служба сохранена; удалена только SDK-копия с полной сверкой сохранённого ZIP. Q34 IN_PROGRESS,30/37 DONE81,1%,7remain; прочие ограничения сохранены. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F497–F498/Q34-F051–F052:** [Universal2 и retired resign](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): устранён arm64 fallback при lipo failure/missing Intel; проверяется полный Mach-O graph и каждый output. Удалён неиспользуемый unchecked SSH-resign helper.58Windows/11Linux методов включая2actualLLVM PASS, workflow lint/docs PASS. Synthetic headers, без full payload/signature/Mac runtime; служба сохранена, own root очищён.Q34IN_PROGRESS30/37DONE81,1%,7remain; прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября, F499–F500/Q34-F053–F054:** [Входы и ресурсы упаковщика](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): закрытие SSH/SFTP на всех путях, отдельные workspace, safe TAR/core до SSH и 4 upload SHA gates.72 Windows/23 Linux методов +3 actual main trials PASS; повреждение сохраняет прежний ZIP. Controlled signer/synthetic headers, без Mac/signature PASS.48 own lab files очищены, service сохранён. NuGet/HTTP дубликаты удалены по SHA, archives/SEALED сохранены. Q34 IN_PROGRESS;30/37 DONE81,1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября, F501/Q34-F055:** [Compiler CI pins](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): устранён implicit stable в7jobs, compiler1.97.0 совпадает с reviewed policy; остальные matrix/nightly choices сохранены. Actual YAML/exactaction default proof,65methods/actionlint4/docs PASS. Source qualification без hosted Actions/rebuild; native/qeli execution inherited. Q34IN_PROGRESS30/37DONE81,1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F502–F503/Q34-F056–F057:** [Событие и охват CI](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): release gate требует push event/exact SHA; green PR merge не заменяет source CI. Paths filters удалены, все root policy inputs запускают CI.132Windows/67Linux methods/actionlint4/docs PASS. Actual Git/controlled gh, не hosted Actions.25ownlabfiles очищены,service сохранён. Developer docs1.97/locked обновлены;F459 latest3.0.3/no patch OPEN.Q34IN_PROGRESS30/37DONE81,1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10октября,F506–F507:** [Soak admission](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md): нулевой цикл TCP и downgraded endurance labels воспроизведены; общий decimal validator до сетевых действий, smoke/full markers и minimum10k/1k только для full endurance wrapper. Обязательный bounded100 сохранён.28Linux/57Windows methods,4workflow lint PASS; без новогоVPNsoak/native rebuild. Q34/Q35IN_PROGRESS,30/37DONE81,1%,7остаётся.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F508/Q35-F005:** [Изоляция runner](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
закрыта конкурирующая очистка TCP/UDP namespaces и общий family-switch hosts.
7 реальных kernel +35 Linux script methods PASS; SIGINT/TERM/KILL удаляют потомков,
соседние процессы/настройки сохраняются. Только живые NAT-счётчики нормализованы
в структурном сравнении, raw сохранён. Новый VPN-soak не заявляется;
Q34/Q35IN_PROGRESS,30/37DONE81,1%,7остаётся.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября, Q35 fuzz фрагментов:** [отчёт](../reports/audit-0.8.2/AUDIT-Q35-FRAGMENT-FUZZ.md): усилены два target, 246 813 настоящих ASan запусков PASS; исходные ошибки тестовой обвязки сохранены. Q35 IN_PROGRESS, 30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября, Q35 длительный roaming:** [отчёт](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md): TCP fake-TLS и UDP QUIC одновременно по 900 переключений, 1850,9 с выполнения и 1835,9 с подтверждённой одновременной активности, 368 полных снимков процессов. Оба сценария PASS без ошибок; RSS/threads/fd/socket в пределах заранее заданных бюджетов. Служба и структура host firewall сохранены; own root удалён после SHA-backup. Полный release endurance/8 ч/другие адаптеры остаются открыты. Q35 IN_PROGRESS,30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F511/Q35-F009:** [Клиентский INI и qeli:// fuzz](../reports/audit-0.8.2/AUDIT-Q35-CLIENT-CONFIG-FUZZ.md): добавлены инварианты канонического повторного разбора для успешных входов и структурированные IPv4/IPv6/roaming/password-link случаи. Закреплённый ASan:18 494 запуска/61с, семь seeds, ноль новых crash artifacts;701 corpus-файл и 723 evidence-файла SHA сохранены. Ошибка первой локальной обвязки сохранена; own root очищен, служба777/845 неизменна. Один target, не полный nightly/DoS. Q35 IN_PROGRESS,30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F512/Q35-F010:** [Допуск release-soak](../reports/audit-0.8.2/AUDIT-Q35-RELEASE-ADMISSION.md): исходный gate давал полный PASS за0,064с с8пустыми детьми. Теперь обязательны результаты восьми фаз, финальные точки TCP10k/UDP10k+3×1k и минимум28800с по монотонным часам.7Linux contract-тестов и Bash syntax PASS; пустой ребёнок/неполная точка/8ч−1нс отклоняются. Реальный8ч VPN-soak остаётся OPEN,Q35IN_PROGRESS30/37DONE.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**12 октября, перенос проверенного кандидата:** [wire pool и фактические результаты](../reports/BENCHMARK.md): при переносе 916 входов совпали с проверенной сборкой; затем только два явно проверенных изменения пробелов/переносов в одном файле для rustfmt, логика прежняя. Четыре строгих feature-профиля, 8+1 тестов PASS. 24 минутных AUTH-прогона / 34644 аутентификаций, пик RSS 336320 КиБ при прежнем лимите 524288; 20+4 составной результат, исходный отказ бюджета файлов и host differences сохранены. 12 новых native сессий /48 функциональных окон IPv4 TCP/UDP P1/P4. Исходники и CI warning gate перенесены. [Q35 endurance](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md): пять ресурсных сценариев завершены, upload 6,8627%>5% FAIL, межсерверный этап NOT_RUN. Android: 23 JNI +2 packaged INI теста подтверждены на прежнем x86_64 native; исходные harness/signature/wlan0 отказы сохранены, полный VPN runtime не заявляется. Q30 DONE в согласованном объёме; итог31/37 (83,8%), остаются Q29/Q31/Q34/Q35/Q36/Q37. Native refresh, hosted CI, performance/cross-node и оставшиеся критерии этих шести разделов открыты. `NO_PUSH_DEPLOY_RELEASE`.

<!-- normative-sync: current-pool-native-20261012 -->

### 12 октября: платформенные библиотеки после исправления пула

[Результаты сборок и runtime-проверок](../../../release/certification/evidence/current-pool-native-20261012.json).
Для исходников `c0aad62a` выполнены две независимые сборки каждой из четырёх
библиотек: Android arm64/x86_64, Windows x64 и macOS universal2. Пары A/B
побайтно совпали, обе копии каждого артефакта обновлены; provenance и SHA256
проверены. На Android проверены точные 55 экспортов каждой ABI, на Windows
и в каждой архитектуре macOS — 33 C-экспорта. На Windows выполнены 22 C ABI
проверки; на Android API34 x86_64 — 23 JNI проверки и 2 теста INI из нового APK.

Новые instrumented Release/test APK и обычный unsigned Release содержат
актуальные обе Android ABI. Проверки R8 и упаковки прошли. Результаты 201 JVM
теста и lint переиспользованы после точного сравнения 679 входных файлов
с уже проверенным исправленным вариантом; это не новое выполнение JVM-тестов
через свежую native-библиотеку. Исходный отказ проверки wlan0 сохранён;
новый стенд дождался carrier (LOWER_UP/state UP) и завершения запуска интерфейса и прошёл строгую проверку
неизменности сетевого состояния. Исходный AVD, SDK и рабочие сервисы сохранены,
созданные для прогонов каталоги и временный swap удалены.

Исходный desktop worker FAIL сохранён: финальная проверка обнаружила только
пустой `.intentionally-empty-file.o`; все 327 входов совпали. Артефакты,
API и C ABI подтверждены из полного SHA-проверенного архива без пересборки.
На .10 сохранён host gate FAIL по iptables4/legacy4; рабочие сервисы и их
бинарные файлы остались прежними. Это не полный PASS состояния хоста.

Итог плана остаётся 31/37 (83,8%); открыты Q29/Q31/Q34/Q35/Q36/Q37.
Эти результаты закрывают обновление native-артефактов после правки пула.
Полный Android VPN data plane, пределы нагрузки, причина TCP-асимметрии,
upload-регрессия Q35 и межсерверный этап остаются вне данного PASS.
Физические Mac/Xcode/iOS, роутер и Windows VM исключены пользователем.
Полный релиз и hosted CI не подтверждены. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: отдельная проверка performance и cross-node

<!-- normative-sync: q35-bounded-performance-crossnode-20261012 -->

[Квалифицированные результаты](../../../release/certification/evidence/q35-bounded-performance-crossnode-20261012.json).
На .11 выполнены четыре заранее объявленные независимые проверки: performance
и cross-node для прежнего CLI `35da83fd` и актуального CLI `52511ceb` с исправлением
пула. Оба performance-прогона сохранили прежние три повтора по 20 секунд,
порог 5%, лимит 2 CPU и проверку upload/download/совокупного CPU. Скорости
перепроверены по исходным receiver-строкам iperf3 для каждого режима и направления,
медианы пересчитаны независимо. Ни один замер не исключён и не заменён повтором.

| Бинарник | Upload off / required, Мбит/с | Снижение upload | Download off / required, Мбит/с | CPU off / required, % | Performance: проваленные критерии | Cross-node |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| Прежний CLI | 515 / 518 | -0.5825% | 626 / 620 | 159.921 / 160.140 | PASS: — | 28 PASS / 0 FAIL |
| CLI с исправлением пула | 515 / 538 | -4.4660% | 615 / 624 | 160.560 / 163.601 | PASS: — | 28 PASS / 0 FAIL |

Cross-node здесь означает два независимых серверных процесса и реестра
в разных network namespaces на одной VM. Проверены отказ JOIN с чужим locator,
потеря основного carrier, переход клиента к полной AUTH, новый адрес и работа
туннеля второго процесса. Это не переключение между физическими серверами.

Исходный 13-часовой release gate остаётся FAIL: 6,8627% снижения upload при
лимите 5%. Сравнение off/required на одном бинарнике не является измерением
регрессии между версиями. Причина старого провала не установлена; эти новые
проверки не доказывают влияние правки пула или фоновой нагрузки. Пять завершённых
ресурсных сценариев не повторялись и принадлежат прежнему SHA. Полный 8-часовой
release gate на актуальном CLI этим пакетом не подтверждён.

Каждый вход и сохранённый файл проверен по SHA; наблюдаемые процессы работали
в private mount/net/PID namespaces. Службы, их PID/start ticks/бинарники и staged
CLI сохранены. Созданный каталог, удалённый архив и transient unit очищены.
Полное структурное сравнение всех backend хоста прошло.
Q35 остаётся IN_PROGRESS; итог плана 31/37 (83,8%), шесть разделов открыты.
Полный релиз и hosted CI не подтверждены. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: 20 Linux-критериев на CLI с исправлением пула

<!-- normative-sync: current-pool-linux-certification-20261012 -->

[Новые результаты и привязка к исходникам](../../../release/certification/evidence/current-pool-linux-matrix-20261012.json).
На .11 заново выполнены все обязательные автоматические Linux-сценарии на
CLI `52511ceb`: 19 самостоятельных запусков, 409 успешных утверждений,
без отказов; двадцатый критерий отсутствия утечек выведен из реальных проб
14 full/split случаев. Длительность — 595.0 с. Старые результаты
другого бинарника и даты их выполнения не переписаны.

Проверены 12 сочетаний outer/inner IPv4/IPv6 и TCP/UDP fake-TLS/UDP QUIC,
два dual-stack split tunnel, TAP с локальными NDP/RA, настоящие systemd-resolved
и DNS через IPv4/IPv6/принудительный TCP, DATA_FRAG/PMTU на MTU 1280 и ICMPv6 PTB,
совместимость с Qeli 0.7.16 в обоих направлениях, 100 переключений TCP и 100 QUIC.
Для каждого случая проверены команды, исходные журналы, итоговые утверждения,
SHA, отдельные mount/net/PID namespaces и нужные функциональные отметки.

Повторная компиляция не выполнялась: из 916 входов существующей квалифицированной
сборки совпали 915; в buffer_pool.rs заново проверены только две прежние явные
замены пробелов/переносов, без изменения логики, строк и комментариев.
Все 453 входа тестовой обвязки совпали. SHA ELF и legacy-клиента закреплены.
DNS-инструменты, зависимости и учётная запись уже присутствовали на .11;
установка или изменение службы не потребовались.

Все сохранённые файлы проверены по SHA. Структурные снимки всех backend хоста
до/после/после очистки совпали. Production PID/start ticks/бинарники, staged CLI,
DNS-инструменты, зависимости и passwd/group сохранены. Созданный каталог,
удалённый архив и transient unit удалены. Сертификат Linux связан с новым
результатом и проверенной применимостью последующих изменений только документации;
первоначальный source/time/raw этого запуска остаётся отдельным неизменным фактом.

Это закрывает устаревшую привязку 20 Linux-критериев после изменения пула.
Короткий 100+100 soak не заменяет восьмичасовой Q35 release gate.
Старый Q35 performance FAIL, Android SIGKILL/ENONET, полный Android VPN data plane,
hosted CI и остальные открытые критерии остаются за пределами этого PASS.
План: 31/37 (83,8%), Q29/Q31/Q34/Q35/Q36/Q37 открыты. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: порядок performance-замеров Q35

<!-- normative-sync: q35-performance-order-20261012 -->

[Исходные результаты и независимая проверка](../../../release/certification/evidence/q35-performance-order-20261012.json).
На .11 выполнены четыре заранее зафиксированных замера на прежнем CLI
`35da83fd`, в порядке off → required → required → off. В каждом режиме
остались три повтора по 20 секунд и прежний порог 5%; CPUQuota — 200%.
Все четыре функциональных сценария прошли (44 утверждений).
Это диагностические сравнения порядка, а не новый общий release gate.

| Order | Policy | Upload Mbps | Download Mbps | CPU % | Host steal % |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | off | 511 | 633 | 159.861 | 0.004 |
| 2 | required | 513 | 635 | 159.519 | 0.008 |
| 3 | required | 527 | 630 | 161.851 | 0.008 |
| 4 | off | 524 | 632 | 161.849 | 0.004 |

- off-first / required-second: upload -0.3914%, download -0.3160%; gates {"upload": true, "download": true, "cpu": true}; PASS.
- off-last / required-third: upload -0.5725%, download 0.3165%; gates {"upload": true, "download": true, "cpu": true}; PASS.

Из receiver-строк iperf3 независимо проверены все 24 результата; медианы и
оба сравнения пересчитаны. Наблюдение сохранило CPU steal, PSI, memory и cgroup
с доступными исходными счётчиками; новые результаты не заменяют старый отказ.
В private sysfs нет смонтированного cgroup filesystem: все cgroup-наблюдения
пусты. Throttling квоты и события memory cgroup этим прогоном не измерены.
Файлы и входы проверены по SHA, private namespaces подтверждены,
host gate до/после/после очистки PASS. Рабочие службы и staged CLI сохранены;
собственный каталог, удалённый архив и transient unit удалены.

В исходном 13-часовом прогоне оба performance-режима использовали новые пары
процессов; их PID/start ticks не пересекаются с ресурсным префиксом по 9395
снимкам. Performance helper не менялся. Поэтому FAIL 6,8627% не доказывает
замедление той же долгоживущей VPN-сессии. Старый сборщик не сохранял host CPU
steal/PSI/cgroup telemetry, и новый короткий тест не восстанавливает те условия.
Даже различие прямого и обратного порядка не устанавливает причину старого FAIL.
Порог не изменён; причина NOT_ESTABLISHED, оригинальный отказ сохранён.
Ресурсный 13-часовой префикс не повторяли.

Q35 IN_PROGRESS; полный 8-часовой gate на текущем CLI не подтверждён.
План остаётся 31/37 (83,8%), шесть разделов открыты. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: Q37 завершён по пяти критериям

<!-- normative-sync: q37-five-criteria-closure-20261012 -->

[Матрица критериев и проверяемые доказательства](../../../release/certification/evidence/q37-closure-20261012.json).

| Критерий | Основание закрытия |
| --- | --- |
| Review и мёртвый код | 297 Rust-модулей / 306 связей; 59 диагностик четырёх Linux-профилей, 73 проверенных подавления. Удалены 41 retired body и лишние прямые зависимости; внешние API, JNI/C/Swift и RAII сохранены. Последующие изменения покрыты актуальными строгими профилями и native A/B. |
| Штатные, граничные и негативные сценарии | Сверены 84 клиентских поля, 134 server defaults и 176 reader keys; реальные INI admissions и исходные отрицательные случаи сохранены. Текущие 8 schema/docs/generated-adapter методов PASS. |
| Отказы и конкуренция | Текущие 4 admission-метода и 2 метода безопасного импорта 24 сценариев PASS; 5 настоящих Linux CI-fixture методов применимы по точным неизменным SHA runner/test. Пустые/неполные/skipped/expected-failure наборы не получают PASS, отказ дочерней команды сохраняется. |
| Интеграция и целевая платформа | Актуальные четыре native A/B, exports/provenance, 22 Windows C ABI, 23 Android JNI и 2 packaged INI; свежие 20 Linux-критериев / 409 проверок. Исключённые пользователем физические платформы не объявлены проверенными. |
| Исправления, повторная проверка и evidence | Исходные отказы F001–F013 и maintenance сохранены; 915/916 входов текущей CLI совпадают, единственный форматный delta отдельно доказан. Все текущие provenance/docs/version/source gates PASS; owned cleanup и исторические host FAIL сохранены. |

Финальная адресная проверка: 14 методов, без failures/errors/skips; provenance,
документация, версия и строгий Linux-сертификат прошли. Исходная обвязка ожидала
один import method вместо двух: сохранён её отказ по счётчику, оба реально
выполненных PASS квалифицированы из исходного лога без повторного запуска.
Прежние полные Rust suites, 149 Linux fixtures, native/JNI и сетевые прогоны
сохраняют исходные даты и SHA; новым выполнением они не названы.

Q37 закрывает документацию, достижимость, подключение и допуск тестов, а также
проверенную интеграцию изменённой обвязки. Полный Android VPN data plane,
SIGKILL recovery/ENONET относятся к Q29; hosted CI и выпуск — к Q34;
SDK/bootstrap — Q31; старый performance FAIL и полный endurance — Q35;
причина TCP-асимметрии и пределы нагрузки — Q36. Они остаются открытыми,
но не дублируются как неопределённый остаток Q37. Не утверждается, что все
возможные исполнения или все публичные API доказаны семантически достижимыми.

**Q37 DONE в согласованном объёме. Итог: 32/37 (86,5%), осталось 5 разделов:**
Q29/Q31/Q34/Q35/Q36. Полный аудит и релиз ещё не завершены.
Сетевые прогоны и большие сборки в этом пакете не повторялись;
новые кэши компиляции не создавались. `NO_PUSH_DEPLOY_RELEASE`.

<!-- q31-current-portable-20261012 -->

**12 октября, Q31-V013:** текущие ARM/MIPS и SDK client-only compile/packaging подтверждены; исправлены0664 права лицензий и устаревшие SDK/opkg assertions.54 scoped методов PASS,533 license files проверены. Сам ELF не менялся при исправленной установке/перепаковке. Own roots удалены, около3,6GiB освобождено, исходные сервисы сохранены. [Полный scope и остаток](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md). Q31:3/5 IN_PROGRESS; bootstrap resource-deferred, physical router USER_EXCLUDED. Полный32/37 (86,5%),5 открытых разделов.

<!-- q29-current-vpn-20261012 -->

**12 октября:** [Q29: текущие VPN-интеграции и надёжность стенда](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md). Исправлены RAM admission, окно post-CONNECTED, Profiles transition и ANR handling.23 helper methods и7 matching-R8 routed cases PASS,72 exact receipts/6 DNS names. Шесть cold attempts FAIL сохранены; последняя остановилась на unpublished storage. SIGKILL/ENONET открыты, ordinary production-rules/current independent UID cold gate не квалифицирован. Q29 IN_PROGRESS;32/37(86,5%),5 разделов осталось.

<!-- q34-current-source-cut-20261012 -->

**12 октября:** Обновлён production OpenWrt pin/hash: два SDK download и prepare проверены, все 3272 tracked files совпали с Git. Настоящий source gate и25 методов PASS;3 прежних skips сохранены. Public pin/CI отсутствуют; bootstrap/IPK не запускались. Q34 IN_PROGRESS;32/37(86,5%),5 разделов открыты. [Q34](../reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-CUT.md). NO_PUSH_DEPLOY_RELEASE.

<!-- q29-storage-startup-20261012 -->

**12 октября:** Q29: закрыт scoped current independent-UID cold UI/startup/lockdown/manual recovery gate.8 fixture methods PASS,336 probes,241 correlated receipts,80/80 post-CONNECTED replies,stopped lockdown48/0. Ожидание storage до APK и push устранило прежний premature INI upload. DNS/null ENONET,SIGKILL и ordinary production-rules APK остаются открыты;общий32/37(86,5%),5 разделов. [Отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).NO_PUSH_DEPLOY_RELEASE.

<!-- q29-production-runtime-20261012 -->

**12 октября:** Обычный production R8 APK проверен через UI/SAF и отдельный UID без instrumentation: 80 post-CONNECTED sockets PASS,230 correlated receipts, stopped lockdown48/0 и manual recovery/DNS PASS. APK payload неизменен после lab signing; реальная release-подпись и физические платформы не квалифицированы. DNS/null ENONET, first-post-APPLIED blocking и historical SIGKILL сохраняются. [Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.

<!-- q29-dns-selection-control-20261012 -->

**12 октября:** Q29: причина generic/null ENONET локализована на текущем API34 image. Ответ dnsproxyd и отдельный platform TUN с другим owner UID воспроизводят отказ; bypassable control получает A+AAAA. Typed/null и explicit VPN DNS идут через TUN. Product APK/JNI/default kill-switch неизменны; compatibility FAIL сохранён, SIGKILL и first-post-APPLIED открыты. [Q29 DNS](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.

<!-- q29-current-sigkill-20261012 -->

Текущий production R8 SIGKILL recovery: FAIL; общий runtime FAIL. Plain/TUN platform-only controls выполнены один раз,45s window сохранён. Manual recovery/revoke и блокировка при dead/force-stopped VPN PASS. Product APK/JNI и byte-identical restart policy неизменны;SIGKILL FAIL не переписан. [Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.

<!-- q29-publication-contract-20261012 -->

Разобрана граница APPLIED/CONNECTED: первые sampled сокеты после APPLIED начаты до CONNECTED;8 отказов в окне и80/80 post-CONNECTED PASS в каждом из двух сохранённых прогонов. Вопрос трактовки закрыт, исходный FAIL_POST_PLAN_BLOCKING сохранён. Helper уже проверяет post-CONNECTED;6 методов PASS. Новые runtime/builds не выполнялись. SIGKILL/DNS compatibility FAIL и Q29 IN_PROGRESS сохраняются. [Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.

### 13 октября: закрыты native copies и полный endurance

<!-- normative-sync: adopted-native-endurance-checkpoint-20261013 -->

[Q34: принятые исправления и свежие native](../reports/audit-0.8.2/AUDIT-Q34-ADOPTED-NATIVE.md):
factory panel build, два assets-теста и 131 HTTP-проверка PASS. Принятый
коммит da776fb8 заново собран A/B для четырёх библиотек; 22 Windows ABI,
23 Android JNI и два packaged INI теста PASS. Все восемь локальных копий,
SHA256SUMS и PROVENANCE обновлены и проверены. Независимая квалификация
архивов и очистка обоих build roots/временного swap/эмулятора завершены.

[Q35: полный актуальный endurance](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md):
13 ч 4 мин, все восемь этапов, 10k TCP/10k QUIC/1k каждого дополнительного
UDP-адаптера, performance и 28 cross-node checks PASS; порог 5% сохранён.
Старый upload FAIL -6,8627% и неустановленная причина сохраняются отдельно.
Q35 требует итогового сопоставления остальных критериев; Q34 — общей
source applicability/certification, публичного source cut и hosted CI.
Q29 platform-scope решение, Q31 bootstrap и Q36 диагностика остаются открытыми.
Общий итог без искусственного изменения статусов: 32/37 (86,5%).
`NO_PUSH_DEPLOY_RELEASE`.

### 13 октября: реальная TUN-диагностика Q36

<!-- normative-sync: q35-final-q36-stage-checkpoint-20261013 -->

### 13 октября: текущая статистическая популяция Q36

Восстановление Qeli после SIGKILL проверено на обычном production R8 APK; отключение/отзыв запрещают возврат служб в 30-секундных окнах. DNS/null остаётся открыт. [Q29 recovery](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md). Plan: 33/37 (89.2%); Q29 IN_PROGRESS.

**14 октября: актуальные ARMv7/MIPS после F030 проверены.** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md):2fresh client-only builds/907Git inputs/staticELF/SHA +32QEMU CLI/INI PASS;allownresourcesarchived/cleaned,productionpreserved. Original preparation/importFAIL retained;SDK/IPK-current-core refresh andbootstrap remainopen,physicalrouterUSER_EXCLUDED;33/37 unchanged,NO_PUSH_DEPLOY_RELEASE.

**14 октября: актуальный SDK/IPK после F030 проверен.** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): штатный SDK 24.10.4 с приватным официальным Rust 1.89; client-only Compile/Install/BuildPackage, 7 opkg, 9 CLI/INI и 533 notices — PASS. Исправлена очистка дочерних процессов и сохранение журналов при timeout; реальный отрицательный тест PASS. Собственные ресурсы очищены, production сохранён. Full feed rustc/std/cargo bootstrap ещё не выполнен; physical router USER_EXCLUDED, public CI/release открыты. 33/37, NO_PUSH_DEPLOY_RELEASE.

**14 октября: F459 / Q34-F013 закрыт для текущего графа панели.** [Client supply](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): принятый Tailwind 4 compiler API удалил braces/CLI/watcher цепочку. Свежий npm audit: старый граф exit 1 / пять затронутых записей; текущий exit 0 / ноль. CSS/build/watch/template входы и прежние 29 Linux / 29 Windows, 36 variants / 96 states, 131 HTTP checks сверены без повторного запуска. Cache удалён; Q34 целиком открыт, 33/37 прежние, NO_PUSH_DEPLOY_RELEASE.

**14 октября: подготовка полного Rust feed проверена.** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): шесть файлов из SDK pin, официальный source SHA, штатный patch, host-prepare/host-configure и семантика GNU host/musl target PASS. Исправлены пропуски feed и host exports в стенде; все ресурсы очищены. Compiler bootstrap/cold graph NOT_RUN, Q31 открыт, 33/37 прежние, NO_PUSH_DEPLOY_RELEASE.

**14 октября: проверен фактический публичный CI.** [Q34](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): три failed jobs в опубликованном e7; source pin404, текущий core не опубликован. Keenetic fixture исправлена и проверена44/root +44/non-root с сохранением настоящих production owner guards. Mac/iOS причины и exact-source hosted gate остаются открыты; физические стенды USER_EXCLUDED,33/37 прежние,NO_PUSH_DEPLOY_RELEASE.

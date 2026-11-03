# Q29: сон и восстановление транспорта в Android Release

<!-- normative-sync: q29-android-release-faults-v1 -->

**5 октября 2026. Семь сценариев Release/R8 PASS: screen-off, forced Doze, TCP reset/reconnect, UDP/QUIC × soft/grace-expiry. Три запуска через интерфейс, 12 стартовых IPv4/IPv6 TCP/UDP payload-проб; 28 подтверждений приёмника. Q29 IN_PROGRESS; общий план 28/37 (75,7%).**

## Метод и артефакты

Три последовательных readonly Android 14/API 34 x86_64 AVD на .11, в частных NET/MNT/PID namespaces. Пара Release/testRelease APK побайтно совпадает с [предыдущей квалификацией Release](AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md). Все 296 исходных входов продукта, JNI/Linux CLI и семь managed-артефактов совпадают. Пересборка, изменение продукта и production proguard rules не потребовались; изменена только Python-обвязка. Сервер .10 не затронут.

Штатный INI file-picker и настоящая OS-политика Always-on + lockdown запускают профиль. Клиент не debuggable; `run-as` запрещён. Тестовый debug certificate используется только для лабы. AndroidJUnitRunner и приватная запись preferences не используются. Независимый UID 10148, отличный от Qeli UID 10149, выполняет ordinary Java socket probes без bind/protect/root/JNI. Перед отказами проверяются IPv4/IPv6 × TCP 16 KiB/UDP 257 байт: полное сравнение ответа, SHA запроса/ответа и TUN source в receipts. После сна и восстановления отдельные UDP-пробы подтверждают рабочую передачу данных.

## Сценарии

| Транспорт | Сценарий | Auth/NetworkPlan | Результат |
| --- | --- | --- | --- |
| TCP | screen-off 5 s → wake | 1/1 → 1/1 | PASS |
| TCP | forced deep IDLE 20 s → wake | 1/1 → 1/1 | PASS |
| TCP | TCP reset → reconnect | 1/1 → 2/2 | PASS |
| UDP | soft path recovery | 1/1 → 1/1; PATH_COMMIT epoch 1 | PASS |
| UDP | grace expiry 15 s → full reconnect | 1/1 → 2/2 | PASS |
| QUIC | soft path recovery | 1/1 → 1/1; PATH_COMMIT epoch 1 | PASS |
| QUIC | grace expiry 15 s → full reconnect | 1/1 → 2/2 | PASS |

Во всех сценариях сохранены PID, TUN, ifindex и адреса. Сон подтверждён dumpsys power; forced Doze достигает настоящего состояния IDLE, постоянного исключения батареи нет. Wake не создаёт новой Auth/NetworkPlan. Reset вызывает native transport error, затем новую успешную Auth/NetworkPlan и reuse Android TUN. Soft UDP/QUIC меняют внешний source port без новой Auth; grace-expiry выполняет строгую последовательность NAT recovery → error → Auth → NetworkPlan. DROP/REJECT создаются только в частном namespace; UDP-правила восстановлены с точным сравнением ownership.

## Отрицательное окно и восстановление

При отказе независимый receiver получает timeout, а sink не получает запроса в окне этой пробы. Это не означает вечного удаления пакета: накопленный запрос может выйти через TUN после успешной Auth восстановления. Анализ pcap сверяет полные байты UDP, source и порядок относительно серверного AUTH на общих часах. Фактические задержки после Auth: tcp 0.047 s, udp 0.048 s, quic 0.092 s. Такая доставка не выдается за физическую утечку или доказательство полной leak-матрицы.

Реальный Settings revoke PASS во всех трёх квалифицированных запусках: `desired=false`, consent `ignore`, сервис/TUN отсутствуют. Preferences только читаются root частного AVD после revoke. Power/battery settings восстановлены, сервер завершился с кодом 0, host/service и userdata SHA/size/mtime не изменились во всех пяти попытках.

## Разбор обвязки и Release runner

Первая попытка прошла три power-сценария и revoke, но финальный gate завершился FAIL: проверка ожидала четыре dual-stack receipts от прежнего Debug bootstrap, которого нет при UI-импорте. Добавлены четыре независимые стартовые payload-пробы. Вторая попытка остановилась до fault-сценариев: новый маркер `Q29READY` отклонён allowlist receiver. Финальная версия использует существующий `Q29PROTECTED`, а размер payload отличает стартовую пробу от короткой проверки состояния. Test APK не менялся; обе неуспешные попытки, XML, логи и исходные версии сохранены и не входят в семь PASS. System UI ANR/Wait также сохраняется в данных запусков.

DEX-анализ предыдущей пары APK подтвердил: определение `androidx.tracing.Trace` отсутствует в обоих APK, но тестовый DEX содержит ссылки на исходные `beginSection/endSection/forceEnableAppTracing`. Это согласуется со стеком прежнего runner FAIL. Свежий dependencyInsight подтверждает одинаковую разрешённую tracing 1.2.0 для приложения и тестов: расхождения версии нет. R8 переносит/удаляет API, используемые только тестами; [официальный issue о minified instrumentation](https://issuetracker.google.com/issues/126429384) описывает эту границу. Точный механизм AGP dependency exclusion здесь не квалифицирован. Не добавлялись широкие keep rules или копия Trace; прошлый instrumentation FAIL не назван PASS и не замаскирован UI-проверками.

## Проверки и пределы

Python/CLI, девять docs checks, panel, generated bindings и проверка сертификата PASS. Новая пересборка или повтор JVM/.NET suites не выполнялись: соответствующие product inputs побайтно неизменны. Raw: `audit-debt-20260924/q29-android-release-faults-20261005`; evidence: `release/certification/evidence/q29-android-release-faults-20261005.json`.

Это короткий forced Doze AVD, а не физический suspend/длительный Doze; временные battery exemptions полностью не классифицированы. Backend offline, physical LTE/Internet не проверены. [Прежняя матрица переходов](AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md) сохраняется отдельно. NAT64/IPv6-only outer, немедленные пакеты и полная leak-матрица, долгий flapping/power, другие API/OEM/arm64 и остальные Release lifecycle сценарии остаются. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) не повторён и не закрыт. USER_SKIPPED и D06 без BPF неизменны; Q29 IN_PROGRESS.

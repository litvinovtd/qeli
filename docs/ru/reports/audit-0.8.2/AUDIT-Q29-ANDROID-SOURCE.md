# Q29 F286–F288: ограниченное чтение и итоговый source review Android

<!-- normative-sync: q29-android-source-v2 -->

6 октября 2026. Критерий review завершён для31 основных Kotlin-файлов, Android resources,
manifest/build/R8 и Rust JNI-входов. Прежние reviews сверены с текущими callers и владельцами
ресурсов. Список private references сам по себе не доказывает достижимость и корректность
всех runtime paths. Q29 остаётся IN_PROGRESS.

## Находки

| ID | Проблема и состояние |
| --- | --- |
| F286 FIXED | Update metadata читались неограниченным `readText`, диагностический журнал загружался целиком до обрезки. Общий `BoundedInput` отклоняет превышение после максимум limit+1 байтов, корректно обрабатывает нулевое bulk-чтение, не зацикливаясь и не теряя данные. Close принадлежит caller; временные буферы очищаются при успехе/ошибке. Update response ограничен4MiB и strict UTF-8. Журнал читает только хвост512KiB плюс24KiB на границу записи, пропускает неполную первую запись, сохраняет последние корректные и атомарно уплотняет. INI/backup imports используют тот же reader с прежними256KiB/8MiB/12MiB budgets. |
| F287 FIXED | В11 местах `validate` повторялся сразу после неизменяемого строгого `VpnConfig.parse`. Удалены повторные JNI-операции в boot/tile/widget/service/Activity; строгий parser продолжает проверку. Проверки после editor `copy`, URI import и принятого службой config сохранены. Удалён `onTaskRemoved`, лишь вызывавший super; родительский callback и manifest `stopWithTask=false` сохранены. Исправлены устаревшие комментарии parser. |
| F288 FIXED | После `WAITING_TRUSTED` → `DISCONNECTED` или `ERROR` Activity сохраняла `isTrustedPaused=true`. Терминальное состояние отображалось, но connect/смена профиля оставались заблокированы. Оба terminal setters очищают pause. Настоящие Activity-тесты вводят оба status transitions; это проверка UI state, а не реального trusted-SSID transition. |
| F289 OPEN | Save настроек сохраняет изменённый глобальный LAN bypass и вызывает `connect()` при connected/connecting. Guard немедленно возвращает управление; обещанный reconnect не происходит. Независимая подтверждённая по source находка; runtime regression/fix в этом пакете не заявлены. Следующий приоритет — явная reconfiguration с владением permission/request и целевой проверкой. |

## Source and liveness / Source и достижимость

| Layer / Слой | Files / Файлы | Review / Разбор |
| --- | --- | --- |
| Android entry points / Android-входы | `QeliApp.kt`, `BootReceiver.kt`, `QeliTileService.kt`, `QeliWidgetProvider.kt`, `QrCaptureActivity.kt` | Manifest, protected boot broadcast, tile permission, explicit widget intents, resource SquareScannerFrame; OS callbacks retained. / Manifest, защищённый boot broadcast, permission плитки, явные widget intents, ресурс SquareScannerFrame; OS callbacks сохранены. |
| Activity and permission request / Activity и permission request | `MainActivity.kt`, `VpnConnectRequest.kt` | Activity lifecycle owns IO/probe/dialog jobs; request survives recreation but drains stale permission results. F280, F284–F285, F288; open F289 below. / Activity владеет IO/probe/dialog jobs; запрос переживает пересоздание и поглощает stale permissions. F280, F284–F285, F288; F289 ниже. |
| Configuration / Конфигурация | `ConfigCore.kt`, `Config.kt`, `ConfigProjection.kt`, `ProfileAppsEditor.kt`, `RouteComplements.kt` | INI/URI Rust core, draft vs strict activation, generated field defaults/carried keys, routing policy. F287 removes only repeated validation of immutable results. / INI/URI в Rust, черновик и строгая активация, generated defaults/carried keys, routing policy. F287 удаляет только повторную проверку неизменённых результатов. |
| Storage and archives / Хранилище и архивы | `ProfileStore.kt`, `ProfileLimits.kt`, `BackupExporter.kt`, `BackupCrypto.kt`, `StrictUtf8.kt`, `BoundedInput.kt` | Keystore/AAD envelope, exact migration/readback/CAS revision, lost-key preserves ciphertext, archive budgets, KDF bounds, write/close errors. F273–F276/F284/F286. / Keystore/AAD, точная migration/readback/CAS revision, lost-key сохраняет ciphertext, archive budgets, KDF bounds, ошибки write/close. F273–F276/F284/F286. |
| Service/native ownership / Владение service/native | `QeliService.kt`, `TransportCore.kt`, `TransportCoreEvent.kt`, `TransportCoreEventDispatcher.kt` | Serialized TUN/protect/teardown; join outside monitor, stale request ACK, bounded event parsing/correlation, cancellation and observer ownership. F277–F283; name-based JNI remains an entry root. / Сериализация TUN/protect/teardown; join вне monitor, stale ACK, bounded events/correlation, cancellation/observer ownership. F277–F283; JNI остаётся точкой входа. |
| Network policy and publication / Политики сети и публикация | `AndroidKillSwitchPolicy.kt`, `AndroidSessionContinuity.kt`, `AndroidVpnPublication.kt`, `AndroidRoamingPolicy.kt`, `TrustedWifiPolicy.kt` | OS lockdown authority, immutable continuity fingerprint, published VPN facts, concrete carrier callbacks, unknown SSID fail-safe and resume ownership. Scoped prior data/handover/DoT evidence retained. / OS lockdown authority, continuity fingerprint, VPN facts, carrier callbacks, unknown SSID fail-safe, resume ownership. Сохранены границы прошлых data/handover/DoT проверок. |
| Diagnostics and display / Диагностика и отображение | `DiagnosticLogStore.kt`, `ProfileAutoProbePolicy.kt`, `UpdateChecker.kt`, `Protection.kt` | Private log rotation/atomic replacement, probe cooldown/cancellation, opt-in private VPN-pinned update request, connected immutable protection facts. F286 bounds external input. / Ротация private log/atomic replacement, probe cooldown/cancellation, opt-in update через конкретную VPN, неизменяемые protection facts. F286 ограничивает внешний ввод. |

Manifest components, resource constructors, OS callbacks, Serializable fields, generated
projections и22 совпадающих Rust/Kotlin JNI symbols — точки входа. Compatibility methods
и stale-generation ACK paths имеют callers/contracts. После исключения комментариев
private-function screen не оставил кандидатов; это фильтр, не доказательство liveness
всей программы. JNI exports нельзя удалять лишь из-за отсутствия обычных Kotlin callers.
`qeliLabel` используется deep-link import.

## Проверки и оставшиеся границы

Один свежий debug test APK: старый продукт **2 ожидаемых F288 FAIL**, исправленный
**10 PASS** (семь Activity/profile/export/status cases и три journal/stream cases).
F286 добавляет семь stream и три journal JVM регрессии; F287 — один strict-parse/
post-copy contract case. Device tests восстанавливают private journal с8MiB corrupt
prefix и проверяют bounded/zero-bulk input. Debug suite даёт ноль VPN echo receipts.

Обычный production R8 Release TCP **PASS**: настоящий UI INI import/always-on lockdown,
два перехода Wi-Fi→Cellular→Wi-Fi,12 ordinary-UID IPv4/IPv6 TCP/UDP полных payloads с
независимыми size/SHA и TUN-source checks;288 sampled sockets включают временные потери
при handover/force-stop и48 блокированных post-stop samples. Новых защищённых запросов
с physical sources нет; capture drop0. Все три attempts сохраняют host service/routes/
firewall/resolver и исходные AVD userdata SHA/size/mtime; namespace addresses/server
teardown PASS. Успешные прогоны не оставляют Qeli service/TUN. Старый F288 failure сохранён;
его final Android service check не объявлен PASS, поскольку instrumentation failure
прервал обычный success path. .10 не затронута.

Свежие199 JVM PASS (11 новых cases), lint0 errors/54 warnings, debug/test/default R8
resource-shrunk Release builds PASS. Native/server/managed SHA неизменны; прошлые
UDP/QUIC/DoT/permission/platform results сохраняют свои границы. Standalone Java Release
probe повторно используется; matching Release instrumentation NOT_RUN. Нет утверждений
о внешнем SAF/cloud provider, реальном GitHub HTTP response, UI latency/OOM benchmark,
older API/OEM/arm64. Ограничения allocations подтверждены consumed-byte tests и source
пути seek/read до декодирования.

Сохранены build diagnostics: неверный Gradle cwd и ожидание `host` в новом тесте вместо
реального `vpn.example.com`; это не продуктовые регрессии. Итоговый исправленный набор
прошёл. Для пакета проверены15 helper tests,6 CLI rejection guards, RU/EN docs и проекции.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-source-20261006.
Evidence: release/certification/evidence/q29-android-source-20261006.json.

Далее F289: явная LAN reconfiguration. [SIGKILL automatic recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md)
и [auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) остаются открыты;
причинный JNI defect не установлен. Новых обязательных permutations не добавлено.
Q29 IN_PROGRESS; итог28/37(75,7%),9 осталось. User-skipped platforms и D06 неизменны.

## Последующее завершение F289

[F289: исправление и границы проверки](AUDIT-Q29-ANDROID-SETTINGS.md). OPEN выше относится к исходному пакету; Q29 по-прежнему IN_PROGRESS.

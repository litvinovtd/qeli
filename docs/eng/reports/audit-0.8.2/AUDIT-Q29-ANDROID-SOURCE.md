# Q29 F286–F288: bounded input and final Android source review

<!-- normative-sync: q29-android-source-v2 -->

6 October 2026. Review criterion completed for 31 main Kotlin files, Android resources,
manifest/build/R8 and their Rust JNI entry surface. This reconciles the earlier stage
reviews with current callers and lifetime owners; the private-reference scan alone is not
proof that every runtime path is reachable or correct. Q29 remains IN_PROGRESS.

## Findings

| ID | Problem and disposition |
| --- | --- |
| F286 FIXED | Update metadata used unbounded `readText`; diagnostic recovery loaded the whole file before trimming. Shared `BoundedInput` rejects excess after at most limit+1 bytes and handles zero bulk reads without spinning or losing data. Caller owns close; temporary byte buffers clear on success/failure. Update response budget is4MiB with strict UTF-8. Journal reads only the final512KiB plus24KiB edge allowance, skips an incomplete first record, retains newest valid entries and atomically compacts. INI/backup imports share this reader with their existing256KiB/8MiB/12MiB budgets. |
| F287 FIXED | Eleven callers repeated `validate` immediately after immutable strict `VpnConfig.parse`. Removed those repeated JNI operations in boot/tile/widget/service/Activity; strict parsing still validates. Validation after editor `copy`, URI import, and received service config remains. Removed super-only `onTaskRemoved`; inherited callback and manifest `stopWithTask=false` remain. Stale parser comments corrected. |
| F288 FIXED | `WAITING_TRUSTED` followed by `DISCONNECTED` or `ERROR` left Activity `isTrustedPaused=true`. The visible terminal state still blocked connect/profile switching. Both terminal state setters clear the pause. Actual Activity tests inject both status transitions; this is UI state qualification, not a real trusted-SSID transition test. |
| F289 OPEN | Settings Save persists changed global LAN bypass, then calls `connect()` when already connected/connecting. Its entry guard immediately returns, so the advertised reconnect does not occur. Source-confirmed independent finding; no runtime regression or fix claimed in this packet. Next priority is an explicit reconfiguration path with permission/request ownership and a targeted check. |

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
projections and22 matching Rust/Kotlin JNI symbols are entry roots. Compatibility methods
and stale-generation ACK paths retain callers/contracts. No unused private-function
candidate survived the comment-stripped reference screen; this is a candidate filter,
not whole-program liveness proof. JNI exports are not deleted merely for lacking Kotlin
call-site references. `qeliLabel` is called by deep-link import.

## Checks and remaining scope

Same fresh debug test APK: old product **2 F288 expected FAIL**, fixed product
**10 PASS** (seven Activity/profile/export/status cases plus three journal/stream cases).
F286 adds seven stream and three journal JVM regressions; F287 adds one strict-parse/
post-copy contract case. Device tests recover an8MiB corrupt private journal and check
bounded/zero-bulk input. Debug suite has zero VPN echo receipts.

Default production R8 Release TCP **PASS**: actual UI INI import/always-on lockdown,
two Wi-Fi→Cellular→Wi-Fi transitions,12 ordinary-UID IPv4/IPv6 TCP/UDP full payloads
with independent exact size/SHA and TUN source checks;288 sampled sockets include
transient handover/force-stop loss and48 post-stop blocked samples. No new protected
requests captured from physical sources; capture drop0. Three attempts preserve host
service/routes/firewall/resolver and original AVD userdata SHA/size/mtime; private
namespace addresses and server teardown PASS. Successful runs leave no Qeli service/TUN.
The old F288 failure is kept; its final Android service check is not called a PASS when
the instrumentation failure aborts the normal success path. .10 untouched.

Fresh199 JVM PASS (11 new cases), lint0 errors/54 warnings, debug/test/default R8
resource-shrunk Release builds PASS. Native/server/managed hashes are unchanged; prior
UDP/QUIC/DoT/permission/platform evidence retains its own scope. Standalone Java Release
probe reused; matching Release instrumentation NOT_RUN. No external SAF/cloud provider,
real GitHub HTTP response, UI latency/OOM benchmark, older API/OEM/arm64 claim. Allocation
bounds are established by consumed-byte tests and the pre-decode seek/read source path.

Build diagnostics retained: one wrong Gradle working directory and one new fixture
expectation used `host` rather than its actual `vpn.example.com`; neither is a product
regression. Corrected final sources pass. Fifteen helper checks, six CLI rejection guards,
RU/EN docs and generated projections checked for this packet.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-source-20261006.
Evidence: release/certification/evidence/q29-android-source-20261006.json.

Next: F289 explicit LAN reconfiguration. [SIGKILL automatic recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md)
and [auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) remain open;
no causal JNI defect established. No additional mandatory permutations introduced.
Q29 IN_PROGRESS; total28/37(75.7%),9 remain. User-skipped platforms and D06 unchanged.

## Subsequent F289 closure

[F289 scoped fix and checks](AUDIT-Q29-ANDROID-SETTINGS.md). The OPEN entry above describes this original packet; Q29 still remains IN_PROGRESS.

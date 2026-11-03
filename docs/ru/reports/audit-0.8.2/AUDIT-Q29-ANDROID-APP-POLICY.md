# Q29: per-app UID и Private DNS

<!-- normative-sync: q29-android-app-policy-v1 -->

5 октября 2026. **Два Release runtime прогона PASS**: include/TCP и exclude/QUIC,
API34 x86_64, readonly AVD .11 в отдельных NET/MNT/PID namespaces. 112 socket-проб:
80 с ответом и 32 ожидаемые блокировки. 52 DNS-операции, 48 A/AAAA/raw ответов.
Q29 остаётся IN_PROGRESS; общий план 28/37 (75,7%).

Ранее проверялся выбранный UID, а исключённым был Settings без сетевой пробы.
Новый framework-only пакет `com.qeli.auditprobe` собирается из существующего
`SystemNetworkProbeReceiver.java`: отдельный UID, без копии реализации, JNI,
Instrumentation, bindSocket или protect. Выбранный отправитель — `com.qeli.test`.
Приложение и оба отправителя имеют разные UID, подтверждённые package manager.

| Состояние | Выбранный UID | Невыбранный/исключённый UID |
|---|---|---|
| До VPN | Физический путь | Физический путь |
| VPN, lockdown выключен | TUN | Физический путь |
| VPN, lockdown включён | TUN | Блокировка |
| Force-stop, lockdown включён | Блокировка | Блокировка |
| Ручное восстановление, lockdown включён | TUN | Блокировка |
| Lockdown снова выключен | TUN | Физический путь |
| Системный revoke | Физический путь | Физический путь |

Для каждого состояния проверены IPv4/IPv6 TCP/UDP и raw DNS. Полные ответы и SHA
сверяются с независимым sink; source address подтверждает TUN/physical маршрут.
Профиль импортирован через настоящий UI из INI; `kill_switch=false` позволяет
проверить оба значения OS lockdown. Это не замена прежних `kill_switch=true` gates.

Private DNS `off`/`opportunistic` проверены при обоих значениях lockdown:
системный `InetAddress` и raw UDP дают ответы выбранному UID через TUN.
При `hostname=q29-unreachable.invalid` VPN LinkProperties содержат
`UsePrivateDns:true`, имя провайдера и `PrivateDnsBroken`; четыре системных lookup
завершились ошибкой, а raw DNS продолжил работать через TUN. Это отрицательная
проверка неразрешимого имени провайдера: **успешный DoT с доверенным сертификатом
не проверялся**. Raw DNS намеренно не использует системный Private DNS.

Независимый разбор обоих PCAP: 52 уникальных имени, 48 plaintext query packets,
нет запросов выбранного UID по physical пути и нет открытого fallback после
ожидаемой блокировки/strict ошибки; kernel drops 0. Блокировка excluded UID под
lockdown — ожидаемая OS-политика, а не ошибка per-app. Настройки Private DNS,
namespace addresses, host/service/firewall/routes и persistent userdata восстановлены;
server exit 0. .10 не затронут. Ручное восстановление не названо автоматическим.

Использована прежняя production-R8 пара из CONNECTED-gate: app SHA
`786e8954762b63a4c2cf8ad873376aeecd594bb5c98999df03d3f58710a8eaf2`,
non-debuggable, лабораторная подпись; инструментированный ABI-вариант из runner
не подменяет этот APK. Product Kotlin/manifest/resources/native и production
ProGuard rules неизменны. Свежие проверки: 6 helper tests, 3 CLI guards, два
runtime и PCAP; прежние JVM/lint/native/managed gates используются по неизменным
inputs. Начальный CLI отказ до запуска стенда сохранён и не назван runtime FAIL.

Проверка активного per-app/lockdown перехода на доступном AVD закрыта. Доверенный
strict DoT, долгий power/flapping, остальные lifecycle, SIGKILL recovery FAIL и
auto/null DnsResolver ENONET остаются открытыми. API28/29, arm64/OEM не проверялись;
USER_SKIPPED/D06 прежние. [Конфиги](../../manuals/CONFIG.md) и
[диагностика](../../manuals/TROUBLESHOOTING.md) уточнены. Android рекомендует доступность
Private DNS provider и вне VPN, и внутри него:
[DevicePolicyManager](https://developer.android.com/reference/android/app/admin/DevicePolicyManager).

Evidence: `release/certification/evidence/q29-android-app-policy-20261005.json`.
Raw: `audit-debt-20260924/q29-android-app-policy-20261005` (вне Git), APK/mapping,
полные логи, captures, source proof и начальная ошибка подготовки сохранены.

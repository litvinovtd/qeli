# Q29: CONNECTED после публикации Android VPN

<!-- normative-sync: q29-android-connected-gate-v1 -->

5 октября 2026. F279 исправлен в проверенном API34 x86_64 Release объёме; Q29 IN_PROGRESS. План 28/37 (75,7%), осталось 9 разделов.

F279: после TUN establishment и ACK интерфейс немедленно показывал CONNECTED, хотя Android ещё не опубликовал маршрутизацию приложений. [Предыдущий прогон](AUDIT-Q29-ANDROID-STARTUP-STATE.md) воспроизводит EACCES/pending-connect даже при active VPN snapshot. Теперь ACK немедленно запускает native packet pump, а UI остаётся CONNECTING до passive VPN NetworkCallback: AVAILABLE, VPN capabilities и LinkProperties с адресами текущего плана, а с API29 также MTU. Факты разных Network не объединяются, LOST удаляет прежние факты. INTERNET/VALIDATED не обязательны для private/split VPN.

Каждый план получает новый observer, включая сохранённый TUN. Владение core/generation/descriptor, активность coroutine и статус проверяются под monitor сервиса перед CONNECTED; stop/revoke/reconnect не позволяют позднему callback опубликовать старую генерацию. При выходе транспорта/teardown ожидание отменяется. Timeout ограничен профильным connection timeout (1–30s); отказ прекращает native генерацию, сохраняя TUN/системный lockdown для retry. После ACK повторный failed ACK не отправляется; ошибка запуска ожидания после ACK также останавливает core. Observer снимается в finally. Timeout/cancel до самого callback проверены исходником, без специального runtime fault injection.

Владелец может наблюдать свою VPN-сеть при исключении собственного UID: [AOSP NetworkCapabilities](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/android14-release/framework/src/android/net/NetworkCapabilities.java). В лабе INI apps_mode=include захватывает только com.qeli.test; Qeli пропускает себя при addAllowedApplication. Обычные независимые UID-сокеты не bound/protected. AOSP branch является reference, а не подтверждённой точной revision image.

| Финальная APK, проверка | Результат |
| --- | --- |
| TCP cold start, include/test UID | CONNECTED после ACK 557.0ms; 34 свежих проб после CONNECTED,0 ошибок |
| UDP cold start, all | CONNECTED после ACK 724.0ms; 46 свежих проб после CONNECTED,0 ошибок |
| TCP include, Wi-Fi ↔ Cellular | 2 перехода, новый ACK/CONNECTED каждой генерации, прежние PID/TUN/адреса,8 dual-stack TCP/UDP payload-проб |
| Unit / lint |172/172,5 новых publication tests;0 lint errors/55 прежних warnings |
| Harness |4 startup helper tests,2 resolver regressions,4 CLI rejection guards |

Три финальных Release/R8 runs: 960 burst socket samples,660 echo receipts. Cold post-CONNECTED: 80/80 PASS; первые свежие family/protocol paths обязательны в каждом cold run, отсутствие sample отвергается. Product log измеряет публикацию liveStatus; получение broadcast Activity отдельно не измерено. Sampled API34 PASS не является обещанием доставки любого первого пакета на любом OEM. Ошибки после APPLIED до CONNECTED и исторические FAIL сохранены.

Независимый nonce/request/reply SHA,sink и private-host pcap: четыре физических пути положительно калиброваны до lockdown; свежие маркированные post-plan доставленные запросы через TUN. Нет новых физических SYN/data/UDP в защищённом steady/stop окне,kernel capture drops0. 144 post-stop проб без ответа/receipt/capture,14 DNS operations/14 отвеченных questions,12 manual recovery payloads,Settings revoke/cleanup PASS. Include дополнительно проверен с сохранённым TUN; это не полная include/exclude/split/Private DNS матрица.

Первый exploratory include/TCP:36 post-CONNECTED PASS,460ms,336samples/216receipts; отдельные APK/mapping/executed helpers сохранены. Полный lint затем обнаружил2 NewApi error,getMtu API29 и clearCapabilities API30. Исправлено без suppression/minSdk bump: на API28 MTU не запрашивается,на API28–29 default capabilities удаляются совместимыми removeCapability. Финальная сборка/172 tests/lint PASS; первоначальный lint FAIL сохранён. API28/29 runtime не исполнялся. Локальные ошибки подготовки driver/report (assertion/missing file/quoting SyntaxError) исправлены до запуска соответствующего этапа; не являются сетевыми FAIL и не скрывают результаты лабы.

Native digest,14 JNI/native hashes и7 managed artifacts прежние; Rust не пересобирался. Service и README изменены,2 source files добавлены;298 source inputs/14 auxiliary inputs закреплены. Подпись только лабораторная,product non-debuggable,production R8/security policy не ослаблены,конфиги только INI. Четыре последовательных runs на .11 в private NET/MNT/PID и readonly AVD;host/service/firewall/routes/userdata unchanged,namespace cleanup/serverexit0. .10 не использовался.

Остаток Q29:split/per-app исключения/Private DNS,долгие power/flapping и другие lifecycle/race проверки;SIGKILL recovery FAIL,generic DnsResolver auto/null ENONET и matching R8 runner Trace FAIL остаются. QUIC cold gate на новой APK не исполнялся. USER_SKIPPED/D06 unchanged.

Raw:audit-debt-20260924/q29-android-connected-gate-20261005;evidence:release/certification/evidence/q29-android-connected-gate-20261005.json.

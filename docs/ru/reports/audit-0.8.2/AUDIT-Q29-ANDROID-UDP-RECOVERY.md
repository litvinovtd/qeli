# Q29: восстановление UDP и QUIC-маскировки Android

<!-- normative-sync: q29-android-udp-recovery-v1 -->

**5 октября 2026. UDP/QUIC × мягкое восстановление/истечение grace: 4/4 свежих runtime PASS. Два bootstrap PASS. Q29 IN_PROGRESS; план 28/37 (75,7%).**

## Проверяемая граница

Два последовательных readonly запуска Android14/API34 x86_64 AVD на .11 в отдельных NET/MNT/PID namespaces. Продуктовый debug APK, JNI и Linux CLI точно переиспользованы; заново собран только test APK. Через штатный encrypted ProfileStore сохранён INI: UDP, fake-tls, roaming=required, full tunnel, IPv6 required, reconnect=true, DNS off; второй запуск включает QUIC-маскировку. Сервер объявляет experimental roaming и heartbeat5000ms, grace15s; оба endpoints продолжают работать во время fault. Реальные Settings включают Always-on/lockdown.

Отдельное test-приложение использует обычный DatagramSocket, не bind/protect/root. Bootstrap проверяет TCP16KiB и UDP257 по IPv4/IPv6 к off-pool целям. После завершения instrumentation профиль запускает система; последующие пробуждения/переподключения не симулируются вызовом методов клиента.

## Свежие результаты

| Транспорт | Мягкое восстановление | Длительный обрыв | Полный запуск |
| --- | --- | --- | --- |
| UDP | PASS; NAT request31,78s, DROP снят32,08s | PASS; NAT request32,40s, DROP снят49,85s | 226,94s |
| UDP + QUIC-маскировка | PASS; NAT request32,22s, DROP снят32,63s | PASS; NAT request31,27s, DROP снят54,16s | 247,33s |

«Мягкий» сценарий восстанавливает транспорт вскоре после запроса нового пути, до истечения его grace. Это не проверка пятисекундного обрыва. В каждом запуске Auth/NetworkPlan остаются2/2, commit меняется0→1, payload снова приходит через TUN. Серверный PATH_CHALLENGE/PATH_COMMIT подтверждает новый внешний source port и epoch1; смена порта реальная, физическая Android Network остаётся прежней.

Длительный fault держит bidirectional UDP DROP до native transport error и отрицательной пробы. Порядок: запрос NAT recovery → ошибка транспорта → новая Auth → NetworkPlan; счётчики Auth/plan меняются2→3, commit остаётся1. Одна успешная полная Auth/plan, без ручного повторного подключения. PID, tun0, ifindex19 и все IPv4/IPv6 адреса совпадают до fault и после восстановления; лог подтверждает reuse TUN. После обоих сценариев реальный Settings revoke PASS. Сервисы/TUN отсутствуют, desired=false, consent ignore; серверexit0, правила и namespace-адреса восстановлены, host/service/userdata неизменны. .10 не затрагивается.

## Отрицательная проба и отложенная доставка

В каждом запуске Q29BLOCKED заканчивается SocketTimeoutException и нулём sink receipts в своём окне. После reconnect этот пакет доставляется **через TUN**, source10.87.0.2. UDP: через0,179s, QUIC-маскировка: через0,257s после новой серверной Auth; точные timings — capture-analysis.json. Серверные timestamps и pcap используют общие host-часы; часы AVD не используются для прямого сопоставления. Отбрасывание навсегда не заявляется.

На каждом ответчике9 receipts: четыре dual-stack bootstrap, физический baseline, подключённая положительная проба, ответы после soft/full recovery и отложенный fault packet. Итого18 доставок, из них16 соответствуют успешным пробам,2 отложенные. Это ограниченная IPv4 UDP fault-проба, не полная TCP/IPv6 leak-матрица.

## Изменения и evidence

scripts/audit_android_data_plane_lab.py получил recovery suite и transport selector, scripts/audit_android_udp_recovery.py — два fault-сценария с точным удалением собственных правил в finally. VpnSystemLifecycleInstrumentedTest принимает проверенные private fixture arguments для UDP/QUIC и roaming, выбирает правильный pin/port/IPv6 prefix. Java receiver и продуктовый Kotlin не менялись. Внешний формат конфигурации остаётся INI.

Новый test APK собран локально offline: удалённая /root/android-project оказалась старой копией, её APK/исходники не использовались. Из296 предыдущих source inputs изменён только один instrumented test,295 идентичны. Product APK,14native и7managed artifacts неизменны; test APK новый. Старые167JVM/28Android/1248.NET,ReleaseR8lint и3+6+7integration остаются историческими областями, не новым общим прогоном. Свежие docs/panel/bindings и Python checks выполнены отдельно.

Raw: audit-debt-20260924/q29-android-udp-recovery-20261005: runtime-udp/runtime-quic, executed sources, новый test APK, server INI, source-proof, capture-analysis и raw-seal. Evidence: release/certification/evidence/q29-android-udp-recovery-20261005.json.

## Остаток Q29

Проверены same-network UDP recovery и fallback, а не смена default physical network. Следующий пакет: реальное переключение доступных carrier networks AVD. Длительный/физический Doze, IPv6-only/NAT64, Release runtime и другие API/OEM остаются не квалифицированы. [Ранее воспроизведённый SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) остаётся открытым; [power/TCP пакет](AUDIT-Q29-ANDROID-POWER.md) сохраняет свою отдельную область. Mac/iOS/router/Windows VM USER_SKIPPED и принятая граница D06 без BPF не изменены.

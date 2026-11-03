# Q29: Android VPN-трафик и lifecycle после Auth

<!-- normative-sync: q29-android-data-v9 -->

**5 октября 2026. Этап PASS; Q29 IN_PROGRESS. План: 28/37 (75,7%), осталось 9 разделов.**

## Что подтверждено

Три новых instrumented-сценария запускают настоящий VpnService и JNI: TCP fake-tls, UDP fake-tls, UDP QUIC. Клиент проверяет pinned server identity и bind_static_to_session; сервер требует client key proof. Каждый режим устанавливает dual-stack TUN и передаёт TCP-поток 16 KiB и UDP-пакеты 32/257/1024 байта в обе стороны по IPv4 и IPv6. Ответчик возвращает обратный TCP payload или UDP payload с отдельным префиксом; проверяются байты, а на сервере сохраняются адреса клиентов и SHA256. Это не benchmark.

После трафика неверный ACTION_CONNECT должен сохранить CONNECTED, negotiated properties, foreground и connection_desired; затем повторный трафик подтверждает сохранение сессии. Ручное отключение завершает сервис и удаляет TUN. TCP дополнительно проходит второй полный запуск после завершённой остановки.

**Новый прогон: 3/3 PASS**, 48 ответов тестового сервера от исправленного APK. Старый APK: 1 тест, 1 ожидаемый FAIL — после успешного IPv4/IPv6-трафика CONNECTED заменён ERROR; это дополнительная проверка уже исправленного F278, без новой правки продукта. Pcap серверного TCP TUN сохранён. Последние тесты явно используют Android VPN Network и ждут выбора kernel source из адресов TUN.

## Стенд и воспроизводимость

scripts/audit_android_data_plane_lab.py запускает Qeli и readonly AVD в новых NET/MNT/PID namespaces на .11, без внешнего uplink и production-профилей. Два INI-профиля используют NAT=false и IPv6 manual: проверяется доставка на адреса самого сервера, без внешней маршрутизации или DNS. Android14/API34 x86_64; запрошено memory768MiB/1core; сохранённый runtime-final/emulator.log сообщает увеличение до2560MB. Linux CLI сверяется с ранее квалифицированным SHA256; новой сборки Rust нет.

Product APK побайтно совпадает с предыдущим этапом. 289 прежних входов, JNI и 7 managed DLL неизменны; прежние 167 JVM,28 Android,1248.NET и Release/R8/lint(0errors55warnings) переиспользованы только в своих исходных областях. Они **не** объявляются новыми прогонами. Свежий общий запуск 31 Android теста не выполнялся. Без специальных аргументов приватного стенда три integration-теста пропускаются; обычный emulator job не подтверждает этот этап.

Старые попытки сохранены: неверное сочетание heartbeat/jitter в INI; несовпадающие ADB-порты; ранние Java-сокеты с физическим source и read timeout; отказ TCP-ответчика после EOF; первоначальная проверка счётчика ответов до завершения worker. Эти результаты не выданы за подтверждённую регрессию transport core. Обвязка ждёт фактический выбор source до отправки и продолжает принимать клиентов после EOF. Отдельная проверка EOF → новый запрос проходит для IPv4/IPv6. Обычный выбор сети приложениями сразу после CONNECTED не квалифицирован и остаётся следующим пунктом Q29: LinkProperties/CONNECTED сами по себе не доказывают готовность kernel routes.

Во всех пяти namespace-прогонах и первом config-only отказе userdata AVD сохранён по SHA256/mtime/size; рабочие сеть и qeli.service .11 совпадают до/после. Финальный сервер завершился с кодом0, адреса приватного namespace восстановлены; app service/TUN отсутствуют после force-stop, AndroidRuntime без FATAL EXCEPTION. .10 не затронут. Arm64 только сверяется в APK, не исполняется.

## Что остаётся

Автоматический выбор VPN обычными приложениями, full-tunnel/lockdown, DNS и внешние маршруты, Wi-Fi/LTE roaming/protect, revoke/process-death/redelivery/always-on/Doze, Release runtime и старые API. Нового физического LTE/OEM backup evidence нет. Этап не закрывает весь Q29. Предыдущие [framework lifecycle](AUDIT-Q29-ANDROID-SERVICE.md) и [TUN/JNI](AUDIT-Q29-ANDROID-LIFECYCLE.md) сохраняют собственные области проверки.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-data-20261005.
Evidence: release/certification/evidence/q29-android-data-20261005.json.

## Дополнительный этап: обычные сокеты

Шесть новых сценариев (TCP fake-tls, UDP fake-tls, UDP QUIC × split/full) используют обычные Socket/DatagramSocket, без Network.bindSocket/socketFactory и без привязки процесса. **6/6 PASS,72 серверных ответа**: IPv4/IPv6, TCP16KiB, UDP32/257/1024, неверный CONNECT после трафика и ручной stop. Native NetworkPlan подтверждает три mode=full и три mode=split. Адреса назначения принадлежат TUN самого сервера: проверка full-конфига ещё не доказывает захват внешнего/default трафика.

Обнаружено окно готовности: в **5/6 запусков первый IPv4-сокет после наблюдаемого CONNECTED выбрал физический source10.0.2.16**. Выбор TUN появился за1–111ms от момента наблюдения статуса; IPv6 при последующей проверке уже выбирал TUN. Это замер с polling25ms, двумя вызовами predicate при успехе и затратами проверок, не точное время применения netd. Диагностический UDP-сокет не отправляет данные. Payload передаётся только после bounded source preflight. Поэтому 6PASS подтверждают передачу после готовности, **не немедленный первый пакет после CONNECTED и не отсутствие утечки при kill_switch=false**. Причина и возможная корректировка публикации статуса остаются открыты; новая регрессия Rust не доказана.

Product APK/JNI неизменны, новых исправлений продукта нет. Свежая сборка test APK и шесть debug-тестов; прежние результаты используются только в исходных областях, общего нового запуска37Android нет. Без private fixture новые шесть тестов skip. Для scripts/audit_android_data_plane_lab.py добавлен --suite ordinary; стандартный explicit выбирает только прежние три метода.

Один прогон занял109,19s, тесты18,913s. Readonly API34 x86_64, отдельные NET/MNT/PID на.11, серверexit0, namespace addresses восстановлены, userdata SHA/mtime/size и рабочая сеть/service неизменны, app service/TUN отсутствуют, AndroidRuntime безFATAL. .10 не затронут. Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-default-20261005; evidence: release/certification/evidence/q29-android-default-20261005.json. Q29 остаётся IN_PROGRESS; далее внешние маршруты/DNS/kill-switch, ранний первый пакет и системный lifecycle.

## Маршруты вне пула, системный DNS и отказ kill-switch

Следующий пакет: **7/7 новых debug instrumented тестов PASS**. Шесть проверяют TCP fake-tls, UDP fake-tls и UDP QUIC в split/full; седьмой проверяет отказ full-tunnel с kill_switch=true при выключенном системном lockdown. Новый полный запуск всех 44 Android-тестов не выполнялся; прежние результаты сохраняют исходные области проверки.

Назначения198.19.0.1 и2001:db8:29::1 находятся вне обоих VPN-пулов. Full-профили не имеют includeRoutes: доставка требует default routes0.0.0.0/0 и::/0, наличие обеих проверяется в LinkProperties. Split-профили имеют явные /32 и/128 и не содержат default routes. Обычные Socket/DatagramSocket без привязки передают TCP16KiB и UDP32/257/1024; сервер подтверждает72 ответа с адресами TUN и хешами payload. Это доказывает захват off-pool трафика клиентом. Адреса принадлежат loopback изолированного сервера: внешний Интернет, серверный FORWARD/NAT/NAT66 и доступность production-сети не проверяются.

В каждом профиле устанавливается tunnel DNS198.19.0.53; его /32-маршрут проверяется отдельно от пользовательских includeRoutes. Обычный InetAddress.getAllByName разрешает шесть уникальных q29-*.test имён. Клиент получил A иAAAA во всех шести случаях; отдельный DNS-ответчик сохранил12 отвеченных вопросов с source из TUN, а pcap подтверждает путь. Посторонним запросам Android ответчик возвращает NXDOMAIN; внешнего uplink нет. Private DNS/DoT и DNS-восстановление после системного process-death не входят в этот этап.

Отрицательный kill-switch сценарий использует валидный профиль: без OS lockdown клиент публикует ERROR, завершает foreground service и не оставляет TUN/connection properties. Положительная работа с Always-on+lockdown и блокировка пакетов при смерти процесса **ещё не квалифицированы**. Подмена secure settings сама по себе не считается включением системной политики.

Первый прогон сохранён:1 негативный тест PASS,6 UDP receive timeout. Pcap показал запрос198.19.0.1:26000 и ответ10.86.0.1:26000 — wildcard-ответчик стенда выбрал неверный source, поэтому connected DatagramSocket отверг ответ. После bind ответчика к каждому адресу назначения все7PASS. Проверка IPv6 default route дополнительно переведена со строки на семейство адреса; исходное форматирование::/0 работало и не было причиной шести отказов. Новых дефектов продукта или правок APK/JNI в этом этапе нет.

Финальный прогон105,94s, тесты21,149s; Android14/API34 x86_64, readonly AVD и сервер в новых NET/MNT/PID на.11. Оба прогона сохранили userdata SHA/mtime/size и рабочие host network/qeli.service; серверexit0, адреса namespace восстановлены, app service/TUN отсутствуют после stop, AndroidRuntime без FATAL. Product APK,289 прежних входов,14 native hashes и7 managed DLL неизменны. Свежая сборка только test APK; старые167JVM/28Android/1248.NET/Release-lint используются в прежнем scope. Без private fixture семь новых тестов skip; команда стенда --suite routed.

Окно между наблюдаемым CONNECTED и фактическим source selection сохраняется в route-readiness.json; отправка payload по-прежнему ждёт bounded unsent preflight. CONNECTED в Qeli публикуется после native ACK, без ожидания framework default network. В [исходнике AOSP Vpn](https://android.googlesource.com/platform/frameworks/base/+/b8e604452076/services/core/java/com/android/server/connectivity/Vpn.java) establish создаёт/регистрирует NetworkAgent и возвращает TUN. Это поддерживает гипотезу о раздельной публикации состояния; данный исходник не является точным build исходником эмулятора и не доказывает длительность netd. Решение о семантике раннего статуса остаётся открытым.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-routes-dns-20261005. Evidence: release/certification/evidence/q29-android-routes-dns-20261005.json. Q29 IN_PROGRESS; план28/37(75,7%). Далее положительный lockdown, revoke/process-death/redelivery/always-on/Doze, Release и оставшиеся платформенные сценарии.


Следующий [системный lifecycle этап](AUDIT-Q29-ANDROID-SYSTEM.md) подтверждает положительный lockdown и блокировку проверяемого трафика после смерти процесса;автоматическая SIGKILL redelivery остаётся FAIL (вопрос открыт). Это отдельная частичная проверка,Q29 не закрыт.


<!-- q29-storage-startup-20261012 -->

**12 октября:** Новый current matching-R8 cold UI/SAF прогон с независимым UID прошёл после bounded storage admission. Все80 post-CONNECTED сокетов успешны; established stopped lockdown48/0,manual recovery/system+raw DNS PASS.241 receipts сверены с UID-журналом. Generic DNS/null ENONET и historical SIGKILL FAIL остаются открыты,ordinary production APK не квалифицирован. [Current scope](AUDIT-Q29-ANDROID-CURRENT-VPN.md). Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-production-runtime-20261012 -->

**12 октября:** Обычный production R8 APK проверен через UI/SAF и отдельный UID без instrumentation: 80 post-CONNECTED sockets PASS,230 correlated receipts, stopped lockdown48/0 и manual recovery/DNS PASS. APK payload неизменен после lab signing; реальная release-подпись и физические платформы не квалифицированы. DNS/null ENONET, first-post-APPLIED blocking и historical SIGKILL сохраняются. [Current scope](AUDIT-Q29-ANDROID-CURRENT-VPN.md).Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-dns-selection-control-20261012 -->

**12 октября:** Q29: причина generic/null ENONET локализована на текущем API34 image. Ответ dnsproxyd и отдельный platform TUN с другим owner UID воспроизводят отказ; bypassable control получает A+AAAA. Typed/null и explicit VPN DNS идут через TUN. Product APK/JNI/default kill-switch неизменны; compatibility FAIL сохранён, SIGKILL и first-post-APPLIED открыты. [DNS comparison](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-current-sigkill-20261012 -->

Текущий production R8 SIGKILL recovery: FAIL; общий runtime FAIL. Plain/TUN platform-only controls выполнены один раз,45s window сохранён. Manual recovery/revoke и блокировка при dead/force-stopped VPN PASS. Product APK/JNI и byte-identical restart policy неизменны;SIGKILL FAIL не переписан. [System scope](AUDIT-Q29-ANDROID-SYSTEM.md).32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-publication-contract-20261012 -->

Разобрана граница APPLIED/CONNECTED: первые sampled сокеты после APPLIED начаты до CONNECTED;8 отказов в окне и80/80 post-CONNECTED PASS в каждом из двух сохранённых прогонов. Вопрос трактовки закрыт, исходный FAIL_POST_PLAN_BLOCKING сохранён. Helper уже проверяет post-CONNECTED;6 методов PASS. Новые runtime/builds не выполнялись. SIGKILL/DNS compatibility FAIL и Q29 IN_PROGRESS сохраняются. [Current contract](AUDIT-Q29-ANDROID-CURRENT-VPN.md).

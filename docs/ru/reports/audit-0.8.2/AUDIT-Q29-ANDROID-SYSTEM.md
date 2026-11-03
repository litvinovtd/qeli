# Q29: системные Always-on, lockdown и смерть процесса Android

<!-- normative-sync: q29-android-system-v8 -->

**5 октября 2026. Частичный результат; Q29 IN_PROGRESS. План28/37(75,7%),9 разделов осталось. Общий системный gate FAIL: автоматическая redelivery после внешнего SIGKILL не подтверждена.**

## Проверяемые границы

Один новый debug instrumented bootstrap сохраняет активный INI-профиль через штатный encrypted ProfileStore, проверяет TCP16KiB и UDP257 по IPv4/IPv6 к off-pool адресам и заканчивается. Android завершает instrumentation через force-stop целевого пакета: оставлять VPN работающим между отдельными am instrument нельзя. Поэтому следующие действия выполняет внешний driver, а UDP-пробы — отдельный Java receiver тестового APK, UID10148, отличный от UID10149 Qeli. Он использует обычный DatagramSocket без bindSocket, привязки процесса, protect или root. Test receiver не попадает в product APK; Java использует только platform classes, поскольку Kotlin runtime тестового APK доступен через target APK только во время instrumentation.

Системная политика включается настоящими Android Settings, с сохранением UI XML: Always-on VPN и Block connections without VPN. Запущенный системой профиль имеет kill_switch=true, full-tunnel, reconnect=true, pinned identity/client key proof; сервер подтверждает Auth и native NetworkPlan. Secure settings читаются как дополнительное свидетельство, их запись не подменяет включение политики.

## Результаты

| Сценарий | Результат |
| --- | --- |
| Bootstrap, dual-stack TCP/UDP payload | 1 новый instrumented PASS,4 ответа |
| Обычная проба без VPN | PASS: цель доступна по физическому пути |
| Настоящий Always-on+lockdown | PASS: ответ с source TUN |
| Внешний kill -9 процесса Qeli | FAIL (вопрос открыт): нет нового процесса/NetworkPlan за45s |
| Проба после SIGKILL | PASS: ошибка сокета,0 доставок на ответчик |
| Пользовательский force-stop | PASS: TUN отсутствует,проба заблокирована,0 доставок |
| Явный повторный запуск и переключение системной политики | PASS: новый Auth/NetworkPlan,foreground и ответ через TUN |
| Отключение политики и Forget VPN в Settings | PASS: сервис/TUN отсутствуют,connection_desired=false,ACTIVATE_VPN=ignore |

Наличие физически доступного ответчика до включения политики отличает блокировку от недоступности сети. Каждый tagged UDP payload имеет независимый SHA256 на ответчике. Отрицательные пробы действительно пытаются отправить пакет; ожидания source/preflight перед отправкой нет. Эти две отрицательные проверки охватывают только IPv4 UDP к одному off-pool назначению; это не полная TCP/IPv6 leak-матрица и не физический Интернет.

## Открытый результат SIGKILL

Перед убийством dumpsys показывает isForeground=true,startRequested=true,startCommandResult=3 и доставленный android.net.VpnService intent. Android фиксирует SIGNALED/status9, а не пользовательский force-stop. Сначала исчезает TUN; системный Vpn.interfaceRemoved пытается unbind уже умершего сервиса и получает DeadObjectException. Затем ActivityManager регистрирует смерть процесса; остаётся ServiceRecord с app=null и без запланированного restart. Отказ повторяется в нескольких независимых readonly запусках. Lockdown при этом продолжает блокировать проверяемый трафик; вручную подключение восстанавливается.

[Документированный контракт START_REDELIVER_INTENT](https://developer.android.com/reference/android/app/Service#START_REDELIVER_INTENT) предусматривает повторную доставку незавершённого intent после смерти процесса. В [ActiveServices Android14 r1](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-14.0.0_r1/services/core/java/com/android/server/am/ActiveServices.java) ошибка unbind вызывает serviceProcessGoneLocked, а killServicesLocked обходит running-service записи для restart. Это поддерживает гипотезу о гонке framework bookkeeping. Источник **не является доказанным исходником точного образа эмулятора**; причинная ошибка продукта не установлена. Произвольная замена REDELIVER на STICKY или добавление watchdog не выполнены. Независимый минимальный VpnService-контроль выполнен ниже;другое системное завершение процесса и иной образ остаются отдельными сценариями. Этот FAIL не превращён в PASS/USER_SKIPPED.

## Независимый платформенный контроль

Отдельный APK com.qeli.audit.restartcontrol содержит только два Java-класса и Android API. Receiver сохраняет режим; foreground VpnService возвращает START_REDELIVER_INTENT и при необходимости создаёт TUN. Нет JNI, Rust, транспорта, парсеров, профилей Qeli, таймеров или watchdog. Оба запуска делает настоящая политика Always-on через Settings; процесс завершает внешний root kill -9. Контроль останавливается, политика отключается и VPN-разрешение отзывается перед Qeli в том же временном AVD.

| Контроль | Наблюдение |
| --- | --- |
| Foreground VpnService без TUN,Always-on,lockdown=0 | Финальный контроль:перезапуск через17,40s;новый PID,flags=1,тот же intent,result=3 |
| Тот же сервис с TUN,Always-on,lockdown=0 | За45,19s новый PID не появился;TUN отсутствует |
| Тот же сервис с TUN,Always-on,lockdown=1 | За45,08s новый PID не появился;TUN отсутствует |

Аналогичный отказ воспроизведён без продуктового кода. Это отделяет наблюдаемую проблему платформенного VPN lifecycle от причинной ошибки JNI/транспорта Qeli. В финальном сравнении при одинаковом lockdown=0 меняется только создание TUN:отказ появляется с TUN. Lockdown не является необходимым условием воспроизведения на этом образе. DeadObjectException при системном unbind до обработки смерти процесса и stale app=null совпадают со следом Qeli. Точный framework commit и универсальность для всех Android14 устройств не установлены. Автовосстановление продукта на данном стенде остаётся FAIL,безопасная блокировка и ручное восстановление имеют отдельные результаты. Изменения START_* или watchdog не добавлены.

Fingerprint:Android/sdk_phone64_x86_64/emu64x:14/UE1A.230829.036.A1/11228894:userdebug/test-keys. Контроль собран javac --release8 + aapt2/D8/zipalign/apksigner;source/APK SHA256 и команды сохранены. Первый прогон остановился до контрольных ячеек:после шестерёнки появился SystemUI ANR. Во второй попытке после обеих контрольных ячеек и продуктового SIGKILL/блокировки ручное восстановление перекрыл запрос батарейного исключения;в третьей uiautomator завершился без XML до измерений. Общий UI helper ждёт экран нужного провайдера,обрабатывает Wait после перехода,выбирает DENY для батарейного исключения и сохраняет отдельный свежий XML с ограниченным повтором dump. Четвёртая попытка выполнила все три контрольные ячейки и повторила продуктовую блокировку,но переход к ручному восстановлению ошибочно выбрал Settings самого Qeli. Выбор UI теперь ограничен системным пакетом com.android.settings;после DENY системный экран открывается повторно. Финальная проверка обвязки выполняет только продуктовый --suite system в отдельном новом AVD,не повторяя завершённый контроль. Предыдущий двухрежимный контроль сохраняется отдельно:16,22s/45,06s;он ещё менял TUN и lockdown совместно.

Raw:C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-restart-control-20261005. Воспроизведение:scripts/build_android_restart_control.py,затем scripts/audit_android_data_plane_lab.py --suite system --restart-control с SHA-квалифицированными APK/CLI. Remote runner также требует android_lab_ui.py,audit_android_restart_control.py,audit_udp_handshake_contracts.py. Контрольные наблюдения диагностические и не заменяют продуктовый acceptance gate.

## Обвязка и воспроизводимость

Исправлены только тесты/driver: singular/plural instrumentation output; ограниченный timeout вместо неверного nc -w; отдельный реальный UID вместо shell/su сокета; Java вместо недоступного Kotlin runtime standalone APK; force-stop после instrumentation; bounded Wait при SystemUI ANR; распознавание уже открытого management экрана вместо поиска отсутствующей шестерёнки; выбор подтверждения FORGET по тексту вместо button1, который здесь означает DISMISS. Все неудачные попытки сохранены отдельно и не объявлены регрессиями ядра.

Стенд Android14/API34 x86_64,readonly AVD с запросом768MiB/1core (это аргумент запуска, не измеренная RAM гостя; уточнение12 октября ниже) и Linux Qeli в новых NET/MNT/PID namespaces .11,без внешнего uplink. Product APK9af9789d… и JNI побайтно прежние; Rust/продукт не изменены.290 прежних source inputs,14 native hashes и7 managed DLL неизменны; текущие входы293,новая сборка только test APK. Старые167JVM/28Android/1248.NET/Release-R8-lint и3+6+7 integration этапы сохраняют исходные области,не выданы за новый общий запуск45Android. Во всех попытках сверяются host network/qeli.service и userdata SHA/mtime/size; .10 не используется. Arm64 не исполняется.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-system-20261005. Evidence: release/certification/evidence/q29-android-system-20261005.json. Команда driver --suite system. Предыдущие [off-pool/DNS и data plane](AUDIT-Q29-ANDROID-DATA.md) остаются отдельными квалификациями. Q29 открыт: SIGKILL recovery,Doze,roam/protect,Release runtime,старые API и физические/OEM сценарии. Ранний CONNECTED/source selection остаётся открытым в предыдущем отчёте.


Предыдущий квалифицированный прогон(r13)213,97s,bootstrap2,421s. Общий gate корректно вернулFAIL только из-за SIGKILL recovery;остальные перечисленные критерии завершены. Семь ответов:4 bootstrap,1 физический baseline,1 protected,1 manual recovery;две блокируемые пробы не доставлены. Финальные service/TUN отсутствуют,AndroidRuntime безFATAL. Во всех13 попытках host/service/userdata неизменны,серверexit0,адреса namespace восстановлены. Отзыв доказан после FORGET по тексту и ожидания ACTIVATE_VPN=ignore;системный onRevoke наблюдался в последовательности отключения политики/Forget,а не при искусственном вызове метода.


Новый окончательный продуктовый прогон(r5):219,07s,bootstrap2.668s,1 свежий PASS и7 ответов;ошибки обвязки нет. Общий gate FAIL только по SIGKILL recovery. Обе отрицательные пробы заблокированы,ручное восстановление и Settings revoke PASS;финальные service/TUN отсутствуют,AndroidRuntime безFATAL. Трёхрежимный контроль(r4) завершён в предыдущем отдельном AVD;его продуктовая часть дошла до SIGKILL/блокировки,но ручное восстановление там не квалифицировано из-за UI. Во всех5 новых попытках host/service/userdata неизменны,серверexit0,адреса namespace восстановлены. Product/test APKs,14 native и7managed не изменены;296 source inputs и6 auxiliary сверены. Evidence:release/certification/evidence/q29-android-restart-control-20261005.json. Старые результаты не пересчитаны в общий свежий набор.


12 октября:768MiB выше были запросом запуска, не измеренной RAM. Control/r4 log сообщает повышение до2560MB. [Исправление и текущий scoped gate](AUDIT-Q29-ANDROID-CURRENT-VPN.md); SIGKILL FAIL сохранён.


<!-- q29-storage-startup-20261012 -->

**12 октября:** Новый current matching-R8 cold UI/SAF прогон с независимым UID прошёл после bounded storage admission. Все80 post-CONNECTED сокетов успешны; established stopped lockdown48/0,manual recovery/system+raw DNS PASS.241 receipts сверены с UID-журналом. Generic DNS/null ENONET и historical SIGKILL FAIL остаются открыты,ordinary production APK не квалифицирован. [Current scope](AUDIT-Q29-ANDROID-CURRENT-VPN.md). Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-production-runtime-20261012 -->

**12 октября:** Обычный production R8 APK проверен через UI/SAF и отдельный UID без instrumentation: 80 post-CONNECTED sockets PASS,230 correlated receipts, stopped lockdown48/0 и manual recovery/DNS PASS. APK payload неизменен после lab signing; реальная release-подпись и физические платформы не квалифицированы. DNS/null ENONET, first-post-APPLIED blocking и historical SIGKILL сохраняются. [Current scope](AUDIT-Q29-ANDROID-CURRENT-VPN.md).Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-dns-selection-control-20261012 -->

**12 октября:** Q29: причина generic/null ENONET локализована на текущем API34 image. Ответ dnsproxyd и отдельный platform TUN с другим owner UID воспроизводят отказ; bypassable control получает A+AAAA. Typed/null и explicit VPN DNS идут через TUN. Product APK/JNI/default kill-switch неизменны; compatibility FAIL сохранён, SIGKILL и first-post-APPLIED открыты. [DNS comparison](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


## 12 октября: текущий production SIGKILL и platform TUN-контроль

Один свежий current ordinary-R8 прогон занял 401.05s на readonly Android14/API34 x86_64. Общий runtime `FAIL`, automatic authenticated recovery `FAIL`. INI импортирован реальным UI/SAF без instrumentation/private-prefs injection;126 канонических Android build inputs прежние. CLI/APK/JNI не пересобирались. Только standalone platform Java restart control APK собран свежим инструментом; plain и TUN+lockdown cells выполнены, прежний TUN без lockdown не повторялся.

| Контроль | Результат | Наблюдение,s | PID |
| --- | --- | --- | --- |
| plain | RESTART_OBSERVED | 18.95 | 1889 → 2329 |
| vpn | NO_RESTART_OBSERVED | 45.49 | 2494 → none |

Текущий plain foreground-контроль перезапускается, а TUN-контроль и Qeli воспроизводят unbind/DeadObjectException до process-death и отсутствие scheduling restart в наблюдавшихся45s. Отказ локализован в Android framework teardown TUN; это не доказательство точной framework-ревизии или бесконечного отсутствия перезапуска.

Перед SIGKILL сервисы имеют isForeground=true,startRequested=true,startCommandResult=3. Exit-info подтверждает SIGNALED/status9; PID берётся из живого процесса перед kill. Системные логи проверены по конкретным component/PID: unbind exception,DeadObjectException,process death и scheduling restart. START_REDELIVER/desired policy байт-в-байт совпадает с историческим source; новый процесс/READY flags1 требуется для фактической redelivery. Изменение START_STICKY не проверялось как исправление. [AOSP Android14 reference](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-14.0.0_r1/services/core/java/com/android/server/am/ActiveServices.java) при исключении unbind удаляет связь с процессом до последующего обхода его сервисов. Это объяснение reference-кода,не доказанная точная сборка AVD.

Отдельный обычный UID проверил блокировку после смерти и force-stop:0 server receipts. Ручное восстановление и отзыв VPN PASS; они не заменяют automatic recovery. Guest1536MiB с lowram,фактический MemTotal=1505648KiB; прежние2560MB attempts не переписаны. Общий runtime failure/ошибка остаются в исходном result. Точность глобальных platform-health выводов ограничена состоянием одного AVD.

Локальный отказ чтения manifest произошёл до запуска теста. Единственный собственный staging root принят только после совпадения SHA всех уже загруженных файлов; служебные metadata дописаны без повторной загрузки APK/ядра. Сервис/PID,host firewall/routes/resolver и original userdata сохранены. Own root удалён после verified recovery и inode/process/fd/mount guards. [Evidence](../../../../release/certification/evidence/q29-current-sigkill-20261012.json). Raw:`audit-debt-20260924/q29-current-sigkill-20261012`. Q29 IN_PROGRESS;32/37(86,5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-publication-contract-20261012 -->

Разобрана граница APPLIED/CONNECTED: первые sampled сокеты после APPLIED начаты до CONNECTED;8 отказов в окне и80/80 post-CONNECTED PASS в каждом из двух сохранённых прогонов. Вопрос трактовки закрыт, исходный FAIL_POST_PLAN_BLOCKING сохранён. Helper уже проверяет post-CONNECTED;6 методов PASS. Новые runtime/builds не выполнялись. SIGKILL/DNS compatibility FAIL и Q29 IN_PROGRESS сохраняются. [Current contract](AUDIT-Q29-ANDROID-CURRENT-VPN.md).


Восстановление Qeli после SIGKILL проверено на обычном production R8 APK; отключение/отзыв запрещают возврат служб в 30-секундных окнах. DNS/null остаётся открыт. [Q29 recovery](AUDIT-Q29-ANDROID-RECOVERY.md).

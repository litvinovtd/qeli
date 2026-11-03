# Q29: сравнение Android DNS API

<!-- normative-sync: q29-android-resolver-diagnostic-v4 -->

**Актуальный итог 15 октября: Q29 завершён в согласованном объёме. Пользователь принял описанное ограничение generic/null DNS на данном API34-образе. ENONET не исправлен, исходный FAIL сохранён; secure VPN и системный kill switch остаются. Полный аудит: 37/37.**

5 октября 2026. Q29 IN_PROGRESS; план 28/37 (75,7%). Один успешный readonly API34 x86_64 Release/TCP run на .11 в private NET/MNT/PID; четыре сохранённые неуспешные попытки. .10 не использовался.

Независимый test APK UID10148, Qeli UID10149. Реальный UI-импорт INI, Always-on/lockdown, dns=tunnel и dns_servers=198.19.0.53. Product APK/JNI/managed прежние; изменены test receiver/manifest и Python helpers. Matching instrumentation не выполнялась, предыдущий Trace FAIL открыт.

| Вариант | Фактический результат |
| --- | --- |
| `connectivity` | 8 no-payload connectivity checks |
| `auto` | ExecutionException:android.net.DnsResolver$DnsException: android.system.ErrnoException: resNetworkQuery failed: ENONET (Machine is not on the network) |
| `a` | 198.19.0.1 |
| `aaaa` | 2001:db8:29::1 |
| `auto-active` | 198.19.0.1,2001:db8:29::1 |
| `a-active` | 198.19.0.1 |
| `aaaa-active` | 2001:db8:29::1 |

`auto` — automatic-family DnsResolver.query с неявной сетью; `a`/`aaaa` — typed overload. Суффикс `-active` передаёт ConnectivityManager.getActiveNetwork. Новое уникальное имя для каждого вызова, cache-bypass flags, ожидание 7 секунд и CancellationSignal. Ошибки сохранены независимо от успешного обычного InetAddress.getAllByName.

`connectivity`: восемь no-payload проверок Os.socket → optional Network.bindSocket → Os.connect(port0), null/active VPN × 8.8.8.8/2000::/два fixture-адреса. Записаны фазы ошибки и metadata capabilities/LinkProperties обычного UID. Это local socket checks, а не доказательство доставки.

Непрерывный private-host pcap: уникальные questions/answers, TTL0, точные A198.19.0.1/AAAA2001:db8:29::1, sink receipts. Все доставленные диагностические DNS-вопросы имеют TUN source10.86.0.2; API error без пакетов не доказывает общую DNS-совместимость.

288 socket samples по шести фазам, 48 post-force-stop без ответа/receipt/capture, семь обычных DNS operations, четыре manual recovery payloads и revoke/cleanup PASS; 174 echo receipts. Первые post-plan сокеты: `NOT_SAMPLED_AFTER_PLAN`. При окончании короткой серии до APPLIED diagnostic opt-in записывает NOT_SAMPLED_AFTER_PLAN; обычный startup gate строгий. Это отсутствие покрытия, не readiness PASS; прежний FAIL открыт.

Четыре failed attempts сохранены: два NameError отсутствующего wait_until (первый патч не совпал с импортом; финальный импорт проверен до запуска) burst ended before APPLIED и KeyError неинициализированного списка диагностики. Два локальных теста смешанных ответов/ошибок и неверного UID PASS. APK-пара одна и та же. Exact executed helpers и cleanup сохранены. Во всех пяти попытках host/service/userdata/namespace restoration неизменны, serverexit0. Product preferences не инъецировались.

Сохранены первичные AOSP android14-release DnsResolver/DnsUtils/Network/NetworkUtils/JNI. Branch не доказан как точная ревизия image. По reference общий overload проверяет семейные socket checks до DNS, typed overload их пропускает. Скрытая сеть getDnsNetwork напрямую не наблюдалась. Различие null/explicit-active само по себе не доказывает дефект маршрутов Qeli.

Первоначальный ENONET, immediate startup publication, split/per-app/Private DNS, long power/flapping и SIGKILL recovery FAIL остаются. Один AVD не квалифицирует OEM/arm64/другие API. USER_SKIPPED/D06 unchanged.

Raw: `audit-debt-20260924/q29-android-resolver-diagnostic-20261005`; evidence: `release/certification/evidence/q29-android-resolver-diagnostic-20261005.json`.


## 12 октября: измеренный выбор DNS-сети и независимый TUN-контроль

Шесть завершённых DNS-сравнений квалифицированы отдельно; последний control-only прогон занял 189.99s на Android14/API34/x86_64. Production R8 APK и JNI прежние;126 канонических Android inputs совпали. Полная cold/startup матрица и native/Gradle/JVM suites не повторялись. Итоговая пара содержит два маленьких самостоятельных platform Java APK: отправитель и минимальный TUN с локальным DNS-ответчиком, без Qeli-кода и `.so`.

Отправитель UID 10150, владелец контрольного TUN UID 10151, Qeli UID 10148. Во всех шести ячейках процесс не привязан к Network. От того же UID напрямую прочитан ответ `getdnsnetid 0` из dnsproxyd: код222 и big-endian netId. Это та же операция выбора, которую использует reference AOSP getDnsNetwork. Записаны выбранная и active сети, capabilities/LinkProperties, bind/connect фазы IPv4/IPv6, пять DNS overload/Network вариантов, уникальные имена и uncached flags.

| Ячейка | Active netId | Selected app netId | Family checks выбранной сети | Generic/null |
| --- | --- | --- | --- | --- |
| physical-baseline | 100 | 100 | 8.8.8.8:True,2000:::True | 198.19.0.1,2001:db8:29::1 |
| qeli-secure-open | 101 | 100 | 8.8.8.8:False,2000:::False | ENONET |
| qeli-secure-lockdown | 102 | 100 | 8.8.8.8:False,2000:::False | ENONET |
| control-secure-open | 101 | 100 | 8.8.8.8:False,2000:::False | ENONET |
| control-secure-lockdown | 102 | 100 | 8.8.8.8:False,2000:::False | ENONET |
| control-bypass-open | 104 | 104 | 8.8.8.8:True,2000:::True | 198.19.0.1,2001:db8:29::1 |

NetId локальны для отдельной загрузки AVD; одинаковые числа в разных загрузках не означают один объект Network. Отказ EPERM наблюдается также без lockdown. При lockdown обе реализации выбирают сеть, отличающуюся от active VPN; оба family-check socket получают отказ, generic/null и generic/selected возвращают ENONET без DNS-вопросов. Typed/null A/AAAA и generic/active получают ответы. На том же минимальном TUN изменение только `allowBypass()` при отключённом lockdown возвращает выбранную VPN-сеть, успешные family checks и generic/null A+AAAA. Таким образом, происхождение scoped ENONET локализовано в выборе/проверке сети Android перед DNS, а не в обработке DNS-пакетов Rust Qeli. Фактический ENONET сохранён: это установление причины на одном image, не универсальная DNS API-совместимость PASS.

[AOSP DnsResolver](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/android14-release/framework/src/android/net/DnsResolver.java) показывает предварительные family checks общего overload; typed overload их пропускает. [Netd DNS context](https://android.googlesource.com/platform/system/netd/+/refs/heads/android14-release/server/NetworkController.cpp) разделяет app_netid и dns_netid; для secure VPN app-network selection отличается от bypassable VPN. Сохранённый reference branch не объявлен точной ревизией AVD. Вывод основан на текущем ответе dnsproxyd и причинном secure/bypassable сравнении, а не только на reference-коде.

Доставка сверена с host DNS receipts и журналом локального контрольного DNS: unique name/qtype/source. При Qeli typed/null и explicit-active ответы идут через TUN10.86.0.2; при контроле те же запросы отвечаются локальным TUN10.88.29.2. Физический baseline сверяется по исходным host peer. В secure/open generic-selected DNS-пакеты отсутствуют; сохранён отказ до DNS, а не tunneled PASS. Дополнительные Qeli socket-пробы не квалифицированы: вспомогательная метка была вне whitelist приёмника. Полный production transport gate имеет прежние отдельные доказательства и здесь не повторялся.

В production Java/Kotlin Qeli нет вызовов DnsResolver или allowBypass. Имя сервера уже разрешается через явно выбранную сеть (`selected.getAllByName(config.serverAddress)`); исходные файлы проверены без изменения. Ошибка относится к generic DNS API обычного стороннего UID.

Тестовый INI явно содержит `kill_switch=false`, чтобы исследовать OS lockdown off/on. Production default и ранее квалифицированный fail-closed профиль не менялись. Первая попытка211,94s не квалифицирована: timeout установлен до LocalSocket.connect, имя вне DNS whitelist и корректный отказ Qeli с `kill_switch=true` без lockdown. Raw FAIL сохранён; перед исправленной попыткой его собственный root удалён после verified recovery. В исправленной фикстуре отправитель и владелец TUN разделены по UID, FD контрольного DNS blocking.

Три Qeli/baseline DNS-ячейки сохранены из второй попытки195,93s, чей общий FAIL из-за вспомогательной socket-метки не переписан. Третий прогон выполняет только оставшиеся три control-ячейки, без повтора Qeli DNS, UI import или production runtime. Третий общий runtime также FAIL: AndroidRuntime зафиксировал падение только `com.android.systemui` из-за `subscriptionId 1 is not in the list of valid subscriptions`. Шесть DNS-ячеек завершены, фактические ответы/UID/policy сверены; полная стабильность AVD и общий runtime не квалифицированы. Этот FAIL не переписан, повторного прогона ради зелёного статуса нет. Хост/service/firewall/routes/resolver и original userdata сохранены; все три собственных root удалены после SHA/inode/process/fd/mount guards. UI/SAF INI import без instrumentation/private-prefs injection. Расследование причины ENONET закрыто в этом scope. Исторический SIGKILL automatic recovery FAIL, first-post-APPLIED blocking и полная release/platform qualification остаются. Q29 IN_PROGRESS;32/37(86,5%). [Evidence](../../../../release/certification/evidence/q29-dns-selection-control-20261012.json). Raw:`audit-debt-20260924/q29-dns-selection-control-r2-20261012` + `q29-dns-selection-control-r3-20261012`; первая попытка:`q29-dns-selection-control-20261012`.NO_PUSH_DEPLOY_RELEASE.


13 октября: дополнительно проверен upstream-код выбора сети. Команда getdnsnetid и в Android16 reference возвращает app_netid. Это не runtime нового Android; изменение DNS-адреса/обновление ОС не объявлены исправлением. Безопасный прозрачный обход для чужих приложений не найден; Q29 открыт, ограничение пользователем не принято. [Primary source](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp).

## 14 октября: фактическая проверка allowBypass вместе с lockdown

Выполнена одна ранее не проверенная ячейка на независимом минимальном VpnService и отдельном UID отправителя DNS, без сборки, установки или запуска Qeli. Исходные шесть ячеек не повторялись. На прежнем Android14/API34/x86_64 `UE1A.230829.036.A1/11228894` параметр контрольного Builder `allowBypass=true` вместе с системным lockdown=1 дал фактическое `bypassable=false`: активная VPN-сеть102, выбранная getdnsnetid сеть100. Две проверки привязки IPv4/IPv6 к выбранной сети вернули EPERM; generic/null и generic/selected вернули ENONET до DNS-вопроса. Typed/null A/AAAA и generic/active получили ожидаемые ответы. Проверены шесть family-check socket и пять DNS-вызовов. Кандидат обхода отклонён; Q29 остаётся открыт, прозрачный безопасный обход для чужих приложений не найден и ограничение пользователем не принято.

Две исходные попытки сохранены отдельно: отсутствие физической default-сети дало NETID_UNSET, затем readiness guard отказал до DNS-ячейки. По журналу найден отказ модема при разрешении ::1; в следующем private NET namespace восстановлены адреса loopback из прежнего проверенного стенда и добавлена проверка AI_ADDRCONFIG. Исправленная ячейка завершилась, не изменив config/userdata исходного AVD. Архивы и результаты проверены; все три собственных root/unit удалены, состояние хоста сохранено. Производственный allowBypass не включался. Это результат данного образа, не квалификация остальных Android/OEM или всей release-матрицы.

[Evidence](../../../../release/certification/evidence/q29-bypass-lockdown-20261014.json). Raw: `audit-debt-20260924/q29-bypass-lockdown-20261014`, `q29-bypass-lockdown-r2-20261014`, `q29-bypass-lockdown-r3-20261014`. NO_PUSH_DEPLOY_RELEASE.

## 15 октября: сохранена обычная защита с системным kill switch

Пользователь отклонил отдельный режим совместимости с разрешением обхода VPN. Производственный Android-клиент сохраняет обычный secure VpnService без allowBypass. INI/URI, значения по умолчанию, интерфейс настроек и native-библиотеки не меняются. При kill_switch=true для полного туннеля по-прежнему требуются Android Always-on VPN и «Блокировать подключения без VPN»; приложение проверяет политику, но само её не переключает.

Разрешение обхода VPN больше не является обязательством аудита; повторные сборки или runtime этого отменённого режима не нужны. Это решение не исправляет наблюдавшийся generic/null DnsResolver ENONET и не превращает его в PASS: отказ до отправки DNS сохранён как ограниченное наблюдение данного API34 image. Typed A/AAAA, явная VPN-сеть, обычные DNS-сценарии и блокировка обхода имеют отдельные положительные доказательства выше.

Последние строки о выборе режима заменяют прежнее ожидание ответа пользователя. Платформенная DNS-особенность остаётся явно описанной; Q29 не закрывается автоматически. Новых Android/DNS runtime-прогонов здесь нет. Полный аудит:34/37 (91,9%); NO_PUSH_DEPLOY_RELEASE.


## 15 октября: итог безопасных кандидатов и практическая граница

На проверенном Android14/API34 ошибка затрагивает generic overload
`DnsResolver.query(network=null, …)` в отдельном вызывающем приложении.
Она возникает до DNS-пакета: выбранная Android сеть отличается от active VPN,
а привязка обеих family-check socket к выбранной сети получает EPERM.
Минимальный независимый VpnService с локальным DNS воспроизводит отказ без
кода Qeli. Это не утверждение об остальных версиях Android или OEM.

На том же стенде обычный DNS, typed/null A/AAAA и generic с явной VPN-сетью
имеют положительные evidence. В 33 текущих production Java/Kotlin-файлах
Qeli нет вызовов DnsResolver и allowBypass; имя VPN-сервера уже разрешается
через явно выбранный carrier. Приложение Qeli не может этим же process-local
API изменить вызов DNS в чужом процессе.

Сведены прежние проверки allowFamily/адресов/маршрутов, DNS-адреса, underlying
networks, HTTP proxy, process/native resolver binding, physical default,
foreign-UID protect/permissions и перехвата DNS в TUN. Нового исполнимого
кандидата, сохраняющего secure VPN и системный kill switch, не выявлено.
Это ограниченный source/API/runtime review, а не доказательство невозможности
любого будущего решения. Отменённый пользователем bypass не возвращается.

Разработчик затронутого приложения на API29+ может передать предназначенную
для запроса VPN-сеть явно в DnsResolver.query либо использовать typed A/AAAA
overloads: эти варианты проверены данным отправителем. Это изменение
вызывающего приложения; переключателя INI, исправляющего его вызов внутри
Qeli, не найдено. Контракт параметра network и overloads описан в
[официальном DnsResolver API](https://developer.android.com/reference/android/net/DnsResolver).
Для пользователя порядок действий приведён в
[диагностике ENONET](../../manuals/TROUBLESHOOTING.md#android-enonet-в-одном-приложении).

[Сводное evidence](../../../../release/certification/evidence/q29-dns-final-review-20261015.json)
закрепляет восемь прежних review/runtime receipts и текущий source snapshot.
Подготовлен локальный черновик отчёта Android с минимальной схемой
воспроизведения и ссылками на сохранённые исходники контроля; он не отправлен.
Новых сборок, runtime-прогонов и платформенных изменений нет.

Пользователь явно выбрал «Принять ограничение и закрыть Q29». Раздел Q29
завершён в согласованном объёме с этим документированным ограничением
API34-стенда. ENONET не исправлен и не переименован в PASS; исходные
результаты, безопасная политика VPN и пределы покрытия сохранены.
Полный аудит: 37/37 (100%) в согласованном объёме. Новых прогонов нет.

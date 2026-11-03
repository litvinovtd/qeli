# Q29: переключение carrier networks Android

<!-- normative-sync: q29-android-handover-v1 -->

**5 октября 2026. UDP/QUIC-маскировка × Wi-Fi→Cellular/Cellular→Wi-Fi: 4/4 целевых перехода PASS. Q29 IN_PROGRESS; план28/37(75,7%).**

## Стенд и метод

Три последовательных readonly AVD Android14/API34 x86_64 на .11 в частных NET/MNT/PID namespaces. Первые UDP/QUIC прогоны используют исходный строгий helper; повторён только UDP после исправления критерия обвязки. Product/test APK, JNI, Linux CLI и все296 ранее проверенных source inputs идентичны. Новая сборка не нужна. Сервер INI включает heartbeat/experimental roaming; сохранённый профиль: full tunnel, UDP/fake-tls, roaming=required, IPv6 required, reconnect=true, DNS off; второй режим включает QUIC-маскировку.

После dual-stack TCP/UDP bootstrap instrumentation завершается. Профиль запускает настоящая системная политика Always-on+lockdown. Затем svc wifi disable/enable вызывает реальную смену Android carrier, без вызова методов/подделки NetworkCallback приложения. Независимый UID10148 отправляет обычные UDP-пакеты к off-pool ответчику; UID10149 принадлежит Qeli. bind/protect/root для payload не используются.

Системный dumpsys connectivity фиксирует активный default network и Current Networks: netid,handle,transport,interface. Исторические event-логи не используются как текущие факты. Структура сверена с [AOSP ConnectivityService](https://android.googlesource.com/platform/frameworks/base/+/8230b03102fd3de01986fed7f1a7e660e366d859/services/core/java/com/android/server/ConnectivityService.java); это reference, не утверждение о точном framework commit образа. В исходниках Qeli новые Networks обрабатывает реальный best-matching NOT_VPN callback; проверяются его commit token и восстановленный трафик.

## Квалифицированные результаты

| Транспорт | Wi-Fi→Cellular | Cellular→Wi-Fi | Полный успешный прогон |
| --- | --- | --- | --- |
| UDP, повтор с исправленным gate | 2,45s;net100→101;commit0→1 | 4,40s;net101→104;commit1→3 | 151,04s |
| UDP+QUIC-маскировка, исходный строгий gate | 2,24s;net100→101;commit0→1 | 4,18s;net101→104;commit1→2 | 148,92s |

В каждом случае новый handle отличается от старого, а committed android token совпадает с новым default carrier. Wi-Fi — wlan0/10.0.2.16, Cellular — eth0/10.0.2.15 в данной AVD. Server PATH_COMMIT подтверждает смену внешних source ports и возрастающие epochs: UDP1/2/3, QUIC1/2. Дополнительной Auth нет: сервер фиксирует только bootstrap и системный запуск; Auth/NetworkPlan2/2 остаются неизменными. Процесс,tun0,ifindex19 и все адреса TUN сохранены.

Два успешных bootstrap проверяют IPv4/IPv6 TCP16KiB и UDP257; после каждого перехода приходит отдельный IPv4 UDP-ответ через TUN. В успешных прогонах16 sink receipts:8 на каждый транспорт (4bootstrap,1physical baseline,1connected,2post-switch). Pcap показывает source10.87.0.2 и передачу tagged packets после server PATH_COMMIT по общим host-часам. Часы AVD напрямую с host не сравниваются.

Actual Settings revoke PASS; service/TUN отсутствуют,desired=false,consent ignore. Wi-Fi/mobile-data settings восстановлены; serverexit0, namespace-адреса восстановлены, host/service и userdata SHA/size/mtime неизменны во всех3 попытках. .10 не затронут. Raw evidence выгружается полным проверенным tar-bundle, включая pcap и UI XML.

## Исправление обвязки и сохранённый FAIL

Первый UDP gate завершился FAIL за128,95s на возврате Wi-Fi: Auth/plan2/2 и payload/TUN уже прошли,но commits изменились1→3 вместо ожидаемых1→2. Лог показывает Network changed и затем Network link properties changed; два commit относятся к одному новому Wi-Fi handle. Реальные изменения адресов/routes/DNS могут потребовать ещё один path update, поэтому требование «ровно один commit» не соответствует проверяемому контракту.

Helper теперь требует минимум один новый commit, **все новые commit должны относиться к подтверждённому целевому handle**; проверки отсутствия новой Auth/plan, неизменного TUN и ответа приложения сохранены. Уточнён delimiter интерфейса в парсере. Повторный UDP опять дал два Wi-Fi commit и прошёл новые условия. QUIC уже прошёл более строгий исходный счётчик; его token/snapshot/pcap отдельно повторно сверены, runtime не повторён. Сохранены оба исполнявшихся варианта helper и источник изменения; этот QUIC результат не выдаётся за исполнение новой версии helper. В неудачной попытке также bootstrap PASS и8receipts,но общий gate остаётся FAIL и не добавляется к4/4. Системный revoke в этой попытке не достигнут; подтверждена только завершающая очистка namespace/AVD.

Добавлены scripts/audit_android_network_handover.py и --suite handover в scripts/audit_android_data_plane_lab.py. Продуктовый Kotlin/JNI/ядро не менялись. Все296 source inputs,14native,7managed и2APKs идентичны предыдущему этапу;10aux inputs проверены. Старые167JVM/28Android/1248.NET,ReleaseR8lint и3+6+7integration остаются историческими областями, не свежим общим набором. Docs/panel/bindings/Python checks выполнены отдельно.

Raw:audit-debt-20260924/q29-android-handover-20261005:runtime-udp(FAIL),runtime-quic(PASS),runtime-r2-udp(PASS),executed sources обоих вариантов,source-proof/source-review,capture-analysis,raw-seal. Evidence:release/certification/evidence/q29-android-handover-20261005.json.

## Остаток и пределы

Это настоящие системные Network в AVD, но оба используют один private offline host backend; физический Wi-Fi/LTE/Интернет не проверен. Post-switch payload охватывает IPv4 UDP; IPv6/TCP после перехода, TCP outer transport, длительная потеря/flapping, IPv6-only/NAT64 и Release runtime остаются. Первые пакеты внутри самого перехода и полная leak-матрица не квалифицированы. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) остаётся открытым; [same-network UDP/grace](AUDIT-Q29-ANDROID-UDP-RECOVERY.md) и [power/TCP](AUDIT-Q29-ANDROID-POWER.md) сохраняют отдельные scopes. Дальше Q29: TCP handover и оставшиеся доступные платформенные проверки. USER_SKIPPED устройства/D06 без BPF не изменены.

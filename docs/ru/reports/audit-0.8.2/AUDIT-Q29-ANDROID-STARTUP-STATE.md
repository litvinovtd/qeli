# Q29: публикация VPN при холодном запуске

<!-- normative-sync: q29-android-startup-state-v1 -->

5 октября 2026. Q29 IN_PROGRESS; план 28/37 (75,7%). Один успешный readonly API34 x86_64 Release/TCP run на .11 в private NET/MNT/PID, одна сохранённая UI FAIL попытка; .10 не использовался.

Независимый обычный UID10148, Qeli UID10149. Реальный UI-импорт INI, Always-on/lockdown и DNS через VPN. Product Release APK/JNI/managed прежние; один Java test receiver изменён и собран matched R8 test APK. Нет изменения Kotlin/core, ослабления lockdown или привязки/protect тестовых traffic sockets.

336 socket samples: 96 cold-start и по 48 в остальных пяти фазах. Непосредственно перед каждой cold-пробой записаны ConnectivityManager active Network, VPN transport, interface, наличие IPv4/IPv6 и два времени чтения. Также зарегистрирован default NetworkCallback до клика TURN ON. Это наблюдение публикации, не атомарный снимок правил ядра. Измерен APPLIED из device log; точное получение CONNECTED Activity не измерялось. В прежнем QeliService APPLIED непосредственно предшествует announceConnected после TUN fd/ACK.

| Первый sample после APPLIED | Задержка, ms | Payload success | Network/VPN/interface | Detail |
| --- | --- | --- | --- | --- |
| ipv4/tcp | 9.0 | False | null/False/null | error=ConnectException:failed to connect to /198.19.0.1 (port 26000) from /:: (port 0) after 250ms: connect failed: EACCES (Permission denied) |
| ipv4/udp | 16.0 | False | null/False/null | error=SocketException:Pending connect failure |
| ipv6/tcp | 19.0 | False | null/False/null | error=ConnectException:failed to connect to /2001:db8:29::1 (port 26000) from /:: (port 0) after 250ms: connect failed: EACCES (Permission denied) |
| ipv6/udp | 7.0 | False | null/False/null | error=SocketException:Pending connect failure |

Локализация: первые четыре сокета отказали через 7–19 ms после APPLIED, active Network тогда null. Четыре отказа через 311–321 ms имеют уже VPN/tun0/dual snapshot, но предшествуют VPN AVAILABLE callback. Callback через 419 ms, 44/44 последующих samples успешны; первый успешный sample через 481 ms. Простая проверка getActiveNetwork/LinkProperties не является барьером готовности. Это измерение одного image/run, не универсальная гарантия callback или точного CONNECTED времени. Product фикс задержки публикации статуса пока не внесён: нужна проверка observer в UID владельца, включая per-app и повторное использование TUN.

Всего после APPLIED 56 samples; из них 48 со снимком active VPN/tun0/IPv4/IPv6, 4 ошибок payload в этой группе. Immediate статус: `FAIL_POST_PLAN_BLOCKING`. Если стартовое окно не покрыто, NOT_SAMPLED не становится PASS. Успешные последующие пробы не переписывают исторический FAIL.

События callback в device-clock времени:

- `BURST_NETWORK run=2 uid=10148 event=AVAILABLE network=100 device_ms=1791219354498`
- `BURST_NETWORK run=2 uid=10148 event=CAPABILITIES_vpn_false network=100 device_ms=1791219354498`
- `BURST_NETWORK run=2 uid=10148 event=LINKS_wlan0 network=100 device_ms=1791219354498`
- `BURST_NETWORK run=2 uid=10148 event=AVAILABLE network=102 device_ms=1791219357266`
- `BURST_NETWORK run=2 uid=10148 event=CAPABILITIES_vpn_true network=102 device_ms=1791219357267`
- `BURST_NETWORK run=2 uid=10148 event=LINKS_tun0 network=102 device_ms=1791219357267`
- `BURST_NETWORK run=2 uid=10148 event=CAPABILITIES_vpn_true network=102 device_ms=1791219357587`

Каждый nonce/request/reply SHA проверен по receiver, sink и непрерывному private-host pcap; TCP собран из сегментов. Доставленные fresh post-plan маркированные запросы только через TUN; до lockdown physical baseline/cold-пакеты сохраняются как фактическая калибровка, не как утечка. Новых физических SYN/data/UDP в защищённом steady/stop окне нет. 48 post-stop проб и две DNS operations без ответа/receipt/capture; 7 DNS operations/7 отвеченных questions, 4 manual recovery payloads, Settings revoke/cleanup PASS. Echo receipts: 224, elapsed 213.91s.

Cold-only диагностическая серия имеет 24 samples на поток и background broadcast: максимум socket deadlines + паузы15,6s. Остальные серии прежние 12 samples/foreground deadline. Сокетные deadlines и алгоритм payload одинаковы; сбор metadata добавляет небольшую задержку и может влиять на race. Порядок callback сохраняется; внутри callback не вызываются синхронные методы ConnectivityManager.

Первая попытка остановилась до сети: uiautomator сообщил успешную запись /sdcard XML, но cat трижды получил No such file. Снимки перенесены в shell /data/local/tmp; точная причина отсутствия /sdcard файла не установлена. APK-пара не менялась. Failed bundle/executed helpers и cleanup сохранены; оба host/service/userdata/namespace restoration unchanged,serverexit0. Два helper contract tests и четыре CLI guards PASS; docs/config bindings проверены.

Исторические ENONET auto/null, matching runner Trace FAIL и SIGKILL recovery FAIL сохранены. Split/per-app/Private DNS,long power/flapping,other API/OEM/arm64 остаются; USER_SKIPPED/D06 не меняются.

Raw: `audit-debt-20260924/q29-android-startup-state-20261005`; evidence: `release/certification/evidence/q29-android-startup-state-20261005.json`.

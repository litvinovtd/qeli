# Q29: IPv4/IPv6 TCP/UDP после переключения Android сети

<!-- normative-sync: q29-android-handover-payload-v1 -->

**5 октября 2026. Три outer транспорта × два перехода Wi-Fi/Cellular × четыре payload-пробы: 24/24 PASS. 6carrier transitions,3bootstrap PASS,42sink receipts. Q29 IN_PROGRESS; план28/37(75,7%).**

Три последовательных readonly Android14/API34 x86_64 AVD на .11 в частных NET/MNT/PID namespaces. Настоящая OS-политика Always-on+lockdown запускает сохранённый INI-профиль после instrumentation. svc wifi disable/enable меняет actual Current Networks между WIFI(wlan0) и CELLULAR(eth0); новые netid/handle подтверждены. .10 не затронут.

После каждого перехода независимый UID10148, отличный от Qeli10149, открывает обычные Java sockets к off-pool sink: IPv4/IPv6 × TCP16KiB/UDP257. Нет bind/protect/root, JNI или зависимости от target APK. TCP ответ — полный reversed payload, UDP — Q29:prefix+payload; receiver сравнивает каждый байт и SHA256 запроса/ответа, обвязка сверяет sink receipts и адрес источника TUN. Результат не основан только на статусе CONNECTED.

| Outer транспорт | Wi-Fi→Cellular | Cellular→Wi-Fi | Payload | Полный прогон |
| --- | --- | --- | --- | --- |
| tcp | 5.79s | 10.38s | 8/8PASS | 163.02s |
| udp | 4.91s | 24.51s | 8/8PASS | 165.02s |
| quic | 5.05s | 27.45s | 8/8PASS | 174.97s |

Время gate включает ADB и четыре пробы; это не чистая длительность простоя. Везде PID,tun0,ifindex19 и все адреса сохранены. TCP: Auth/NetworkPlan2/2→3/3→4/4,новые внешние порты,Android TUN reused,0UDPcommits. UDP/QUIC:Auth/plan2/2 неизменны,PATH_COMMIT с новыми внешними портами/epochs; все новые Android commit token относятся к подтверждённому целевому carrier.

Pcap подтверждает8post-switch requests на транспорт с IPv4/IPv6 TUN source после соответствующего server AUTH/PATH_COMMIT на общих host-часах. TCP requests полностью собраны по sequence с проверкой совпадения overlap/retransmission bytes; SHA всех16KiB сверяется с receiver/sink. Первоначальный offline parser ошибочно ожидал frame length и payload в одном IP-пакете; этот отказ и исправление сохранены отдельно, runtime не повторялся. В каждом run14receipts:4dual-stack bootstrap,1physical baseline,1connected,8post-switch. Всего42receipts,из них24новые целевые payload.

Settings revoke и очистка PASS во всех3runs:desired=false,consent ignore,нет service/TUN. Wi-Fi/mobile-data settings восстановлены,host/service иuserdata SHA/size/mtime неизменны,serverexit0,namespace-адреса восстановлены. Product APK/JNI/LinuxCLI/managed неизменны;295из296source inputs совпадают,изменён только test receiver. TestAPK пересобран offline;10aux inputs закреплены. Изменения обвязки не означают повторное исполнение старых suites на новом testAPK.

Fresh build/Python/CLI,docs9checks,panel и generated bindings PASS. Raw:audit-debt-20260924/q29-android-handover-payload-20261005; evidence:release/certification/evidence/q29-android-handover-payload-20261005.json. Предыдущие JVM/Android/.NET/Release/integration результаты остаются историческими областями,не свежим полным набором.

## Пределы и остаток

Закрыт доступный AVD post-switch IPv4/IPv6 TCP/UDP payload для TCP/UDP/QUIC outer. Каждый TCP probe открывает новое соединение; сохранение уже открытого длинного потока не проверено. Системные AVD carriers используют общий private offline backend;physical Wi-Fi/LTE/Internet не проверены. IPv6 inner не означает IPv6-only outer/NAT64. Первые пакеты внутри перехода,полная leak-матрица,IPv6-only/NAT64,Release runtime и длительный/физический Doze/flapping остаются. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) открыт. Предыдущие [UDP/QUIC](AUDIT-Q29-ANDROID-HANDOVER.md) и [TCP](AUDIT-Q29-ANDROID-TCP-HANDOVER.md) scopes сохранены;USER_SKIPPED/D06 без BPF не изменены,Q29IN_PROGRESS.

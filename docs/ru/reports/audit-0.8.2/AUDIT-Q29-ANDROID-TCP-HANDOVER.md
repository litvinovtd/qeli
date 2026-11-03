# Q29: TCP при переключении Android Wi-Fi/Cellular

<!-- normative-sync: q29-android-tcp-handover-v1 -->

**5 октября 2026. TCP × Wi-Fi→Cellular/Cellular→Wi-Fi: 2/2 PASS; bootstrap PASS; 8 sink receipts. Q29 IN_PROGRESS, план 28/37 (75,7%).**

Использован один readonly Android14/API34 x86_64 AVD на .11 в частных NET/MNT/PID namespaces. Product/test APK, JNI, Linux CLI, все296 source inputs идентичны предыдущему этапу. Изменена только обвязка: --suite handover поддерживает --transport tcp, bootstrap выбирает roaming=off, проверяет TCP full reconnect вместо UDP soft path commit. Recovery suite отвергает TCP до изменения namespace.

Настоящая OS-политика Always-on+lockdown запускает сохранённый INI-профиль после завершения instrumentation. svc wifi disable/enable переключает actual default Current Networks между WIFI(wlan0) и CELLULAR(eth0); новые netid/handle подтверждены dumpsys. Независимый UID10148, отличный от Qeli10149, посылает ordinary IPv4 UDP к off-pool sink: без bind/protect/root.

| Переход | Время gate | netid | Auth / NetworkPlan |
| --- | --- | --- | --- |
| WIFI→CELLULAR | 3.29s | 101→102 | 2/2→3/3 |
| CELLULAR→WIFI | 4.35s | 102→105 | 3/3→4/4 |

TCP правильно выполняет повторную Auth и применяет свежий NetworkPlan. В обоих переходах PID, TUN, ifindex и все адреса сохранены; лог подтверждает Android TUN reused. Roaming commits=0: не используется UDP path migration. Server AUTH/новые внешние source ports сверены с pcap; каждая post-switch probe проходит через source10.86.0.2 после соответствующей новой Auth на общих host-часах. Gate time включает ADB/проверки и не является чистым временем простоя.

8receipts:4dual-stack bootstrap (IPv4/IPv6 TCP16KiB и UDP257),1physical baseline,1connected,2post-switch IPv4UDP. Settings revoke PASS: desired=false, consent ignore, нет service/TUN. Wi-Fi/mobile-data settings восстановлены; host/service, userdata SHA/size/mtime неизменны, serverexit0, namespace-адреса восстановлены. .10 не затронут. Полный прогон 153.03s.

Python/CLI, docs (9checks), panel и generated bindings checks PASS. 296source inputs,14native,7managed,2APK повторно сверены;10aux inputs закреплены. Предыдущие JVM/Android/.NET/Release/integration результаты исторические и не объявляются свежим полным набором. Raw: audit-debt-20260924/q29-android-tcp-handover-20261005; evidence: release/certification/evidence/q29-android-tcp-handover-20261005.json.

## Пределы и остаток

Реальные системные Networks в AVD используют один private offline backend; физический Wi-Fi/LTE/Интернет не проверены. Post-switch payload только IPv4UDP: IPv6/TCP после перехода, первые пакеты внутри самого переключения, полная leak-матрица, IPv6-only/NAT64, Release runtime и длительный/физический Doze/flapping остаются. [UDP/QUIC handover](AUDIT-Q29-ANDROID-HANDOVER.md) имеет отдельный scope. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) открыт; Q29 IN_PROGRESS. USER_SKIPPED устройства/D06 без BPF не изменены.

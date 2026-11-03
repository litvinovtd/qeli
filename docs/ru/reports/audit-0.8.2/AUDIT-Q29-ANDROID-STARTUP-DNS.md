# Q29: системный DNS и холодное включение Android Release

<!-- normative-sync: q29-android-startup-dns-v1 -->

**5 октября 2026. Частичный пакет проверок DNS/блокировки; немедленная доставка после NetworkPlan рассматривается отдельно. Q29 IN_PROGRESS, план 28/37 (75,7%).**

## Метод

Release/R8, настоящий INI-import через file picker, Always-on/lockdown через Settings; readonly API 34 x86_64 AVD на .11 в отдельных NET/MNT/PID namespaces. Product APK/JNI/Linux CLI и семь managed-артефактов побайтно прежние; из 296 source inputs изменён только Java receiver тестового APK. Production rules не менялись. Initial test build 24 s, пересборка с обычным resolver 15 s, журналом 15 s. Подпись прежним лабораторным сертификатом; публикация не выполнялась. Instrumentation runner не запускался.

Профиль задаёт `dns = tunnel`, `dns_servers = 198.19.0.53`, full dual-stack и kill-switch. Это конфигурация DNS через VPN; прежний `dns = off` намеренно сохраняет настройки системного резолвера и не проверяет этот режим. Receiver UID 10148 отличается от Qeli UID 10149; нет bind/protect/root/JNI или private preferences injection.

Обычный системный lookup выполняется `InetAddress.getAllByName` для нового `q29-<nonce>.test`. Каждое имя уникально, ответы тестовой authority имеют TTL 0; cache hit не подменяет wire evidence. A/AAAA сравниваются с адресами fixture. Отдельный UDP DNS-запрос к той же authority проверяет явный DNS-сокет и калибрует физический выход до lockdown. Receiver ждёт lookup не более 7 s, но blocking native resolver сам по себе этим не отменяется; это предел обвязки, а не гарантия завершения Android resolver.

До подтверждения TURN ON уже идут четыре потока свежих IPv4/IPv6 TCP/UDP сокетов. Время APPLIED и начала каждого sample записывается по часам Android. До включения OS lockdown физическая доставка разрешена и не объявляется утечкой. После APPLIED проверяется источник каждого доставленного маркированного запроса; сразу после первой серии идёт ещё одна серия без source preflight или ожидания UI. Capture `any` внутри приватного namespace охватывает порты 53/26000, разбираются полные TCP frames, UDP/DNS questions/answers и SHA.

## Наблюдения, которые остаются неуспешными

Первый strict startup run FAIL: свежие сокеты через 67–78 ms после APPLIED получили EACCES/pending-connect, вместо немедленной доставки. Capture и логи сохранены. Установка TUN/передача fd/ACK происходят до публикации CONNECTED в QeliService, но это не доказывает синхронную готовность Android UID routing. Точная причина задержки и требуемый контракт CONNECTED пока не подтверждены; продуктовый fix не заявлен. Успешная следующая серия не превращает первую проверку в PASS.

Второй run FAIL на коротком physical DNS reply timeout. Authority получила вопрос и ответила, хотя Android не дождался ответа за 1,5 s. Outbound calibration квалифицируется по настоящему запросу в sink/pcap; timeout ответа остаётся timeout, не успешная блокировка и не клиентский DNS PASS.

Третий run FAIL: automatic-family overload `DnsResolver.query(null, ...)` вернул ENONET до отправки fixture-вопроса. [API Android](https://developer.android.com/reference/android/net/DnsResolver) выбирает семьи по доступности сети; просмотренный Android 14 source предварительно выполняет `haveIpv4`/`haveIpv6` с network-bound сокетами. Полная причина ENONET не установлена. Этот API-отказ сохранён отдельно; результат обычного `getAllByName` не закрывает его.

Четвёртый QUIC run FAIL на неполном logcat: отсутствовала одна из 48 записей (поздний dump также содержал 47). Добавлен append-журнал в приватных данных только тестового APK; root используется для чтения доказательств, сетевые сокеты по-прежнему принадлежат обычному UID. Повторяется только QUIC; успешные TCP/UDP сохраняют прежнюю пару APK и исходники. Отказ не переименован в PASS.

Пятый QUIC run FAIL до сетевых проб: uiautomator сообщил об успешном dump, но shell-read трижды не нашёл XML на /sdcard. Это отсутствие требуемого UI evidence, а не сетевой FAIL. Диагностика/cleanup сохранены; выполнен ещё один ограниченный повтор без изменения продукта или условий.

## Результаты

| Транспорт | Socket samples | Первые свежие сокеты после APPLIED | Следующая серия | Ответившие DNS questions | После force-stop | Всего echo receipts |
| --- | --- | --- | --- | --- | --- | --- |
| TCP | 288 | FAIL: 28–247 ms | 48/48 | 7 | 0/48 | 166 |
| UDP | 288 | FAIL: 27–36 ms | 48/48 | 7 | 0/48 | 170 |
| QUIC | 288 | FAIL: 85–146 ms | 48/48 | 7 | 0/48 | 202 |

Все три ordinary system lookups после подключения и три после ручного восстановления вернули точные A/AAAA. Raw DNS также проходит через TUN. Шесть уникальных DNS operations без VPN не дали вопроса/ответа/authority receipt ни в одном capture; 144 свежих socket samples при сохранённом OS lockdown без PID/TUN заблокированы. После ручного re-enable прошли 12 полных IPv4/IPv6 TCP 16 KiB/UDP 257 payload probes с SHA и TUN source. Всего 538 echo receipts включают calibration и обычные контрольные пробы, а не только burst success.

Первый следующий TCP burst начался через 1 919 ms после APPLIED. Это включает задержки чтения evidence и dispatch; не утверждается, что Android был недоступен все эти 1 919 ms. Точные времена всех samples находятся в raw. В QUIC часть поздних cold samples уже получила ответ; первые свежие сокеты после marker всё равно дали отказ. Ни availability FAIL, ни сохранённый generic DnsResolver ENONET не закрываются последующими PASS.

Физические socket baselines получили только 8/48 replies на транспорт, но capture/sink приняли 46/48/44 полных исходящих запросов; все четыре вида исходящего пути откалиброваны. В cold phase физические requests до OS policy сохранены. После APPLIED все доставленные свежие marked requests имеют TUN source; отрицательные samples не отправили payload. В steady/force-stop/blocked окне нет новых физических SYN/data/UDP; pcap parser отделяет поздний pre-VPN calibration flow. DNS question/answer bytes, RDATA/TTL 0, peer, nonce и raw reply SHA сверены независимо; zero kernel capture drops. Это ограниченные окна, не полный leak PASS.

Revoke/desired=false/consent ignore/no service/TUN, server exit 0, namespace addresses restored, host/service и persistent userdata SHA/size/mtime сохранены во всех восьми попытках. .10 не затронут. Python parse/4 CLI guards, docs 9 checks, panel, generated bindings и сертификат PASS. Product JVM/.NET/native suites при неизменных inputs повторно не запускались. TCP/UDP квалифицированы с pre-journal test APK, QUIC — с новым test APK/journal; оба target Release APK идентичны. Корректность журнала подтверждена полным QUIC runtime; старый missing-log run остаётся FAIL.


## Предел и остаток

Проверяются конкретные имена/порты и ограниченные серии, а не произвольный трафик или все миллисекунды старта. Сам APPLIED marker не является точным временем получения CONNECTED другим приложением. Cold-start availability и generic DnsResolver failure остаются отдельными наблюдениями; DNS split/per-app, Private DNS/DoT, альтернативный IPv6 resolver, длинный power/flapping, другие API/OEM/arm64 и оставшийся lifecycle ещё не квалифицированы. SIGKILL redelivery FAIL и прежний matching instrumentation Trace FAIL не повторялись и не закрыты. USER_SKIPPED и D06 без BPF неизменны.

Raw: `audit-debt-20260924/q29-android-startup-dns-20261005`; evidence: `release/certification/evidence/q29-android-startup-dns-20261005.json`. Неуспешные прогоны, их версии обвязки/APK и cleanup остаются в sealed raw. Общий план 28/37; Q29 открыт.

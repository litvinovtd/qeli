# Q29: доверенный Private DNS / DoT

<!-- normative-sync: q29-android-trusted-dot-v1 -->

На API34 x86_64 production Release R8 в изолированной лабе .11 прошли четыре
strict Private DNS сценария для TCP, UDP и QUIC. Доверие и имя проверяет системный
resolver Android; клиент и его TLS-настройки не изменены. Q29 IN_PROGRESS,
общий план 28/37 (75,7%); этот результат закрывает ограниченный DoT-блок.

| Transport | Seconds | DNS operations | A/AAAA/raw answers | Burst samples | Result |
|---|---:|---:|---:|---:|---|
| TCP | 245.27 | 13 | 13 | 192 | PASS |
| UDP | 241.21 | 13 | 13 | 192 | PASS |
| QUIC | 234.18 | 13 | 13 | 192 | PASS |

## Что подтверждено

- Недоверенный тестовый CA: TLS отказ, системный lookup завершается ошибкой.
- CA временно добавлен только в readonly AVD: уникальное имя приложения возвращает
  A/AAAA через строгий DoT, TLS receipt содержит правильный SNI и адрес TUN.
- Доверенный CA с неверным SAN: TLS отказ; системный lookup не переключается на
  открытый DNS. Отдельная raw UDP-проба успешна и показывает, что путь доступен.
- Правильный provider возвращён: повторный uncached lookup через DoT успешен.

39 DNS-операций, 39 A/AAAA/raw ответов; из них 12 аутентифицированных A/AAAA ответов
в trusted/recovered. Имена уникальны; plaintext capture, TLS receipts и app journal
сопоставлены. Bootstrap имени provider учитывается отдельно от пользовательских
nonce-запросов. Неверные CA/SAN не дают пользовательских DNS receipts/fallback.

36 полных IPv4/IPv6 TCP/UDP payload-проб (12 bootstrap, 12 при DoT, 12 manual recovery)
с SHA, 576 burst samples; 144 post-stop заблокированы. Три независимых PCAP: нет новых
физических запросов в проверенном защищённом окне, kernel drops 0. Не заявляется
универсальная немедленная доставка первого пакета после смены состояния.

## Исправления обвязки и сохранённые неуспехи

`StartupDns.diagnose` больше не требует UID 10148: используется UID пакета из
Package Manager. Тест с UID 10149 падал на прежнем коде, теперь проходит;
посторонний UID по-прежнему отвергается. UDP и DoT используют общий builder ответов.
Свежие 12 helper tests и три CLI guard checks PASS; 172 JVM/lint проверки
переиспользованы по неизменным продуктовым inputs, без лишней пересборки.

Две начальные попытки FAIL сохранены и исключены из PASS-счётчиков. В первой после
установки CA для прежнего имени provider новая строгая TLS-проверка не наблюдалась.
Положительный сценарий теперь использует отдельное имя из SAN; предполагаемый cache
root cause отдельно не доказан. Во второй необязательный `nsenter` ошибочно
интерпретировался как отсутствие CA directories. Shell/netd имеют общее mount
namespace; root-команды выполняются напрямую, прочие ошибки не скрываются.

## Воспроизводимость и границы

`--suite private-dns --variant release --leak-bursts --transport tcp|udp|quic`
требует `apps_mode=all`, закреплённые fixed APK/manifest, OpenSSL, root и выделенный
`/var/tmp/qeli-q29-data-*`. Создаются частные NET/MNT/PID namespaces и readonly AVD.
Сертификаты короткоживущие, private keys не включены в evidence. Исходные CA hashes,
mounts, Private DNS settings, host/service/firewall/routes и persistent userdata
восстановлены после всех пяти попыток; .10 не затронут.

Та же production R8-пара и matching mapping из CONNECTED gate, приложение
non-debuggable, лабораторная подпись. Product APK SHA
`786e8954762b63a4c2cf8ad873376aeecd594bb5c98999df03d3f58710a8eaf2`.
299 source inputs (только README изменён), 22 auxiliary inputs (два изменены,
три добавлены), 14 native / 7 managed artifacts неизменны; один прежний regression
input изменён для динамического UID. Не использован opt-in instrumented ABI APK.

Raw: `audit-debt-20260924/q29-android-trusted-dot-20261005`.
Evidence: `release/certification/evidence/q29-android-trusted-dot-20261005.json`.

[Прежний SIGKILL FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) и
[auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) остаются
открыты. Другие API/OEM/arm64, физический sleep и многочасовой soak этим прогоном
не квалифицированы. Mac/iOS/router/Windows VM USER_SKIPPED; D06 без BPF сохранён.

# Q29 F282–F283: владелец защиты сокета и отказы доверенного Wi-Fi

<!-- normative-sync: q29-android-controller-v2 -->

F282 запрещает уже взятому из JNI-очереди запросу защиты сокета выбирать или привязывать
carrier после начала остановки либо замены core. Каждая попытка protect теперь проверяет
stopping, identity core и active config под монитором службы, до платформенных действий.
Задержки повторов и JNI acknowledgement остаются вне монитора. Параметры INI,
Rust/JNI и managed код не изменены.

## Воспроизведение и проверки

Один свежий test APK запускается на предшествующем F281 debug продукте и исправленном.
Старый: восемь тестов, ровно три ожидаемых отказа. Исправленный: восемь PASS. Старый
код выбирал carrier после остановки, позволял старому core выбирать carrier текущего
подключения и блокировался только внутри выбора сети, а не на проверке владельца protect.

Три protect-сценария используют настоящие native socket requests и packaged JNI, а
объект службы подключён к Context с явно заданным lifecycle/core owner. Конкурентная
проверка удерживает его монитор и проверяет заблокированный production frame до снятия
блокировки. Это adapter fixtures, а не полная framework гонка stop/revoke или доказательство
утечки kernel FD. Сокет настоящий; transport не заменяется, protect event не подделан.

Пять остальных сценариев используют настоящую framework-службу, Activity, Wi-Fi/Cellular
callbacks и TCP transport. Два новых: отключение Android location visibility скрывает
наблюдаемый SSID и восстанавливает туннель, возвращение видимости снова разрешает паузу;
пауза с последующим queued disconnect не возрождает контроллер, новый explicit start работает.
Последнее проверяет очередь команд, а не детерминированный барьер внутри native teardown join.
Три прежних pause/resume/cancellation/kill-switch refusal сценария повторяются.
Permissions выдаются извне; SSID settings заданы adapter локально, без UI editor.
Четыре вида сокетов явно привязаны к VPN Network. Семь authenticated stages передают
28 полных IPv4/IPv6 TCP16KiB/UDP257 ответов с независимыми sink SHA и TUN sources.

Свежие 182 JVM, default production R8 Release/debug builds и lint PASS (0 ошибок,
55 прежних warnings). Новых JVM cases нет; пять новых сценариев исполнены на Android.
Private helper `--suite trusted-wifi --variant debug --transport tcp` выбирает восемь тестов.
Standalone production Release smoke использует настоящий INI file picker, Android Settings
lockdown и отдельный UID Java probe; matching Release instrumentation NOT RUN.
В evidence закреплены каждый runtime outcome и точные source/APK hashes.

## Итог объединённого прогона

| Запуск | Результат | Подтверждённая область |
| --- | --- | --- |
| Предыдущий debug продукт, свежие тесты | 5 PASS, 3 ожидаемых FAIL | Тот же APK с восемью тестами воспроизводит F282 |
| Исправленный debug продукт | 8/8 PASS | Три проверки владельца protect, пять framework-сценариев доверенного Wi-Fi; 28 полных ответов |
| Production R8 TCP | PASS | Два перехода сети, 12 полных ответов отдельному UID, 288 пробных запросов |
| Production R8 UDP | PASS | Два перехода сети, 12 полных ответов отдельному UID, 288 пробных запросов |
| Production R8 QUIC | PASS | Два перехода сети, 12 полных ответов отдельному UID, 288 пробных запросов |

Всего: шесть Release-переходов, 36 Release и 28 debug полных ответов (64), 864 Release
пробных запроса, включая 144 заблокированных после остановки. Независимая сборка pcap
проверяет SHA всех 36 помеченных Release payload и TUN sources. Все четыре вида исходящих
физических запросов положительно откалиброваны; новых физических запросов в проверяемых
окнах нет, kernel drops всех трёх захватов равны нулю. Это не обещание handover без потерь:
на переходе от Wi-Fi ответы TCP44/48, UDP40/48, QUIC44/48; при возврате48/48 у каждого.
Все пять runtime-попыток восстанавливают host/service, readonly AVD userdata и адреса
namespace, останавливают приватный сервер, не оставляют службу Qeli или TUN.

Происхождение закреплено для303 Android/build inputs (четыре изменены),23 auxiliary inputs
(один изменён),пяти неизменных regression inputs,14 неизменных native files,семи managed
artifacts и шести APK. Native/server/managed переиспользованы явно; упаковка arm64 JNI
проверена, исполнения arm64 не было. Пятнадцать helper tests и четыре CLI guards PASS.

## F283: владелец снятого сетевого callback

Callback сохранял доступ к выбору carrier и политике доверенного Wi-Fi после снятия или
замены наблюдателя, а также начала обычной остановки. Новый dispatcher проверяет identity
наблюдателя и stopping под монитором службы до каждого available, capabilities,
link-properties и lost handler. Регистрация/снятие используют тот же монитор, публикация
наблюдателя volatile. Намеренная trusted-пауза сохраняет наблюдателя: настоящая смена сети
по-прежнему может завершать паузу и возобновлять VPN.

Пять новых сценариев регистрируют настоящие Android observers на Context-attached adapter
службы, сохраняют старый callback и вызывают его напрямую с настоящими physical Network/
Capabilities/LinkProperties. Проверяются stopping, снятие, замена, capabilities вместе с
link-properties и lost. Это управление границей поздней доставки, а не доказательство
естественного такого расписания Android на всех устройствах. Старый F282 APK:13тестов,
ровно5ожидаемых FAIL,8прежних PASS; исправленный:13/13PASS с тем же свежим test APK.
Старый lost меняет Wi-Fi107 на carrier101, available/capabilities публикуют107 после снятия.
Объединённый старый capabilities/link сценарий падает на capabilities; link handler
исполнен в исправленном сценарии, отдельного воспроизведения старого link отказа нет.

Настоящая framework trusted-Wi-Fi suite повторена без изменений:пять сценариев,семь
аутентифицированных стадий и28полных explicit-VPN-Network ответов. Свежие182JVM и
обычные defaultR8/debug builds PASS;lint0ошибок55прежнихwarnings. В комментариях build/model
исправлены ссылки на удалённые Kotlin PacketCipher/PacketCodec/ObfsStreamTest и handshake
методы службы; реализация codec и криптографическое поведение не меняются.

Свежий обычный production R8 UDP Release PASS:два перехода Wi-Fi→Cellular→Wi-Fi,
12полных ответов отдельному UID IPv4/IPv6 TCP/UDP,288проб,включая48заблокированных после
остановки. Все12помеченных payload независимо собраны из TUN pcap и проверены по sink SHA;
четыре исходящих физических вида проб положительно откалиброваны, новых физических
запросов0/kernel drops0 в проверяемых окнах. При уходе ответы43/48, возврате48/48;
переход без потерь не обещан. PID/TUN сохранены, soft commits выбирают настоящий новый
carrier без нового Auth/NetworkPlan. Все три попытки сохраняют host/service/readonly
userdata и адреса namespace, останавливают приватный сервер и не оставляют службу/TUN.
Предыдущие F282 TCP/UDP/QUIC результаты сохраняют свою область; TCP/QUIC здесь заново не
исполнялись.

В этом пакете закреплены303 Android/build inputs (пять изменены),23 auxiliary inputs
(один изменён),пять неизменных regression inputs,14 неизменных native files,семь managed
artifacts и шесть APK. Standalone Java Release probe переиспользован без изменений.
Свежие15helper tests и4CLIguards PASS. Первые три module-style вызова helper не дошли до
сценариев: imports требуют scripts directory; прямые вызовы scripts PASS, отказные логи
сохранены. Matching Release instrumentation NOT RUN; arm64 не исполнялся.

Raw:`audit-debt-20260924/q29-android-observer-20261006`.
Evidence:`release/certification/evidence/q29-android-observer-20261006.json`.
Предыдущие F282 packet/evidence неизменны и не переименованы в новый запуск.

## Область результата и остаток

Raw: `audit-debt-20260924/q29-android-controller-20261006`.
Evidence: `release/certification/evidence/q29-android-controller-20261006.json`.
[Прежний SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) и
[auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) открыты.
Настоящий отзыв permissions, который может убить приложение, отличается от redaction
через location switch. Actual observer-registration failure, deterministic native
pause-in-flight, оставшиеся lifecycle пути и другие API/OEM/arm64 не закрыты этими тестами.
Q29 остаётся IN_PROGRESS, общий план28/37(75,7%). Ограниченные API34 x86_64 readonly AVD
запуски не подтверждают physical/OEM long sessions. User-skipped платформы и D06 сохранены.

# Аудит Qeli 0.8.2

Отчёты Q01–Q37 собраны по этапам плана аудита. Каждый отчёт сохраняет свои даты, результаты, ограничения и историю промежуточных статусов.

[План аудита](../../plans/FULL-SYSTEM-AUDIT.md) · [Учёт технического долга](../../plans/AUDIT-DEBT.md) · [Документация](../../index.md)

Текущий итог: 37/37 в согласованном объёме; это не означает PASS каждого исторического сценария или готовность релиза к публикации. ENONET API34 и D06 остаются принятыми ограничениями, физические исключения сохранены.

## Q01

- [Q01 — серверный INI: первый проход аудита](AUDIT-Q01-SERVER-INI.md)

## Q02

- [Q02 — клиентские парсеры: ссылки и граница импорта](AUDIT-Q02-CLIENT-PARSERS.md)

## Q03

- [Q03 — Панель: состояние и ошибки загрузки](AUDIT-Q03-PANEL-STATE.md)

## Q04

- [Q04: авторизация панели и границы API](AUDIT-Q04-WEB-AUTH.md)

## Q05

- [Q05/Q07 — бюджет backup/restore и полнота снимка](AUDIT-Q05-ARCHIVE-BUDGET.md)
- [Q05 — асинхронная проверка firewall tools в панели](AUDIT-Q05-HEALTH-PROBES.md)
- [Q05: конфигурационные транзакции, live reload и restart](AUDIT-Q05-HTTP-TRANSACTIONS.md)
- [Q05 — транзакции панели, preflight и отмена](AUDIT-Q05-PANEL-TRANSACTIONS.md)
- [Q05: сроки и лимиты чтения сетевого состояния preflight](AUDIT-Q05-PREFLIGHT.md)

## Q06

- [Q06: пользователи и отзыв доступа — завершение](AUDIT-Q06-USERS-ACCESS.md)

## Q07

- [Q07: backup, restore и history — пакеты 1–3](AUDIT-Q07-BACKUP-RESTORE.md)

## Q08

- [Q08: криптография, identity и ключи](AUDIT-Q08-CRYPTO-KEYS.md)

## Q09

- [Q09: итоговый аудит handshake/pre-auth и сохранение KICK](AUDIT-Q09-FINAL.md)
- [Q09: TCP-аутентификация и полный разбор ClientHello](AUDIT-Q09-TCP-PARSER.md)
- [Q09: владение UDP AUTH и PMTU до авторизации](AUDIT-Q09-UDP-AUTH.md)
- [Q09: UDP handshake, публикация admission и очистка](AUDIT-Q09-UDP-CONTRACTS.md)

## Q10

- [Q10: PacketCodec, replay и подтверждения CONTROL_V2](AUDIT-Q10-CODEC-CONTROL.md)

## Q11

- [Q11: REALITY, TLS 1.3 и HTTP/2](AUDIT-Q11-REALITY-TLS-H2.md)

## Q12

- [Q12: транспорты и wire-маскировка](AUDIT-Q12-TRANSPORTS.md)

## Q13

- [Q13: recordizer, padding и shaping](AUDIT-Q13-MORPHOLOGY.md)

## Q14

- [Q14: control socket, границы API и lifecycle hooks](AUDIT-Q14-CONTROL.md)
- [Q14: supervisor, workers и профили](AUDIT-Q14-CURRENT-LIFECYCLE.md)
- [Q14 — ожидание, сроки и завершение DNS INPUT lease](AUDIT-Q14-DNS-INPUT-BUDGET.md)
- [Q14: владение DNS-правилами после неудачной очистки](AUDIT-Q14-DNS-OWNERSHIP.md)
- [Q14 — точное восстановление серверного firewall после crash](AUDIT-Q14-FIREWALL-JOURNAL.md)
- [Q14: серверный HTTP/2, остановка профиля и pre-auth admission](AUDIT-Q14-H2-TASKS.md)
- [Q14: память вывода и завершение hook-процессов](AUDIT-Q14-HOOKS.md)
- [Q14: частичный acquire IPv6 sysctl и повторный rollback](AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md)
- [Q14: mixed nft/legacy/firewalld после SIGKILL](AUDIT-Q14-MIXED-FIREWALL.md)
- [Q14 — общий срок очистки NAT](AUDIT-Q14-NAT-CLEANUP-BUDGET.md)
- [Q14: конечная очистка правил NAT и диагностика отказов](AUDIT-Q14-NAT-CLEANUP.md)
- [Q14: сроки и лимиты вывода серверных NAT-команд](AUDIT-Q14-NAT-COMMANDS.md)
- [Q14 — срок установки NAT, forwarding и DNS REDIRECT](AUDIT-Q14-NAT-SETUP-BUDGET.md)
- [Q14: итоговая проверка DNS и IPv6 sysctl при остановке worker](AUDIT-Q14-OWNED-SHUTDOWN.md)
- [Q14: ошибки задач профиля и очистки TUN при остановке](AUDIT-Q14-PROFILE-SHUTDOWN.md)
- [Q14/Q15: фоновые службы worker и полный учёт трафика сессий](AUDIT-Q14-Q15-WORKER-USAGE.md)
- [Аудит Q14/Q19: завершение профиля и DNS-слушатели](AUDIT-Q14-Q19-LIFECYCLE.md)
- [Q14/Q25: общая проверка firewall и точечная очистка DNS](AUDIT-Q14-Q25-FIREWALL-CHECKS.md)
- [Q14/Q32: ограничения отправки уведомлений и завершение задач](AUDIT-Q14-Q32-NOTIFICATIONS.md)
- [Q14/Q33: доверие прочитанному конфигу для Linux-команд](AUDIT-Q14-Q33-CONFIG-TRUST.md)
- [Q14 — точная очистка NAT и результат завершения поколения](AUDIT-Q14-RETAINED-CLEANUP.md)
- [Аудит Q14: supervisor, worker и управляющие события](AUDIT-Q14-SUPERVISOR.md)
- [Q14: результат восстановления sysctl и повторное получение lease](AUDIT-Q14-SYSCTL-RECOVERY.md)
- [Q14 — владение worker в network namespace](AUDIT-Q14-WORKER-NETWORK-LEASE.md)

## Q15

- [Q15: сессии, IP-пулы и лимиты](AUDIT-Q15-CURRENT-SESSIONS.md)
- [Q15-F002: локальный адрес ответа UDP wildcard](AUDIT-Q15-UDP-LOCAL-ADDRESS.md)

## Q16

- [Q16: ACL, push routes и site-to-site](AUDIT-Q16-ACL-ROUTES.md)

## Q17

- [Q17: IPv4 NAT, forwarding и sysctl](AUDIT-Q17-IPV4-NETWORK.md)

## Q18

- [Q18: IPv6 off/manual/route/nat66 и NDP](AUDIT-Q18-IPV6-NDP.md)

## Q19

- [Аудит Q19: память кеша, подписанные обмены и заголовки DNS](AUDIT-Q19-DNS-CACHE.md)
- [Аудит Q19: EDNS, RDATA и сроки жизни кеша](AUDIT-Q19-DNS-EDNS.md)
- [Q19: серверный и клиентский DNS](AUDIT-Q19-DNS-FINAL.md)
- [Аудит Q19: серверный DNS-прокси](AUDIT-Q19-DNS-PROXY.md)
- [Аудит Q19/Q22: общий план DNS и маршрутов](AUDIT-Q19-Q22-NETWORK-PLAN.md)

## Q20

- [Q20: DHCP и жизненный цикл аренды](AUDIT-Q20-DHCP-FINAL.md)

## Q21

- [Q21: TUN/TAP, IP и MTU/PMTU](AUDIT-Q21-PACKETS-FINAL.md)

## Q22

- [Q22: transport core, FFI/JNI и память](AUDIT-Q22-CORE-FFI-FINAL.md)

## Q23

- [Q23: роуминг, resume и CONTROL_V2](AUDIT-Q23-ROAMING-FINAL.md)

## Q24

- [Q24: multipath, bonding и общий бюджет](AUDIT-Q24-BONDING.md)

## Q25

- [Q25-F186: индекс активного профиля Android](AUDIT-Q25-ANDROID-ACTIVE-INDEX.md)
- [Q25-F193 — Android per-app редактор и секции INI](AUDIT-Q25-ANDROID-APPS-INI.md)
- [Q25-F167: точное чтение клиентского INI на Android](AUDIT-Q25-ANDROID-FILE-IMPORT.md)
- [Q25-F203 — Android Private DNS, VPN-трафик и смена Wi‑Fi](AUDIT-Q25-ANDROID-NETWORK-IDENTITY.md)
- [Q25-F174: подтверждённая запись Android-профилей](AUDIT-Q25-ANDROID-PROFILE-TRANSACTIONS.md)
- [Q25-F176: строгая загрузка Android profile store](AUDIT-Q25-ANDROID-STORE-DECODING.md)
- [Q25-F179: Android profile store не принимает устаревшую запись](AUDIT-Q25-ANDROID-STORE-VERSION.md)
- [Q25 — ошибки и сохранность атомарной записи состояния](AUDIT-Q25-ATOMIC-STATE.md)
- [Q25-F216/F217: единый bootstrap INI для Linux CLI](AUDIT-Q25-CLI-BOOTSTRAP.md)
- [Q25: ограничения клиентских системных команд и проверка IPv4-защиты](AUDIT-Q25-CLIENT-COMMANDS.md)
- [Q25-F166: устаревшее удаление и применение клиентского INI](AUDIT-Q25-CLIENT-DELETE-REVISION.md)
- [Q25-F197 — матрица общего INI-редактора](AUDIT-Q25-CLIENT-INI-MATRIX.md)
- [Q25-F102: предупреждение о legacy-таблицах блокировало клиент](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md)
- [Q25: отключённый IPv6 и резервирование TUN всех Linux-клиентов](AUDIT-Q25-CLIENT-NAMESPACE.md)
- [Q25-F133: Linux client-only сборка и exit WAN monitor](AUDIT-Q25-CLIENT-ONLY-BUILD.md)
- [Q25-F165: ограничение автозапуска и диагностики клиента](AUDIT-Q25-CLIENT-PROFILE-BOUNDS.md)
- [Q25-F164: ревизии клиентских INI в панели](AUDIT-Q25-CLIENT-PROFILE-REVISION.md)
- [Q25-F177: ревизия клиентского UI и применение активного профиля](AUDIT-Q25-CLIENT-PROFILE-UI-REVISION.md)
- [Q25-F196 — проверка пароля share URI во всех адаптерах](AUDIT-Q25-CLIENT-SHARE-PARITY.md)
- [Q25-F194 — переносимый пароль в ссылке и сборка редактора](AUDIT-Q25-CLIENT-SHARE-PASSWORD.md)
- [Q25-F195 — ошибки выдачи ссылки в клиентском UI](AUDIT-Q25-CLIENT-SHARE-UI.md)
- [Q25-F169: текстовый клиентский INI до общего парсера](AUDIT-Q25-CLIENT-UI-INI-INPUT.md)
- [Q25-F198 — бюджет прямого импорта qeli://](AUDIT-Q25-CLIENT-URI-BUDGET.md)
- [Q25: ошибки жизненного цикла ядра должны проходить через очистку](AUDIT-Q25-CORE-LIFECYCLE.md)
- [Q25/Q33: ограниченное выполнение команд пароля и ранняя остановка клиента](AUDIT-Q25-CREDENTIAL-COMMANDS.md)
- [Q25-F168: файловый клиентский INI в desktop CLI](AUDIT-Q25-DESKTOP-CONFIG-FILES.md)
- [Q25-F189: стабильность ID профилей desktop](AUDIT-Q25-DESKTOP-PROFILE-IDENTITY.md)
- [Q25-F173: транзакции профилей в desktop UI](AUDIT-Q25-DESKTOP-PROFILE-TRANSACTIONS.md)
- [Q25-F192 — общее хранение настроек Windows/macOS](AUDIT-Q25-DESKTOP-SETTINGS-STORE.md)
- [Q25-F183: ограничение чтения desktop profile store](AUDIT-Q25-DESKTOP-STORE-BOUNDS.md)
- [Q25-F178: межпроцессная запись desktop profile store](AUDIT-Q25-DESKTOP-STORE-CONCURRENCY.md)
- [Q25-F184: конечное ожидание desktop profile-store lock](AUDIT-Q25-DESKTOP-STORE-LOCK-WAIT.md)
- [Q25-F191 — null в полях desktop-профиля](AUDIT-Q25-DESKTOP-STORE-NULL-FIELDS.md)
- [Q25-F172: отказоустойчивость desktop-хранилищ профилей](AUDIT-Q25-DESKTOP-STORE-RECOVERY.md)
- [Q25-F185: структура desktop profile store](AUDIT-Q25-DESKTOP-STORE-STRUCTURE.md)
- [Q25-F171: кодировка desktop-хранилищ профилей](AUDIT-Q25-DESKTOP-STORE-UTF8.md)
- [Q25 — общий срок применения клиентского DNS](AUDIT-Q25-DNS-BUDGET.md)
- [Q25: DNS принадлежит конкретному поколению соединения](AUDIT-Q25-DNS-LEASES.md)
- [Q25 — DNS-маркеры: доверенный каталог и поколение namespace](AUDIT-Q25-DNS-MARKER-STORAGE.md)
- [Q25: сохранение DNS-снимка при ошибке восстановления](AUDIT-Q25-DNS-RECOVERY.md)
- [Q25-F200 — структура и языковые пары отчётов аудита](AUDIT-Q25-DOC-PARITY.md)
- [Q25: владение NAT exit-node и конфликт политик kill-switch](AUDIT-Q25-EXIT-OWNERSHIP.md)
- [Q25-F124: exit-node и policy routing на другом WAN](AUDIT-Q25-EXIT-POLICY-ROUTING.md)
- [Q25-F128: собственный exit-TUN не может быть WAN](AUDIT-Q25-EXIT-SELF-WAN.md)
- [Q25-F127: смена exit WAN без VPN path COMMIT](AUDIT-Q25-EXIT-WAN-MONITOR.md)
- [Q25-F107/F108: асинхронные операции kill-switch и сохранение DROP при отказе unhook](AUDIT-Q25-FIREWALL-TASK.md)
- [Q25 — общий срок операций gateway/exit-node](AUDIT-Q25-GATEWAY-BUDGET.md)
- [Q25: владение gateway при setup, roaming и cleanup](AUDIT-Q25-GATEWAY-IDENTITY.md)
- [Q25-F120: повторная проверка IPv6 WAN при обновлении exit-node](AUDIT-Q25-GATEWAY-IPV6-ROAM.md)
- [Q25: откат gateway, изоляция туннелей и проверки firewall](AUDIT-Q25-GATEWAY-ROLLBACK.md)
- [Q25: определение WAN и очистка gateway](AUDIT-Q25-GATEWAY-WAN.md)
- [Q25: HTTP/2 workers и завершение клиентского поколения](AUDIT-Q25-H2-TASKS.md)
- [Q25-F112/F113: ограниченные файлы идентичности и безопасный TOFU](AUDIT-Q25-IDENTITY-FILES.md)
- [Q25-F114: TOFU worker, отмена handshake и поздние ошибки](AUDIT-Q25-IDENTITY-WORKER.md)
- [Q25-F187: индекс активного профиля при iOS restore](AUDIT-Q25-IOS-ACTIVE-INDEX.md)
- [Q25-F181: уведомление iOS о применении активного профиля](AUDIT-Q25-IOS-ACTIVE-PROFILE-RECONNECT.md)
- [Q25-F180: пустой iOS profile archive не заменяется шаблоном](AUDIT-Q25-IOS-EMPTY-ARCHIVE.md)
- [Q25-F182: снимок iOS-профиля при редактировании и удалении](AUDIT-Q25-IOS-PROFILE-SNAPSHOT.md)
- [Q25 — общий срок очистки самостоятельного kill-switch](AUDIT-Q25-KILL-SWITCH-BUDGET.md)
- [Q25-F122: поздний IPv4-маршрут не обходит kill-switch](AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV4.md)
- [Q25-F121: поздний IPv6 не обходит kill-switch](AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV6.md)
- [Q25 — владение независимым kill switch и проверки reconnect](AUDIT-Q25-KILL-SWITCH-IDENTITY.md)
- [Q25: срок владения kill-switch и доказательства IPv6-защиты](AUDIT-Q25-KILL-SWITCH-LIFETIME.md)
- [Q25 — kill-switch при аварийном перезапуске](AUDIT-Q25-KILL-SWITCH-REBUILD.md)
- [Q25 — срок обновления kill-switch и неопределённые проверки](AUDIT-Q25-KILL-SWITCH-REFRESH.md)
- [Q25 — срок установки kill-switch и проверяемый откат](AUDIT-Q25-KILL-SWITCH-SETUP.md)
- [Q25: безопасный отказ от старого глобального DNS recovery](AUDIT-Q25-LEGACY-DNS.md)
- [Q25 — сведения об интерфейсе в текущем namespace](AUDIT-Q25-LINK-OBSERVATION.md)
- [Q25: Linux CLI и восстановление сети — итог](AUDIT-Q25-LINUX-CLI-FINAL.md)
- [D09: подтверждение Linux lifecycle и системных отказов](AUDIT-Q25-LINUX-LIFECYCLE-CLOSURE.md)
- [Q25-F170: предел мобильного клиентского INI](AUDIT-Q25-MOBILE-CONFIG-BUDGET.md)
- [Q25-F188: границы мобильного хранилища и backup](AUDIT-Q25-MOBILE-STORE-BOUNDS.md)
- [Q25-F175: защита мобильных профилей после отказа загрузки](AUDIT-Q25-MOBILE-STORE-LOAD-FAILURE.md)
- [Q25 — поколение network namespace в sysctl-журнале v4](AUDIT-Q25-NAMESPACE-GENERATION.md)
- [Q25 — удержание namespace на время sysctl-транзакции](AUDIT-Q25-NAMESPACE-PIN.md)
- [Q25-F199 — входы воспроизводимой native-сборки](AUDIT-Q25-NATIVE-BUILD-INPUTS.md)
- [Q25-F202 — воспроизводимые native cores и Android runtime](AUDIT-Q25-NATIVE-REBUILD.md)
- [Q25: сохранение kill-switch при ошибке очистки forwarding](AUDIT-Q25-NETWORK-CLEANUP.md)
- [Q25-F105: применение NetworkPlan вне async-потока](AUDIT-Q25-NETWORK-TASK.md)
- [Q25/Q14: ограниченное чтение пароля и финальный статус клиента](AUDIT-Q25-PASSWORD-FILES.md)
- [Q25-F201 — сверка архива патчей и возраста свидетельств](AUDIT-Q25-PATCH-RECONCILIATION.md)
- [Q25: ограниченные команды Linux-монитора сети](AUDIT-Q25-PATH-MONITOR.md)
- [Q25: persistent TUN/TAP после SIGKILL](AUDIT-Q25-PERSISTENT-TUN.md)
- [Q25-F110: запуск TUN pump и ранний откат в присоединяемом worker](AUDIT-Q25-PUMP-START.md)
- [Q25 — проверка системного resolver-конфига](AUDIT-Q25-RESOLVER-CONFIG.md)
- [Q25 — контекст службы DNS и прямые D-Bus-вызовы](AUDIT-Q25-RESOLVER-CONTEXT.md)
- [Q25-F104: чтение resolver-файлов до установки kill-switch](AUDIT-Q25-RESOLVER-FILES.md)
- [Q25: владение Linux-маршрутами после изменений администратором](AUDIT-Q25-ROUTE-ATTRIBUTES.md)
- [Q25 — общий срок клиентских route-транзакций](AUDIT-Q25-ROUTE-BUDGET.md)
- [Q25: исходный TUN и namespace при очистке маршрутов](AUDIT-Q25-ROUTE-IDENTITY.md)
- [Q25: восстановление физических маршрутов клиента после аварии](AUDIT-Q25-ROUTE-JOURNAL.md)
- [Q25: результат неуспешного изменения carrier route](AUDIT-Q25-ROUTE-OUTCOME.md)
- [Q25: параметры удаления маршрутов и подтверждённая очистка](AUDIT-Q25-ROUTE-OWNERSHIP.md)
- [Q25: неопределённые операции и освобождение осиротевших записей маршрутов](AUDIT-Q25-ROUTE-PENDING.md)
- [Q25: подтверждение удаления и восстановления carrier-маршрутов](AUDIT-Q25-ROUTE-POSTCONDITIONS.md)
- [Q25: изоляция маршрутов по владельцу подключения](AUDIT-Q25-ROUTE-SCOPE.md)
- [Q25-F161: ошибки перечисления при восстановлении архива](AUDIT-Q25-SERVER-ARCHIVE-SCAN.md)
- [Q25-F135: отказ NAT auto-WAN при неполном списке default routes](AUDIT-Q25-SERVER-AUTO-WAN-FAILURE.md)
- [Q25-F158: согласование сохранённой и действующей политики блокировок](AUDIT-Q25-SERVER-BLOCKED-LIVE.md)
- [Q25-F160: ревизия INI при сохранении политики блокировок](AUDIT-Q25-SERVER-BLOCKED-REVISION.md)
- [Q25-F141: одинаковый допуск серверного INI в CLI, панели и runtime](AUDIT-Q25-SERVER-CHECK-CONFIG-PARITY.md)
- [Q25-F115: серверная очистка без блокировки async executor](AUDIT-Q25-SERVER-CLEANUP-WORKER.md)
- [Q25-F146: конкурентная запись серверного INI](AUDIT-Q25-SERVER-CONCURRENT-WRITES.md)
- [Q25-F117: DNS firewall серверного профиля вне async executor](AUDIT-Q25-SERVER-DNS-SETUP-WORKER.md)
- [Q25-F152: матрица INI и полный рестарт для logging](AUDIT-Q25-SERVER-FIELD-MATRIX-LOGGING.md)
- [Q25-F130: допуск server worker после принудительной отмены](AUDIT-Q25-SERVER-FORCED-DROP-LEASE.md)
- [D07: глобальные поля серверного INI](AUDIT-Q25-SERVER-GLOBAL-FIELDS.md)
- [Q25-F142: имя профиля не выходит из каталога серверного ключа](AUDIT-Q25-SERVER-IDENTITY-NAME.md)
- [Q25-F143: доверие к путям identity_key и logging.file](AUDIT-Q25-SERVER-IDENTITY-TRUST.md)
- [Q25-F190 — ошибки истории серверного INI](AUDIT-Q25-SERVER-INI-HISTORY.md)
- [Q25-F159: стабильный порядок динамических полей INI](AUDIT-Q25-SERVER-INI-ORDER.md)
- [Q25-F140: приватные права серверного INI после записи панели](AUDIT-Q25-SERVER-INI-PERMISSIONS.md)
- [Q25-F138: единый предел серверного INI](AUDIT-Q25-SERVER-INI-SIZE.md)
- [Q25-F136: граница NAT44 для выхода через другой интерфейс](AUDIT-Q25-SERVER-NAT44-EGRESS.md)
- [Q25-F134: NAT66 не выпускает пакет через другой WAN](AUDIT-Q25-SERVER-NAT66-EGRESS.md)
- [Q25-F118: привязка NDP proxy вне async executor](AUDIT-Q25-SERVER-NDP-BIND-WORKER.md)
- [Q25-F162: уведомления только в INI и ограниченная загрузка](AUDIT-Q25-SERVER-NOTIFY-INI.md)
- [Q25-F163: конкурентное сохранение уведомлений](AUDIT-Q25-SERVER-NOTIFY-REVISION.md)
- [Q25-F151: панель не повышает доверие к недоверенному INI](AUDIT-Q25-SERVER-PANEL-SAVE-TRUST.md)
- [Q25-F150: доверие к INI в панельных identity, Share и users](AUDIT-Q25-SERVER-PANEL-SNAPSHOT-TRUST.md)
- [D07: базовые поля серверного профиля](AUDIT-Q25-SERVER-PROFILE-FOUNDATION.md)
- [D07: поля obf.* серверного профиля](AUDIT-Q25-SERVER-PROFILE-OBF.md)
- [Q25-F154: Quick Start и политика блокировок](AUDIT-Q25-SERVER-QUICKSTART-BF-SAVE.md)
- [Q25-F119: общий бюджет установки серверного профиля и готовность listeners](AUDIT-Q25-SERVER-SETUP-BUDGET.md)
- [Q25-F116: TUN/NAT setup серверного профиля вне async executor](AUDIT-Q25-SERVER-SETUP-WORKER.md)
- [Q25-F137: отказ SIGHUP без частичного обновления VPN-аутентификации](AUDIT-Q25-SERVER-SIGHUP-AUTH.md)
- [Q25-F155: SIGHUP и изменения, требующие рестарта](AUDIT-Q25-SERVER-SIGHUP-RESTART-HINTS.md)
- [Q25-F148: проверка TLS-файлов в check-config](AUDIT-Q25-SERVER-TLS-CHECK-CONFIG.md)
- [Q25-F149: доверие к TLS-путям и сохранение пары Let's Encrypt](AUDIT-Q25-SERVER-TLS-PATH-TRUST.md)
- [Q25-F147: загрузка TLS PEM и неполная автопара панели](AUDIT-Q25-SERVER-TLS-PEM.md)
- [Q25-F144: доверие к нестандартному auth.users_file](AUDIT-Q25-SERVER-USERS-PATH-TRUST.md)
- [Q25-F145: SIGHUP и рестарт при смене users_file](AUDIT-Q25-SERVER-USERS-SIGHUP-RESTART.md)
- [Q25-F132: неоднозначный auto-WAN серверного профиля](AUDIT-Q25-SERVER-WAN-ECMP.md)
- [Q25-F131: наличие WAN при установке серверной маршрутизации](AUDIT-Q25-SERVER-WAN-PRESENCE.md)
- [Q25-F153: аутентификация панели при сохранении INI](AUDIT-Q25-SERVER-WEB-AUTH-SAVE.md)
- [Q25-F156: проверка хеша панели при admission и live reload](AUDIT-Q25-SERVER-WEB-HASH-VALIDATION.md)
- [Q25-F139: живое состояние панели после сохранения INI](AUDIT-Q25-SERVER-WEB-LIVE.md)
- [Q25-F157: результат живой перезагрузки панели](AUDIT-Q25-SERVER-WEB-RELOAD-RESULT.md)
- [Q25: начальная установка физических маршрутов и подтверждённый flush](AUDIT-Q25-SETUP-FLUSH.md)
- [Q25: проверка владельца при setup и roaming](AUDIT-Q25-SETUP-IDENTITY.md)
- [Q25-F109: стартовое восстановление в присоединяемом worker](AUDIT-Q25-STARTUP-RECOVERY-TASK.md)
- [Q25 — доверие к каталогу состояния и целостность lock](AUDIT-Q25-STATE-DIRECTORY.md)
- [Q25-F111: последовательная запись диагностики вне async-потока](AUDIT-Q25-STATUS-WRITER.md)
- [Q25 — namespace на внутренних границах sysctl](AUDIT-Q25-SYSCTL-CONTEXT-IO.md)
- [Q25 — безопасное чтение и ожидание sysctl-журнала](AUDIT-Q25-SYSCTL-JOURNAL-IO.md)
- [Q25: изоляция журнала sysctl по namespace](AUDIT-Q25-SYSCTL-NAMESPACE.md)
- [Q25: подтверждение владельцев sysctl и сохранение восстановления](AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md)
- [Q25 — владение исходным sysctl интерфейса](AUDIT-Q25-SYSCTL-TARGET.md)
- [Q25: сроки системных команд TUN и DNS](AUDIT-Q25-SYSTEM-COMMANDS.md)
- [Q25-F103: ожидание системного DNS и остановка клиента](AUDIT-Q25-SYSTEM-RESOLVER.md)
- [Q25: владение TCP-задачами и остановка Linux-монитора путей](AUDIT-Q25-TCP-TASKS.md)
- [Q25: безопасный допуск и создание Linux TUN/TAP](AUDIT-Q25-TUN-ADMISSION.md)
- [Q25-F123: контекст sysfs при TUN dev_attach](AUDIT-Q25-TUN-ATTACH-CONTEXT.md)
- [Q25: attach без создания TUN и сохранение формата устройства](AUDIT-Q25-TUN-ATTACH.md)
- [Q25: передача ошибок очистки TUN, маршрутов и DNS](AUDIT-Q25-TUN-CLEANUP.md)
- [Q25: исходные дескрипторы TUN сохраняются до завершения очистки](AUDIT-Q25-TUN-LIFETIME.md)
- [Q25-F106: асинхронная очистка установленного туннеля](AUDIT-Q25-TUN-TEARDOWN.md)
- [Q25: отмена shutdown и владение потоками TUN](AUDIT-Q25-TUN-WORKERS.md)
- [Q25: единая установка TUN/TAP-маршрутов и удаление старых реализаций](AUDIT-Q25-TUNNEL-ROUTES.md)
- [Q25: задачи UDP и порядок отката пути](AUDIT-Q25-UDP-TASKS.md)
- [Q25-F129: неоднозначный ECMP default WAN](AUDIT-Q25-WAN-ECMP.md)
- [Q25-F126: выбор WAN по метрике default route](AUDIT-Q25-WAN-METRIC.md)
- [Q25-A125: повторное использование имени WAN](AUDIT-Q25-WAN-NAME-REUSE.md)
- [Q25-F204 — ресурсный churn Linux worker](AUDIT-Q25-WORKER-RESOURCE-CHURN.md)

## Q26

- [Q26: общий C# и managed/native граница — DONE/PASS](AUDIT-Q26-MANAGED-FINAL.md)

## Q27

- [Q27: переходы службы, SCM, автозапуск и settings — этап PASS](AUDIT-Q27-WINDOWS-CONTROL.md)
- [Q27: Windows GUI, служба и драйверы — DONE/PASS в согласованном объёме](AUDIT-Q27-WINDOWS-FINAL.md)
- [Q27: регистрация службы, статус и логи — этап PASS](AUDIT-Q27-WINDOWS-OBSERVATION.md)
- [Q27: Windows-хранилища и служебный профиль — этап PASS](AUDIT-Q27-WINDOWS-STORAGE.md)

## Q28

- [Q28: daemon macOS, helper и состояние](AUDIT-Q28-MACOS-CONTROL.md)
- [Q28: macOS forwarding — владение и восстановление](AUDIT-Q28-MACOS-FORWARDING.md)
- [Q28: guardian — готовность и владение поколением](AUDIT-Q28-MACOS-GUARDIAN.md)
- [Q28: итоговая интеграция macOS](AUDIT-Q28-MACOS-INTEGRATION.md)
- [Q28: очистка сети macOS и владелец firewall](AUDIT-Q28-MACOS-NETWORK.md)
- [Q28: per-app bridge, Swift-политика и пути сборки](AUDIT-Q28-MACOS-PERAPP.md)
- [Q28: native socket lifetime и пределы I/O](AUDIT-Q28-MACOS-SOCKETS.md)
- [Q28: хранилища macOS и ключ профилей](AUDIT-Q28-MACOS-STORAGE.md)

## Q29

- [Q29: per-app UID и Private DNS](AUDIT-Q29-ANDROID-APP-POLICY.md)
- [Q29: CONNECTED после публикации Android VPN](AUDIT-Q29-ANDROID-CONNECTED-GATE.md)
- [Q29 F282–F283: владелец защиты сокета и отказы доверенного Wi-Fi](AUDIT-Q29-ANDROID-CONTROLLER.md)
- [Q29: актуальные VPN-интеграции и надёжность Android-стенда](AUDIT-Q29-ANDROID-CURRENT-VPN.md)
- [Q29: Android VPN-трафик и lifecycle после Auth](AUDIT-Q29-ANDROID-DATA.md)
- [Q29: ограниченный Doze и повторные переключения сети](AUDIT-Q29-ANDROID-ENDURANCE.md)
- [Q29: IPv4/IPv6 TCP/UDP после переключения Android сети](AUDIT-Q29-ANDROID-HANDOVER-PAYLOAD.md)
- [Q29: переключение carrier networks Android](AUDIT-Q29-ANDROID-HANDOVER.md)
- [Q29: пакеты на границе переключения сети и force-stop](AUDIT-Q29-ANDROID-LEAK-BURSTS.md)
- [Q29: конкурентная остановка Android TUN и JNI](AUDIT-Q29-ANDROID-LIFECYCLE.md)
- [Q29: Android Release в сети IPv6-only с DNS64/NAT64](AUDIT-Q29-ANDROID-NAT64.md)
- [Q29: владение запросом разрешений при подключении Android](AUDIT-Q29-ANDROID-PERMISSIONS.md)
- [Q29: Android — экран, deep idle и восстановление TCP](AUDIT-Q29-ANDROID-POWER.md)
- [Q29: восстановление Android VPN после смерти процесса](AUDIT-Q29-ANDROID-RECOVERY.md)
- [Q29: сон и восстановление транспорта в Android Release](AUDIT-Q29-ANDROID-RELEASE-FAULTS.md)
- [Q29: инструментированный Release runner](AUDIT-Q29-ANDROID-RELEASE-RUNNER.md)
- [Q29: минифицированный Release и сетевой runtime Android](AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md)
- [Q29: сравнение Android DNS API](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md)
- [Q29: команды и жизненный цикл Android foreground-сервиса](AUDIT-Q29-ANDROID-SERVICE.md)
- [Q29 F289: применение LAN-настроек к активному соединению](AUDIT-Q29-ANDROID-SETTINGS.md)
- [Q29 F286–F288: ограниченное чтение и итоговый source review Android](AUDIT-Q29-ANDROID-SOURCE.md)
- [Q29: системный DNS и холодное включение Android Release](AUDIT-Q29-ANDROID-STARTUP-DNS.md)
- [Q29: публикация VPN при холодном запуске](AUDIT-Q29-ANDROID-STARTUP-STATE.md)
- [Q29: Android — хранилище, редактор профиля, backup и Release](AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md)
- [Q29: системные Always-on, lockdown и смерть процесса Android](AUDIT-Q29-ANDROID-SYSTEM.md)
- [Q29: TCP при переключении Android Wi-Fi/Cellular](AUDIT-Q29-ANDROID-TCP-HANDOVER.md)
- [Q29: доверенный Private DNS / DoT](AUDIT-Q29-ANDROID-TRUSTED-DOT.md)
- [Q29 F281: доверенный Wi-Fi при включённом lockdown](AUDIT-Q29-ANDROID-TRUSTED-LOCKDOWN.md)
- [Q29: работа сервиса на доверенном Wi-Fi](AUDIT-Q29-ANDROID-TRUSTED-WIFI.md)
- [Q29: восстановление UDP и QUIC-маскировки Android](AUDIT-Q29-ANDROID-UDP-RECOVERY.md)

## Q30

- [Q30: статус приложения и порядок управляемых настроек](AUDIT-Q30-IOS-APP-PREFERENCES.md)
- [Q30: владение первой записью идентификатора и доверенного ключа в Keychain](AUDIT-Q30-IOS-KEYCHAIN.md)
- [Q30: владение провайдером, stop/start и поздние ответы ОС](AUDIT-Q30-IOS-LIFECYCLE.md)
- [Q30: сообщения провайдера и состояние запросов backup UI](AUDIT-Q30-IOS-MESSAGES-BACKUP.md)
- [Q30: числовые MDM-политики и асинхронные ответы расширения](AUDIT-Q30-IOS-POLICY-SNAPSHOT.md)
- [Q30: лимиты памяти, владение probe и итоговая сверка исходников](AUDIT-Q30-IOS-SOURCE-MEMORY.md)

## Q31

- [Q31: управление LuCI, публикация INI и ошибки firewall](AUDIT-Q31-OPENWRT-CONTROLS.md)

## Q32

- [Q32: ограничение чтения логов и публикация trace](AUDIT-Q32-LOGS-TRACE.md)
- [Q32: корректность метрик после пропусков и смены worker](AUDIT-Q32-METRICS.md)
- [Q32: доверие к INI уведомлений и корректность доставки](AUDIT-Q32-NOTIFICATIONS.md)
- [Q32: сброс usage на границе атомарной публикации](AUDIT-Q32-USAGE.md)

## Q33

- [Q33: подготовка payload и состояния при установке из бинарника](AUDIT-Q33-BINARY-INSTALLER.md)
- [Q33: итоговая сверка установки, обновления, файлов и hooks](AUDIT-Q33-COMPLETION.md)
- [Q33: lifecycle Debian-пакета и защита рабочего состояния](AUDIT-Q33-DEBIAN-LIFECYCLE.md)
- [Q33: конфигурация Docker entrypoint и публикация при первом запуске](AUDIT-Q33-DOCKER-ENTRYPOINT.md)
- [Q33: зависимости installer и допуск Debian-пакета](AUDIT-Q33-INSTALLER-ADMISSION.md)
- [Q33: настоящий CLI установщика и совместимость чтения версии](AUDIT-Q33-INSTALLER-CLI.md)
- [Q33: ранние проверки installer и публикация подготовленного INI](AUDIT-Q33-INSTALLER-CONFIG.md)
- [Q33: публикация секретов installer и web-конфига](AUDIT-Q33-INSTALLER-SECRETS.md)
- [Q33: настоящий portable DEB, обновление и откат](AUDIT-Q33-PACKAGE-MANAGER.md)
- [Q33: транзакции обновления и отката серверного пакета](AUDIT-Q33-SERVER-UPDATER.md)
- [Q33: смена пользователя службы и права на секреты установщика](AUDIT-Q33-SERVICE-USER.md)
- [Q33: настоящий systemd sandbox, SIGHUP и режим root](AUDIT-Q33-SYSTEMD.md)

## Q34

- [Q34 — нативные библиотеки после принятия исправлений панели](AUDIT-Q34-ADOPTED-NATIVE.md)
- [Q34: Android dependency locks and checksum verification](AUDIT-Q34-ANDROID-DEPENDENCIES.md)
- [Q34: лицензии проекта и Maven NOTICE в Android APK](AUDIT-Q34-ANDROID-NOTICES.md)
- [Q34 — Android build recipe and runtime evidence](AUDIT-Q34-ANDROID-RUNTIME.md)
- [Q34: происхождение артефактов и атомарные checksums](AUDIT-Q34-ATTESTATION-CHECKSUMS.md)
- [Q34: зависимости сборки клиентов и подписи Windows](AUDIT-Q34-CLIENT-SUPPLY.md)
- [Q34: зависимости Rust, политика CI и PEM TLS](AUDIT-Q34-DEPENDENCY-POLICY.md)
- [Q34: полная amd64 Docker build и release admission](AUDIT-Q34-DOCKER-BUILD.md)
- [Q34: неизменяемые Docker frontend и APT inputs](AUDIT-Q34-DOCKER-INPUTS.md)
- [Q34: полный перечень fuzz-целей в CI](AUDIT-Q34-FUZZ-INVENTORY.md)
- [Q34: воспроизводимый fuzz CI и полный ASan smoke](AUDIT-Q34-FUZZ-TOOLCHAIN.md)
- [Q34/Q25 — Linux packet matrix и проверка переключений](AUDIT-Q34-LINUX-MATRIX.md)
- [Q34: .NET notices и лицензия встроенных шрифтов](AUDIT-Q34-MANAGED-NOTICES.md)
- [Q34: безопасность Maven-графов Android](AUDIT-Q34-MAVEN-SECURITY.md)
- [Q34: общий комплект Cargo legal resources](AUDIT-Q34-NATIVE-NOTICES.md)
- [Q34: точный локальный source cut OpenWrt](AUDIT-Q34-OPENWRT-SOURCE-CUT.md)
- [Q34: Git trust flags в OpenWrt source gate](AUDIT-Q34-OPENWRT-SOURCE-FLAGS.md)
- [Q34: допуск release source и Docker notices](AUDIT-Q34-PUBLICATION-GATES.md)
- [Q34/Q25 — память при 100 release handover](AUDIT-Q34-RELEASE-SOAK.md)
- [Q34: SDK .NET и фиксация зависимостей](AUDIT-Q34-SDK-LOCKS.md)
- [Q34: точный источник MicroCom.Runtime](AUDIT-Q34-SOURCE-BINDING.md)
- [Q34: notices стандартных библиотек и runtime toolchain](AUDIT-Q34-TOOLCHAIN-NOTICES.md)
- [Q34: постоянная проверка GitHub Actions](AUDIT-Q34-WORKFLOW-LINT.md)

## Q35

- [Q35 — инварианты клиентского INI и qeli:// при fuzzing](AUDIT-Q35-CLIENT-CONFIG-FUZZ.md)
- [Q35 — итог fuzz, отказов, конкуренции, DoS и soak](AUDIT-Q35-FINAL.md)
- [Q35 — проверка сборщиков UDP-фрагментов](AUDIT-Q35-FRAGMENT-FUZZ.md)
- [Q35 — длительная одновременная проверка TCP и UDP roaming](AUDIT-Q35-LONG-SOAK.md)
- [Q35 — допуск полного release-soak](AUDIT-Q35-RELEASE-ADMISSION.md)

## Q36

- [Q36: текущая статистическая популяция data plane](AUDIT-Q36-CURRENT-STATISTICS.md)
- [Q36 — итог аудита бенчмарков](AUDIT-Q36-FINAL.md)
- [Q36: одинаковая суммарная нагрузка P1/P4 и счётчики TUN](AUDIT-Q36-MATCHED-LOAD.md)
- [Q36 — реальная диагностика границ TUN и влияние наблюдателя](AUDIT-Q36-TUN-STAGE.md)
- [Q36-F018: остановка UDP и сохранение ошибок задач](AUDIT-Q36-UDP-SHUTDOWN.md)

## Q37

- [Q37: документация и тестовая обвязка — 11 октября 2026](AUDIT-Q37-DOCUMENTATION.md)

## Сверка документации

[Сверка документации 0.8.2 после аудита — 16 октября](DOCUMENTATION-REVIEW.md)

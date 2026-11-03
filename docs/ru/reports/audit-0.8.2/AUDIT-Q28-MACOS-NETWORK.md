# Q28: очистка сети macOS и владелец firewall

<!-- normative-sync: audit-q28-macos-network-v1 -->

**5 октября 2026: этап PASS; Q28 IN_PROGRESS. План 27/37 (73,0%), осталось 10 разделов.**

## Исправления

| ID | Дефект и итоговое поведение |
|---|---|
| F249 | Пустой filter разрешал reload /etc/pf.conf с потерей NAT/rdr/scrub. Resolve требует уже действующую безусловную ссылку qeli либо com.apple/*, отказывает при отсутствующем/условном anchor и не перезагружает основной ruleset. |
| F250 | Disengage снимал anchors без проверки живого чужого владельца и мог выключить глобальный pf после активации другим инструментом. PfRecovery проверяет ограниченный строгий owner stamp, защищает владельца/refresh и сохраняет последний журнал до успешной очистки. Глобальный pf остаётся включённым. State/rules/locks используют защищённый fd-store ServiceState; повреждённый/legacy журнал без владельца требует ручного ремонта. |
| F251 | Recovery старого DNS мог удалить новый журнал/override. Вложенная sidecar-блокировка охватывает recovery/claim/mutation/release; release остаётся повторяемым. Чтение ограничено и использует строгий UTF-8, только отсутствие означает отсутствие; production root-store проверяет descriptor и публикует закрытые файлы атомарно. Исключения read/write становятся failed result с rollback частичного apply. |
| F252 | Неудачное удаление адреса возвращало false внутри Action и терялось как успех; частичный apply не регистрировался. Undo адреса сохраняется до команды, отказывает при ошибке без подтверждения отсутствия интерфейса/адреса и допускает повтор. Prefix/interface проверяются до apply. |
| F253 | Неизвестный networksetup output превращался в automatic DNS, отсутствие primary service подменялось Wi-Fi, allowlist принимал multicast/broadcast IPv4 и mapped loopback. DNS разбирает полный список IP либо точную диагностическую фразу; service selection отказывает при ошибке; IPv6-only использует службу своего IPv6 default. Общая PhysicalDnsPolicy фильтрует physical resolvers Windows/Mac. Unicast loopback/link-local server endpoints разрешены отдельно; литералы pf проверяются. |
| F254 | Конкурентные Open/Dispose utun теряли/повторно закрывали fd, утилиты могли наследовать его. Lifetime сериализован, descriptor закрывается один раз, имя/длина/терминатор проверяются; FD_CLOEXEC выставляется архитектурным Darwin fcntl. |
| F255 | Ошибка route query выглядела отсутствием; cleanup удалял внешнюю замену carrier route. Неизвестный query отказывает до изменений; owner проверяется до удаления, новая внешняя запись сохраняется. Network/pf/sysctl используют bounded ToolProcess; forwarding retry сбрасывает только успешно восстановленную family. Генерация правил идёт до startup recovery. |

## Проверки и evidence

- Mac network-selftest: **117/117 PASS**. Прежние DNS/route/roaming fixtures и рабочие PfRecovery, DNS-транзакции, повреждённые/слишком большие snapshots, частичные DNS/address failures, внешняя замена маршрута, lease contention, resolver matrix и injected descriptor lifetime.
- Mac control **83/83**, storage **54/54**, Windows **325/325**, shared conformance **549/549 PASS**, новые проверки после общей policy.
- Baseline **10/10 ожидаемых FAIL**, exit 1: исходные NetworkConfigurator + Roaming, DnsJournal, KillSwitch и Windows resolver. Подменены только namespace, service directory и Exec/Pf; реальный изолированный Windows child даёт живой чужой PID. Есть детерминированная гонка старого recovery с новым владельцем.
- Release Mac/Windows/shared: 0 errors/warnings. Docs/bindings/panel/diff, неизменённые native provenance и 14 checksum rows PASS.
- Production pf generator выполняется без startup recovery. Вывод сохранён; native pf parse/load/блокировка трафика здесь не исполнялись.

Исходные протоколы: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-network-20261005.
Evidence: release/certification/evidence/q28-macos-network-20261005.json. Профили, установленные службы, сеть и лаба не изменены.

## Границы и остаток

Это C#/fake-command/filesystem проверки на Windows, не Mac kernel E2E. Реальные Darwin fcntl/flock/openat/renameatx_np/utun, pf precedence/state, networksetup diagnostics, IPv6 scope и Intel/ARM dylib остаются **USER SKIPPED**. Root fd-adapter проверен по коду, Windows tests подменяют его границу. Точная английская фраза automatic DNS — консервативный fixture; изменение диагностики даёт безопасный отказ. Генерация правил не равна native pf parse.

Getter fd остаётся заимствованным: Rust дублирует его по контракту lifetime поколения туннеля. Блокировки не ограничивают всю операцию владельца/native OS I/O; команды имеют отдельные deadlines. Прямая замена state от root не поддерживается. Physical DNS exceptions позволяют другим приложениям обращаться к этим resolvers при reconnect; чужие quick rules/порядок pf оценивает администратор. Сохранение глобального pf включённым при release намеренное.

Остаток Q28: Swift per-app providers/helper/guardian, entitlements/build contracts; forwarding ownership/crash recovery и финальный обзор интеграции cleanup. Реальные Mac SIGKILL/sleep/roaming/чужой firewall не проверены; новых Linux/JNI/soak/бенчмарков нет.

Первичные контракты: [Darwin fcntl/FD_CLOEXEC](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/fcntl.h), [utun kernel interface](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.h), [Apple ARM64 calling conventions](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms).

Последний guard размера журнала сначала не скомпилировался (long/int в relational pattern). Сравнение исправлено; неудачная сборка сохранена, после неё выполнены новая чистая сборка и все три Mac-набора на новой DLL.

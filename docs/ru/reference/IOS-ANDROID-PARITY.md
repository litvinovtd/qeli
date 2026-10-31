# Реестр функционального соответствия Android и iOS

Русский · [English](../../eng/reference/IOS-ANDROID-PARITY.md)

## Текущий аудит, 28 октября 2026

[Подробная матрица, исправления и границы проверки](../reports/IOS-ANDROID-PARITY-2026-10-28.md).
Ниже описана реализация, а не подтверждённое соответствие Apple runtime.

- Добавлены opt-in foreground автопроверки профилей с ограниченными параллелизмом
  и интервалами, отменой при уходе приложения в фон или активации VPN.
- Добавлены ограниченные текущий/аварийный диагностические отчёты, opt-in хранение,
  редактирование приватных данных и числовые carrier snapshots C ABI 1.17.
  Сохранение последней ошибки выключено по умолчанию.
- Сохраняются комментарии/порядок импортированного INI; динамический UI и виджет
  используют выбранный язык. QR использует AVFoundation вместо VisionKit с порогом A12.
- Первый DNS-отказ входит в общий reconnect budget, включая cold recovery через
  physical-interface-scoped lookup. Повторный NWPath callback не отменяет pending
  recovery. Явные split-tunnel routes также используют `enforceRoutes`.
- Нужен новый XCFramework из ABI 1.17 sources. Старые библиотеки не дают новый
  символ; их provenance этим source audit не переименовывался.

## Реализованная основа

- Навигация Connection / Profiles / Log и визуальный язык Qeli. Собственные iOS
  экраны используют те же явные light/dark palette, размеры headers, segmented
  navigation, контуры cards и status colors, что Android, вместо UIKit grouped list.
  Панель Profiles подстраивается под узкую ширину и Dynamic Type без усечения
  русских надписей; строки используют Android card/menu model с Move up/down.
  Apple permission prompts, share sheets, pickers и прочие OS surfaces остаются native.
- CRUD профилей, блокировка выбора/удаления активного профиля при подключении
  с alert и затемнением недоступных строк, reorder и reachability. TCP — connect
  probe, UDP — ABI 1.8 `qeli_client_udp_probe`, использующий общий Rust
  X25519+ML-KEM first-flight/fragment/QUIC/obfs builder. При активном VPN оба
  протокола измеряют точный authenticated tunnel gateway, не public endpoint;
  UDP остаётся first-flight probe.
- RU/EN UI и выбор языка в приложении. Как на Android, default English на каждом
  устройстве: приложение не следует системной локали.
- Карточка свойств появляется только при Connected и следует общим решениям
  `ProtectionSummary`: wire mode/transport, hybrid-PQ или plain X25519, pinned key
  или TOFU, предупреждение вместо фактов при сужении туннеля. Детали показывают
  выданные IP/DNS/MTU, bonded streams и adaptive ramp, routes, действующие
  padding/heartbeat/shaping. Список routes ограничен в `PushedFacts.routeSample`,
  потому что сервер способен выдать произвольный объём. Session token не выводится:
  это credential для присоединения bonded stream.
- Импорт flat INI из файла/clipboard, QR и `qeli://` deep link. Legacy JSON как
  конфиг отклоняется; JSON остаётся в backup/diagnostics/internal ABI. Активный
  профиль редактируется, но изменения требуют ручного reconnect.
- Share link, генерация QR и системный share sheet.
- Шифрование профилей на диске и совместимый с Android шифрованный backup.
- Тема, auto-connect при запуске, VPN On Demand, LAN bypass только full tunnel,
  настройки меток времени логов.
- Очистка логов при disconnect включена по умолчанию, как на Android. iOS сразу
  сохраняет настройку, extension применяет её при нормальном stop без UI.
  Startup/authentication/transport errors всегда сохраняют journal. Reconnect и
  возобновляемые network/On Demand pauses сохраняют историю; поздние callbacks
  старой сессии не воссоздают очищенный журнал. Новые storage/settings XCTest
  требуют Xcode.
- Opt-in release check с privacy gate по Android public metadata flow.
- Network Extension manager/provider lifecycle и общий status/log channel.
- Production Packet Tunnel использует ABI 1.17 core для carrier diagnostics,
  optional path contracts ABI 1.12–1.14 и NOTICE/KICK ABI 1.15 общего Rust
  whole-client core Linux/Android/Windows/macOS. Rust владеет DNS/connect,
  plain/hybrid-PQ authentication, TCP/UDP/QUIC/obfs/REALITY, packet crypto,
  heartbeat/shaping, MTU discovery, fixed/adaptive bonding, общей TCP/UDP roaming
  policy. Swift владеет Apple path observer, path-scoped DNS/NAT64 probe,
  socket binding и requested excluded-route executor.
- Swift выполняет Apple platform operations: Keychain device/trust, настройки
  `NEPacketTunnelNetworkSettings`, lifecycle/status, ограниченные packet batches
  между `NEPacketTunnelFlow` и `qeli_client_tun_push/pull`. `NetworkPlan` получает
  ACK только после применения всех active-family IPv4/IPv6 routes и поддержанного
  DNS; неподдержанный plan отклоняется безопасно.
- UI authenticated `NetworkPlan` различает pushed server routes и local/client
  routes; показывает effective post-push padding/heartbeat/shaping без Swift
  parsing handshake payloads.
- Восемь старых Swift handshake/transport/runtime files, 4,046 строк, удалены
  из production target. Оставшиеся Swift crypto/protocol — conformance/KAT code,
  исключённый из Packet Tunnel.
- Фиксированный memory budget packet bridge: два Rust pools по 32 × 65,535 байт,
  всего 4,194,240 байт, очереди 128 slots, не более трёх reusable caller buffers
  Swift по 256 КиБ, backpressure без fallback allocations в packet path.
  Отдельная diagnostics sampling использует максимум 64 КиБ native JSON с
  ограниченными decoding/storage.
- `build_native.sh` по умолчанию строит device/simulator с
  `transport-core-ffi experimental-roaming`, упаковывает canonical ABI header и
  XCFramework. CI собирает его, generated Xcode project для simulator и unit tests.
  Подписанная device build и реальный runtime pass остаются невыполненными.
- `NWPathMonitor` игнорирует tunnel/loopback и передаёт generation-scoped path/wake.
  UDP `NWConnection` с `requiredInterface` получает effective local/remote endpoints
  после DNS/NAT64. PREPARE сохраняет old+new exact carrier exclusions, BIND
  применяет Darwin interface/source binding к borrowed socket, COMMIT оставляет
  new-only routes, ABORT восстанавливает old-only. Обычный TCP и все UDP modes
  используют эту Rust transaction. Явные `local`/non-zero `lport`, old/default cores
  и unsupported peers выполняют обычный reconnect.
- WidgetKit status widget с authenticated App Intent и iOS 18 Control Center /
  Lock Screen / Action button control. Toggle управляет установленным туннелем
  из widget process без foregrounding приложения, как Android widget/Quick Settings.
  При недоступном туннеле запрос ставится в очередь до следующего запуска приложения.
- Reader managed app configuration и корректно описанные Per-App VPN / IKEv2
  Always On [MDM-шаблоны](../manuals/IOS-MDM.md).

## Оставшиеся этапы проверки

1. Собрать feature-enabled Rust XCFramework ABI 1.17 и generated project на
   macOS/Xcode 16+, app и Packet Tunnel. Строгий Rust cross-target Clippy
   `aarch64-apple-ios` прошёл Linux lab, но не заменяет Swift/NetworkExtension build.
2. Выполнить device interop всех Android/server wire modes: packet loss,
   Wi-Fi/cellular, wake, same-network NAT rebinding, NAT64, rollback маршрутов,
   per-app/MDM и bonded-stream failures.
3. Измерить device memory/backpressure/throughput/UDP loss/MTU packet pump.
   Buffer/queue tuning — отдельный performance pass после architecture migration.
4. Завершить App Store signing/provisioning и Apple Network Extension entitlement
   approval финальных bundle IDs. Runtime capability check превращает неверную
   переподпись в одно actionable signing alert вместо серии Keychain/Network
   Extension errors; `scripts/verify_ios_ipa.py` отклоняет такой IPA до поставки.

## Ограничения обычного consumer-приложения iOS

- В protection card нет Apps / Always-on buttons Android. Per-app routing требует
  MDM, Always-On switch приложение предлагать не может. Ближайший аналог —
  VPN On Demand в Settings; карточка показывает routing scope, controls находятся
  там, где они реализованы. System lockdown row также только Android:
  `VpnService.isLockdownEnabled` не имеет iOS counterpart, доступного Packet Tunnel Provider.
- Правила произвольных приложений требуют MDM-managed apps; consumer VPN не может
  перечислить установленные приложения. `apps_mode` сохраняется, **но не применяется**.
  Карточка определяет scope по enforced routes, а не по этому полю, и предупреждает
  о неиспользуемом выборе. Android использует apps_mode для scope непосредственно,
  поскольку там правило действует: это намеренное различие одного профиля.
- Настоящий Always-On VPN требует supervised MDM и IKEv2 Always On Apple;
  custom Packet Tunnel Provider Qeli этот enforcement mode недоступен. Для
  consumer Qeli VPN On Demand ближе всего к Android boot auto-connect.
- Нет Android battery-optimization exemption flow или foreground service.

## Аудит исходников Q30, 6 октября 2026

[MDM/provider callback fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-POLICY-SNAPSHOT.md)
отклоняют truncated numeric policy и invalidated stale replies при смене туннеля.
Шесть новых XCTest сохранены, но NOT_RUN на Windows; шесть Python IPA-verifier
fixture regressions — PASS. Это не simulator/device qualification. На этом этапе
Q30 IN_PROGRESS; Apple runtime исключён пользователем.

[Keychain fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-KEYCHAIN.md) распространяют
first-writer ownership master key на device ID/TOFU и явно проверяют stored key
sizes. Семь Keychain XCTest — NOT_RUN, cross-process/runtime claim отсутствует.
Provider/engine completion review на этом этапе открыт.

Malformed/stale explicit provider profile requests отклоняются без fallback
к persisted profile, Q30-F294; четыре новых selector XCTest — NOT_RUN.

[Lifecycle fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-LIFECYCLE.md) делают Stop
монитора terminal, ограничивают provider effects current engine и сериализуют
OS operations разных engines через callback-owned leases и общий 15s budget.
13 helper XCTest — NOT_RUN; OS callback drain/memory/native joins/Apple build
не квалифицированы. Отмена не равна завершению операции ОС.

[Application preference fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-APP-PREFERENCES.md)
устраняют пять status/epoch bypasses, сериализуют managed reconciliation.
Settings читаются при admission; generations и Task cancellation отсекают старые
preference steps. Три gate XCTest — NOT_RUN; Apple runtime исключён.
На этом этапе Q30 IN_PROGRESS, provider-message/backup UI и final source review открыты.

[Messages/backup fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-MESSAGES-BACKUP.md)
ограничивают caller wait settings-message до 20s, защищают response ownership,
допускают один unfinished snapshot poll на status epoch. Backup password
фиксируется на запрос, filename определяется реальными bytes. 11 XCTest —
NOT_RUN. Timeout не отменяет/откатывает OS apply; final memory/dead-code review
на этом этапе ещё открыт.

F302 переносит Swift wire-crypto helpers вместе с Protocol из app target в XCTest
и удаляет неиспользуемые X25519/auth helpers. Backup продолжает использовать
CryptoKit; Rust/native crypto не меняется. Xcode build и binary-size effects — NOT_RUN.

[Source/memory reconciliation](../reports/audit-0.8.2/AUDIT-Q30-IOS-SOURCE-MEMORY.md)
закрывает source Review/dead-code: 92 Swift inputs, 12 framework entry points.
F303–F306 унифицируют probe ownership, удаляют obsolete pings, ограничивают logs
4 КиБ/message и 1 МиБ encoded archive, update stream 1 МиБ. 11 XCTest — NOT_RUN;
реальные Apple callbacks/RSS/leaks/worker joins не квалифицированы. Q30 на этом
этапе IN_PROGRESS; source closure заменяет только прежнее open-review wording.

**Согласование объёма 12 октября:** Q30 SOURCE REVIEW и portable checks завершены;
Swift/Xcode/Apple execution — USER_SKIPPED по прямому решению пользователя.
XCTest, реальные callbacks/RSS/leaks/signing и physical network scenarios — NOT_RUN.
92 Swift inputs соответствуют reviewed inventory: 91 byte-identical, один
исправленный test profile; project.yml получил только LICENSE/notices resources.
Свежие IPA-verifier 6, plist 10, bindings и read-only-overlay docs 9 — PASS.
Это заменяет историческое IN_PROGRESS всего раздела; Apple runtime PASS не заявляется.

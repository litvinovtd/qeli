# qeli 0.8.0 (beta) — IPv6, session roaming and a new packet data plane

> ⚠️ **Beta — may be unstable.** The **1.0** line will be the first stable one.
>
> ⚠️ **Бета — возможна нестабильность.** Стабильной станет линейка **1.0**.

**Release candidate prepared · Кандидат подготовлен:** 2026-08-31

**Language · Язык:** [English](#english) · [Русский](#русский) ·
[Artifacts](#artifacts--артефакты)

This document describes the fundamental changes since `v0.7.16`. The canonical itemised history,
including smaller fixes, is available in [CHANGELOG.md](../CHANGELOG.md).

---

## English

qeli 0.8.0 is not a collection of isolated fixes. It changes the foundation on which transports,
sessions and routes are built: IPv6 becomes a first-class network family, a VPN session can survive
a change of physical path, and encrypted record formation is no longer tied one-to-one to IP packet
boundaries. Reality transport also moves to a genuine TLS 1.3 and HTTP/2 carrier.

### Why 0.8.0 instead of 0.7.17

A `0.7.17` version would imply another compatible patch within the same operating model. This
release introduces a new capability-negotiated data plane, a new session/path lifecycle, dual-stack
server configuration and a new native-core ABI. These are platform-wide capabilities shared by the
server, mobile and desktop applications, router clients and the administration layer—not local bug
fixes in one component.

The release remains `0.8.0`, rather than `1.0`, because qeli is still in beta and the rollout is
designed to preserve mixed-version operation. Legacy clients can continue through negotiated
fallback or reconnect, existing profiles are not silently rewritten, and the new recordizer and
roaming policies can be introduced gradually. The minor-version bump signals a substantial new
architecture while the compatibility controls keep it short of a deliberately breaking major
release.

### IPv6 becomes a first-class network layer

IPv6 is no longer treated as an optional address attached to an IPv4-oriented tunnel. It now
participates in configuration validation, address allocation, route ownership, DNS, PMTU discovery,
fail-closed decisions and platform path changes on the same terms as IPv4.

- New server templates are dual-stack. Every profile receives an IPv4 pool and a separate IPv6 ULA
  `/64`, with NAT44 and NAT66 support and DNS listeners for both address families.
- The installer checks for a real IPv6 default route, a usable WAN interface, a public GUA and
  `ip6tables` NAT support. When the host is suitable, it generates a random RFC 4193 Global ID and a
  unique ULA `/48`; when it is not, installation safely falls back to IPv4-only operation.
- Existing configurations are intentionally left unchanged. IPv6 is enabled through an explicit
  migration, including the tunnel address family, IPv6 pool, NAT66/routing and DNS listener. This
  prevents an upgrade from unexpectedly taking ownership of IPv6 traffic.
- Route-family mismatches and unsafe path updates fail closed. The same IPv4/IPv6 contract is used by
  Linux, Windows, macOS, Android, iOS and router clients.

The result is a real dual-stack VPN path rather than IPv6 traffic being leaked, ignored or handled by
platform-specific exceptions. See the [IPv6 guide](../docs/eng/manuals/IPV6.md) for deployment and
migration details.

### Roaming separates the session from the connection

Previously, changing Wi-Fi, mobile data, NAT mapping or another uplink normally meant losing the
carrier and establishing a new VPN session. In 0.8.0 the authenticated session has its own lifetime
and can move to a new network path without being equated with one TCP connection or UDP tuple.

- Roaming is negotiated by the shared Rust core for ordinary TCP and all UDP camouflage modes.
  Clients expose `off`, `auto` and `required` policies; `required` rejects an incomplete peer or
  platform contract before credentials and full authentication are sent.
- TCP uses make-before-break with a two-phase path commit. The old carrier stays active until the new
  path is established, applied by the platform and acknowledged. An ambiguous post-commit state is
  terminated and recovered by a clean reconnect rather than left as a traffic black hole.
- UDP migration uses authenticated epochs and a bounded pre-commit queue. It accepts NAT rebinding
  and reordered traffic while rejecting stale paths and unbounded buffering.
- Android and iOS feed physical-network changes into the same generation state machine used by the
  desktop platforms. If a platform or native core cannot prove that a path switch succeeded, qeli
  falls back to reconnect instead of reporting a migration that did not happen.

Newly generated server profiles enable roaming with bounded limits and clients default to
`roaming = auto`. Existing profiles keep roaming disabled when `roaming.enabled` is absent, so the
feature is never activated silently. The full state and compatibility contract is documented in the
[roaming plan](../docs/eng/plans/ROAMING.md).

### Recordizer changes traffic morphology across transports

`PACKET_MUX_V1`, referred to as the recordizer, adds a negotiated layer between TUN packets and the
selected TCP or UDP carrier. It removes the observable structural rule that one incoming IP packet
must produce one qeli encrypted record.

The recordizer can batch several packets into one record, emit partial or full records, and split a
large packet across several encrypted records before reconstructing it at the peer. Batching and
reassembly are strictly bounded. The outer transport remains unchanged, so the same mechanism works
across all supported TCP and UDP camouflage modes rather than being a feature of one carrier.

Recordizer parameters are authenticated and supplied by the server during negotiation; no new
client secret or qeli-link field is needed. The rollout policies are:

- `off` — retain the legacy packet-to-record mapping;
- `prefer` — use `PACKET_MUX_V1` when both peers support it and preserve rolling compatibility;
- `required` — reject peers without the new data plane after the fleet has been upgraded.

Shipped profiles use `prefer`. Recordization reduces a transport-independent packet-boundary
fingerprint, but it is not presented as making traffic undetectable.

### Reality gets a genuine HTTP/2 carrier

The `reality-tls` mode now uses an actual TLS 1.3 connection with ALPN `h2`, standard HTTP/2 framing
and one long-lived bidirectional POST stream. Random short batching is performed within real H2
frames, while qeli PacketCodec AEAD remains as the authenticated payload layer. The redundant inner
fake-TLS handshake and framing are removed.

This matters operationally as well as on the wire: the qeli heartbeat is unnecessary for this
carrier, traffic shaping can operate on genuine H2 frames, and the transport has one clear framing
model instead of nested imitations. A 0.8.0 server still accepts the legacy Reality carrier, but the
new client is H2-only and does not downgrade. Therefore the server must be upgraded first. Reality/H2
also requires transparent TCP pass-through to qeli; TLS termination, H2 conversion or HTTP routing
by an intermediate reverse proxy breaks authentication.

### What this gives qeli

Together, these changes move qeli from a tunnel whose lifetime and packet shape are largely defined
by one connection into a unified cross-platform transport system. The server and every client family
now share the same model of address families, session generations, path migration and encrypted
record formation.

In practical terms, this gives qeli:

- **real dual-stack operation** — IPv4 and IPv6 follow one validated routing and fail-closed policy,
  reducing the risk of IPv6 bypasses and platform-specific behaviour;
- **continuity while the network changes** — an authenticated session can survive switching between
  Wi-Fi, mobile data, NAT mappings and other uplinks, reducing visible interruptions and repeated full
  reconnects;
- **transport-independent traffic morphology** — recordization removes the fixed relationship
  between an IP packet and an encrypted record across all supported carriers, rather than improving
  only one camouflage mode;
- **one implementation of critical behaviour** — the shared Rust core keeps roaming, PMTU, path
  ownership and compatibility decisions consistent across desktop, mobile and router clients;
- **a controlled evolution path** — capability negotiation, `prefer` policies and fail-closed
  `required` modes allow new protocol behaviour to be deployed server-first without cutting off the
  existing fleet;
- **a foundation for future transports** — new carriers can reuse the same session, routing and
  recordization layers instead of implementing their own platform-specific data plane.

For users, the visible result is a more stable connection during movement between networks, correct
IPv6 tunnelling and more consistent behaviour across devices. For operators, it is predictable
rollout, explicit compatibility controls and aggregate transport/roaming health in the panel without
exposing session identifiers, proofs or secrets.

Supporting application work exposes these capabilities safely: profile editors understand roaming
policy, while Windows per-app routing preserves direct traffic outside selected processes. Routing,
PMTU handling, configuration validation and recovery were strengthened around the new architecture;
detailed individual changes remain in the changelog.

### Upgrade order

1. Upgrade the server and run `qeli check-config` before restarting it.
2. Keep `obf.recordizer.policy = prefer` during a mixed-version rollout. Reconnect clients so the
   authenticated capability negotiation is repeated.
3. Migrate existing profiles to IPv6 explicitly only after validating host IPv6 and NAT66 support.
4. Update applications and native cores, then test IPv4, IPv6 and network switching on the platforms
   used by the deployment.
5. Enable `roaming = required` or recordizer `required` only after every required peer and platform is
   known to support the complete contract.

For all configuration fields see the [configuration reference](../docs/eng/manuals/CONFIG.md) and
[transport-core reference](../docs/eng/reference/TRANSPORT-CORE.md).

### Release verification

The current source passed the Rust workspace, CLI/configuration, dependency-policy, jemalloc and
Linux compatibility gates. The Linux IPv6 base matrix passed 14/14 cases. Native cores were rebuilt for Android
arm64-v8a/x86_64, Windows x64 and macOS universal2; the platform/ABI pairs were verified for
reproducibility.

This is not yet a release-readiness claim. The files currently stored in `release/dist/v0.8.0`
predate the final H2/native-core changes and must be rebuilt before publication. Android signing,
macOS signing/notarization, final Windows/OpenWrt/Keenetic packages, the special IPv6 cases and the
physical roaming/IPv6 matrix must be verified again against one final commit.

---

## Русский

qeli 0.8.0 — это не набор отдельных исправлений. В этой версии меняется основа, на которой построены
транспорты, сессии и маршрутизация: IPv6 становится полноценным семейством сети, VPN-сессия может
переживать смену физического пути, а формирование шифрованных записей больше не привязано один к
одному к границам IP-пакетов. Транспорт Reality также переведён на настоящий TLS 1.3 и HTTP/2.

### Почему 0.8.0, а не 0.7.17

Номер `0.7.17` означал бы очередное совместимое исправление в рамках прежней модели работы. Этот
релиз добавляет новый согласуемый data plane, новый жизненный цикл сессии и сетевого пути,
dual-stack-конфигурацию сервера и новую ABI нативного ядра. Это общие возможности всей платформы —
сервера, мобильных и настольных приложений, роутерных клиентов и панели, — а не локальные исправления
одного компонента.

При этом версия остаётся `0.8.0`, а не `1.0`: qeli всё ещё находится в бета-стадии, а обновление
спроектировано для смешанного парка версий. Старые клиенты продолжают работать через согласованный
fallback или переподключение, существующие профили не переписываются молча, recordizer и роуминг
можно включать поэтапно. Повышение минорной версии подчёркивает существенную смену архитектуры, а
механизмы совместимости не превращают её в намеренно ломающий major-релиз.

### IPv6 становится полноценным сетевым уровнем

IPv6 больше не рассматривается как необязательный адрес внутри IPv4-ориентированного туннеля. Теперь
он наравне с IPv4 участвует в проверке конфигурации, распределении адресов, владении маршрутами, DNS,
определении PMTU, fail-closed-решениях и смене пути на каждой платформе.

- Новые серверные шаблоны работают в dual-stack. Каждый профиль получает IPv4-пул и отдельную IPv6
  ULA-подсеть `/64`, поддержку NAT44 и NAT66, а также DNS-listener для обоих семейств адресов.
- Установщик проверяет реальный IPv6 default route, пригодный WAN-интерфейс, публичный GUA-адрес и
  поддержку NAT в `ip6tables`. На подходящем сервере он генерирует случайный RFC 4193 Global ID и
  уникальную ULA-сеть `/48`; если необходимых условий нет, установка безопасно остаётся IPv4-only.
- Существующие конфигурации намеренно не изменяются автоматически. IPv6 включается явной миграцией:
  задаются семейство адресов туннеля, IPv6-пул, NAT66/маршрутизация и DNS-listener. Поэтому обновление
  не начинает неожиданно перехватывать IPv6-трафик.
- Несовпадения семейств маршрутов и небезопасное обновление пути завершаются fail-closed. Linux,
  Windows, macOS, Android, iOS и роутерные клиенты используют один контракт IPv4/IPv6.

В результате qeli предоставляет настоящий dual-stack VPN-путь, а не пропускает IPv6 мимо туннеля и
не полагается на отдельные исключения каждой платформы. Порядок развёртывания и миграции описан в
[руководстве по IPv6](../docs/ru/manuals/IPV6.md).

### Роуминг отделяет сессию от соединения

Раньше смена Wi-Fi, мобильной сети, NAT mapping или другого uplink обычно означала потерю carrier и
создание новой VPN-сессии. В 0.8.0 аутентифицированная сессия имеет собственный жизненный цикл и может
переехать на новый сетевой путь, не будучи жёстко привязанной к одному TCP-соединению или UDP tuple.

- Роуминг согласуется общим Rust-ядром для обычного TCP и всех UDP camouflage modes. На клиенте есть
  политики `off`, `auto` и `required`; `required` отклоняет неполный контракт peer или платформы до
  отправки credentials и полной аутентификации.
- TCP использует make-before-break и двухфазную фиксацию пути. Старый carrier остаётся активным, пока
  новый путь не установлен, не применён платформой и не подтверждён. Неоднозначная post-commit ошибка
  завершает generation и запускает чистое переподключение, а не оставляет соединение в blackhole.
- Миграция UDP использует аутентифицированные epoch и ограниченную очередь до commit. Она корректно
  обрабатывает смену NAT mapping и переупорядочивание трафика, отклоняя устаревшие пути и не допуская
  неограниченного накопления данных.
- Android и iOS передают смену физической сети в ту же generation state machine, что используется на
  desktop-платформах. Если платформа или native core не может подтвердить успешную смену пути, qeli
  выполняет reconnect, а не сообщает о миграции, которой фактически не произошло.

Новые серверные профили включают роуминг с ограниченными лимитами, а клиенты по умолчанию используют
`roaming = auto`. В существующем профиле отсутствие `roaming.enabled` по-прежнему означает `false`,
поэтому функция не активируется молча. Полный контракт состояний и совместимости приведён в
[плане роуминга](../docs/ru/plans/ROAMING.md).

### Recordizer меняет морфологию трафика для всех транспортов

`PACKET_MUX_V1`, или recordizer, добавляет согласуемый слой между пакетами TUN и выбранным TCP- или
UDP-carrier. Он устраняет структурное правило, при котором один входящий IP-пакет обязательно
превращался ровно в одну шифрованную запись qeli.

Recordizer может объединить несколько пакетов в одну запись, формировать полные и частичные записи,
а также разделить большой пакет между несколькими шифрованными записями и восстановить его на другой
стороне. Batching и reassembly имеют строгие лимиты. Внешний транспорт при этом не меняется, поэтому
механизм одинаково работает во всех поддерживаемых TCP- и UDP-режимах маскировки, а не принадлежит
только одному carrier.

Параметры recordizer приходят от сервера внутри аутентифицированного согласования; новый секрет или
поле qeli-ссылки клиенту не требуется. Для поэтапного внедрения предусмотрены политики:

- `off` — сохранить прежнее соответствие пакетов и записей;
- `prefer` — использовать `PACKET_MUX_V1`, когда его поддерживают обе стороны, сохраняя rolling
  compatibility;
- `required` — отклонять peer без нового data plane после обновления всего парка.

Поставляемые профили используют `prefer`. Recordizer снижает транспортно-независимый fingerprint по
границам пакетов, но это не заявляется как полная неразличимость трафика.

### Reality получает настоящий HTTP/2 carrier

Режим `reality-tls` теперь использует реальное TLS 1.3-соединение с ALPN `h2`, стандартный HTTP/2
framing и один долгоживущий двусторонний POST stream. Короткий случайный batching выполняется внутри
настоящих H2 frames, а PacketCodec AEAD qeli остаётся аутентифицированным слоем полезной нагрузки.
Лишние внутренние fake-TLS handshake и framing удалены.

Это важно не только для вида трафика, но и для эксплуатации: собственный heartbeat qeli для этого
carrier больше не нужен, shaping работает с настоящими H2 frames, а вместо вложенных имитаций остаётся
одна понятная модель framing. Сервер 0.8.0 продолжает принимать прежний Reality carrier, однако новый
клиент работает только через H2 и не выполняет downgrade. Поэтому первым обязательно обновляется
сервер. Reality/H2 также требует прозрачного TCP pass-through до qeli: TLS termination, H2 conversion
или HTTP routing на промежуточном reverse proxy ломают аутентификацию.

### Что это даёт qeli

Вместе эти изменения превращают qeli из туннеля, жизненный цикл и форма трафика которого в основном
определялись одним соединением, в единую кроссплатформенную транспортную систему. Сервер и все
семейства клиентов теперь используют общую модель семейств адресов, поколений сессии, миграции пути
и формирования шифрованных записей.

На практике qeli получает:

- **настоящую dual-stack-работу** — IPv4 и IPv6 подчиняются одной проверяемой политике маршрутизации
  и fail-closed, что снижает риск обхода туннеля через IPv6 и различий между платформами;
- **непрерывность при смене сети** — аутентифицированная сессия может пережить переход между Wi-Fi,
  мобильной сетью, разными NAT mapping и другими uplink, сокращая заметные разрывы и повторные полные
  подключения;
- **независимую от транспорта морфологию трафика** — recordizer убирает фиксированную связь между
  IP-пакетом и шифрованной записью во всех поддерживаемых carrier, а не улучшает только один режим
  маскировки;
- **единую реализацию критической логики** — общее Rust-ядро одинаково управляет роумингом, PMTU,
  владением сетевым путём и совместимостью на настольных, мобильных и роутерных клиентах;
- **контролируемое развитие протокола** — согласование возможностей, политика `prefer` и fail-closed
  режим `required` позволяют сначала обновить сервер и постепенно внедрить новое поведение, не
  отключая существующий парк клиентов;
- **основу для следующих транспортов** — новые carrier смогут использовать готовые слои сессии,
  маршрутизации и recordizer вместо отдельного platform-specific data plane.

Для пользователя итогом становятся более стабильное соединение при переходах между сетями,
корректное туннелирование IPv6 и одинаковое поведение на разных устройствах. Для оператора —
предсказуемое поэтапное обновление, явное управление совместимостью и агрегированное состояние
транспорта/роуминга в панели без идентификаторов сессий, proof и секретов.

Сопутствующие изменения приложений безопасно открывают эти возможности: редакторы профилей понимают
политику роуминга, а Windows per-app сохраняет прямой трафик процессов вне выбранного списка.
Маршрутизация, PMTU, проверка конфигурации и восстановление усилены вокруг новой архитектуры; полный
перечень небольших изменений остаётся в changelog.

### Порядок обновления

1. Сначала обновите сервер и перед рестартом выполните `qeli check-config`.
2. Во время работы смешанного парка версий оставьте `obf.recordizer.policy = prefer`. Переподключите
   клиентов, чтобы аутентифицированное согласование возможностей выполнилось заново.
3. Переносите существующие профили на IPv6 только явно и после проверки IPv6/NAT66 на хосте.
4. Обновите приложения и native cores, затем проверьте IPv4, IPv6 и смену сети на используемых
   платформах.
5. Включайте `roaming = required` или recordizer `required` только после подтверждения полного
   контракта на всех обязательных peer и платформах.

Все параметры приведены в [справочнике конфигурации](../docs/ru/manuals/CONFIG.md) и
[описании transport core](../docs/ru/reference/TRANSPORT-CORE.md).

### Проверка релиза

Текущие исходники прошли release gates Rust workspace, CLI/configuration suites, dependency policy,
jemalloc и совместимости Linux. Базовая IPv6-матрица Linux прошла 14/14 сценариев. Native cores
пересобраны для Android arm64-v8a/x86_64, Windows x64 и macOS universal2; пары platform/ABI
проверены на воспроизводимость.

Это ещё не утверждение о готовности релиза. Файлы в `release/dist/v0.8.0` собраны до последних
изменений H2/native core и должны быть пересобраны перед публикацией. Android signing, macOS
signing/notarization, финальные Windows/OpenWrt/Keenetic-пакеты, специальные IPv6-сценарии и
физическая roaming/IPv6-матрица должны быть повторно проверены на одном финальном коммите.

---

## Artifacts · Артефакты

The directory currently contains a **pre-hardening snapshot** of 17 payloads. Its `SHA256SUMS`
matches those files, but they are not publishable as the final 0.8.0 build and the table is retained
only to identify the snapshot that must be replaced. Каталог сейчас содержит **снимок до финального
hardening** из 17 файлов. Его `SHA256SUMS` соответствует файлам, но это не финальная публикуемая
сборка 0.8.0; таблица сохранена только для идентификации кандидата, который требуется заменить.

| Artifact | Size | SHA-256 (first 16) |
|---|---:|---|
| `qeli-android-0.8.0.apk` | 9.6 MB | `2741450f4e55a84e` |
| `qeli-linux-amd64` | 12.5 MB | `5b7d3a0ba3512516` |
| `qeli_0.8.0_amd64.deb` | 4.0 MB | `4193d1ed182d8036` |
| `Qeli-macOS-universal.zip` | 57.9 MB | `55690faa05f9839c` |
| `QeliWin-net-required.exe` | 7.9 MB | `b5341871f7105124` |
| `QeliWin-standalone.exe` | 72.7 MB | `23f33967dbc9ed6e` |
| `qeli-client-keenetic-aarch64` | 3.9 MB | `0583c37c5e3f7d04` |
| `qeli-client-keenetic-mipsel` | 5.6 MB | `8fc2bfe18038e4c6` |
| `qeli-client-openwrt-aarch64` | 3.9 MB | `0583c37c5e3f7d04` |
| `qeli-client-openwrt-armv7` | 4.1 MB | `82e02f0ffc9744d0` |
| `qeli-client-openwrt-mipsel` | 5.6 MB | `8fc2bfe18038e4c6` |
| `qeli-client-openwrt-x86_64` | 4.6 MB | `641a74ac938b8e8b` |
| `qeli-openwrt-files.tar.gz` | 12.7 KB | `be01d128f7d0c241` |
| `install-keenetic.sh` | 2.3 KB | `fa12354977d6a81e` |
| `Wintun-LICENSE.txt` | 5.3 KB | `9aaf948856ce8845` |
| `WinDivert-LICENSE.txt` | 61.3 KB | `c00a04bf0dcca8f7` |
| `WinDivert-NOTICE.txt` | 0.3 KB | `8018c935ccc84a54` |

The Keenetic/OpenWrt aarch64 pair and the Keenetic/OpenWrt mipsel pair are intentionally
byte-identical. Полностью совпадающие хеши этих пар являются ожидаемым результатом.

### Candidate handling · Работа с кандидатом

Do not publish or install this snapshot as the final release. Rebuild every payload from the final
commit, regenerate `SHA256SUMS`, then complete signing and certification. Не публиковать и не
устанавливать этот снимок как финальный релиз: сначала пересобрать все файлы из финального коммита,
обновить `SHA256SUMS`, затем завершить подпись и сертификацию.

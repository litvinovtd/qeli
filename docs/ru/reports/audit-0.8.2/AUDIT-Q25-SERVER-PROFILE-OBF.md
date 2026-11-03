# D07: поля obf.* серверного профиля

1 октября 2026. Сверены 59 уникальных ключей `obf.*` из TCP/UDP [fixture](../../../../scripts/gen_roundtrip_fixture.py) с [INI-кодеком](../../../../qeli/src/config/server_ini.rs), общей [валидацией профиля](../../../../qeli/src/server/mod.rs), [TCP](../../../../qeli/src/server/handler.rs), [UDP](../../../../qeli/src/server/udp_handler.rs) и [генератором ссылок](../../../../qeli/src/config/share.rs). Это статическая трассировка потребителей; parse/serialize уже покрыты полным round-trip из Q25-F152.

| Семейство и число ключей | Фактическое применение и ограничение |
|---|---|
| `mode`, `obfs_key`, `obfs_fronting` — 3 | Wire handshake; ключ обязателен для obfs. WebSocket fronting относится к TCP obfs; UDP не выполняет TCP nonce exchange. Plain и reality-tls на UDP отвергаются. |
| `tls.server_name` и `tls.reality_proxy.*` — 8 | `server_name` не управляет серверным listener: он нужен share-ссылке без REALITY. Для REALITY decoy target, port, short IDs, real TLS, handrolled и peek timeout используются в TCP proxy/terminator. При активном REALITY ссылка теперь берёт SNI из `reality_proxy.target`, даже если `server_name` остался другим. |
| `padding.*` — 5 | Условная проверка диапазона/вероятности, шифрование исходящих записей TCP/UDP и передача политики клиенту в AuthOK. |
| `fragmentation.*` — 4 | Фрагментация TCP wire-вывода; это не механизм UDP PMTU/DATA_FRAG. На UDP значения сохраняются как неактивные. |
| `heartbeat.*` — 4 | Проверка интервала, jitter и размера; TCP/UDP таймеры и AuthOK. Активный traffic shaping заменяет периодический heartbeat. |
| `traffic_normalization.*` — 2 | Проверка списка размеров; общая функция шифрования TCP/UDP добавляет padding до выбранного размера, настройки также передаются клиенту. |
| `traffic_shaping.*` — 9 | Проверка лимитов, Poisson idle cover на TCP/UDP и клиенте. `stealth`/скорость реально применяются только на TCP; обе UDP-стороны выключают stealth из-за измеренного ущерба пропускной способности. |
| `recordizer.*` — 14 | Проверка policy/batch/record/fragment, согласование способности клиента, TCP/UDP сборка и разбор записей. При policy=off параметры настройки остаются в INI, но не применяются. |
| `anti_fingerprinting.*` — 2 | TCP jitter handshake; на UDP значения хранятся, но TCP handshake отсутствует. |
| `awg.*` — 4 | TCP obfs junk и UDP junk перед handshake. На TCP fake-tls/reality-tls настройка не действует, валидатор предупреждает, share-ссылка её не рекламирует. |
| `multipath.*` — 3 | TCP bonding, cap/adaptive в AuthOK. На UDP один поток, валидатор предупреждает о неэффективной настройке. |
| `quic.enabled` — 1 | Только UDP QUIC-shaped оболочка; это совместимая маскировка, не полноценный QUIC/HTTP/3. Входящий UDP QUIC распознаётся и при выключенном флаге исходящего профиля; на TCP валидатор предупреждает о no-op. |

Обнаруженный дефект: при разных `tls.server_name` и `reality_proxy.target` генератор записывал в REALITY share-ссылку первый адрес, хотя прокси обращался ко второму. Исправлен общий источник `ClientLink::for_profile`, используемый CLI и панелью; ручной клиент по-прежнему должен задать SNI, совпадающий с target. Профильный `server_name` остаётся применим для ссылок без REALITY. На изолированной лабе `.11` прошли новый тест для fake-tls+REALITY, real-TLS и отсутствия REALITY с URI round-trip, все 12 тестов share-кодека, `cargo fmt --check` и строгий Clippy; сервисы не менялись.

Остаются смешанные save/reload/import сценарии D07 и гонка с внешним редактором, не использующим advisory lock. Статическая матрица не доказывает каждый сетевой вариант obf на работающем сервере.

Продолжение 2 октября: [Q25-F209 в реестре](../../plans/AUDIT-DEBT.md) закрывает смешанные API save/INI/history/Quick Start/archive/restart проверки D07 и фиксирует обязательный sidecar lock внешнего писателя. Исторические числа выше не являются новым прогоном. Сетевые комбинации и итоговая сертификация остаются D10/D15.

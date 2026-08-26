# qeli 0.8.0 (development) — Reality/H2 and PACKET_MUX migration notes

Дата документа: 2026-08-26. Это описание текущей dev-ветки, а не объявление опубликованного релиза.
Полный технический список изменений находится в [CHANGELOG](../CHANGELOG.md).

## Что изменилось

`reality-tls` после аутентифицированного TLS 1.3 теперь открывает настоящий HTTP/2 carrier:
один долгоживущий двунаправленный `POST /v1/events/stream`, ALPN `h2`, стандартные H2
SETTINGS/frames и случайный batching 2–8 мс. Прежнего второго fake-TLS handshake/framing внутри
внешнего TLS больше нет. Внутренний PacketCodec AEAD сохранён как defence-in-depth.

Пользовательского параметра для включения H2 нет: он автоматически является carrier режима
`reality-tls`. Старые `obf.http2_masking.*` выведены из эксплуатации и не должны добавляться в конфиг.

Во всех TCP- и UDP-режимах появился общий, серверно-конфигурируемый `PACKET_MUX_V1` recordizer.
После аутентификации он объединяет исходные IP-пакеты, меняет границы зашифрованных qeli-записей
и при необходимости фрагментирует один пакет между несколькими внутренними записями. Это не новый
transport mode и не H2-only функция: поверх него остаётся выбранный carrier — plain/fake-TLS,
REALITY/H2, obfs/WebSocket, UDP QUIC-shape или AWG.

Recordizer включается в каждом серверном профиле параметром:

```ini
obf.recordizer.policy = prefer
```

`prefer` согласует новую форму с обновлённым клиентом и оставляет legacy data-plane старому.
`required` отклоняет старого клиента до выдачи lease, а `off` полностью сохраняет старую форму.
Все параметры batch/record/fragment задаются на сервере и приходят клиенту в аутентифицированном
push; менять qeli-ссылки или добавлять клиентские recordizer-ключи не нужно. Полный список и
ограничения: [справочник конфигурации](../docs/ru/CONFIG.md).

## Как перейти

1. Сначала обновите серверный бинарник. Сохраните identity, ключи, SNI/target и остальные
   transport-параметры действующих профилей.
2. Добавьте `obf.recordizer.policy = prefer` во все профили, где нужна общая морфология, и
   перезапустите qeli. Остальные `obf.recordizer.*` можно не задавать: применятся defaults.
3. Для Reality убедитесь, что серверный профиль использует `obf.mode = reality-tls` с
   `obf.tls.reality_proxy.enabled = true` и `real_tls = true`; на клиенте используйте
   `mode = reality-tls`, тот же `reality_sid` и публичный ключ сервера в `key`. Старое
   серверное написание `obf.mode = fake-tls` с теми же Reality-флагами принимается для миграции.
4. Проверьте подключение старого клиента: при `prefer` он должен продолжить работу на legacy
   data-plane. Затем обновляйте клиентские бинарники/приложения. Новый сервер принимает и H2, и legacy
   Reality carrier. Новый клиент использует только H2 и не делает downgrade, поэтому обратный
   порядок может оставить его без связи со старым сервером.
5. Переподключите сессии: recordizer согласуется один раз на AUTH. После обновления всего парка
   при необходимости смените `prefer` на `required`; не делайте это раньше, если старые клиенты
   ещё должны подключаться. Для rollback верните `off` и снова переподключите сессии.
6. Bare `fake-tls` без Reality — отдельный carrier. Он получает тот же recordizer, но не получает
   настоящий TLS/H2 или защиту Reality от active probe; при необходимости держите отдельный профиль/порт.

Полные примеры: [сервер](reality-tls/server-reality.conf),
[клиент](reality-tls/client-reality.conf) и [справочник конфигурации](../docs/ru/CONFIG.md).

## Изменившиеся defaults и эксплуатация

- В поставляемых серверных Reality/max-obfuscation шаблонах `obf.heartbeat.enabled = false` и
  `obf.traffic_shaping.enabled = true`.
- H2 carrier принудительно отключает qeli heartbeat независимо от старого локального или pushed
  значения. Liveness обеспечивает транспорт; отдельные qeli heartbeat frames создавали бы телл.
- Для других режимов heartbeat работает как раньше, но интервал после активности/отправки каждый
  раз заново случайно выбирается в диапазоне `interval ± jitter` (шаблонный jitter — 5000 мс).
- Промежуточный reverse proxy/LB должен делать прозрачный TCP pass-through. TLS termination,
  H2 conversion или HTTP routing перед qeli ломают REALITY-аутентификацию и carrier.

## Как проверить

Ожидаемые маркеры:

- клиент: `REALITY-TLS carrier: genuine HTTP/2 stream`;
- сервер: `REALITY: genuine HTTP/2 carrier established`.

Проверьте `Auth OK`, двусторонний IPv4/IPv6-трафик, реконнект и отсутствие повторяющегося qeli
heartbeat в Reality/H2 capture. Для каждого TCP/UDP carrier отдельно проверьте, что при `prefer`
новый клиент согласует `PACKET_MUX_V1`, а legacy-клиент остаётся рабочим; при `required` legacy
клиент должен быть отвергнут до lease. Датированный lab PCAP завершил 6/6 H2-сессий; прежний classifier
совпал в 0/6 при 0/6 false positives на controls. Это результат конкретного стенда и classifier,
не проверка ещё не снятого общего recordizer по всем carriers, не обещание «0% обнаружения» и не
full-speed benchmark. Новая общая логика требует отдельного повторного PCAP/DPI corpus.

Отчёт: [Reality/H2 PCAP/DPI, 2026-08-26](dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md).
Остаточные задачи: browser-family TLS/H2 profiles, target-specific H2 SETTINGS, hostile active probes,
malformed/reconnect/long-lived сценарии, PCAP каждого recordizer/carrier сочетания, чистый
throughput-прогон и настоящий H3.

---

## English summary

Development 0.8.0 replaces the legacy inner fake-TLS Reality carrier with one genuine,
randomly batched H2 POST. Upgrade **server first**: a new server accepts both carriers, while a
new client is H2-only and does not downgrade. H2 is automatic and has no config switch. Shipped
Reality templates disable qeli heartbeat and enable shaping; the H2 path forcibly ignores an old
heartbeat request. The same release adds authenticated `PACKET_MUX_V1` record morphology to every
TCP/UDP mode. Put `obf.recordizer.policy = prefer` on the server for a staged rollout, update the
shared native core on clients, reconnect, and use `required` only after the fleet is upgraded; no
client recordizer keys are needed. Use transparent TCP pass-through in front of qeli. See the
configuration guide, CHANGELOG, and dated PCAP report above; the 6/6 lab result covers the H2
capture only and is not a universal detection probability.
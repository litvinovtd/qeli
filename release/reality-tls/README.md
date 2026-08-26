# reality-tls — REALITY TLS 1.3 + genuine HTTP/2 on :443

Этот каталог содержит готовую пару конфигов для актуального `reality-tls`. После
аутентифицированного браузероподобного TLS 1.3 qeli открывает настоящий HTTP/2 carrier:
один долгоживущий двунаправленный `POST /v1/events/stream` с ALPN `h2`, настоящими
SETTINGS/HEADERS/DATA и случайным batching 2–8 мс. Прежнего второго fake-TLS
handshake/framing внутри внешнего TLS больше нет; PacketCodec AEAD остаётся как
независимый внутренний слой защиты.

`handrolled=true` включает cert-borrowing и зеркалирование формы ServerHello/JA3S target'а.
Это уменьшает расхождения с сайтом-приманкой, но не означает полную идентичность браузеру,
Xray или конкретному target по всем TLS/H2/тайминговым признакам. Невалидные ClientHello
прозрачно мостятся на `target`.

Файлы:

- `server-reality.conf` — основной серверный профиль `reality-tls` на TCP :443;
- `client-reality.conf` — полный клиентский INI с `mode=reality-tls`.

Подробная история перехода: [release notes 0.8.0](../RELEASE_NOTES_0.8.0.md),
[CHANGELOG](../../CHANGELOG.md) и [CONFIG](../../docs/ru/CONFIG.md).

## Совместимость и порядок обновления

Обновляйте **сначала сервер, затем клиентов**. Новый сервер различает H2 и прежний
Reality carrier после внешнего TLS и принимает оба. Новый клиент использует только H2 и
не делает downgrade, поэтому со старым сервером он не подключится.

Это не означает, что любой bare `fake-tls` клиент стал совместим с Reality. Bare `fake-tls`
остаётся отдельным wire-режимом; при необходимости держите его на отдельном профиле/порту.
Канонический новый профиль задаёт `obf.mode = reality-tls`, `reality_proxy.enabled = true`
и `real_tls = true`. Legacy-написание серверного профиля через `obf.mode = fake-tls` с теми
же Reality-флагами временно принимается только для миграции.

## Конфиг

1. Создайте short_id: `openssl rand -hex 8`.
2. В `server-reality.conf` замените `REPLACE_WITH_OWN_SHORT_ID`, настройте `target`/SNI,
   пути identity/users и сеть TUN.
3. Получите публичный ключ: `qeli show-identity --config server-reality.conf`.
4. В `client-reality.conf` задайте endpoint, логин/пароль, тот же short_id в
   `reality_sid`, публичный ключ в `key` и SNI, совпадающий с target.
5. Проверьте оба файла через `qeli check-config` / `qeli check-config --client`.

H2 включается автоматически режимом `reality-tls`; отдельного H2-параметра нет.
Старые `obf.http2_masking.*` выведены из эксплуатации и не должны добавляться в конфиг.
В поставляемом профиле heartbeat выключен, shaping включён. Сам H2 path принудительно
игнорирует включённый qeli heartbeat, в том числе пришедший из старого pushed config.

REALITY-токен содержит timestamp с окном ±120 секунд. На сервере и клиентах должен работать
NTP; при большем рассинхроне настоящий клиент выглядит как probe и молча мостится на target.

## Проверка на стенде

1. Запустите новый сервер до обновления клиента.
2. Старым Reality-клиентом подтвердите legacy-совместимость.
3. Запустите новый клиент и найдите:
   - клиент INFO: `REALITY-TLS carrier: genuine HTTP/2 stream`;
   - сервер DEBUG: `REALITY: genuine HTTP/2 carrier established with <addr>`;
   - затем обычные `Server identity verified` и `Auth OK`.
4. Проверьте двусторонний IPv4/IPv6-трафик, реконнект и длительную сессию.
5. В PCAP должен быть настоящий TLS 1.3 с ALPN `h2`; после расшифровки тестовыми ключами —
   H2 preface/SETTINGS и один streaming POST, без второго fake-TLS handshake.
6. Probe без корректного токена должен получить настоящий target. Reverse proxy/LB перед qeli
   допустим только как прозрачный TCP pass-through: TLS termination, H2 conversion и HTTP routing
   ломают REALITY-аутентификацию/carrier.

Ошибки `REALITY HTTP/2 carrier timed out/failed` означают несовместимый или повреждённый H2
carrier после успешного Reality discriminator; сверяйте порядок обновления и отсутствие TLS/H2
терминации перед qeli.

Датированный lab PCAP: [6/6 завершённых H2-сессий, старый classifier 0/6](../dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md).
Это результат конкретного capture/classifier, не обещание «0% обнаружения» и не speed benchmark.
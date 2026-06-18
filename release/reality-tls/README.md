# reality-tls (настоящий REALITY) — дефолт на :443

Перевод qeli с **fake-tls** (мимикрия под TLS, но с DPI-теллами 1.1–1.6 из
[docs/DPI-AUDIT.md](../../docs/ru/DPI-AUDIT.md)) на **reality-tls** — настоящий
Chrome-грейд TLS 1.3 на проводе, который сервер терминирует и несёт qeli-туннель
внутри. С `handrolled=true` (дефолт в шаблоне ниже) сервер **одалживает настоящую
цепочку серта target'а** (cert-borrowing) + зеркалит JA3S — паритет с Xray-REALITY;
`handrolled=false` → rustls-путь с self-signed сертом. Код готов и протестирован
e2e (Rust/Android/Windows/macOS), но раньше нигде не включался по умолчанию (все
боевые конфиги были `fake-tls`).

**Дефолт — один основной профиль на :443 в режиме reality.** Другие профили/порты
включаются вручную отдельными секциями `[profile:...]` по необходимости.

Файлы рядом:
- `server-reality.conf` — основной профиль `maxobf` на :443 (`real_tls=true`,
  `handrolled=true` → cert-borrowing, `short_ids`).
- `client-reality.conf` — клиентский INI (`mode=reality-tls` + `reality_sid`).

## Важно про переключение живого :443

`real_tls=true` требует, чтобы КЛИЕНТ говорил `mode=reality-tls`. Старые fake-tls
клиенты на :443 перестанут подключаться сразу после включения — их нужно перевести
на `client-reality.conf`. Если нужен бесшовный поэтапный переход, временно поднимите
ВТОРОЙ профиль (старый fake-tls) на другом порту, мигрируйте клиентов по одному,
затем уберите его. По умолчанию же :443 = reality.

## Важно про часы (±120 с)

REALITY-токен несёт timestamp с окном **±120 секунд** (anti-replay). Если часы
клиента и сервера расходятся сильнее, сервер **молча** мостит клиента на target,
как чужого: симптом — «не подключается, ошибок нет», а `curl` до сервера
показывает настоящий сайт. На сервере и устройствах должна работать
автосинхронизация времени (NTP); чаще всего сбивается на Android без автовремени
и в VM после suspend. Подробнее — [docs/ru/CONFIG.md](../../docs/ru/CONFIG.md),
секция REALITY.

## Шаг 1. Лабораторный e2e (перед продом)

На лабе (.10/.11, см. [[reference_qeli_lab_build]]):

1. Сгенерировать свой short_id вместо примера: `openssl rand -hex 8` →
   подставить в `server-reality.conf` (`short_ids`) и `client-reality.conf`
   (`reality_sid`).
2. Собрать свежий бинарь: `cargo build --release` (на .10), задеплоить.
3. Запустить сервер с `server-reality.conf`, клиент с `client-reality.conf`.
4. Логи сервера: `REALITY: Qeli client detected ...` (токен опознан из
   real-ClientHello) + `REALITY real-TLS termination enabled` / `real TLS established`.
5. Клиент: `Wire mode: reality-tls` → `Server identity verified` → `Auth OK, IP …`.
6. `ping` сквозь туннель (0% loss), двусторонний трафик.
7. **tcpdump на :443** — настоящий TLS 1.3: record-типы `16 03` (CH/SH),
   `14 03` (CCS), `17 03` (зашифрованный flight + туннель), SNI =
   `www.microsoft.com`, сертификат **зашифрован** (не виден в ServerHello).
8. **Активный пробинг** без токена (`openssl s_client -connect host:443
   -servername www.microsoft.com`) → **прозрачно сброшен в реальный
   microsoft.com** (валидный серт), а не qeli-ответ.
9. Реплей перехваченного ClientHello в окне 120 c → лог
   `replayed session_id ... bridging as probe` (anti-replay).

## Шаг 2. Прод

1. Залить новый бинарь + `server-reality.conf` на боевой (YOUR_PROD_HOST).
   `systemctl restart qeli-server` (см. [[project_qeli_dpi_obfuscation]] —
   юнит `qeli-server.service`, не `qeli`).
2. Перевести клиентов на `client-reality.conf` (:443).
3. (Опционально) для бесшовности — временный fake-tls профиль на другом порту,
   как описано выше.

## qeli:// ссылка / QR

С момента закрытия пробела ссылка `qeli://` несёт `rsid=<short_id>`, так что
reality-tls можно раздавать QR-кодом (а не только полным INI). Сервер генерирует
ссылку с `rsid` автоматически (`/api/share`), когда у профиля задан `short_ids`.

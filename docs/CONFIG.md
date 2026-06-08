# Конфигурация qeli

## Формат: flat-INI (единственный; TOML/JSON выпилены)

Конфиги — **текстовый flat-INI**. Структура:

- Глобальные секции `[auth]`, `[web]`, `[logging]`.
- Один `[profile:<name>]` на интерфейс; вложенные поля структуры — **dotted-ключи**:
  `bind.port`, `tun.address`, `obf.tls.reality_proxy.enabled`, `perf.connection.max_clients`.
- Пользователи/группы — секции `[user:<name>]` / `[group:<name>]` (инлайн в
  серверном конфиге, либо в отдельном файле `auth.users_file`).
- Повторяемые ключи: `route = <cidr> gateway=<ip> metric=<n>`, `pool.exclude`,
  `pool.reservation.<user> = <ip>`.
- Клиентский конфиг — одна секция `[qeli]`; это же разворачивается из `qeli://`-ссылки
  (QR-импорт). Ключи INI ↔ query-параметры qeli://:
  `server`(host:port), `proto`(tcp|udp), `user`, `pass`, `key`(пиннинг, hex),
  `mode`(plain|fake-tls|obfs|reality-tls), `sni`, `obfs_key`(=`obfs` в ссылке),
  `reality_sid`(=`rsid` в ссылке — REALITY short_id для `reality-tls`),
  `front`(websocket|none — anti-FET fronting для obfs, дефолт websocket),
  `quic`(=`quic=1`/`true` — QUIC-маскировка для UDP; **обязателен для udpquic-профиля**,
  иначе клиент шлёт не-QUIC и сервер с `obf.quic.enabled` молчит),
  `dev`(имя TUN-интерфейса на клиенте, дефолт `vpn0` — **только в INI**, не в ссылке;
  задайте своё, если `vpn0` занят другим приложением или нужно поднять несколько клиентов
  на одном хосте; иначе клиент при старте «отбирает» существующий `vpn0`).
  *Замечание:* `quic`/`front` парсят все три клиента (Android, Windows, Rust-CLI) и эмитят
  серверные генераторы ссылок (`qeli add-client`, web `/api/share`).

> **⚠️ Комментарии — только на отдельной строке** (ведущий `#`). Inline-комментарий
> после значения (`port = 443  # https`) НЕ срезается и попадёт в значение.

Полные документированные примеры — [server.conf](../qeli/config/server.conf),
[client.conf](../qeli/config/client.conf), [users.conf](../qeli/config/users.conf),
[server-maxobf.conf](../qeli/config/server-maxobf.conf). Пути по умолчанию:
`/etc/qeli/server.conf`, `/etc/qeli/client.conf`, `/etc/qeli/users.conf`.
Структурное сохранение через Web-UI/control-CLI (`PUT /api/config`) перезаписывает
конфиг из serde-структур — комментарии при этом теряются. Чтобы их сохранить,
используйте **raw-редактор**: `GET /api/config/raw` отдаёт файл дословно, а
`PUT /api/config/raw` валидирует через `parse_server_config` и пишет текст **как
есть** (комментарии целы); в Web-UI это вкладка «Raw INI». Точная карта ключей —
`qeli/src/config/server_ini.rs` (сериализатор) и serde-структуры в `config/`.



## Дефолты профиля (INI применяет per-field — футган устранён)

В INI-загрузчике каждый профиль строится из `baseline_profile()` (скелет с
применёнными per-field serde-дефолтами), поверх которого накладываются заданные
ключи. Поэтому **опускать целые подсекции безопасно** — пропущенные ключи получают
реальные дефолты (`keepalive_secs=30`, `max_clients=64` и т.д.), а не нули.

Историческая справка (актуально было для старого TOML/JSON, где пропуск *всего
вложенного объекта* давал `Default::default()` = нули): пропуск `performance`
приводил к —

| Пропущено | Эффект |
|---|---|
| `performance.tcp.keepalive_secs` → 0 | `setsockopt(TCP_KEEPIDLE, 0)` → **EINVAL**, каждое TCP-соединение рвётся при установке |
| `performance.connection.handshake_timeout_secs` → 0 | таймаут рукопожатия = 0 → мгновенный таймаут, ни один клиент не подключится |
| `performance.connection.max_clients` → 0 | «max clients (0) reached» → отказ всем |

Значения зависят от развёртывания (канал, число клиентов, латентность), поэтому
**в коде они не захардкожены** — задавайте их в конфиге. Минимально рабочий
профиль:

```ini
[auth]
users_file = /etc/qeli/users.conf

[logging]
level = info
file = /var/log/qeli/server.log

[profile:tcp]
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.9.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.exclude = 10.9.0.1
routing.nat.enabled = true
routing.forward_private = true
dns.enabled = false
obf.mode = fake-tls
obf.padding.enabled = true
obf.padding.min_bytes = 32
obf.padding.max_bytes = 256
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
obf.heartbeat.jitter_ms = 2000
perf.tcp.nodelay = true
perf.tcp.keepalive_secs = 60
perf.tun.read_buffer_size = 65535
perf.connection.max_clients = 128
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 300
```

(Полный, исчерпывающе прокомментированный пример — [server.conf](../qeli/config/server.conf).)

## Многоядерность сервера (`tun.queues`)

По умолчанию дата-плоскость использует **все ядра**: per-connection шифрование/
дешифрование уже раскладывается по ядрам, а **`tun.queues`** (per-profile) задаёт число
очередей TUN (Linux `IFF_MULTI_QUEUE`) — сколько параллельных reader/writer-задач качают
интерфейс, чтобы и сама TUN-помпа (и пер-очередь encrypt) шла на нескольких ядрах, а не
через единую воронку.

```ini
[profile:tcp]
tun.queues = 0     # 0 = auto (= число ядер, по умолчанию); N = столько очередей; 1 = legacy одно-поточная помпа
```

- `0`/auto = `nproc` (рекомендуется). Зажато сверху 256 (потолок tun-очередей ядра
  Linux, `MAX_TAP_QUEUES`) — auto=nproc на реальных серверах не урезается.
- `1` = прежнее поведение (одна помпа) — для отката.
- Не-ломающее, **только сервер**: на проводе ничего не меняется, клиентов пересобирать
  не нужно (TUN — локальный интерфейс ядра ОС). Распараллелены **и TCP** (N очередей
  TUN), **и UDP** (N воркеров на `SO_REUSEPORT`-сокетах — ядро раздаёт датаграммы по
  flow, клиент привязан к одному воркеру). Читатели TUN — блокирующие (на простое 0% CPU).
- Эффект растёт с числом ядер и клиентов: один туннель упирается в свою decrypt-задачу
  (~1 ядро) независимо от очередей — выигрыш даёт МНОГО соединений/большой сервер. На
  2-ядерной лабе замерено **+18% агрегата** (2 туннеля: 607→718 Мбит/с при `queues=1`→`2`;
  один туннель без изменений, 458≈455), и это нижняя граница — хост уперся в насыщение
  (`iperf3`-сток на том же сервере); на больших серверах — больше. Развёрнутый A/B с
  таблицей — [BENCHMARK.md](BENCHMARK.md).

## MTU туннеля (`tun.mtu`) и пуш клиенту

Сервер задаёт MTU своего TUN через `tun.mtu` (per-profile, дефолт 1400) **и пушит это
значение клиенту** при auth. Приоритет на клиенте:

1. **явный клиентский MTU** (`mtu` в `[qeli]`-INI / `qeli://`-ссылке / `tun.mtu` в JSON, `> 0`) — побеждает;
2. иначе — **MTU, пушнутый сервером** (значение `tun.mtu` его профиля);
3. иначе (старый сервер ничего не пушит) — фоллбэк **1400**.

**`mtu = 0` на клиенте = «авто» (это дефолт)** — клиент берёт серверный. Поэтому MTU
обычно задают **один раз в профиле сервера**, и все клиенты подхватывают его сами —
ничего в клиентских конфигах/ссылках менять не нужно (генерируемые `qeli://`-ссылки идут
с `mtu=0`/без него = авто). Явный `mtu` на клиенте нужен лишь чтобы принудительно
переопределить серверное значение.

```ini
# сервер: централизованно задаёт MTU для всех клиентов этого профиля
[profile:reality-tls]
tun.mtu = 1380
```
```ini
# клиент: переопределить вручную (редко нужно); 0/отсутствие = авто/пуш
[qeli]
mtu = 1280
```

> Замечание про reality-tls/fake-tls (TCP-транспорт): на throughput inner-MTU влияет
> слабо (узкое место — внешний TCP-сегмент и путь), но корректный MTU важен против
> фрагментации и для UDP-режимов. См. разбор MTU в [BENCHMARK.md](BENCHMARK.md).

## Тюнинг ОС сервера (sysctl + iptables) — ОБЯЗАТЕЛЬНО для прод

Это **настройки операционной системы сервера**, не qeli-конфиг. Без них TCP-режимы
(reality-tls/fake-tls/obfs-tcp) на реальных (особенно мобильных) клиентах **рвут
соединение под нагрузкой и душат скорость**. Применять на каждом VPN-сервере.

### 1. MSS-clamping (КРИТИЧНО — иначе обрыв загрузки)

Трафик из интернета приходит клиенту через NAT с MSS под 1500-байтный путь, но внутрь
туннеля (`tun.mtu`, напр. 1280) не влезает; при потере ICMP «fragmentation needed»
получается **PMTU-чёрная дыра**: крупные пакеты молча дропаются, мелкие проходят →
загрузка зависает, клиент отваливается по таймауту. Лечится клампом MSS форвардимого
TCP под MTU туннеля (`tun.mtu − 40`). Это делают все VPN; у qeli в конфиге его нет —
ставится на уровне firewall:

```bash
# MSS = tun.mtu(1280) − 40 = 1240; vpn+ = все tun-интерфейсы профилей (vpn0, vpn1, …)
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o vpn+ -j TCPMSS --set-mss 1240
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i vpn+ -j TCPMSS --set-mss 1240
iptables-save > /etc/iptables/rules.v4      # сохранить (netfilter-persistent)
```
> Если меняешь `tun.mtu` — пересчитай MSS (`tun.mtu − 40`).

### 2. sysctl: BBR + буферы + MTU-probing

cubic (дефолт) на мобильных потерях роняет окно вдвое → обвал скорости. **BBR** держит
полосу по модели канала (Google внедрял ровно для медленного TCP по lossy-линкам) —
главный выигрыш для reality-tls на телефоне. Плюс крупные буферы под высокий мобильный
RTT и MTU-probing против остаточных PMTU-чёрных дыр.

```ini
# /etc/sysctl.d/99-qeli-perf.conf  (применить: sysctl --system; модуль: modprobe tcp_bbr)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr     # главный фикс для мобильного TCP
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_mtu_probing=1
```
```bash
modprobe tcp_bbr && echo tcp_bbr > /etc/modules-load.d/qeli-bbr.conf   # загрузка модуля при бутe
sysctl --system                                                       # применить
sysctl -n net.ipv4.tcp_congestion_control                             # проверка: должно быть bbr
```

### 3. padding для reality-tls — лучше выключить

`obf.padding` (40–400 б на пакет) для reality-tls бесполезен (трафик и так внутри
настоящего TLS — снаружи padding не виден), но ест полосу. В профиле reality-tls:
`obf.padding.enabled = false`.

> Применено на проде 222.167.246.143 (2026-06-08): BBR/буферы/mtu_probing + MSS-clamp
> 1240 + `tun.mtu 1280` + padding off. Скрипт: `scripts/prod_tcp_tune.py`.
> Откат: удалить `/etc/sysctl.d/99-qeli-perf.conf` + `/etc/modules-load.d/qeli-bbr.conf`
> (`sysctl --system`), снять правила mangle, вернуть `tun.mtu`/padding.

## Бондинг потоков — multipath (`obf.multipath.*`)

Одиночное TCP-соединение (reality-tls/fake-tls/obfs) на мобильной сети упирается в
потолок «TCP поверх TCP» (на проде ~6 Мбит, тогда как UDP/WireGuard — десятки). Multipath
открывает **несколько параллельных соединений к одному порту :443**, а сервер агрегирует
их в **ОДИН туннель** (один tun-IP); исходящие IP-пакеты раскидываются round-robin.
DPI-чисто — браузер тоже открывает к HTTPS-хосту 6+ параллельных TLS; одно долгоживущее
TCP с непрерывным потоком как раз подозрительнее.

**Настройки — per-profile** (как `tun.mtu`/`padding`), сервер пушит их клиенту:

```ini
[profile:reality-tls]
obf.multipath.enabled = true       # включить бондинг на этом профиле
obf.multipath.max_streams = 4      # ЖЁСТКИЙ потолок потоков на сессию (сервер энфорсит)
obf.multipath.adaptive = false     # false = открыть РОВНО max_streams; true = авто-подбор
```

- **`enabled`** (дефолт `false`) — вкл/выкл бондинг на профиле.
- **`max_streams`** (дефолт `4`) — **жёсткий потолок** параллельных соединений на одну
  сессию; сервер отклоняет лишние. `max_clients × max_streams` = бюджет соединений сервера.
- **`adaptive`** (дефолт `false`):
  - `false` — клиент открывает **ровно `max_streams`** соединений (фиксированно);
  - `true` — клиент **сам подбирает** число от 1 до `max_streams` по измеренной скорости
    (старт с 1, под нагрузкой добавляет поток пока растёт throughput, стоп на плато).
    В этом режиме `max_streams` работает только как **потолок**, не как цель.

Клиент может открыть и **меньше** потолка: `streams = N` в `[qeli]` (0/отсутствие = авто =
серверный `max_streams`; в `adaptive`-режиме игнорируется как цель).

> **Только для TCP-режимов** (reality-tls/fake-tls/obfs/plain) — у них есть HoL-блокировка.
> UDP-профилям (udp-*) бондинг не нужен (нет «TCP поверх TCP») — оставляй `enabled = false`.
>
> **Совместимо/откатно:** старый клиент игнорит пуш и работает в 1 поток; старый сервер не
> шлёт `max_streams` → клиент в 1 поток. Каждое соединение делает свой ключевой обмен →
> независимая крипта на поток (никакого nonce-reuse).

## Wire-режимы обфускации (`obfuscation.mode`)

`mode` выбирает, как выглядит соединение «на проводе»; задаётся **одинаково на
сервере (в профиле) и на клиенте**. Режимы `plain`/`obfs`/`reality`/`reality-tls`
— **только TCP** (потоковые); на UDP проводной режим — `fake-tls` (+ опц.
QUIC-masking), остальные на UDP отвергаются на старте.

| `mode` | Поведение | Против чего | Заметки |
|---|---|---|---|
| `"plain"` | Без обфускации: сырой обмен X25519-ключами и голые записи `[len][nonce][ct]` (никакой TLS-мимикрии). Обычный шифрованный VPN-туннель | Ничего — на проводе высокоэнтропийный поток без узнаваемого протокола (сам по себе сигнал для энтропийного DPI) | Самый дешёвый, скорость ≈ fake-tls. **Только TCP.** Для доверенных сетей, где DPI не важен |
| `"fake-tls"` (по умолчанию) | Псевдо-TLS-1.3 рукопожатие (ClientHello с GREASE и рандомным порядком расширений → JA3 меняется), затем data-плоскость в TLS-Application-Data записях | Пассивный сигнатурный DPI | Дешевле по CPU; «выглядит как TLS» |
| `"obfs"` | Весь поток XOR-ится потоковым ключом ChaCha20; начало соединения по умолчанию замаскировано под рукопожатие WebSocket Upgrade (см. `obfs_fronting`), далее псевдослучайные байты | DPI, сигнатурящий *известные* протоколы (в т.ч. fake-TLS/JA3) + энтропийный «fully encrypted» детект (GFW/ТСПУ) | Требует `obfs_key` (PSK), общий для сервера и клиента. ~11% overhead (двойное шифрование) |
| `"reality-tls"` | Клиент шлёт **настоящий** браузерный TLS 1.3 ClientHello (Chrome JA4) с REALITY-токеном в `session_id`; сервер терминирует настоящий TLS (rustls) и несёт туннель внутри. «Чужие» соединения проксируются на реальный сайт | Активный пробинг + JA3/JA4 + энтропийный DPI (на проводе — настоящий TLS) | Клиенту нужны `key`(пин) + `reality_sid`; серверу `reality_proxy.real_tls=true` + `short_ids`. ↓-скорость ниже (вложенный TLS). **Только TCP.** См. секцию REALITY ниже |

> **Как выбрать режим (позиционирование).** Дефолт `fake-tls` рассчитан на
> **пассивный** DPI (D1/D2) и дёшев по CPU. Если в модели угроз есть **активный
> пробинг** (D3 — цензор сам достукивается до сервера: GFW, ряд провайдеров) —
> включайте **`reality-tls`** явно (это не дефолт, т.к. дороже по CPU и медленнее
> из-за вложенного TLS, но единственный режим, неотличимый от настоящего HTTPS и
> отдающий проберу реальный сайт). `obfs` — против энтропийного «fully-encrypted»
> детекта (без мимикрии под конкретный протокол). `plain` — только доверенные сети
> (на проводе самый заметный). Подробная модель обнаружимости — [DPI-AUDIT.md](DPI-AUDIT.md).

### `obfs_fronting` (anti-FET, только для `mode = obfs`)

Ключ `obf.obfs_fronting` (сервер) / `front` в qeli://-ссылке и `[qeli]`-секции
(клиент). **Должен совпадать на сервере и клиенте.**

| Значение | Поведение |
|---|---|
| `"websocket"` (по умолчанию) | Перед обменом nonce клиент шлёт `GET … Upgrade: websocket`, сервер — `101 Switching Protocols` (с корректным `Sec-WebSocket-Accept`). Первый пакет — printable HTTP-текст → проходит энтропийные эвристики «fully encrypted traffic» GFW/ТСПУ. Запрос рандомизирован (path/Host/key) — нет статической сигнатуры |
| `"none"` | Legacy: сразу случайный nonce-пролог. «Выглядит как ничто» — блокируется энтропийным DPI. Только для отката |

Пример `obfs` (фрагменты):

```ini
# server.conf — в профиле [profile:obfs]:
obf.mode = obfs
obf.obfs_key = ОБЩИЙ-СЕКРЕТ
obf.obfs_fronting = websocket
```
```ini
# client.conf — секция [qeli]:
mode = obfs
obfs_key = ОБЩИЙ-СЕКРЕТ
front = websocket
```

Ограничение `obfs`: keystream IETF-ChaCha20 = 256 ГиБ на направление на сессию.
При превышении соединение завершается с ошибкой и переподключается со свежим
nonce (fail-safe, без повторного использования keystream). Для очень
высокообъёмных долгоживущих линков это означает реконнект примерно каждые 256 ГиБ.

UDP-обфускация — отдельный механизм (`obfuscation.quic`, маскировка под QUIC);
`mode: "obfs"` применяется только к TCP-профилям.

### REALITY (`mode = reality-tls`, ключи `obf.tls.reality_proxy.*`)

«REALITY» в qeli — два уровня, оба в профиле сервера:

| ключ (сервер) | значение |
|---|---|
| `obf.tls.reality_proxy.enabled` | включить REALITY-обработку входящих соединений |
| `obf.tls.reality_proxy.target` / `target_port` | реальный сайт, куда прозрачно проксируются «не-наши»/пробинг-соединения (напр. `www.microsoft.com:443`) |
| `obf.tls.reality_proxy.short_ids` | allow-лист 8-байтовых (16 hex) ID «своих». Задан → дискриминатор криптографический (токен в `session_id`); пуст → legacy-эвристика «нет ALPN» |
| `obf.tls.reality_proxy.real_tls` | `true` → сервер терминирует **настоящий** TLS 1.3, туннель внутри (режим клиента `reality-tls`); `false` → fake-TLS на проводе, REALITY только мост/токен |
| `obf.tls.reality_proxy.handrolled` | `true` → hand-rolled TLS-терминатор: **одалживает настоящую цепочку серта target'а** (cert-borrowing — при старте профиля probe захватывает реальный серт, напр. microsoft; **авто-refresh раз в 12ч**, target-серты ротируются) + зеркалит его JA3S/ServerHello. `false` (по умолчанию) → rustls: **self-signed** серт + свой JA3S. **Для паритета с Xray-REALITY нужен `true`** (требует `real_tls=true`) |

- **proxy-bridge (`real_tls=false`):** клиент шлёт `mode=fake-tls`; на проводе fake-TLS,
  но «чужие» хендшейки уходят на `target` (активный пробер видит настоящий сайт).
  Скорость ≈ `plain`.
- **`reality-tls` (`real_tls=true`):** клиент шлёт `mode=reality-tls` + **обязательно**
  `key` (пин static-ключа профиля, из `show-identity`) + `reality_sid` (один из
  `short_ids`). На проводе — настоящий Chrome-TLS 1.3, туннель внутри; закрывает
  теллы 1.1–1.6 ([DPI-AUDIT.md](DPI-AUDIT.md)). ↓-скорость ниже (вложенный TLS — см.
  [BENCHMARK.md](BENCHMARK.md)). Раздаётся QR-ссылкой (`rsid=` несёт short_id).
  Шаблоны конфигов — [release/reality-tls/](../release/reality-tls/).

## Идентичность сервера (per-profile)

У **каждого профиля свой** долговременный static-ключ (X25519) — он привязан к
интерфейсу профиля. Приватные ключи лежат в `/etc/qeli/identity/<profile>.key`
(права `0600`, каталог `0700`); путь можно переопределить полем профиля
`identity_key`. Публичный ключ выводится из приватного, его клиент пиннит.

При первом старте профиля ключ генерируется автоматически (если файла нет) и
сохраняется. Логируется: `Profile '<name>': server identity public key (pin on client): <hex>`.

CLI для управления ключами (без запуска сервера, нужен root):

```bash
# показать публичные ключи всех профилей (создаёт отсутствующие)
qeli show-identity --config /etc/qeli/server.conf
# PROFILE   BIND                 SERVER PUBLIC KEY (pin on client)
# tcp       tcp://0.0.0.0:443    33f399e6…d532450
# udp       udp://0.0.0.0:4443   35d12dd2…7d764e04
# obfs      tcp://0.0.0.0:8443   26c45f81…9dbca952

# сменить ключ одного профиля (затем перезапустить qeli)
qeli rotate-identity udp --config /etc/qeli/server.conf
```

### Как передать ключ на клиента (pinning)
Публичный ключ профиля (hex из `show-identity`) вносится в **клиентский** конфиг:

```ini
# client.conf — клиент, подключающийся к профилю tcp; секция [qeli]:
user = alice
pass = секрет
key = 33f399e6…d532450
```

Передача — **out-of-band** (скопировать hex: вывод `show-identity`, защищённый
канал, QR и т.п.). Клиент сверяет полученный от сервера ключ с запиненным; при
несовпадении — ошибка `SERVER KEY MISMATCH` (анти-MITM). Если поле не задано —
TOFU: клиент подключается и печатает ключ-кандидат в лог (без защиты от подмены).
Клиент пиннит ключ **того профиля**, к которому подключается (по порту).

После `rotate-identity` публичный ключ меняется → всем клиентам этого профиля
нужно раздать новый hex (иначе `SERVER KEY MISMATCH`).

### Обязательный пиннинг — `auth.require_client_key_proof`
По умолчанию клиент без пина (`key` в `[qeli]`) подключается в режиме TOFU (без
защиты от MITM). Чтобы **запретить** подключение клиентов, не запинивших ключ:
```ini
# server.conf — секция [auth]:
require_client_key_proof = true
```
Тогда клиент обязан доказать знание серверного static-ключа: он считает
доказательство из **запиненного** ключа (`key` в `[qeli]`), а сервер
сверяет его своим приватным ключом. Клиент без ключа (или с неверным) —
отклоняется (`AUTH DENIED … server key not pinned by client`). Работает на TCP и UDP.

Порядок (by design, безопасно): клиент сначала **аутентифицирует сервер**
(сверяет static-ключ с запиненным) и только потом шлёт логин/пароль — иначе
MITM мог бы перехватить креды. Поэтому «отправлять ключ после авторизации»
нельзя. Сам static-ключ — публичный, его «утечка» сканеру даёт лишь фингерпринт.

## Авторизация пользователей по профилям (изоляция интерфейсов)

В `users.conf` (или инлайн-секции `[user:<name>]` в server.conf) у пользователя
есть ключ `profiles` — список профилей (интерфейсов), к которым ему разрешено
подключаться:

```ini
[user:alice]
password_hash = $argon2id$...
profiles = tcp
```

- **пусто** (ключ отсутствует) → разрешены **все** профили (обратная совместимость);
- **непусто** → только перечисленные (через запятую). Юзер с `profiles = tcp` при подключении к `udp`
  получает отказ `AUTH DENIED … not permitted on profile 'udp'` даже с верным
  паролем. Так интерфейсы изолируются: доступ к одному не даёт доступа к другому.

Проверка выполняется после верификации пароля и на TCP, и на UDP.

## Клиент: учётные данные, маршрутизация, reconnect

**Учётные данные клиента** — в секции `[qeli]`:
```ini
# client.conf
user = alice
pass = секрет
```
В flat-INI пароль задаётся только ключом `pass` (вариантов password_file/command у
INI-клиента нет). На **сервере** пользователей можно держать инлайн — секциями
`[user:<name>]` прямо в server.conf (с Argon2-хешами); если они есть, используются
вместо `auth.users_file`:
```ini
# server.conf:
[user:alice]
password_hash = $argon2id$...
profiles = tcp
```

**Маршрутизация — преимущественно со стороны сервера.** Flat-INI клиент (`[qeli]`)
намеренно минимален: маршруты/DNS/MTU приходят с сервера при рукопожатии. Сервер
раздаёт маршруты повторяемым ключом `route` в профиле (или индивидуально на юзера —
тот же ключ `route` в `[user:<name>]`, переопределяет глобальные); клиент применяет
их к tun автоматически:
```ini
# server.conf, в профиле [profile:tcp]:
route = 192.168.50.0/24 gateway=10.0.0.1 metric=50
```
Проверено: клиент получает `192.168.50.0/24 via <tun_gw> dev <tun>` в таблице.
Единственный клиентский routing-ключ flat-INI — `route_local = true` (`[qeli]`):
завернуть в туннель RFC1918 + раздаваемые сервером локальные подсети.

**Авто-reconnect** включён по умолчанию (отдельных ключей в flat-INI `[qeli]` нет —
применяются дефолты: экспоненциальный backoff, cap 60с, бесконечные ретраи). Клиент,
оставленный включённым при недоступном сервере (даже сутки+), повторяет попытки и
**переподключается, как только сервер вернётся**. Мёртвый сервер на простаивающем
туннеле детектится по RX-liveness (нет данных от сервера >3× heartbeat) за десятки секунд.

## Логирование

Секция `[logging]` (в server.conf и client.conf):

```ini
[logging]
# error | warn | info | debug | trace  (RUST_LOG переопределяет)
level = info
# если задан — логи пишутся в файл (каталог создаётся);
# если опущен — stderr (под systemd попадает в journald)
file = /var/log/qeli/server.log
```

В лог на уровне `info` пишутся все ключевые события: старт/останов профилей и
слушателей, установка соединения (`New TCP connection`, `Client … connected … IP …`),
аутентификация (`AUTH attempt/OK/FAIL/BLOCKED`, в т.ч. блокировки brute-force),
разрыв соединения (`Client … disconnected`), административные команды через
control-сокет (`CONTROL action=… user=…` — kick/disable/enable/set-bandwidth),
SIGHUP-перезагрузка. Причины разрыва на стороне data-плоскости пишутся на уровне
`debug`.

Минимально для диагностики достаточно `level: "info"` с заданным `file`.
```

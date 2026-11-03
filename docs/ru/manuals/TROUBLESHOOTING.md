# Qeli — диагностика подключения и справочник по ошибкам

> **Статус документации:** текущая ветка разработки **0.8.3**; планируемый full-IPv6 релиз **0.8.3**;
> версия пакетов в этом руководстве **0.8.3**.
> Фактическую версию установленного бинарника показывает `qeli --version`.
> Готовые файлы и статус публикации нужной версии — в [GitHub Releases](https://github.com/litvinovtd/qeli/releases).
> Ссылки на файлы этой версии работают после её публикации.

Подробный практический гайд: как включить debug, как читать лог по стадиям
подключения, что означает каждая ошибка сервера и клиентов (Windows / macOS /
Android) и как её чинить. Все строки — точные, как они появляются в логе.

> Для отдельного чеклиста inner/outer IPv6, `off/manual/route/nat66`, NDP proxy, PMTU, DNS и утечек см.
> [руководство по IPv6](IPV6.md).

> Строки ошибок в коде **на английском** (так они и печатаются). Ниже к каждой —
> расшифровка и метод исправления. Если строки в вашем логе нет здесь — ищите по
> ключевому слову, разделы сгруппированы по подсистемам.

**Содержание**
1. [Включение debug-логов](#1-включение-debug-логов)
2. [Архитектура и жизненный цикл подключения](#2-архитектура-и-жизненный-цикл-подключения)
3. [Пошаговая диагностика](#3-пошаговая-диагностика)
4. [Каталог ошибок — сервер](#4-каталог-ошибок--сервер)
5. [Каталог ошибок — клиенты (Windows / macOS / Android)](#5-каталог-ошибок--клиенты)
6. [Типовые сценарии («симптом → причина → фикс»)](#6-типовые-сценарии)
7. [Справочник: статусы, цвета индикаторов, суффиксы лога](#7-справочник)
8. [Чеклисты команд](#8-чеклисты-команд)

---

## 1. Включение debug-логов

### 1.1 Сервер

Уровень по умолчанию — **`info`**. Бо́льшая часть причин отказа в подключении
(проблемы хендшейка/крипто/MTU **до** аутентификации) логируется на уровне
**`debug`** — при `info` их не видно. Поэтому первый шаг любой диагностики
«клиент не подключается, а на сервере тишина после `New TCP connection`» —
включить debug.

Два способа (**`RUST_LOG` имеет приоритет над `[logging] level` в конфиге** — это
задано в `main.rs::init_logging`):

**A. Через systemd drop-in (ничего в конфиге не трогаем):**
```bash
mkdir -p /etc/systemd/system/qeli.service.d
printf '[Service]\nEnvironment=RUST_LOG=debug\n' > /etc/systemd/system/qeli.service.d/zz-debug.conf
systemctl daemon-reload && systemctl restart qeli
journalctl -u qeli -f
# откат: rm /etc/systemd/system/qeli.service.d/zz-debug.conf && systemctl daemon-reload && systemctl restart qeli
```

**B. Через конфиг** — в секции `[logging]` поставить `level = debug`, затем
`systemctl restart qeli`. Ключи секции: `level` (`error`/`warn`/`info`/`debug`/`trace`),
`file` (путь к лог-файлу; по умолчанию stderr → journald), `time_format`, `format`.

**Метка времени — `time_format`.** Строка лога всегда `<метка> LEVEL target: сообщение`,
ключ задаёт форму метки: `datetime` (дефолт, локальное время) / `rfc3339` (UTC) / `time`
(без даты) / `epoch` / `none`. Два практических случая:

- **сводите логи клиента и сервера** (или нескольких серверов) — ставьте `rfc3339` с обеих
  сторон: UTC убирает расхождение часовых поясов, и строки корректно сортируются;
- **лог идёт в journald/syslog** — `none`: systemd и procd штампуют строку сами, иначе в
  `journalctl` получаются две метки времени подряд.

Полная таблица вариантов — в [CONFIG.md](CONFIG.md#time_format--метка-времени). То же
самое настраивается в приложениях: «Настройки → Время в логе» (Windows, macOS, Android)
и `log_time_format` в UCI/LuCI на OpenWrt.

> **Формат серверного журнала:** `[logging] format = plain|json` выбирает текст или
> один JSON-объект на запись. `time_format` отдельно задаёт время. После изменения
> нужен полный рестарт сервера: worker restart не перенастраивает logger supervisor.
> Конфигурация остаётся INI. Подробнее — [журналирование](CONFIG.md).

Точечная фильтрация (меньше шума): `RUST_LOG=qeli::server::handler=debug,qeli::server::udp_handler=debug,info`.

**Разовый запуск в форграунде** (быстро посмотреть, без правки юнита):
```bash
systemctl stop qeli
RUST_LOG=debug /usr/bin/qeli server --config /etc/qeli/server.conf   # .deb ставит в /usr/bin
```

### 1.2 Клиенты (Windows / macOS)

Отдельного «debug-режима» нет — **клиент логирует всё сразу** во вкладку **Log** /
**Журнал** в окне приложения. По умолчанию строка начинается с локальной даты и времени:
`2026-07-18 18:10:03.259  …`. **С 0.7.12** форма метки настраивается — «Настройки →
Время в логе», варианты те же, что у `[logging] time_format` на сервере (дата и время /
RFC 3339 в UTC / только время / Unix / без метки); чтобы сверять лог приложения с
серверным, ставьте `RFC 3339` с обеих сторон. Кнопки **Copy log** / **Clear log** в шапке журнала.
«Тяжесть» строки задаётся префиксом: `ERR:`, `WARN:`, `NOTE:`, `[SECURITY]`, а
вложенные причины — строками `  <- …`.

### 1.3 Клиент Android

VPN-сервис ведёт приватный постоянный журнал, даже когда Activity закрыта или интерфейс приложения
пересоздан. Хранятся последние 1000 событий, но не более 512 КиБ; при открытии Qeli они
восстанавливаются во **вкладке «Журнал»** (индекс 3). Файл находится в приватном no-backup
каталоге Android и не содержит пароль, приватные ключи или полный профиль.

<!-- normative-sync: android-disconnect-log-settings-v1 -->

В **«Настройки → Очищать лог после отключения»** очистка **включена по умолчанию**,
в том числе после обновления, если выбор ещё не сохранялся. После завершённой остановки VPN
сервис удаляет сохранённый журнал и очищает открытую вкладку, даже если приложение было
свёрнуто или закрыто. Завершение соединения с ошибкой также очищает журнал; сообщение об
ошибке остаётся на главном экране.

Для диагностики заранее выключите эту опцию и нажмите **«Сохранить»**: история останется
после отключения и будет восстановлена при следующем открытии приложения; **Copy log**
включит события, произошедшие при выключенном экране. Настройка применяется к следующему
отключению без переподключения и не стирает записи в момент сохранения. Отмена диалога
не меняет выбор. Автореконнект, смена сети, перенастройка активного соединения и пауза на
доверенном Wi-Fi не вызывают автоочистку. Кнопка **«Очистить»** доступна независимо от опции.

Уровень Info фиксирует границы сессии, причину остановки, потерю сети/реконнект, redelivery или
отзыв VPN со стороны Android и предупреждение об оптимизации батареи. Debug/Trace дополнительно
записывает время выключения/включения экрана и подробные события адаптера. Формат времени по-прежнему
настраивается в «Настройки → Время в логе»; восстановленные строки сохраняют исходное время события.
По умолчанию показывается только время, чтобы полная дата не съедала ширину экрана.

Активное пользовательское подключение возвращает `START_REDELIVER_INTENT`, поэтому после убийства
процесса Android может повторно доставить точную команду Connect. Явное отключение сначала
синхронно сбрасывает durable-флаг и никогда не перезапускается. OEM force-stop и агрессивные
ограничения фона всё равно могут запретить любой рестарт, поэтому при диагностике исключите Qeli
из оптимизации батареи. Тот же процессный вывод доступен через `adb`:
```bash
adb logcat -s VpnSvc VpnMain
```
`VpnSvc` — VPN-сервис, `VpnMain` — Activity. Строки необработанного Android runtime crash всё ещё
могут остаться только в logcat; собственные диагностические события Qeli сохраняются в журнале.

### Журнал клиента iOS

<!-- normative-sync: ios-disconnect-log-settings-v1 -->

**«Настройки → Оформление → Очищать лог после отключения»** — **включено по умолчанию**,
в том числе после обновления. В отличие от кнопки сохранения в Android, iOS сохраняет
переключатель сразу: он применяется при следующей остановке текущего соединения,
а само переключение журнал не стирает. Выключите его перед воспроизведением проблемы,
чтобы история в общей App Group переживала отключение и повторное открытие приложения.
Журнал ограничен 500 записями, 4 КиБ на сообщение и 1 МиБ закодированной истории.

VPN-расширение очищает историю после окончательной остановки или ошибки запуска,
даже при закрытом интерфейсе; статус ошибки остаётся доступен. Переподключение внутри
работающего расширения и перенастройка историю не очищают. История сохраняется при
остановках, которые iOS обозначает как потерю/смену сети, сон или обновление приложения,
а также при остановке без указанной причины, пока On Demand ожидает продолжения
запрошенного соединения (включая ожидание на доверенном Wi-Fi).
Поздние сообщения завершённой сессии журнал не восстанавливают. Ручная кнопка **Clear**
работает независимо. При принудительном убийстве процесса расширение может не успеть
выполнить очистку.

### 1.4 Трассировка пакетов (`QELI_TRACE`, Rust-сервер и Rust-клиент)

Когда логов мало, трассировка показывает время и размеры пакетов в точках обработки
внутри приложения. Включается переменной окружения, иначе выключена:

```bash
# клиент
QELI_TRACE=/tmp/qeli-client.csv qeli client -c /etc/qeli/client.conf

# сервер (systemd): drop-in, затем рестарт
systemctl edit qeli
#   [Service]
#   Environment=QELI_TRACE=/tmp/qeli-server.csv
```

Выгрузка — по сигналу, в любой момент (процесс продолжает работать):

```bash
kill -USR1 $(pgrep -f 'qeli client')      # клиент
kill -USR1 $(pgrep -f 'qeli _worker')     # сервер: именно worker, не supervisor
```

В логе появится `packet trace: wrote N events`, в файле — CSV:

```
# qeli packet trace — shapes only, no payloads, no addresses
# overwritten=0 contended=0
t_us,dir,site,size,seq
479384,tx,client.tcp,40,0
```

- `t_us` — микросекунды от инициализации трассировки в данном процессе, `dir` — `tx` (из TUN в туннель) / `rx`
  (из туннеля в TUN), `site` — точка съёма, `size` — байты, `seq` — индекс потока.
- Пишутся **только формы пакетов**: ни payload, ни адресов — трассу можно приложить к
  issue, не раскрывая трафик.
- Буфер кольцевой на 65 536 событий. Строка `overwritten=` в шапке говорит, сколько
  событий затёрлось (трасса длиннее буфера), `contended=` — сколько потеряно из-за
  конкуренции: трасса **не бывает молча неполной**.
- Обе стороны пишут свои файлы с отдельным началом отсчёта времени. `seq` — индекс
  потока, а не идентификатор пакета или TCP sequence number.

<!-- normative-sync: q36-trace-correlation-v1 -->

Для сравнения клиентской и серверной трасс сначала нужна внешняя привязка их шкал
времени. Совпадение времени и размера после такой привязки — лишь предположение:
несколько пакетов могут иметь одинаковый размер. По CSV нельзя доказать доставку
конкретного ACK или измерить его точную задержку между сторонами.

Событие означает достижение точки `site`, а не завершение передачи по сети. Например,
`server.stream` записывается после извлечения пакета из очереди, до ограничения скорости,
шифрования и записи в сокет; `client.tcp` при приёме — до принятия пакета очередью TUN.
Запись может существовать и при последующем отказе очереди или отправки. Размер в этой
точке также может отличаться от размера зашифрованной записи и сетевого пакета.
Для проверки доставки и задержек используйте отдельный захват на нужных интерфейсах
с идентификацией пакетов и проверенной привязкой часов. Учитывайте неполноту кольцевого
буфера и влияние диагностического захвата на нагрузку.

<!-- normative-sync: q32-log-trace-io-v1 -->

Выгрузка публикуется атомарной заменой файла с Unix-правами `0600`. Симлинк
или FIFO в месте назначения заменяется; запись по его ссылке не выполняется.
Родительский каталог должен существовать. Ошибка до публикации сохраняет прежний
файл; ошибка синхронизации каталога после rename означает состоявшуюся публикацию
с неподтверждённой долговечностью. Запись выполняется вне потоков Tokio, допускается
одна выгрузка на процесс. Зависший файловый syscall может удерживать этот слот
после остановки наблюдателя. Нужен `SIGUSR1`: автоматической выгрузки при завершении
нет. Разным процессам нужны разные пути; при общем пути остаётся последняя
публикация. Сейчас точки записи покрывают TCP/UDP Rust-клиента и TCP сервера.
UDP сервера, транспортные пути под управлением ядра и трассировка отдельного
`qeli-client` этим механизмом не квалифицированы. Отсутствие записи не доказывает
потерю пакета.

Страница Logs опрашивает `/api/logs`; SSE не используется. Требуется авторизация.
Чтение ограничено последними 4 МиБ, максимум 2000 строками и четырьмя одновременно
выполняемыми задачами чтения на процесс. Занятый reader возвращает `ok=false`;
запрос можно повторить. API-параметр `filter` ограничен 1024 UTF-8 байтами и ищет
только в этом недавнем окне. Допускаются обычные файлы внутри `/var/log/qeli`.
Подмена пути симлинком или FIFO после проверки отклоняется; ротация не перенаправляет
уже открытый дескриптор. Если файл не задан, ответ объясняет работу с journald,
но не транслирует его. Ограничены задачи чтения, а не все незавершённые HTTP-ответы
и не задержка диска.

Накладные расходы при выключенной трассировке — одна атомарная загрузка на пакет, так
что переменную можно держать невзведённой в проде без опасений.

---

## 2. Архитектура и жизненный цикл подключения

### 2.1 Сервер: supervisor + worker

Процесс `qeli server` — это **supervisor**: держит веб-панель и порождает
дочерний **data-plane worker** (`qeli _worker`). Отсюда две важные вещи:

- **«Apply & Restart» в панели делает ПОЛНЫЙ `systemctl restart`** — применяется всё,
  включая сокет панели (`web.bind`/`port`/`tls`/`base_path`). Рестарт только worker'а
  (`POST /api/server/restart`) остался автоматическим фолбэком там, где systemd
  недоступен (контейнер). Ссылки в панели (share) читают конфиг **свежим с диска**
  (фикс #69), поэтому смена SNI видна в ссылке без перезапуска.
- В логе старт видно так:
  ```
  Starting server (supervisor) with config: /etc/qeli/server.conf
  Web UI (HTTPS) listening on https://0.0.0.0:8080
  supervisor: data-plane worker started (pid NNNN)
  Starting data-plane worker with config: /etc/qeli/server.conf
  Starting profile 'fake-tls' (tcp://0.0.0.0:443)
  Profile 'fake-tls': server identity public key (pin on client): 320a4700…
  Profile 'fake-tls' listening on 0.0.0.0:443 (TCP)
  ```
  Если worker падает на старте (валидация конфига) — supervisor логирует
  `supervisor: worker stopped unexpectedly — respawning in Ns` и рестартит с backoff.

Повторные ошибки создания процесса и неожиданные выходы используют задержки
1, 2, 4, 8, 16, затем максимум 30 секунд. После поколения, прожившего не меньше
30 секунд, задержка сбрасывается. SIGINT/SIGTERM обрабатываются и во время retry.
В логе отдельно выводится статус завершившегося worker; его PID в метриках
сбрасывается, пока нового процесса нет.

При **внутреннем** рестарте worker (`POST /api/server/restart`) новая конфигурация
читается после завершения старого процесса без crash-backoff. Restart во время
ожидания retry будит его; накопленные старые команды объединяются. ReloadUsers
действующего worker сохраняет соединения, а при отсутствии/завершении worker
пользователей перечитает следующее поколение.

На штатное завершение worker даётся 60 секунд, затем supervisor запрашивает SIGKILL
и дожидается выхода. Повторный Restart не продлевает этот срок. Сообщение
`worker did not stop within 60s — killing and reaping it` означает принудительный
выход: post_down мог не выполниться, полный откат firewall этим не гарантируется.
Следующий worker очищает старые NAT-правила при старте. 60 секунд ограничивают
ожидание graceful shutdown, а не зависание внутри ядра после SIGKILL.

`worker service 'usage sweep' failed: ...` или `stopped unexpectedly` означает отказ
обязательной службы учёта и квот. То же относится к `UDP loss report`: worker начинает
очистку вместо незаметного продолжения работы без этой службы. Неактивный packet trace
необязателен и может завершаться штатно. При graceful stop текущий периодический цикл
заканчивается до остановки профилей, затем последние байты собираются и сохраняются
при удержании исключительного права worker. `usage: shutdown flush failed` означает
ошибку финальной записи; проверьте место на диске, права и предшествующее сообщение.
Worker сообщает об ошибке; сохранность ещё не записанной статистики не гарантируется.

Предупреждения уведомлений: `notify: queue full` означает превышение лимита 128
отправок на процесс; новые события отбрасываются без бесконечного retry.
`notify: shutdown deadline` — истекли десять секунд drain, оставшиеся отправки отменены.
Проверьте транспортные/HTTP-предупреждения нужного канала: адресат может медленно отвечать
или отклонять запросы. **Send test** делит общий лимит и явно сообщает ошибку очереди,
отмены или timeout. Подробные ограничения описаны в [мануале панели](PANEL.md).

### 2.2 Стадии одного подключения (по логу)

Локализуйте отвал по последней успешной строке:

| # | Стадия | Клиентская строка | Серверная строка |
|---|---|---|---|
| 1 | TCP/UDP коннект | `Connecting TCP/UDP <ip>:<port> as user '<u>'…` → `TCP connected` / `Bound carrier socket…` | `New TCP connection from …` / `UDP handshake started for …` |
| 2 | Отправка ClientHello | `ClientHello sent (NNNN B, hybrid X25519+ML-KEM)` | `Received ClientHello: N bytes` *(debug)* |
| 3 | Проверка личности сервера | `Server identity verified [OK]` | `Sent server auth proof…` *(debug)* |
| 4 | Аутентификация | *(парс `OK:` из ответа)* | `AUTH attempt … user=…` → `AUTH OK …` |
| 5 | Применены пуш-параметры | `Applied server-pushed obfuscation params` | — |
| 6 | Выдан IP | `Auth OK, IP 10.x.x.x` | `Client … connected …, IP: 10.x.x.x` |
| 7 | Поднятие TUN | `Wintun adapter …` / `utun …` → `TUN MTU …` → маршруты → DNS | — |
| 8 | Туннель активен (🟢) | `TUN ready, entering tunnel loop` → **статус Connected** | — |

> **🟢 «Connected» = TUN поднят, а НЕ «Auth OK».** Между `Auth OK, IP …` и
> `Connected` статус остаётся **жёлтым** (Connecting), пока идёт `SetupTun` (на
> Windows открытие Wintun — до ~10 с). Это намеренно (issue #69): раньше зелёный
> зажигался на Auth OK, и падение установки TUN сбрасывало backoff → плотный
> reconnect-шторм.

---

## 3. Пошаговая диагностика

1. **Сервер жив и слушает?**
   ```bash
   systemctl is-active qeli
   ss -ltnp | grep -E ':443|:8443|:8444'      # TCP-профили
   ss -lunp | grep -E ':8448|:8449|:8450'     # UDP-профили
   journalctl -u qeli --since '5 min ago' -p warning --no-pager
   ```
2. **Порт открыт в облачном фаерволе / Security Group?** (частая причина «TCP
   connected» вообще не появляется).
3. **Клиентский лог: до какой стадии дошло?** (таблица §2.2). Последняя успешная
   строка указывает подсистему.
4. **Дошло до сервера?** На сервере ищите `New TCP connection` / `UDP handshake
   started` с IP клиента. Если строки нет — трафик не долетает (фаервол/маршрут/не
   тот IP-порт).
5. **Дошло, но «тишина» после accept?** Включите **debug** (§1.1), переподключитесь,
   и ищите **ровно одну** решающую строку:
   - `handshake timeout for <addr>` → клиент не дослал ClientHello (или ответ не
     дошёл) = **сетевая чёрная дыра по MTU** (см. §6.1);
   - `Client <addr> disconnected on profile '…': <причина>` → см. `<причина>` в §4.2;
   - `AUTH FAIL/DENIED/BLOCKED …` (видно уже на `info`) → креды/бан/права (см. §4.3).
6. **Сверьте ключ и режим.** Публичный ключ сервера виден в логе старта
   (`server identity public key (pin on client): …`) и по `qeli show-identity`.
   Клиентский `key=`/`reality_sid=`/`mode=` должны совпадать (см. §6.4).

---

## 4. Каталог ошибок — сервер

### 4.1 Валидация конфига — worker не стартует (`bail!`, фатально)

Эти ошибки **прерывают старт worker'а**; supervisor логирует падение и рестартит
по кругу с backoff. Все на уровне ERROR.

| Сообщение | Причина | Фикс |
|---|---|---|
| `no profiles defined in server config` | нет ни одной `[profile:*]` | добавить профиль |
| `all profiles are disabled (enabled = false) — enable at least one` | все `enabled = false` | включить профиль |
| `duplicate profile name: '<n>'` | два профиля с одним именем | переименовать |
| `profile '<n>': unknown bind.transport '<t>' — expected 'tcp' or 'udp'` | опечатка в транспорте | `bind.transport = tcp` или `udp` |
| `profile '<n>': unknown obf.mode '<m>' — expected 'fake-tls', 'obfs', 'plain' or 'reality-tls'` | опечатка в wire-режиме | исправить `obf.mode` |
| `profile '<n>': perf.connection.handshake_timeout_secs and perf.connection.max_clients must be > 0…` | один из flat-INI ключей явно задан нулём | удалить нулевой ключ для baseline-дефолта либо задать положительное значение |
| `profile '<n>': plain (raw) wire mode is TCP-only — set bind.transport = tcp` | `obf.mode=plain` на UDP | сменить транспорт на tcp |
| `profile '<n>': obfs wire mode requires a non-empty obfuscation.obfs_key…` | пустой `obfs_key` (публично выводим → нет DPI-защиты) | задать `obf.obfs_key` |
| `profile '<n>': reality_proxy.enabled requires at least one non-empty obf.tls.reality_proxy.short_ids entry…` | REALITY без short_id | задать `obf.tls.reality_proxy.short_ids` |
| `profile has an empty name` | секция вида `[profile:]` без имени | назвать профиль |
| `profile '<n>': obf.heartbeat.interval_ms must be > 0 when the heartbeat is enabled` | включён heartbeat с нулевым интервалом | задать `obf.heartbeat.interval_ms` |
| `profile '<n>': obf.heartbeat.jitter_ms (<j>) must be smaller than …` | джиттер ≥ интервала — расписание становится бессмысленным | уменьшить `obf.heartbeat.jitter_ms` |
| `profile '<n>': obf.heartbeat.data_size_bytes (<b>) must be <= <max>` | heartbeat-пакет крупнее допустимого размера записи | уменьшить `obf.heartbeat.data_size_bytes` |
| `profile '<n>': pool.cidr '<c>': <ошибка>` | пул не разбирается как CIDR (нет префикса, мусор, слишком узкий) | привести к виду `10.9.0.0/24` |
| `profile '<n>': invalid tun.address '<a>': … — expected a plain IPv4 address (e.g. 10.9.0.1)` | адрес с префиксом/маской или опечатка | оставить голый IPv4 |
| `profile '<n>': tun.address <a> is not a usable host inside pool.cidr <c>` | шлюз вне подсети VPN либо совпадает с адресом сети/broadcast | выбрать пригодный адрес внутри `pool.cidr`; его префикс — единственная настройка маски |

Не фатальные (профиль стартует), уровень WARN — просто предупреждают о
бессмысленной/слабой настройке: `obf.multipath.enabled has no effect on a UDP
transport…`, `obf.awg.enabled has no effect on a TCP … profile…`,
`reality_proxy.target '<t>' is a bare IP…`, `wire mode 'fake-tls' has LOW DPI
resistance…` (на UDP-профиле в этом последнем предлагается только `obfs` —
reality-tls живёт поверх TCP и на UDP недоступен).

### 4.1.1 Предстартовые проверки — служба не запускается вовсе (supervisor)

Отдельный класс: эти проверки выполняются **в супервизоре, до** того как поднимется
панель, стартует worker и появится хоть один TUN. Поэтому здесь не рестарт-петля
worker'а, а отказ службы целиком — и это намеренно: конфиг, попавший под такую
проверку, при запуске **отрезал бы доступ к самой машине**.

Проверяется пересечение адресации туннеля с тем, что хост уже использует. Худший
случай — `tun.address`, совпадающий с адресом шлюза: при подъёме TUN шлюз становится
локальным адресом, весь исходящий трафик умирает в туннеле, и сервер пропадает из сети
вместе с SSH и пингом, а в логе при этом всё выглядит как успешный старт.

| Сообщение | Причина | Фикс |
|---|---|---|
| `profile '<n>': tun.address <a> is this host's DEFAULT GATEWAY…` | адрес туннеля = шлюз хоста | увести туннель в свободный диапазон (`10.9.0.1` / `10.9.0.0/24`) |
| `profile '<n>': tun.address <a> is already assigned to interface '<if>'` | адрес уже занят интерфейсом хоста | выбрать адрес вне собственных сетей хоста |
| `profile '<n>': pool.cidr <c> contains this host's DEFAULT GATEWAY <gw>…` | пул накрывает шлюз | сменить пул |
| `profile '<n>': pool.cidr <c> contains <a>, the address of interface '<if>'…` | пул накрывает собственный адрес хоста | сменить пул |
| `profile '<n>': pool.cidr <c> overlaps the existing route <r> on interface '<if>'…` | пул пересекается с уже маршрутизируемой сетью (LAN, сеть провайдера) | сменить пул |
| `profile '<n>': pool.cidr <c> overlaps profile '<other>' pool <o>…` | два профиля делят диапазон | развести (`10.9.0.0/24`, `10.9.1.0/24`, …) |

Свои сети смотрите через `ip route` и `ip -4 addr`. Проверить конфиг **до** запуска:
`qeli check-config --config /etc/qeli/server.conf` — выполняет ту же проверку против
текущего хоста и печатает `would NOT start on this host — <причина>`.

Отдельный WARN: `pre-flight: could not read the host's network state (ip missing or
unreadable) — skipping the subnet-collision check`. Состояние хоста прочитать не
удалось, проверка пропущена, старт продолжается (fail-open — это защита от ошибки
оператора, а не граница безопасности). Убедитесь вручную, что `tun.address` и
`pool.cidr` не пересекаются с адресами, шлюзом и маршрутами хоста.

### 4.2 Хендшейк — до аутентификации (в основном DEBUG)

> **Ключевой момент:** эти ошибки возвращаются из `handle_client` и логируются в
> accept-цикле как **`Client <addr> disconnected on profile '<name>': <причина>`**
> на уровне **DEBUG**. При `info` — тишина. Включите debug (§1.1).

| `<причина>` в строке disconnected / отдельная строка | Что значит | Фикс |
|---|---|---|
| `handshake timeout for <addr>` | клиент не дослал ClientHello за `handshake_timeout_secs` (нет внутреннего таймаута на чтение — только этот внешний). Почти всегда = **PMTU-blackhole** большого PQ-ClientHello | см. §6.1 (MSS-clamp / MTU) |
| `failed to read ClientHello: <e>` | не прочиталась TLS-запись (обрыв/мусор) | сеть/MTU; проверить, что клиент шлёт fake-tls, а профиль — fake-tls |
| `failed to parse ClientHello` | `FakeTlsHandshake::parse_client_hello` вернул None (битая TLS-запись) | несовпадение wire-режима клиент↔сервер |
| `ClientHello missing the X25519MLKEM768 key_share` | клиент без ML-KEM (старый/классический) — PQ-гибрид обязателен во всех не-plain режимах | обновить клиент |
| `ML-KEM encapsulation failed (malformed ek)` | битый ключ ML-KEM в ClientHello | версия-скью/повреждение; обновить обе стороны |
| `rejected low-order client public key` | защита от small-subgroup (низкопорядковая X25519-точка) | клиент-баг/атака; обновить клиент |
| `invalid client public key length` | key_share ≠ 32 байт | версия-скью |
| `auth packet too short` / `invalid auth format` | первый пакет короче 32 Б / креды без `:` | версия-скью/повреждение |

### 4.3 Аутентификация — видно уже на `info` (WARN)

Если в логе есть `AUTH attempt … user=…`, значит хендшейк прошёл и дело в кредах/
правах. Все строки — **WARN** (видны без debug).

| Сообщение | Что значит | Фикс |
|---|---|---|
| `AUTH DENIED … — server key not pinned (require_client_key_proof)` | `auth.require_client_key_proof=true`, а клиент не пинит ключ сервера (нет/не тот `key=`) | прописать клиенту `key=<pubkey сервера>` (см. `qeli show-identity`) |
| `AUTH BLOCKED … — source IP locked for Ns…` | IP залочен брутфорс-защитой | подождать `lockout_secs`, или `qeli unblock <ip>`; проверить причину флуда |
| `AUTH FAIL … — not found or disabled` | юзера нет в БД или он выключен | проверить `users.conf` / `qeli add-client` |
| `AUTH FAIL … — wrong password` | неверный пароль (Argon2 не сошёлся) | перевыпустить ссылку (`qeli add-client … --link`) |
| `invalid password hash: <e>` | битый PHC-хеш пароля у юзера | пересоздать юзера |
| `AUTH DENIED … not permitted on profile '<n>'` | креды верны, но юзеру не разрешён этот профиль | добавить профиль в `profiles = …` юзера |
| `AUTH DENIED … — account expired` | истёк `expire_at` (Tier-2) | продлить аккаунт |
| `AUTH DENIED … — download quota exhausted (…GB down)` | выбрана квота скачивания | сбросить/поднять `data_limit_gb` |

Замечания: юзернейм **никогда** не лочится жёстко (анти-DoS), лочатся только
IP-адреса; неизвестному юзеру всё равно «тратится» dummy-Argon2 (анти-энумерация).

### 4.4 Приём соединений / rate-limit

| Сообщение | Уровень | Что значит |
|---|---|---|
| `New TCP connection from <addr> on profile '<n>'` | INFO | принято (прошло rate-limit), уходит в обработчик |
| `Rate limit exceeded for <ip> on profile '<n>'` | WARN | превышен лимит **новых соединений** с IP (`new_session_rate_max` за `new_session_rate_window_secs`) — соединение дропнуто **до** хендшейка. Частая причина — реконнект-шторм клиента или флуд probe'ов |
| `Accept error on profile '<n>': <e> — backing off 100ms` | ERROR | `accept()` упал (напр. EMFILE — исчерпаны fd); пауза 100мс от спина |
| `obfs accept failed for <addr> …` | DEBUG | не прошёл obfs/websocket-nonce обмен до qeli-хендшейка (несовпадение `obfs_key`/`fronting`) |

### 4.5 UDP-специфика

| Сообщение | Уровень | Что значит / фикс |
|---|---|---|
| `UDP handshake started for <addr> … (fragmented, QUIC-masked)` | INFO | принят ClientHello, отправлен ServerHello |
| `UDP handshake failed for <addr> …: <e>` | DEBUG | причина ниже |
| `UDP initial too small (NB < 1200B) — anti-amplification guard` | DEBUG | первый датаграм меньше 1200 Б — защита от рефлектор-амплификации. Нормой клиент паддит до ≥1200; если видите — старый/битый клиент |
| `UDP drop … no handshake permit (pre-auth crypto saturated)` | DEBUG | исчерпан семафор пре-авторизационного PQ-крипто (защита от спуф-флуда). Под реальной нагрузкой безобидно; под флудом — работает как задумано |
| `UDP drop … QUIC unwrap failed (<e>)` | DEBUG | датаграм заявил QUIC-маскировку, но не развернулся — несовпадение `quic` клиент↔сервер |
| `AUTH attempt UDP … user=…` → `UDP client … authenticated …, IP: …` | INFO | обычный успешный путь; auth использует те же WARN-строки из §4.3 |
| `UDP writer for <addr> kicked on profile '<n>'` | INFO | writer сессии получил kick: supersede (реконнект того же устройства) / session-cap / кража static-IP / reaper / over-quota. **Само по себе не ошибка** — см. §6.3 |

### 4.6 REALITY (`reality-tls` / reality-proxy)

Крипто REALITY молчит: невалидный клиент **прозрачно проксируется на `target`**
(защита от активного зондирования), обычно без лога или DEBUG
`REALITY: bridging non-Qeli connection … to <target>`.

| Сообщение | Уровень | Что значит |
|---|---|---|
| `REALITY: Qeli client detected from <addr> …` | INFO | клиент прошёл short_id-дискриминатор + anti-replay |
| `REALITY: Qeli client <addr> … failed after the handshake discriminator (likely config/version/core mismatch): <e>` | WARN | short_id совпал, но аутентифицированный carrier или следующий qeli-обмен упал — обычно рассинхрон конфига/версии/ядра (не probe). Сверьте `key`, `reality_sid`, версии и порядок обновления |
| `REALITY: genuine HTTP/2 carrier established with <addr>` | DEBUG | текущий H2 carrier установлен; далее идёт обычная qeli-аутентификация |
| `REALITY HTTP/2 carrier timed out/failed for <addr>: <e>` | WARN/error context | REALITY discriminator прошёл, но H2 не поднялся. Проверьте server-first порядок и уберите TLS termination/H2 conversion перед qeli |
| `REALITY: replayed session_id … — bridging as probe` | WARN | повтор session_id в окне (replay захваченного ClientHello) — забриджено как probe |
| `REALITY: failed to connect to backend <target>: <e>` | WARN | сервер не смог достучаться до decoy-сайта |

Условия, при которых клиент считается «не-qeli» и бриджится (тихо): не распарсился
ClientHello; key_share ≠ 32 Б; AEAD session_id не открылся **или** таймстамп вне
±120 с (проверьте часы!); **short_id не в allow-list** (`short_ids`). Последнее —
самая частая причина «reality не пускает»: `reality_sid` клиента должен быть в
`obf.tls.reality_proxy.short_ids` сервера.

На актуальном пути клиент также пишет INFO `REALITY-TLS carrier: genuine HTTP/2 stream`.
Обновляйте сначала сервер: новый сервер принимает H2 и legacy Reality carrier, новый клиент —
только H2. Reverse proxy/LB перед qeli должен работать как прозрачный TCP pass-through.

### 4.7 Веб-панель

| Сообщение | Уровень | Что значит / фикс |
|---|---|---|
| `Web panel NOT started: bind <addr> has NO admin password…` | ERROR | **fail-closed**: публичный бинд без `web.password_hash` → панель НЕ стартует (VPN работает!). Задать пароль: `qeli set-web-password`, включить `web.tls = true` |
| `Web panel on non-loopback <addr> WITHOUT TLS…` | WARN | публичный бинд без TLS — креды в открытом виде. Включить `web.tls` |
| `Web panel CSRF protection is DISABLED (web.csrf=false)…` | WARN | `web.csrf=false` (опасно на публичном бинде) |
| `panel: REFUSING live web-settings reload — … NO admin password…` | ERROR | live-reload панели тоже fail-closed |
| `Web UI (HTTPS) listening on https://<addr>` / `Web UI listening on http://<addr>` | INFO | панель поднялась |

---

## 5. Каталог ошибок — клиенты

Windows, macOS и Android используют общий транспорт в Rust; C#/Kotlin-адаптеры
добавляют сообщения системных API, служб и UI. Общие ошибки ядра собраны ниже;
платформенные отличия помечены. Текст и префикс могут зависеть от адаптера и версии.

### 5.1 Подключение / хендшейк

| Строка | Что значит | Фикс |
|---|---|---|
| `Service started: TCP/fake-tls` (`+QUIC` для UDP+quic) | первая строка коннекта | — |
| `Connecting TCP/UDP <ip>:<port> as user '<u>'…` | резолв+коннект к серверу | если дальше нет `TCP connected` — порт закрыт/фаервол/не тот IP |
| `TCP connected` / `Bound carrier socket to …` | несущий сокет установлен | — |
| `ClientHello sent (NNNN B, hybrid X25519+ML-KEM)` | отправлен PQ-ClientHello | если дальше тишина → **PMTU** (см. §6.1) или сервер молча дропнул (режим/ключ) |
| `Server identity verified [OK]` | личность сервера сошлась | — |
| `Auth failed: <текст сервера>` | сервер ответил не `OK:` — **неверные креды/бан** | сверить юзера/пароль; на сервере смотреть WARN `AUTH FAIL` (§4.3) |
| `Failed to parse ServerHello` / `Failed to parse hybrid ServerHello` | ответ сервера не распарсился как ServerHello | версия-скью **или** UDP-реконнект с чужими пакетами / битый QUIC-фрейм (см. §6.2) |
| `Auth OK, IP 10.x.x.x` | сессия установлена, выдан IP | — |
| `Applied server-pushed obfuscation params` | применены пуш-настройки obfs | — |

**Крипто/пиннинг (Windows/macOS бросают `SecurityException` → терминальный стоп
без ретраев; Android — `[SECURITY]` + stop):**

| Строка | Что значит | Фикс |
|---|---|---|
| `[SECURITY] Server identity changed — possible MITM…` / `SERVER KEY MISMATCH - possible MITM` | пиннутый ключ ≠ ключ сервера | если ключ сервера **намеренно** сменился — убрать пиннинг/старую TOFU-запись и переподключиться; иначе это MITM |
| `SERVER KEY MISMATCH for <id> … Pinned <a>, got <b>. If you deliberately rotated the key, remove its line from <known_hosts>…` | TOFU-запись устарела | удалить строку сервера из known_hosts (десктоп) / очистить сохранённый ключ (Android) |
| `server sent proof-only but no server_public_key pinned` / `server auth proof INVALID` | доказательство личности не сошлось | сверить `key=` с `qeli show-identity` |
| `Pinned server key for <id> on first use (TOFU)…` | первый коннект — ключ запомнен (не ошибка) | для явного пиннинга задать `key=` |

**Guard'ы конфига на этапе коннекта (бросаются, не в парсере):**

| Строка | Что значит / фикс |
|---|---|
| `obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)` | режим obfs без `obfs_key` — задать ключ |
| `reality-tls requires a pinned server key (auth.server_public_key)` / `server key must be 32 bytes (64 hex chars)` / `reality-tls requires reality_sid` | reality-tls без `key=`/`reality_sid=` — дозадать |
| `bind_static_to_session is on but no server key is pinned…` / `… all-zero TOFU sentinel…` | `bind_static` требует пиннинга ключа — задать `key=` или `bind_static = false` |

### 5.2 TUN / адаптер / маршруты

| Строка | Платформа | Что значит / фикс |
|---|---|---|
| `Wintun prewarm failed (<e>); will open in SetupTun` | Win | фоновое (параллельное хендшейку) создание адаптера не удалось — откроется синхронно (медленнее) |
| `NOTE: a Wintun driver (X.Y) is already loaded by another app…` | Win | другой VPN (OpenVPN/WireGuard/Tailscale) держит общий Wintun-драйвер иной версии — возможны конфликты; нужен совпадающий 0.14.x |
| `WintunCreateAdapter failed (err …; fresh name/GUID retries also failed)` | Win | не создать адаптер (нет прав администратора / повреждён драйвер). Запускать от админа |
| `WintunStartSession failed` / `WintunReceivePacket failed` | Win | сбой сессии Wintun |
| `utun: socket(PF_SYSTEM) failed (errno …) — are you root?` | mac | нет root — запустить через `sudo` или включить launchd-демон |
| `utun: connect failed / getsockopt(IFNAME) failed …` | mac | не открыть utun |
| `Failed to establish VPN interface` | Android | `VpnService.Builder.establish()` вернул null |
| `TUN establish with IPv6 failed (<e>); retrying IPv4-only` | Android | ROM отверг только синтетический IPv6-адрес блокировки утечки в IPv4-плане. Реальный согласованный IPv6-адрес никогда не downgrade'ится: такая ошибка фатальна |
| `WARN: could not determine physical gateway; full-tunnel may loop` | все | не найден физический шлюз — full-tunnel может зациклиться; проверить сеть/маршруты |
| `local = <addr>: not pinning the server route — carrier follows the bound interface's routing` | Win/mac | при заданном `local`/`lport` серверный bypass-маршрут не ставится (намеренно) |
| `Default route now via tunnel (0.0.0.0/1 + 128.0.0.0/1)` | все | full-tunnel поднят |
| `IPv6 captured into tunnel (…)` | все | закрыта dual-stack IPv6-утечка (`allow_ipv6_leak=true` отключает) |
| `Pinned server route <ip> via <gw>` | Win/mac | несущий маршрут к серверу через физ. шлюз |
| `exclude routes need Android 13+ (API 33); ignoring N` | Android | `exclude`/точечный LAN-bypass требует Android 13+ |
| `split: app not installed: <pkg>` | Android | пакет из per-app списка не установлен (пропущен) |
| `bad dns <ip>: <msg>` / `bad route <cidr>: <msg>` | все | сервер запушил/в конфиге битый резолвер/маршрут — пропущен |
| `<exe> <args> -> exit <code>: …` (`InvalidOperationException`) | Win/mac | обязательная команда `netsh`/`route`/`ifconfig` вернула ненулевой код — смотреть stdout/stderr в строке |
| `full tunnel: could not install route 0.0.0.0/1 …` / `… is not in the routing table … after being added` | Linux | **с 0.7.12 фатально.** Раньше это писалось в `warn` и клиент продолжал работу — половина IPv4 шла мимо туннеля при зелёном индикаторе. Теперь подключение отклоняется. Смотреть текст `ip` в строке: обычно нет прав (не root) или конфликт с уже существующим маршрутом |
| `full tunnel: could not pin the server bypass route …` | Linux | фатально: без обхода зашифрованный путь к серверу сам ушёл бы в строящийся туннель |
| `could not route included subnet <cidr> … refusing to run` | Linux | фатально: заказанная в `include` подсеть ушла бы в открытую |
| `could not install blackhole <half>` | Linux | в согласованном full-tunnel плане нет этой address family, а qeli не смог поставить fail-closed блокировку. Исправьте `ip route`/права, используйте dual-профиль либо осознанно включите соответствующий `allow_ipv4_leak`/`allow_ipv6_leak` |
| `kill-switch: could not install N allow rule(s) in QELI_KS_<if> …` | Linux | **с 0.7.12** цепочка не арминается, если не встало разрешающее правило (иначе хост отрезало бы от самого туннеля). Смотреть перечисленные правила |
| `interface '<dev>' already exists …` | Linux | клиент только ждёт освобождения имени; сервер отказывает сразу. Автоматическое удаление при recovery отключено; диагностика — §6.47 |

### 5.3 Liveness / реконнект (почему рвётся и переподключается)

RX-watchdog считает только записи, прошедшие framing, проверку длины и AEAD-аутентификацию.
Reality/H2 принудительно выключает qeli heartbeat даже при старом local/pushed значении; liveness
обеспечивают carrier и обычный аутентифицированный трафик. В остальных режимах для heartbeat
порог равен `max(3×(interval+jitter), 30с)`, для shaping —
`max(3×(idle_gap_max+1с), 30с)`. При потере аутентифицированного downlink клиент рвёт линк
и переподключается. Если оба механизма выключены, RX-watchdog отсутствует. Backoff
экспоненциальный (потолок 60с), ретраи по умолчанию бесконечны.

| Строка | Что значит |
|---|---|
| `no authenticated data from server for >Ns` | до вычисленного порога `rxDead` не пришла валидная heartbeat/cover/data-запись. Сырая или поддельная UDP-датаграмма сессию живой не удерживает |
| `resumed after ~Ns suspend — reconnecting` | хост спал (стенные часы прыгнули ≫ монотонных) — немедленный реконнект. L1 |
| `Network changed — reconnecting` / `<reason> — reconnecting` | сменилась физическая сеть (Wi-Fi↔Ethernet/LTE) — проактивный `ForceReconnect`. Сопутствующая ошибка сокета (`recvfrom EBADF` / EBADF) **намеренно гасится** и в лог не идёт как `ERR:` |
| `Reconnect attempt N in Xs` | обычный backoff-ретрай |
| `Max retries reached, giving up` | достигнут заданный лимит ретраев (по умолчанию бесконечно) |
| `Reconnect disabled, giving up` | `reconnect = false` в конфиге |
| `WARN: could not prepare a safe reconnect: …; retrying recovery N/5 in Xs` | Windows/macOS повторяет восстановление предыдущего сетевого состояния **до** нового подключения. Учитываются настроенная политика ретраев и отмена; успешное восстановление сбрасывает счётчик последовательных отказов |
| `[SECURITY] could not prepare a safe reconnect: …; recovery stopped …` / `recovery retry policy exhausted` | достигнут предел последовательных отказов или политики ретраев либо не удалось безопасно подготовить классификатор/firewall. Клиент прекращает переподключение и показывает Error |
| `platform cleanup failed; egress remains fail-closed` | Windows/macOS не завершила очистку. Kill-switch/временная защита и владение ресурсами сохраняются для повторной попытки; после устранения указанной ошибки платформы повторите отключение |
| `ERR: reconnect loop faulted: …` | внешняя обработка поймала неожиданную ошибку жизненного цикла. Выполняется завершающая очистка и публикуется Error; отказ очистки не снимает защитную блокировку |
| `Connection closed cleanly` | сервер закрыл соединение чисто |
| `ERR: [<Класс>] <msg>` + `  <- <причина>` | обобщённая ошибка цикла (сокет/хендшейк) — читать вложенные `<-` причины |

**Android-специфика:** `PacketTooLarge` / oversized-record под нагрузкой и
EMSGSIZE на UDP исторически валили цикл в reconnect-шторм — в актуальных сборках
паддинг обрезается под MTU, а UDP send-error дропает пакет (не фатально). Если
видите шторм на старом APK — обновите клиент.

### 5.4 Парсинг конфига

**Android** (`Config.kt`) — бросает исключения (в UI: тост `Invalid config: …`):
`config: missing [qeli] section`, `[qeli] missing required key 'server' (host:port)`,
`'server' must be host:port, got '…'`, `'server' has empty host`, `'server' has
invalid port: '…'`; для ссылок: `not a qeli:// link`, `qeli:// authority missing
:port`, `invalid port in qeli:// link`, `empty host in qeli:// link`,
`qeli:// authority malformed IPv6 [host]:port`.

**Windows/macOS** (`VpnConfig.cs`) — INI-парсер **лениентный, не бросает**: конфиг
без `[qeli]` даёт дефолты; **невалидный порт молча откатывается на 443**; guard на
пустой `obfs_key` — не в парсере, а на этапе коннекта (§5.1). Ошибки бросает только
`FromQeliUri` (те же `FormatException`, что выше). Редактор профиля валидирует поля
отдельно: `Enter the server address.`, `Invalid port (1–65535).`, `Enter the username.`.

---

## 6. Типовые сценарии

### 6.1 «accept → тишина с обеих сторон» = PMTU black-hole

**Симптом:** клиент `ClientHello sent (…B)` и висит; сервер `New TCP connection` /
`UDP handshake started` и дальше тишина; при debug — `handshake timeout for <addr>`.

**Причина:** PQ-ClientHello крупный (~1.4–1.5 КБ, с TLS/TCP/IP уже >1500). Если на
пути MTU < 1500 (PPPoE 1492, LTE/CGNAT, VPN-поверх-VPN) и ICMP «fragmentation
needed» режется — большой сегмент молча пропадает. TCP-рукопожатие прошло
(`New TCP connection` есть), а прикладной ClientHello/ServerHello не долетает.

**Фикс (сервер, обе стороны клэмпа):**
```bash
# сервер→клиент (ServerHello): клэмп на входящий SYN
iptables -t mangle -A PREROUTING -p tcp --dport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
# клиент→сервер (ClientHello): клэмп на исходящий SYN-ACK (обычно ставит установщик)
iptables -t mangle -A OUTPUT     -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -L OUTPUT -n -v | grep TCPMSS   # проверить, что применилось
# Если listener есть и на IPv6: 1280−IPv6(40)−TCP(20) = MSS 1220.
ip6tables -t mangle -A PREROUTING -p tcp --dport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
ip6tables -t mangle -A OUTPUT     -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
```
IPv4 `--set-mss 1240` и IPv6 `--set-mss 1220` оба помещаются в путь MTU 1280. Подтверждение:
подключиться **с другой сети** (проводной Ethernet 1500). Если там работает — MTU
**вероятная**, но не единственная причина: тот же симптом дают DPI, NAT-hairpin
(см. §6.8), блокировка UDP и правила файрвола. Отличить просто: при MTU крупные пакеты
молча теряются, а мелкие ходят — то есть хендшейк проходит, а загрузка виснет. Если же
не устанавливается само соединение, MTU ни при чём. На клиенте можно снизить `mtu`
в профиле.

### 6.2 `Failed to parse ServerHello` на UDP-реконнекте

**Симптом:** первый коннект удачен, затем watchdog/событие сети инициирует реконнект →
`Failed to parse ServerHello` несколько раз; на сервере видно
повторную аутентификацию с **нового** source-порта и `UDP writer … kicked`.

**Причина:** UDP-реконнект с новым source-портом (NAT-ремап, особенно
VPN-поверх-VPN) + возможный рассинхрон QUIC-фрейминга/фрагментации ServerHello.
Актуальные сборки (0.7.11) переработали UDP-сессии (kick_all, фрагментированный
ServerHello, лечение утечки writer'ов). **Фикс:** обновить сервер до 0.7.11 или новее и
перетестить; проверить, что `quic` совпадает клиент↔сервер (`quic = true`/`quic=1`).

### 6.3 Reconnect-шторм / бан хостинга

**Симптом:** плотный цикл `Connecting… → Auth OK → closed/reconnect`, на сервере
`Rate limit exceeded for <ip>` и/или AUTH-флуд.

**Причины (все задокументированы в коде, issue #69):** преждевременный «Connected»
до поднятия TUN сбрасывал backoff; EMSGSIZE-петля на udp-quic; короткий (<5 Б)
UDP-record ронял цикл; быстрый Wi-Fi↔LTE флап без пола ретраев. **Фикс:** обновить
клиент (в 0.7.9+ добавлены пол реконнекта, «Connected только после TUN»,
дренаж UDP). На сервере — не снижать `new_session_rate_max` слишком агрессивно.

### 6.4 «Клиент не тот, что сервер» (ключ/режим)

**Симптом:** на сервере (info) `AUTH DENIED … server key not pinned`, или reality
`Qeli client … failed after the handshake discriminator`, или клиент — крипто-ошибка.

**Фикс:** сверить с `qeli show-identity --config <cfg>` публичный ключ; клиентский
`key=`, `mode=`, `reality_sid=` должны совпадать с сервером. Перевыпустить ссылку:
```bash
qeli add-client <user> --password '<pw>' --link --host <public-ip>:<port> \
  --link-profile <profile> --config /etc/qeli/server.conf
```

### 6.5 Серый индикатор профиля ≠ «не подключено»

Серая точка на карточке профиля — это **проба доступности сервера**
(Unknown/серый = ещё не проверяли), а **не** статус туннеля. Статус туннеля —
отдельный индикатор (Disconnected/Connecting/Connected/Error). Нажмите «Ping» /
подождите авто-опрос. Зелёный при подключённом активном профиле выставляется
напрямую (проба сквозь живой full-tunnel ненадёжна).

### 6.6 `protect() failed …` (Android) = конфликт с always-on VPN

`WARN: protect() failed for <label> after retries — the socket may not bypass the
tunnel (another active/always-on VPN, or VpnService not ready)` — почти всегда
установлен **другой always-on VPN**. Отключить его / снять «Always-on VPN» в
настройках Android.

### 6.7 Панель :8080 не поднимается, но VPN работает

`Web panel NOT started: non-loopback bind … NO admin password` (fail-closed). VPN
жив, только панель не стартует. Задать пароль (`qeli set-web-password`) + `web.tls = true`,
затем рестарт. Не путать со сбоем VPN.

### 6.8 Клиент и сервер в одной локальной сети → реконнект-петля

**Симптом:** клиент и сервер в **одной подсети** (например, оба `192.168.50.0/24`).
Хендшейк проходит полностью — `Server identity verified`, `Auth OK`, `TUN ready` — но
трафик не идёт: срабатывает аутентифицированный RX-watchdog (если включён
heartbeat/shaping) или сервер рвёт idle-сессию через ~20с (`Удаленный хост принудительно разорвал` / на сервере — реап неактивной
сессии) → бесконечный реконнект. **Тот же профиль с другой сети (интернет / другая
подсеть) работает** — это и есть главный признак.

**Причина (маршрутизация, не баг клиента/сервера):** десктоп-клиент пинит /32-маршрут
на сервер **через физический шлюз** (`Pinned server route <srv> via <gw>`), чтобы несущий
трафик не заворачивался обратно в туннель. Когда сервер **on-link** (та же подсеть, что и
клиент), это создаёт асимметрию: исходящие идут `клиент → шлюз → сервер`, а ответы —
`сервер → клиент` напрямую (та же подсеть). Шлюз пропускает пару пакетов хендшейка, но
рвёт устойчивую data-плоскость. С другой сети сервер реально за шлюзом → маршрут
симметричный → всё работает.

**Фикс:** в клиентском профиле задать `local` = IP этого хоста в локалке:
```ini
local = 192.168.50.50
```
При заданном `local` клиент привязывает несущий сокет к этому интерфейсу и **не** пинит
сервер через шлюз → сервер достаётся on-link напрямую → симметрия, туннель на той же
локалке работает. Быстрая проверка причины — подключиться с другой сети (проводной
Ethernet / мобильный интернет): если там работает, а в локалке нет — это оно.

Диагностика на сервере (пока клиент подключён, но трафик стоит): счётчики сессии
показывают `SENT`/`RECV` = 0 и растут только при реальном обмене — при этой проблеме
оба нуля даже под нагрузкой, т.к. асимметричный несущий поток не проходит.
```bash
qeli list-clients                      # SENT/RECV сессии (0/0 = data-плоскость не идёт)
```

### 6.9 Панель не даёт сгенерировать QR/ссылку — «нет прав на `/etc/qeli`»

**Симптом:** установка прошла, VPN работает, но в панели не выпускается ссылка или QR;
в логе — отказ по правам на `/etc/qeli/users.conf.lock` (или на сам `users.conf`).

**Причина.** Служба и панель работают от пользователя `qeli`, но CLI обычно запускают
через `sudo`. Атомарная запись — «записать во временный файл и `rename`» — подставляла
**новый inode, принадлежащий тому, кто писал**, поэтому один `sudo qeli add-client`
переводил `/etc/qeli/users.conf` из `qeli:qeli` в `root:root`. Файл блокировки создаётся
с владельцем охраняемого файла, тоже становился root-овым — и панель, работая от `qeli`,
больше не могла взять блокировку. Ownership repair из postinst тут не помогает: он отрабатывает
при установке, **до** этих записей.

**Исправлено** начиная с 0.7.13: атомарная запись сохраняет владельца заменяемого файла
(регрессионный тест `atomic_write_preserves_owner`, запускается от root). На **уже
сломанной** установке владельца надо вернуть руками — один раз:
```bash
sudo qeli set-service-user qeli
sudo systemctl restart qeli
```
Проверка: конфиги/identity/users службы и их locks должны принадлежать `qeli`; каталог `client-links` остаётся root0700, резервные копии `*.bak-*` сохраняют владельца.
```bash
ls -la /etc/qeli/
```

### 6.10 Клиент отказывается менять DNS: systemd-resolved не является резолвером

**Симптом:** подключение с `dns = tunnel` останавливается с сообщением
`refusing to replace /etc/resolv.conf with tunnel DNS`.

**Причина.** В `/etc/resolv.conf` должны быть фактические `nameserver` только
`127.0.0.53`/`127.0.0.54`; обычный файл тоже допустим, имя symlink ничего не доказывает.
Отдельно проверяются доступность и контекст systemd-resolved/D-Bus. Установка службы
без её запуска недостаточна; Qeli не активирует её автоматически. См. §6.76.

Начиная с 0.7.15 qeli намеренно **не подменяет постоянный `/etc/resolv.conf`**: после
`SIGKILL`, сбоя питания или удаления клиента в нём мог остаться адрес исчезнувшего туннеля
и отключить DNS всей машины. Новые backup-файлы не создаются, а старые требуют
ручного восстановления по §6.20: startup больше не меняет глобальный resolver.
Включите безопасную per-link настройку:
```bash
sudo systemctl enable --now systemd-resolved
sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```
Проверка (обычная рекомендуемая ссылка на stub):
```bash
ls -l /etc/resolv.conf
```
Если DNS уже управляет NetworkManager, dnsmasq или платформа OpenWrt, оставьте это управление
ей и задайте `dns = off` в профиле qeli.

### 6.11 После сохранения настроек в панели службу приходится рестартить руками

**Симптом:** «Применить и перезапустить» отрабатывает без видимой ошибки, но служба
продолжает работать со старой конфигурацией.

**Причина.** Панель работает не от root, а `systemctl restart` непривилегированному
пользователю разрешает правило polkit. В `.deb` оно есть; при установке скриптом или
вручную — нет. Панель запрашивает у polkit право фактического пользователя службы на
фактический unit и при отказе возвращает `polkit_missing`. Сам файл правила не проверяется:
в Ubuntu каталог `/etc/polkit-1/rules.d` может быть недоступен пользователю `qeli`, хотя
polkitd успешно загрузил правило.
```bash
sudo qeli install-polkit
sudo systemctl restart qeli
```
Проверять нужно итоговое разрешение, а не чтение каталога с правилами:
```bash
sudo -u qeli systemctl restart qeli.service
```

**В контейнере** правило не поможет: `systemctl` там не управляет хостом, поэтому
«Применить и перезапустить» перезапустить службу не может — панель сообщает об этом
отдельно (`kind: container`). Перезапускать надо снаружи:
```bash
docker restart <имя-контейнера>
```

### 6.12 Клиенты: долгое восстановление после сна или разблокировки телефона

**Симптом:** после выхода из сна туннель поднимается около минуты; иногда за это время
туннель пропадает совсем и трафик идёт мимо VPN.

**Причина.** Экспоненциальный бэкофф реконнекта существует, чтобы не долбить лежащий
сервер, но он засчитывал и попытки, падавшие в **ещё не поднявшуюся сеть** (Wi-Fi
переассоциируется, DHCP не завершён). При базовой задержке 1с задержка удваивается
каждую попытку, так что несколько попыток, сгоревших за время подъёма сети, оставляли
клиента спать 16–32с уже **после** того, как сеть заработала. При заданном
`max_retries` те же попытки могли его исчерпать, а отказ от реконнекта снимает TUN и
маршруты — отсюда и уход трафика в обход туннеля.

**Чинилось в два приёма, оба в 0.7.13.** Первая правка ограничила паузы **между** попытками
(повтор не реже чем раз в ~4с в течение 30с после пробуждения). Сама по себе она верна, но
главного не покрывала: время уходило **внутри одной попытки**, и в сборках 0.7.13 до второй
правки задержка оставалась прежней.

**Что закрыла вторая правка.** Резолв имени шёл блокирующим вызовом **без таймаута**, а на
connect и на чтения хендшейка отсчитывался `ConnectionTimeoutSecs` — по умолчанию **30с
каждый**. Одна неудачно попавшая попытка перекрывала всё окно оседания целиком. Теперь на
время оседания весь этап до data-plane (резолв + connect + хендшейк) ограничен 5с, а резолв
ограничен по времени всегда. Вдобавок само окно в самом частом случае вообще не взводилось:
оно ставилось за проверкой «туннель ещё подключён», а после сна туннель к моменту события
Resume уже мёртв. Отдельных действий не требуется — нужна актуальная сборка 0.7.13.

**Закрытие мобильного и headless-сценария в 0.7.15.** Android wake lock не даёт уснуть CPU,
но не сохраняет Wi-Fi association или NAT mapping, а тот же объект Android `Network` может
пережить смену DHCP/link. Теперь сервис сравнивает capabilities, адреса, маршруты и DNS этой
сети, а после включения экрана коротко ждёт готовности физического IPv4-пути и заменяет native
generation, сохраняя TUN. iOS после `PacketTunnelProvider.wake()` тоже заменяет установленную
generation, а не только пишет событие в лог. Windows Service и macOS launch daemon сами опрашивают
отфильтрованную сигнатуру физической сети: GUI-callback не владеет headless-туннелем. На Android
и iOS одновременно допускается только один незавершённый блокирующий resolver call, поэтому
повторные реконнекты не накапливают DNS-потоки.

Ручное отключение в 0.7.15 — тоже асинхронная граница. Android показывает `Отключение`, пока
Rust runner не завершился и не закрыл все дубликаты TUN-дескрипторов; только после этого сервис
публикует `Отключено` и разрешает новое подключение. Для DNS это существенно: запуск новой
generation при ещё живом старом TUN мог оставить системный resolver Android на дескрипторе, у
которого уже нет data plane. Если после ручного отключения пропадает DNS, нужен лог от
`Отключение` до следующего `Подключено`; предупреждение о teardown дольше 5 секунд укажет на
native-владельца дескриптора, который не остановился вовремя.

Проверить по логу (вкладка **Журнал** → **Copy log**): после пробуждения должна появляться
строка `Network settling — short attempt budget 5s for the next 30s`. Если она есть, а
восстановление всё равно долгое — время уходит в другом месте, и такой лог от пробуждения
до `Connected` нужен целиком. На мобильной 0.7.15 в этом интервале также ожидаются
`Device woke` / `Device wake: replacing...` (iOS) либо
`Device woke after ... screen-off — reconnecting` (Android).

### 6.13 Панель за reverse-proxy: 404 либо выброс в корень

**Симптом, по которому диагноз ставится сразу:** с `base_path` панель отдаёт **404**, а без
него — грузится, но выбрасывает в корень сайта.

> ⚠️ **Сначала проверьте, что в строке `base_path` нет комментария.** В flat-INI `#` и `;`
> начинают комментарий **только с начала строки**, поэтому
> `base_path =    # оставить пустым` задаёт значением literal `# оставить пустым`. Панель
> монтируется под префиксом, которого никто не запрашивает, и **все** маршруты, включая
> `/login`, отдают 404. Начиная с этой версии сервер такое значение отвергает и пишет в лог
> `web.base_path = "…" is not a plain URL path`, поднимая панель в корне. Пустое значение
> пишется просто как `base_path =`, без хвоста.

**Причина.** У префикса два независимых потребителя, и настраиваются они разными вещами:

| Что | Откуда берётся | Когда применяется |
|---|---|---|
| Монтирование маршрутов | **только** `web.base_path` | на старте процесса |
| `<base href>` и редиректы | `X-Forwarded-Prefix`, иначе `web.base_path` | на каждый запрос |

Отсюда две рабочие конфигурации — и они взаимоисключающие:

| | `web.base_path` | Прокси |
|---|---|---|
| A | пусто | режет префикс, шлёт `X-Forwarded-Prefix` |
| B | `/qeli` | префикс **не** режет |

**404 при заданном `base_path` означает, что ваш прокси префикс режет** — то есть вам нужен
вариант A, а не B. В nginx это решает слеш в конце `proxy_pass`: без слеша исходный URI
уходит целиком (вариант B), со слешем — префикс срезается (вариант A).

**А выброс в корень — это `trusted_proxies`.** Страницы грузятся, потому что относительные
ссылки разрешаются от URL запроса. Но каждая страница без сессии делает
`Redirect::to("/login")`, а логин — `Redirect::to("/")`, и префикс к этим редиректам
добавляется **только если он непустой**. `X-Forwarded-Prefix` принимается лишь от адреса,
указанного в `web.trusted_proxies` — при пустом списке заголовок отбрасывается, префикс
становится пустым, и редирект уводит на корень сайта.

> Именно поэтому симптом кажется плавающим: с живой сессией редиректа нет и всё работает,
> а после рестарта службы или истечения сессии панель начинает «выбрасывать в корень».

Рабочий вариант A целиком:

```ini
[web]
bind = 127.0.0.1
base_path =
trusted_proxies = 127.0.0.1
public_host = вашдомен.ru
```

```nginx
location /qeli/ {
    proxy_pass http://127.0.0.1:1444/;          # слеш ЕСТЬ — срезает /qeli
    proxy_set_header X-Forwarded-Prefix /qeli;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

`base_path` применяется только при **полном** рестарте процесса, `trusted_proxies` —
подхватывается живым.

Проверка:
```bash
curl -s https://вашдомен.ru/qeli/login | grep -o '<base href="[^"]*"'
```
Ожидается `<base href="/qeli/">`. Если `/` — в логе сервера ищите строку
`panel: ignoring X-Forwarded-Prefix from … not covered by web.trusted_proxies`: она прямо
называет адрес, который надо внести в список.

### 6.14 macOS: после удаления Qeli остался DNS `10.9.0.1`

`/etc/resolv.conf` в macOS генерируется системой; не исправляйте его вручную. Сначала
посмотрите recovery-журнал — в `previousServers` могут быть ваши собственные DNS, которые
нужно вернуть вместо `empty`:

```bash
sudo cat "/Library/Application Support/Qeli/dns-override.json" 2>/dev/null
sudo launchctl bootout system/ru.qeli.app.daemon 2>/dev/null || true
sudo launchctl bootout system/ru.autocash.qeli.daemon 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/ru.qeli.app.daemon.plist
sudo rm -f /Library/LaunchDaemons/ru.autocash.qeli.daemon.plist
networksetup -listallnetworkservices
sudo networksetup -setdnsservers "Wi-Fi" empty
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
networksetup -getdnsservers "Wi-Fi"
scutil --dns
```

Замените `Wi-Fi` точным именем активной службы. Если `previousServers` содержит адреса,
передайте их команде `-setdnsservers` вместо `empty`. Только после успешной проверки можно
удалить старый журнал:

```bash
sudo rm -f "/Library/Application Support/Qeli/dns-override.json"
```

В 0.7.15 daemon хранит намерение Connect отдельно от установки, проверяет настоящий
`launchctl bootout` и не подтверждает Disconnect, пока исходный DNS не восстановлен.

Начиная с 0.8.3 подтверждённая чистая остановка демона сохраняет `Disconnected` без
работающего heartbeat. Отметка сбрасывается до нового подключения или запуска через
launchd, поэтому неуспешный перезапуск не может её использовать. Остановка также
проверяет восстановление DNS, firewall Qeli и forwarding и требует от демона статуса
`Disconnected`; ошибка очистки, отсутствие или неопределённость конечного статуса не
выдаются за успех. При незавершённом восстановлении сохраняйте recovery-журналы и
проверяйте `service.log`; не удаляйте файлы состояния ради снятия ошибки в интерфейсе.
На Apple Silicon версия 0.8.3 также исправляет права при создании lock-файлов и безопасно
восстанавливает их у затронутых root-owned обычных файлов с единственной жёсткой ссылкой.

---

### 6.15 Linux: hooks игнорируются или password_command запрещён после chmod

Сообщения с `ignoring post_up`, `ignoring post_down` либо
`refusing to run auth.password_command` содержат причину запрета команды.
Используйте обычный конфиг вместо symlink, с владельцем root либо эффективным UID службы,
без записи для группы/остальных (обычно `chmod 600 /path/to/config`). Файл должен оставаться
доступен на чтение реальному пользователю службы. Проверьте также скрипты и их зависимости.

Затем перезапустите клиент или worker сервера. Одного исправления прав, повторного запуска
профиля либо SIGHUP недостаточно, чтобы разрешить команды из ранее недоверенного конфига.
Разрешённая очистка старого работающего поколения по-прежнему может выполнить сохранённый
`post_down` после изменения пути; новый конфиг применяется при следующем запуске worker.

`configuration changed while reading; retry with a stable file` означает обнаруженное
изменение содержимого или метаданных. Дождитесь завершения записи и повторите запуск;
при сохранении предпочтительна атомарная замена. `configuration must be a regular file`
отклоняет каталоги, устройства и FIFO. См. [безопасность конфигурации](CONFIG.md#безопасность).

---

### 6.16 Linux: таймаут поставщика пароля, большой вывод или скрытый stderr

`auth.password_command exceeded its execution/output deadline` означает, что выполнение,
EOF stdout либо выход shell не завершились за 30 секунд. Используйте неинтерактивный
поставщик: stdin закрыт. Фоновый потомок с открытым stdout тоже расходует этот срок;
перенаправьте его потоки, если он намеренно должен продолжить работу.

`stdout exceeds 16384 bytes` отклоняет весь вывод, в том числе короткий пароль с большим
количеством пробелов. `stdout is not valid UTF-8` отклоняет некорректные байты. Выводите
в stdout только пароль; после trim действует меньший лимит AUTH.
`failed with ...; command output is not logged` сохраняет статус выхода, скрывая stderr
от журналов Qeli. При необходимости исследуйте поставщик в защищённой сессии оператора;
не публикуйте секреты в обращениях и не включайте диагностику с паролями.
SIGINT/SIGTERM во время ожидания поставщика отменяют запуск и очищают его process group.

---

### 6.17 Linux: отказ password_file или ожидание файлового I/O при остановке

`auth.password_file must resolve to a regular file` отклоняет FIFO, устройство или каталог.
Используйте обычный файл секрета; symlink хранилища секретов поддерживается. `exceeds 16384
bytes`, `is not valid UTF-8` и `changed while reading` отклоняют весь пароль. Удалите лишний
вывод, исправьте кодировку либо закончите запись/атомарно замените файл перед повтором.
Сообщение ошибки не содержит пароль.

`auth.password_file exceeded its read deadline` относится к бюджету ожидания/чтения
30 секунд. Задача в очереди отменяется, но уже выполняющийся файловый syscall должен
вернуться до завершения штатного stop/timeout. Если остановка ждёт, проверьте файловую
систему и состояние mount. Повторная отмена вызывающей стороны не создаёт дополнительные
чтения: работающая задача удерживает единственный слот процесса до возврата I/O и выхода.

Финальный статус клиента записывается после отмены и join sampler/signal watchers.
Поэтому старый снимок sampler не перезапишет `stopped`/`failed`; зависшая синхронная запись
диагностики тоже может задержать финальную публикацию. После SIGKILL либо принудительной
отмены всей клиентской future терминальный статус не гарантируется.

---

### 6.18 Linux: kill-switch сохранён после ошибки очистки

`kill-switch retained because forwarding/NAT cleanup did not complete` означает, что
предыдущая ошибка не позволила надёжно очистить gateway/exit-node. Qeli намеренно
сохраняет включённый kill-switch. Исправьте указанную ошибку firewall/утилиты и повторите
штатную очистку либо контролируемое восстановление администратором; до этого сеть может
оставаться ограниченной. При отключённом kill_switch сообщение не выдаётся. Ошибка самого
снятия kill-switch означает другое: удаление могло частично выполниться, сохранение не
обещается.

---

### 6.19 Linux: ошибка запуска или остановки transport core

После настройки kill-switch ошибка жизненного цикла ядра завершает клиент со статусом ошибки;
она не повторяется как обычный отказ соединения. `post_down` получает `core_start_failed` /
`core_start` либо `core_stop_failed` / `core_stop` (причина / код ошибки). При отказе обоих этапов
приоритет имеет `core_stop_failed`, а сообщение сохраняет причины запуска и очистки.
Одновременный SIGINT/SIGTERM не превращает отказ остановки ядра в успешную остановку.

`kill-switch retained because transport core teardown did not complete` означает, что Qeli
не смог подтвердить остановку ядра. Очистка forwarding всё равно выполняется. Если она тоже
не удалась, сообщение указывает обе причины. Сохраните журнал ошибки и проверьте состояние
процесса, firewall и маршрутов перед восстановлением администратором; вызов хука не доказывает
успешный сброс сети. Пользовательские hook-скрипты могут самостоятельно менять firewall.

---

### 6.20 Linux: восстановление старого DNS не удалось; снимок сохранён

`legacy global DNS state ... administrator recovery required` означает, что обнаружен
`/var/lib/qeli/dns-backup.json` или `dns-holders` от старого клиента. Текущая версия
сохраняет их и отказывает в запуске, включая `dns = off`/`system`. Эти файлы не содержат
доказательства владения текущим resolver или исходного namespace. Даже корректный
снимок и отсутствие PID не разрешают автоматическую перезапись `/etc/resolv.conf`.

1. Установите исходную машину, network/mount view и остановите всех старых владельцев
   DNS. Штатный stop старого клиента перед обновлением предпочтителен. PID из файла
   может относиться к другой загрузке/PID namespace; не завершайте процесс только
   по совпадению номера.
2. Сохраните legacy evidence и состояние текущего resolver. Перед чтением снимка
   проверьте тип, размер, владельца и путь; FIFO, каталог или неизвестная symlink
   требуют отдельного разбора. Qeli не открывает их содержимое.
3. Восстановите DNS через его ответственный network manager либо проверенный оригинал.
   Для `file` нужны проверенные content/права, для `symlink` — проверенная цель.
   `absent` не разрешает удалять уже нужный resolver. `managed-no-original` означает,
   что оригинал неизвестен: DNS выбирает администратор, публичный fallback не применяется.
4. Проверьте DNS и отсутствие старых владельцев. Только после этого архивируйте
   разобранные `dns-backup.json`/`dns-holders` вне рабочих имён и повторите запуск.
   Не удаляйте живые lock-файлы и весь `/var/lib/qeli`. Один оставшийся стабильный
   `dns-holders.lock` без legacy записей запуску не мешает.

На старых бинарниках диагностика `failed to restore /etc/resolv.conf ... (backup kept
at ...)` означала неудачную автоматическую попытку. Обновление не повторяет такую
попытку. Новые подключения используют per-link systemd-resolved; snapshots старого
глобального resolver не присваиваются. [Отчёт](../reports/audit-0.8.2/AUDIT-Q25-LEGACY-DNS.md).

---

### 6.21 Linux: зарегистрированы ошибки очистки сетевых ресурсов

`kill-switch retained because network resource cleanup reported errors` означает, что
в этом запуске клиента произошла ошибка очистки DNS, маршрутов, forwarding либо отката NetworkPlan.
Клиент пытается очистить forwarding, завершает работу с ошибкой и не выполняет reconnect.
`post_down` получает `network_cleanup_failed` / `network_cleanup`; если отказала и остановка
ядра, приоритет имеют `core_stop_failed` / `core_stop`. Одновременный сигнал остановки не
скрывает ошибку. Если сервер также прислал terminal kick, его причина сохраняется в ошибке.

<!-- normative-sync: manual-terminal-policy-v1 -->

Полученный authenticated `KICK` с `reconnect_allowed=false` запрещает автоматическое
переподключение, даже если одновременно закрывается TCP stream или платформа не смогла
принять событие. Обычный EOF без KICK следует настройкам reconnect. Если старый клиент
после вытеснения снова подключается, обновите его native core: [Q09-F010/F011](../reports/audit-0.8.2/AUDIT-Q09-FINAL.md).
Непрочитанный либо потерянный пакет этим правилом не считается полученным.


Guard может повторить очистку, но поздний успех не стирает исходный отказ и не снимает
kill-switch автоматически. Проверьте первую ошибку каждого ресурса и текущее состояние DNS,
маршрутов и интерфейса перед восстановлением администратором. Запись ограничена тремя
категориями ресурсов по первым 2048 символам; это не полная история всех повторов.
Пользовательские hook-скрипты могут самостоятельно изменять firewall.

---

<!-- normative-sync: manual-management-receipts-v1 -->

ACK management-сообщения требует полного корректного payload. Повтор фрагмента до завершения сборки, неверный KICK и конфликт содержимого под прежним ID не подтверждаются. Точный повтор принятого сообщения подтверждается снова; повтор отправляется в новом authenticated PacketCodec record, поскольку повтор ciphertext отсекает replay window. [Проверки Q10](../reports/audit-0.8.2/AUDIT-Q10-CODEC-CONTROL.md).

<!-- normative-sync: manual-realtls-policy-v1 -->

REALITY-TLS использует общий строгий ServerHello decoder и post-handshake policy в async/sans-IO. Уже проверенные application bytes выдаются перед фатальной ошибкой следующей записи; после ошибки сеанс не принимает/не отправляет новые записи. Fragmented NewSessionTicket ограниченно собирается и пропускается; KeyUpdate не поддерживается и требует переподключения. В старом `qeli_realtls_open` предшествующий plaintext выдаётся с `0`, затем следующий вызов получает terminal `-1`; close_notify использует тот же terminal код, поскольку отдельного EOF-кода в ABI нет. [Q11](../reports/audit-0.8.2/AUDIT-Q11-REALITY-TLS-H2.md).

### 6.22 TCP: остановка ожидает фоновые операции

Штатная остановка закрывает создание TCP-задач и ждёт завершения reader/writer, decrypt
pipeline и обслуживания соединения перед очисткой сети. Ошибка управляющего события тоже
проходит эту последовательность. Linux-монитор путей в TCP и UDP дополнительно ждёт уже
начатое чтение маршрутов или применение обновления пути. Отдельные команды маршрутов,
firewall, TUN и busctl имеют [пределы](#627-linux-system-command-timed-out-или-output-limit-exceeded);
общий срок остановки также зависит от числа команд, проверок и ожидания выхода процессов.

При задержке проверьте журнал и состояние дочерних ip/iptables/busctl; не считайте
сетевую очистку завершённой только по запросу остановки. Принудительное завершение процесса
не гарантирует join, восстановление сети и post_down. [Отчёт и пределы проверки](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md).

---

### 6.23 UDP: завершение кандидата и старого пути

При остановке соединения Qeli ждёт задачи приёма, подключение кандидата и Linux-монитор
перед откатом платформенного пути и очисткой DNS/TUN. Отказ или истечение кандидата
завершает его receive pump; рабочий путь продолжает приём. После commit приём со старого
пути продолжается только в предусмотренном окне drain, затем его задача завершается.

Завершение не должно зависеть от прихода следующего пакета на тихий сокет или свободного
места в очереди. Задержку системной blocking-операции всё ещё нужно проверять отдельно.
Принудительная отмена всего клиента не подтверждает rollback или async join.
[Отчёт и проверенные сценарии](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md).

---

### 6.24 Завершение потоков TUN/Wintun при отмене остановки

Даже если ожидание shutdown отменено, уничтожение pump дожидается его reader/writer.
При отмене это может выполняться синхронно. Занятый blocking pool не мешает такому Drop
самому завершить join; уже работающий join дожидается обоих потоков.

Stop и закрытие входной очереди позволяют выйти из ожидания пакетов и blocking_send.
Ограниченные ожидания циклов не гарантируют конечный срок вызовов драйвера/ОС. Если
остановка зависла, различайте ожидание TUN workers, системной команды и платформенного
ACK по журналу/дампу потоков. Запрос stop или статус интерфейса не доказывает завершение
всей сетевой очистки. [Проверенные сценарии и ограничения](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).

---

### 6.25 HTTP/2: остановка при задержанном response или полном окне

Для `reality-tls` клиент учитывает внутренние H2 driver/bridge вместе с TCP-задачами,
начиная с подключения. Штатное завершение группы ждёт их освобождения до DNS/TUN cleanup.
Отмена native TCP-попытки также ждёт группу перед учётом завершения поколения.

Нулевое окно peer или заполненный bridge не должны требовать нового сетевого события
для отмены. Half-close остаётся штатным: после завершения отправки допускается ответ.
Это не обещание общего deadline остановки, подтверждение раннего rollback или гарантия
join после уничтожения всего runtime. [Отчёт и сценарии](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).

---

### 6.26 Серверный HTTP/2: остановка профиля и отклонённые запросы

В `reality-tls` профиль учитывает H2 driver, bridge и ограниченный flush отказа вместе
с задачами сессий. Штатный teardown ждёт их освобождения; отмена ожидания shutdown
сохраняет возможность повторного join. Нулевое окно peer не должно блокировать отмену.

Неверный H2-запрос по-прежнему получает соответствующий HTTP-статус. Пока соединение
отправляет отказ, его pre-auth слот остаётся занят; flush ограничен одной секундой.
H2 200 ещё не означает успешную внутреннюю AUTH. Общий срок shutdown и поведение при
уничтожении runtime этим не гарантируются. Проверки на Linux runtime остаются открытыми;
[отчёт и воспроизводители](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).

---

### 6.27 Linux: system command timed out или output limit exceeded

Для клиентских команд маршрутов, kill-switch/gateway, интерфейса TUN и `busctl`
эти ошибки означают превышение
15 секунд либо 16 МиБ на один поток вывода. Ошибка запуска и ненулевой exit code
обрабатываются отдельно. Qeli пытается завершить процесс, на Linux — также его группу,
и ожидает выход; частичный вывод не принимается за результат команды.

Применение DNS (`dns` + `domain`) делит 15 секунд от начала настройки. Сообщение
`DNS setup command budget exhausted` означает исчерпанный общий срок до следующего
шага; timeout второй команды возможен раньше её собственных 15 секунд. Lease остаётся
у поколения для отдельного отката. [Проверки](../reports/audit-0.8.2/AUDIT-Q25-DNS-BUDGET.md).

Не считайте timeout доказательством отсутствия изменений. При ошибке D-Bus `RevertLink`
marker остаётся для повтора владеющим guard. Startup не сбрасывает живой link только
по маркеру (см. §6.50). Ошибка rollback поколения видна в журнале; сообщение о попытке отката не означает успешный revert. Проверьте конкретный
интерфейс и состояние systemd-resolved. Полный срок shutdown остаётся зависимым от других
операций: команды и проверки выполняются последовательно, а kill/reap может ждать kernel.
[Исходный runner и тесты](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md),
[маршруты и firewall](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md).

---

### 6.28 Сервер: NAT cleanup ... incomplete

Это предупреждение означает, что очистка правил не подтверждена: команда чтения,
удаления или проверки завершилась ошибкой либо собственные правила остались после
успешного ответа на удаление. Журнал указывает таблицу/цепочку и причину. Qeli выполняет
конечный проход по найденным правилам и продолжает остальные цепочки при отказе.

Проверьте указанную цепочку тем же backend (`iptables` или `ip6tables`), доступность
утилиты и права процесса. У смешанных native nft-цепочек `-S` может не работать даже
при рабочем точечном DNS cleanup. Не считайте это предупреждение подтверждением
оставшегося правила без проверки: чтение могло завершиться ошибкой. Аналогично,
успешный выход сервера пока не доказывает восстановление firewall. Не очищайте целиком
таблицу администратора ради одного профиля. [Охват и открытые замечания](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md).

---

### 6.29 Linux: firewall inspection failed / DNS INPUT cleanup failed

Ошибка проверки firewall теперь отличается от подтверждённого отсутствия правила.
Проверьте путь инструмента, его backend, права и конкретную причину в stderr. Отказ
доступа с кодом 1 не означает, что правило уже удалено. Неизвестное или дополнительное
сообщение также оставляет состояние неподтверждённым; приложите полный журнал при разборе.

При очистке серверных DNS permits Qeli проверяет обе ветви UDP/TCP, даже если одна
завершилась ошибкой. Удаление ровно 1024 одинаковых правил поддерживается; сообщение
`still present after 1024 deletion attempts` означает, что последняя проверка ещё видела
правило. Возможны накопленные копии, конкурентное добавление или успешный no-op backend.
Итоговый retry известных DNS leases теперь влияет на код выхода worker — см. §6.31.
Это ещё не подтверждает очистку всех ресурсов сервера. [Отчёт о проверках](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).

---

### 6.30 Сервер: exact DNS INPUT ownership retained for retry

Удаление DNS permits не подтверждено, но worker сохранил их полное описание для
повторения. Проверьте причину перед этой строкой: доступность `iptables`/`ip6tables`,
права, backend и результат exact check/delete. Последующая очистка профиля и новая
попытка установки его DNS правил сначала повторяют неудачную очистку. Пока она
не прошла, новые DNS permits этого профиля не устанавливаются.

`DNS INPUT ownership limit reached (4096)` означает заполнение реестра активными
и ожидающими очистку наборами правил. Каждый resolver занимает один набор UDP+TCP;
IPv4/IPv6 занимают отдельные наборы. Сначала устраните ошибки очистки; успешное
освобождение правил возвращает место, старые записи автоматически не вытесняются.

Сведения находятся только в памяти текущего worker. Не рассчитывайте на сохранение
этого retry после crash или перезапуска; отдельного persistent journal пока нет.
Итоговая проверка перед выходом worker описана в §6.31; она не заменяет проверку всех
ресурсов сервера. [Отчёт и ограничения](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md).

---

### 6.31 Сервер: Server shutdown failed — owned network cleanup

Worker после завершения профилей повторяет очистку сохранённых DNS INPUT rules и
оставшихся IPv6 sysctl leases. Если она не подтверждена, остановка worker по сигналу
завершается с кодом 1 и строкой `Server shutdown failed: owned network cleanup: ...`.
При других сбоях строка также содержит `worker`, `profile/worker task cleanup`
и/или `usage shutdown flush`.
Статистика сохраняется даже после ошибки очистки сети.

`DNS INPUT lease still active at worker shutdown` означает оставшееся активное владение;
проверка не удаляет такие правила. При обычном отказе cleanup проверьте указанную
firewall-утилиту, доступ к sysctl и предыдущие ошибки профиля. Если последний retry
подтвердил очистку, прежний временный отказ сам по себе не меняет успешный код выхода.

Внешний supervisor передаёт ошибку финальной остановки worker вызывающему CLI и пишет
`Supervisor shutdown failed: ...`. Nonzero exit и принудительный kill после grace
не считаются успешной остановкой. Успешный выход worker даёт успешный результат.
При явном Restart или неожиданном падении без запроса остановки supervisor по-прежнему
перезапускает worker; ошибка завершения журналируется.

Эта проверка покрывает только известные worker DNS/IPv6 sysctl leases. Успешный код
не доказывает отсутствие generic NAT правил и ресурсов прежних поколений.
Учёт ошибок задач профиля и TUN teardown описан в §6.32.
DNS ownership после выхода процесса теряется; автоматическое восстановление exact
rules после перезапуска пока не гарантировано.
[Отчёт и открытые границы](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md).

---

### 6.32 Сервер: profile/worker task cleanup и teardown incomplete

`Server shutdown failed: profile/worker task cleanup: ...` означает ошибку завершения
задач или текущего поколения профиля. Вложенный текст различает listener/service/child
panic, ошибку профильного supervisor и TUN queue timeout/panic.
Профиль также может записать `teardown incomplete: ...`.

Ошибка одного профиля не отменяет ожидание остальных, итоговую очистку известных
DNS/IPv6 sysctl leases и сохранение статистики. Worker при остановке по сигналу возвращает
exit 1, внешний supervisor передаёт отказ вызывающему CLI. Обычная отмена дочерней
задачи при shutdown не является ошибкой. Отмена ожидания или повторный вызов shutdown
не стирают уже собранную диагностику задач.

При `queue thread(s) did not stop` поток не завершился за три секунды и может удерживать
устройство. Проверьте предыдущие ошибки профиля и указанный TUN; механизм освобождает
свои дескрипторы без удаления устройства по имени (см. §6.49). Сообщение `teardown attempted` сообщает
о попытке очистки, а не подтверждает отсутствие всех NAT правил или старых устройств.
Ошибки прежнего поколения после перехода к retry/replacement требуют отдельного учёта.
[Проверки и ограничения](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).

---

### 6.33 Сервер: could not restore stale host sysctl value(s)

При старте worker восстановление журнала sysctl обнаружило параметры без живого
владельца, которые не удалось восстановить. Запуск возвращает ошибку; в сообщении
перечислены пути. Проверьте доступ службы к указанным sysctl и предыдущие сообщения
`host networking`. Не удаляйте `sysctls.state`: сохранённые исходные значения нужны для retry.
После устранения причины повторный запуск повторит восстановление.

Один сбой не пропускает остальные записи журнала. Значения с живыми владельцами
сохраняются, как и внешние изменения администратора. Неудачное повторное получение
lease теперь сохраняет прежнего владельца, чтобы recovery не восстановил original
под ещё работающим компонентом. Политика перезапуска supervisor остаётся прежней.
[Отчёт и границы проверки](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md).

Сообщение `cannot verify host sysctl owner(s)` означает, что состояние одного из
сохранённых владельцев нельзя проверить. Проверьте доступ службы к `/proc/<pid>/stat`,
ограничения procfs и согласованность PID/network namespace с владельцами журнала.
Отказ доступа, ошибочное содержимое и скрытый существующий процесс сохраняют владельца;
новый lease и startup recovery возвращают ошибку. При release независимая очистка
может завершиться, но неизвестные совладельцы остаются и входят в итоговую ошибку.

Отсутствующий sysctl и ошибочное/пустое значение сохраняют запись для восстановления.
Исчезновение прежнего имени интерфейса больше не разрешает забыть исходное значение:
причиной может быть rename или замена объекта. После потери живого sysctl-дескриптора
повторный запуск не восстанавливает такое свидетельство. Не удаляйте журнал ради обхода
проверки. [Текущий контракт](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md).

Журнал v4 разделён по network namespace. `host sysctl PID namespace mismatch` или
`host sysctl time namespace mismatch` означает обращение к одной сети из другого
контекста наблюдения процессов; выполняйте recovery в исходных PID/time namespace.
`procfs PID namespace mismatch or unavailable NStgid` требует procfs текущего PID namespace
и ядра, которое предоставляет нужные данные. Отсутствие или ошибка чтения net/pid namespace
metadata тоже останавливает операцию. Минимальные ядра без этих интерфейсов не проверены.

`legacy host sysctl journal has no namespace identity` сохраняет непустой v1 текущей
загрузки; `legacy v2 host sysctl journal lacks live descriptor ownership` — непустой v2.
До обновления остановите старых участников и завершите восстановление в исходном
контексте, пока исходные интерфейсы подтверждены. Если они уже заменены/переименованы,
нужна ручная проверка, а не слепой запуск прежнего recovery. Альтернатива — плановая
перезагрузка хоста; обычный restart Qeli не меняет boot-id. Не меняйте version/boot-id
и не удаляйте журнал для обхода проверки. Работа разных версий с одним журналом
не поддерживается. Чужие network-группы сохраняются, поэтому успех в одной сети
не подтверждает очистку остальных. [Миграция и ограничения](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md).

---

### 6.34 Сервер: IPv6 sysctl acquisition failed — rollback incomplete

Ошибка настройки route/nat66 может включать и исходный отказ acquire, и
`rollback incomplete`: не удалось подтвердить восстановление sysctl после отказа.
Это возможно даже при ошибке первого accept_ra, поскольку запись могла выполниться
до неудачной проверки. Профильный scope сохраняется для повторной очистки.

Обычный cleanup профиля и итоговая остановка worker повторяют освобождение scope.
Если оно всё ещё не удаётся, итог содержит `owned network cleanup` с `IPv6 sysctls/<profile>`.
Проверьте доступ службы к указанным sysctl и журналу, сохраните `sysctls.state` для retry.
Успешный финальный retry снимает эту сетевую ошибку; исходный отказ текущего поколения
может отдельно оставаться в `profile/worker task cleanup`.

Пока старый scope не освобождён, другой WAN/TUN для того же профиля не подменяет его.
Порядок accept_ra → forwarding и режимы `off`/`manual` сохранены; новых INI-ключей нет.
[Отчёт и проверки](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md).

---

### 6.35 Сервер: system command timed out / output limit exceeded в NAT cleanup

Команды из серверного NAT-слоя, включая iptables/ip6tables, PATH version probes и
WAN route lookup, используют срок 15 секунд и лимит 16 МиБ отдельно для stdout/stderr.
`--wait 5` остаётся ожиданием xtables lock внутри этой попытки. При timeout процесс
завершается через общий runner; превышенный вывод не передаётся парсеру частично.

`system command timed out` не означает, что firewall остался неизменным. Проверьте
причину задержки backend/xtables и предыдущие сообщения профиля. Exact DNS rule specs
сохраняются для повторной очистки в текущем worker; не считайте ошибку проверки отсутствием
правила. Generic NAT sweep сохраняет прежний best effort и журналирует неудачу.

Это ограничение отдельной команды: полная последовательность cleanup и ожидание
завершения процесса могут занять больше времени. Preflight отдельно покрыт в §6.36;
клиентские firewall/routes этим изменением не покрываются. Новых INI-параметров нет.
[Охват и подтверждённые проверки](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md).

### 6.36 Сервер: задержка preflight или недоступное состояние сети

Четыре запроса `ip` для адресов/маршрутов IPv4/IPv6 делят общий бюджет 15 секунд,
по 16 МиБ stdout/stderr на команду. Превышенный вывод не разбирается частично.

Предупреждение `pre-flight: could not read the host's network state` означает, что
IPv4 snapshot недоступен: причиной могут быть отсутствие `ip`, ненулевой exit,
ошибка чтения, timeout или превышение лимита. По существующей политике старт допускается;
отсутствие сетевой коллизии этим не подтверждается. Проверьте адреса и маршруты хоста.

Отказ чтения IPv6 адресов или маршрутов не отбрасывает IPv4 и доступную часть IPv6;
отдельного предупреждения для такого частичного отказа пока нет. Наблюдаемая коллизия
по-прежнему блокирует применение. Успешный пустой вывод допустим.

Панель выполняет preflight асинхронно до config lock; следующий шаг получает остаток
общего срока. Вся транзакция, файловый I/O и завершающий kill/reap могут занять дольше
15 секунд. Новых INI-параметров нет.
[Актуальный контракт](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md).


### 6.37 Linux-клиент: ошибка наблюдения пути или задержка остановки

При debug-логе `Linux roaming path sample failed` монитор не смог получить пригодное
наблюдение маршрутов/адресов. Его три read-only запроса `ip` теперь имеют срок 15 секунд
каждый и лимиты stdout/stderr по 16 МиБ. Timeout или превышение вывода возвращает ошибку;
неполные данные не публикуются как новый путь. Служебный вывод iproute2 не меняет
INI-формат пользовательских профилей.

При штатной остановке клиент ожидает уже запущенную команду через владельца поколения,
даже если async-монитор отменён. Это не срок всей остановки: запросы последовательны,
ожидание процесса может продлить вызов. Изменяющие маршруты команды также ограничены
по отдельности. При проблеме проверьте доступность iproute2 и предыдущий debug-лог.
[Проверки и границы](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md).


### 6.38 Linux gateway/exit-node: определение WAN и очистка

WAN выбирается независимо для IPv4 и IPv6. Сначала Qeli читает default route, затем
использует fallback — локальный route-get для `1.1.1.1` или `2606:4700:4700::1111`.
Каждый запрос имеет срок 15 секунд и отдельные лимиты stdout/stderr по 16 МиБ.
После ошибки первого запроса fallback может дать пригодный WAN; отказ обоих оставляет
WAN недоступным. Проверьте наличие iproute2 и таблицу маршрутизации нужного семейства.

Очистка exit-node использует все сохранённые WAN данного TUN, включая прежние uplink,
без поиска текущего маршрута для семейства с известными целями. При ошибке очистки
его targets сохраняются для повторной попытки. Если ownership пуст, discovery остаётся
best-effort; это не восстанавливает владение, потерянное при crash.

Срок относится к отдельному read-only запросу. Последовательный fallback и ожидание
процесса могут занять больше времени; firewall-команды gateway/kill-switch ещё требуют
отдельных ограничений. Новых INI-параметров нет.
[Проверки и границы](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-WAN.md).

### 6.39 Linux roaming: неизвестное состояние после ошибки маршрута

Неуспешная `ip route add/replace/del` могла изменить маршрут до возврата ошибки.
Для неудавшегося add/replace Qeli проверяет destination после отката предыдущих шагов:
обычный отказ с сохранением прежнего пути требует подтверждения прежнего состояния.
Удаление и восстановление оцениваются по последующему снимку независимо от статуса
команды: подтверждённое отсутствие завершает retirement, точный прежний снимок —
восстановление (см. 6.42). Неподтверждённое прежнее состояние при отказе транзакции
передаётся контроллером как `PlatformStateUnknown` и требует остановки текущего
поколения соединения.

Сообщения `failed route mutation ... did not preserve the previous route` и
`ambiguous route snapshot` объясняют причину неудачной проверки.
Проверьте затронутый IPv4/IPv6 destination и предшествующие ошибки команд.
Несколько непустых строк снимка отклоняются; восстановление multipath-снимка не реализовано.

Это не гарантия удаления всех неопределённых маршрутов. Неуспешный add не доказывает
владение; такой маршрут может остаться для проверки. Неопределённые roaming-операции
сохраняются отдельно как pending reservations без права удаления (см. 6.43).
Постоянный crash recovery и сроки команд остаются отдельной работой. Новых INI-полей нет.
[Доказательства и ограничения](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md).

### 6.40 Linux: изменившееся владение маршрутом и повтор очистки

При очистке физического маршрута Qeli сравнивает записанные gateway/device и остальные
переданные параметры с текущим exact route. `owned route changed; preserving replacement`
означает, что наблюдаемая замена оставлена на месте, а устаревшая запись журнала удалена.
Уже отсутствующий маршрут также не требует delete.

`command succeeded but route remains` означает, что совпадающий маршрут остался после
команды. Недоступный, повреждённый или неоднозначный снимок тоже даёт ошибку очистки;
спецификация сохраняется для retry. При потере результата команды очистка может завершиться,
если последующий запрос подтверждает отсутствие. Успешная смена пути обновляет параметры
будущей очистки.

Журнал остаётся в памяти, но записи уже разделены по владельцу подключения (см. 6.41).
Recovery после crash, атомарная защита от изменений других процессов и сроки команд
остаются открытыми. Новых INI-параметров нет.
[Проверки селекторов](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md).

### 6.41 Linux: владелец маршрутов завершён или ещё занят

`route owner is stopped/has expired` означает, что старый prepare/commit больше не
может менять маршруты после начала очистки или освобождения владельца. Новый план
должен получить собственный owner; повтор номера generation не возобновляет прежний.

`still live or has pending cleanup` означает, что имя TUN занято живым guard либо
осталась неподтверждённая очистка. Живой guard повторяет только свою очистку. Если
последний guard уже освобождён с остатками, новое подключение может освободить
резервирование только после read-only подтверждения их отсутствия и при выполнении
условий 6.43. Автоматического присвоения/удаления неподтверждённого маршрута нет.
Сначала выясните причину исходной ошибки и состояние соответствующих маршрутов;
перезапуск процесса сам по себе не доказывает их удаление.

`belongs to another Qeli owner` означает конфликт carrier/exclude/blackhole с другим
подключением этого процесса. Совместное владение таким маршрутом не поддерживается.
`dev_attach=true` оставляет маршруты внешнему управляющему: Linux не объявляет
`ROAMING_PATH`, `roaming=auto` использует reconnect, `required` недоступен.
[Регрессии и границы](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md).

### 6.42 Linux roaming: результат удаления или восстановления не подтверждён

`carrier route ... remains after retirement` означает, что после delete маршрут остался,
даже если команда вернула успех или «уже отсутствует». `changed before retirement`
означает, что прежний снимок изменился ещё до удаления: Qeli не удаляет наблюдаемую
замену и не воссоздаёт маршрут, исчезнувший до этого шага.

`could not restore carrier route ... snapshot differs` означает, что повторный снимок
не совпал с сохранённым; `could not verify restored carrier route` — что проверку
после восстановления выполнить не удалось. Успешный exit status сам по себе недостаточен.
Если прежний снимок подтверждён после потерянного результата, восстановление считается
завершённым. Аналогично подтверждённое отсутствие завершает удаление.

При отказе Qeli проверяет откат всех выполненных шагов. Если состояние прежнего пути
не доказано, требуется остановка поколения, а не продолжение на предположительно
восстановленном пути. Проверьте указанный destination, текущий снимок и предыдущие ошибки;
учёт pending и условия освобождения отсутствующих orphan описаны в 6.43.
Полного семантического сравнения всех атрибутов и атомарной защиты от внешних изменений
нет; новых INI-параметров также нет.
[Регрессии и границы](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md).

### 6.43 Linux: pending reservation после неопределённого результата

`unresolved route mutation; destination remains reserved without delete authority`
означает, что результат команды не позволил доказать владение, а destination всё ещё
присутствует. Qeli сохраняет запись операции и ошибку cleanup, но не удаляет этот
маршрут на основании pending. Совпадение его параметров с планом не доказывает авторство.
`could not verify pending route` означает, что не удалось получить корректный снимок.

Неизвестный результат commit сразу закрывает новые route-операции этого owner,
включая gateway refresh. Живой guard может повторять cleanup; pending снимается
только после подтверждённого отсутствия destination. После успешной очистки старый
owner остаётся закрытым, а новый возможен после освобождения последнего guard.

Если guard уже освобождён, новое подключение того же процесса выполняет read-only
проверку orphan только после ранее подтверждённого результата IPv4/IPv6 interface flush.
Подтверждается пустое состояние, а не только успешный статус команды (см. 6.44). Требуются
отсутствие всех сохранённых destinations и пустые маршруты интерфейса в обеих семьях.
`orphan route reservation ... is still present` и
`could not confirm empty interface routes` означают, что освобождение запрещено.
Иная ошибка запроса также сохраняет reservation; маршруты не перезаписываются.

Проверьте указанные адреса, интерфейс и исходную ошибку. Запись pending не разрешает удаление маршрута.
Независимая очистка принадлежащего Qeli интерфейса описана в 6.46. Без предшествующей очистки, после неподтверждённого
interface flush или при живом guard автоматическое освобождение недоступно. Этот механизм
работает внутри процесса: он не восстанавливает journal после crash/restart. Pending также
используется при initial setup carrier/exclude/blackhole и TUN/TAP с возможным остатком (см. 6.44–6.46).
INI-параметры не добавлены. [Отчёт и ограничения](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md).

### 6.44 Linux: проверка initial setup и очистки маршрутов интерфейса

Перед установкой carrier/exclude/blackhole и TUN/TAP Qeli проверяет exact-снимок destination.
Совпадающий существующий маршрут используется без присвоения. `initial route conflicts
with an existing route` означает конфликт до записи. Ошибка чтения тоже запрещает add.

`route is absent after initial add` означает, что команда не создала проверяемый маршрут.
`initial add outcome is not proven; destination remains reserved` и
`could not verify initial route` означают возможный неподтверждённый остаток.
Setup завершается ошибкой; pending не даёт права удалить маршрут. Даже `File exists`
после исходного отсутствия не делает внезапно появившийся маршрут безопасно заимствуемым.

После flush обеих IP-family проверяется отсутствие маршрутов интерфейса.
`interface routes remain` означает реальный остаток независимо от статуса команды.
`could not confirm empty interface routes` означает, что пустое состояние не доказано.
Потерянный результат flush допускает успех, если отсутствие подтверждено.
Отказ одной семьи не пропускает очистку другой.

Если route-query вернул отрицательный статус из-за уже удалённого TUN, Qeli подтверждает
отсутствие точного имени через отдельный `ip -o link show`. Одной строки `Cannot find device`
недостаточно. `invalid link snapshot`, ошибка выполнения, не-UTF-8 вывод или найденный
интерфейс сохраняют ошибку очистки. При I/O-ошибке route-query требуется повтор проверки.

Сопоставьте адрес, интерфейс и предыдущие ошибки в журнале; живой guard может повторить
cleanup. Это не подтверждение crash recovery, произвольных policy tables/VRF или завершения
TUN workers. Новых INI-параметров нет.
[Проверки и границы](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md).

### 6.45 Linux: таймаут route/firewall и неизвестный IPv4-путь

Команды `ip` для маршрутизации клиента и команды `iptables/ip6tables` kill-switch/gateway
используют общий предел 15 секунд на вызов и по 16 МиБ stdout/stderr. При превышении
возвращается ошибка, частичный вывод не используется. Это не 15 секунд на весь setup,
cleanup или reconnect: последующие проверки и ожидание выхода процесса требуют времени.

Если команда могла изменить сеть, таймаут сам по себе ничего не откатывает.
Неподтверждённый add остаётся pending без права удаления по этой записи.
После flush проверяется реальное отсутствие маршрутов; ошибка этого запроса требует
повтора. Недоступная firewall-цепочка тоже не считается отсутствующей.
Проверьте предыдущие ошибки, работоспособность iproute2/iptables и состояние конкретного
интерфейса; не объявляйте cleanup успешным только по завершению дочернего процесса.

`IPv4 can become active` означает, что IPv4 firewall не установлен. Отсутствие
текущего default route не гарантирует отсутствие IPv4-пути на всю сессию: маршрут может
появиться позже. Исправьте `iptables` либо осознанно задайте `allow_ipv4_leak = true`.
Этот параметр разрешает утечку IPv4; он не восстанавливает firewall.

Новые ключи конфигурации не добавлены. Linux runtime, полный gateway rollback и общий
deadline транзакции остаются отдельными проверками.
[Отчёт и evidence](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md).

### 6.46 Linux: TUN/TAP-маршрут не подтверждён или повреждён список route_local

Установка connected pool, full-tunnel capture, pushed/include/DNS routes и override
локальных сетей проходит через общий installer. `initial route conflicts with an
existing route` означает, что точный prefix уже имеет другой интерфейс, gateway или
метрику. Прямой L3 TUN не заимствует маршрут с gateway. Успешного exit code недостаточно:
после add проверяется фактический снимок; при неизвестном результате setup завершается
ошибкой и owner больше не принимает route-операции.

Проверьте текущую запись и ожидаемый план. Не удаляйте конфликтующий маршрут только
по совпадению prefix: он может принадлежать другой настройке или другому владельцу Qeli.
Нулевая метрика IPv4 может не отображаться; IPv6 metric 0 имеет эффективное значение
1024. Qeli учитывает эти формы и проверяет остальные явно запрошенные метрики.

При cleanup pending не разрешает отдельный `route del`. Принадлежащий Qeli TUN/TAP
независимо очищается по интерфейсу; это охватывает и маршруты на нём, которые ранее
были заимствованы. После flush Qeli проверяет отсутствие pending destinations.
Удалённый таким образом остаток снимает reservation; маршрут на другом интерфейсе
или недоступный snapshot сохраняет ошибку. Это правило не разрешает присвоить интерфейс,
открытый через `dev_attach`.

`invalid connected IPv4 address snapshot for route_local` означает повреждённый ответ
`ip -4 -o address show up scope global`. Qeli отказывается считать его пустым списком
и останавливает setup до записи маршрутов. Проверьте доступность и вывод iproute2.
Корректный пустой ответ допустим; адреса своего TUN и сети вне RFC1918 не создают overrides.

Пользовательские конфиги остаются INI, новых ключей нет.
[Проверки и ограничения](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md).

### 6.47 Linux: занятое имя TUN/TAP и отказ создания

При обычном создании Linux-клиент ждёт освобождения занятого `dev` около 6 секунд
(120 пауз по 50 мс плюс время проверок). Он не удаляет существующий интерфейс
по списку PID и не меняет его persistence. Non-persistent TUN исчезнет после
закрытия последнего дескриптора владельцем.

- `still present after waiting for release` — имя осталось занятым. Завершите
  прежнего владельца или выберите другой `dev`; если это TUN/TAP внешнего менеджера,
  осознанно настройте `dev_attach=true` и соответствующий `device_type`.
- `cannot inspect interface` — запрос к ядру завершился ошибкой. Исправьте причину
  из сообщения; ошибка не считается отсутствием устройства.
- `was replaced while waiting for release` — под тем же именем наблюдается другой
  ifindex; текущая попытка прерывается.
- `Device or resource busy` при создании может означать, что устройство появилось
  после проверки. Эксклюзивное создание не подключается к нему автоматически.

Сервер при занятом `tun.name` отказывает сразу. Первая очередь клиента/сервера
создаётся эксклюзивно; последующие очереди используют возвращённое ядром имя.
`dev_attach` требует заранее созданный подходящий интерфейс; запрет создания
при его исчезновении описан в §6.48. Подмена уже существующим устройством и identity
при последующем cleanup остаются отдельными пунктами аудита.
[Проверки и ограничения](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md).

### 6.48 Linux: attach запрещает создание и проверяет формат пакетов

`cannot prohibit TUN creation while attaching` означает отказ установить защиту
перед attach. Проверьте поддержку/разрешение `TUNSETIFINDEX` в ядре и sandbox;
Qeli не продолжает открытие без защиты. То же требование относится к дополнительным
серверным multiqueue-очередям; первое эксклюзивное создание от него не зависит.
Если имя исчезло, последующий ioctl отказывает вместо создания нового TUN.

`uses IFF_VNET_HDR` означает, что внешний интерфейс использует virtio-заголовок,
который Qeli не обрабатывает. Предоставьте отдельный TUN/TAP без VNET_HDR, с NO_PI
и нужным `device_type`. Не меняйте формат устройства, используемого другим приложением.
`unsupported tun_flags` означает неизвестные features: они не сбрасываются молча.

Поддерживаемые ONE_QUEUE/NAPI/NAPI_FRAGS и режим очередей сохраняются; persistence
не изменяется. Внешний менеджер должен удерживать устройство и стабильный формат
на время открытия. Sysfs должен относиться к текущему network namespace.
Ошибка `refusing foreign tun_flags` означает, что `ifindex` из текущего namespace
не совпадает с `/sys/class/net/<имя>/ifindex`: исправьте mount sysfs, а не меняйте
флаги чужого устройства. Совпадение индексов разных namespace возможно, поэтому
защита не доказывает identity замены с тем же именем. Освобождение через дескрипторы
описано в §6.49; identity DNS/маршрутов при внешней подмене остаётся открытой.
[Отчёт, Linux-тесты и ограничения](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md).

---

### 6.49 Linux: освобождение TUN через собственные дескрипторы

Disconnect/rollback клиента и остановка профиля сервера больше не вызывают `ip tuntap del`.
Клиентский guard хранит исходный fd до окончания очистки DNS/маршрутов; серверный после
дублирования worker-fd сохраняет один оригинал до очистки сети и остановки workers.
Непостоянное устройство исчезает после закрытия всех подключённых дескрипторов.
Attach закрывает только заимствованный дескриптор
и не снимает persistence внешнего устройства.

Если устройство осталось, проверьте его фактического владельца и предыдущие ошибки
остановки очередей. Внешние держатели fd, изменённый persistence либо серверный worker,
не завершившийся вовремя, могут удерживать его. Qeli не удаляет имя принудительно.
DNS и route cleanup дополнительно проверяют исходный fd и namespace (см. §6.50–6.51).
Привилегированные внешние изменения между проверкой и командой остаются ограничением.
[Проверки и точные границы](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md).

---

### 6.50 Linux: владение DNS lease и восстановление маркеров

Сбрасывать per-link DNS может только соединение, получившее DNS lease. `dns=off/system`,
план без resolvers и отказ получить владение не выполняют per-link cleanup. Lease сохраняется
при откате setup и отключении; ошибки очистки DNS остаются терминальными.

`DNS link already has an active owner` означает lock другого поколения на этом интерфейсе.
`unrecovered DNS ownership marker` означает оставшуюся запись; она не перезаписывается.
Новые файлы — `dns-link-v2-<boot>-<netns-device>-<netns-inode>-<cookie>-<ifindex>.state` и `.lock`
в `$STATE_DIRECTORY` (по умолчанию `/var/lib/qeli`), общем с route/sysctl/firewall state. Cookie берётся из
`SO_NETNS_COOKIE`; его отсутствие запрещает managed DNS. Каталог должен быть без symlink,
чужих владельцев и group/world write. Новые файлы получают 0600; небезопасные существующие
права или владелец вызывают ошибку без автоматического исправления. Не снимайте эти проверки
удалением evidence; сначала устраните причину и проверьте фактическое состояние DNS.
Startup пропускает активных/чужих владельцев, сохраняет живые индексы и удаляет маркеры
подтверждённо отсутствующих индексов без resolver-команды. Сохранённые имя/индекс сами
по себе не запускают revert живого интерфейса.

`Legacy DNS v1 marker ... lacks namespace generation` означает сохранённый `dns-link-v1-*`.
Он не мигрирует автоматически: старый inode не доказывает поколение namespace. Совпадающие
boot/device/inode/ifindex блокируют новый lease до ручного восстановления.
`legacy DNS marker ... needs administrator recovery` относится к старым `dns-resolvectl-*`.
Перед обновлением штатно остановите старый клиент, чтобы он удалил собственный маркер.
Остановите затронутого владельца, определите настоящий интерфейс, проверьте `resolvectl status`
и восстановите DNS ответственным сетевым менеджером либо выполните revert проверенного
Qeli-интерфейса. Только затем архивируйте/удалите точный осиротевший маркер. Не удаляйте
живые `.lock`, все state-файлы сразу и не смешивайте старых/новых DNS-владельцев одного link.
После аварии на внешнем постоянном интерфейсе может потребоваться эта процедура.

Для управления DNS нужны разрешённые `TUNGETIFF`/`TUNGETDEVNETNS`, CAP_NET_ADMIN для namespace
ioctl и доступные namespace/boot metadata procfs. `cannot verify TUN namespace`,
`DNS cleanup namespace changed`, `DNS link identity changed` либо смена маркера запрещают
изменения и сохраняют evidence. Команды используют сохранённый числовой индекс после проверки
исходного fd; обычный rename поддерживается, а отключённый от удалённого устройства fd
не даёт права делать revert замены. Сервис resolved должен обслуживать тот же network namespace.
Внешние изменения после последней проверки и внешние DNS writers остаются ограничениями.
[Контракт lease](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md) ·
[Безопасность файлов и переход на v2](../reports/audit-0.8.2/AUDIT-Q25-DNS-MARKER-STORAGE.md).

---

### 6.51 Linux: original TUN ... was renamed, detached or changed

`route owner network namespace changed; refusing route commands` означает, что текущий
поток находится не в сохранённом namespace маршрутов. `original TUN ... was renamed,
detached or changed; preserving route reservations` означает потерю исходного имени,
индекса или связи fd с устройством. Ошибка metadata/ioctl также запрещает очистку.
Qeli не удаляет маршруты по имени, которое уже могло перейти другому устройству.

Проверки действуют в TCP/UDP disconnect, аварийном Drop и частичном setup rollback.
При доказанном namespace независимые физические bypass/blackhole всё ещё удаляются по
журналу; borrowed physical routes сохраняются. При смене namespace не запускаются даже
запросы, которые могли бы ошибочно освободить reservation. Ошибка остаётся в прежнем
контракте cleanup: удержание kill-switch не снимается лишь из-за попытки очистки.

Не переименовывайте и не перемещайте управляемый Qeli TUN во время сессии. Проверьте
имена/индексы через `ip -o link show`, маршруты обеих семей через `ip route show` и
`ip -6 route show`, namespace через `/proc/<pid>/task/<tid>/ns/net`; сверяйте поток,
выполнявший операцию. Сначала остановите внешнего менеджера, меняющего этот интерфейс,
и завершите затронутую сессию. Удаляйте вручную только остатки, принадлежность которых
подтверждена; общий flush старого имени опасен. Внешне удалённый исходный TUN не
восстанавливается созданием нового устройства с таким же именем.

Пока исходный guard жив и его identity снова подтверждается, повтор очистки допустим.
Если guard уже потерян, неподтверждённый flush сохраняет имя в процессном registry до
завершения процесса. После проверки/восстановления маршрутов и оставшихся защитных правил
может понадобиться перезапуск затронутого Qeli-процесса. В daemon сначала завершите
его другие активные сессии; перезапуск не является доказательством очистки сети.

`actual TUN name ... differs from route owner ...; refusing setup` требует точного
поддерживаемого `dev`. Управляемым маршрутам нужны CAP_NET_ADMIN, разрешённые
`TUNGETIFF`/`TUNGETDEVNETNS` и procfs namespace metadata даже с `dns=off`. Attach не
устанавливает/очищает managed routes. Поддержка rename в DNS не означает поддержку
rename всего сетевого плана. Наблюдения и iproute2 не атомарны; правила для physical
uplink и остальные setup/gateway/firewall операции ещё требуют отдельного аудита.
[Находки и проверки](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md).

---

### 6.52 Linux: route owner identity lost during path commit

`route owner identity lost before path commit`, `route owner identity lost during path
commit`, `route owner previously lost identity; refusing further setup` означают отказ
продолжать настройку текущего поколения. Смотрите вложенную причину: исходный TUN
переименован/удалён, потерян его объект-владелец, не совпадает namespace или не удалось
прочитать metadata/ioctl. Это не обычный временный отказ нового roaming-маршрута.

Qeli проверяет исходный TUN перед маршрутными командами setup/prepare/commit, до/после
platform callback и перед подтверждением успешного плана. Для managed MAC/address/up
тоже есть проверка перед каждым вызовом. Проверки не дают права считать безопасными
внутренние gateway/firewall/sysctl операции произвольного callback.

Если потерян только TUN, клиент пытается независимо откатить подтверждённые физические
маршруты в исходном namespace. Если потерян namespace, этот откат блокируется и журнал
сохраняется. Даже успешный откат не разрешает продолжить поколение с потерянной identity.
Возвращение имени или namespace после отказа не оживляет его. Неопределённые результаты
установки остаются pending и сами не разрешают удаление маршрута.

Уберите конфликт с внешним менеджером интерфейса и проверьте маршруты/namespace по
§6.51. Завершите затронутую сессию; запускайте новое поколение после подтверждённого
восстановления. Новый интерфейс с прежним именем не заменяет исходный fd. При оставшейся
процессной reservation может понадобиться описанное в §6.51 завершение процесса.
Не удаляйте общие маршруты или защитные правила только ради обхода этой диагностики.

`route owner has no original TUN identity` означает отсутствие успешного bind managed
TUN; `original TUN descriptor owner has expired` — утрату исходного объекта. Prepared
path и route journal не продлевают его жизнь: они используют Weak, а не новую очередь.
Гонка между последней проверкой и внешней командой, identity физических uplinks и
остальные gateway/firewall операции остаются ограничениями.
[Находки и проверки](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md).

---

### 6.53 Linux: gateway owner или router cleanup не подтверждён

`router ... has no bound NetworkPlan owner` означает вызов gateway без исходного
владельца. `route owner is stopped; refusing router setup` запрещает менять завершённое
поколение. `router ownership ... still reserved by another generation` означает, что
старое владение ещё не очищено. Проверяйте вложенную причину `router-plan cleanup failed`:
ошибку команды, потерю исходного TUN, namespace или доступа к ioctl/metadata.

При полном reconnect Qeli теперь удаляет gateway/exit правила и освобождает sysctl scope
до закрытия исходного TUN. Следующее поколение создаёт их заново. При roaming внутри
поколения старые WAN-правила сохраняются до его завершения. Kill-switch продолжает
действовать через reconnect по отдельному контракту.

Если TUN потерян, подтверждённые tagged правила ещё можно удалить в исходном namespace.
Восстановление sysctl целиком откладывается: даже общие forwarding/rp_filter могут остаться
включёнными, поскольку scope также содержит настройки исходного интерфейса. При потере
namespace gateway не выполняет rule queries/deletes и не обращается к sysctl journal.
Остатки и reservation сохраняются, автоматический reconnect блокируется ошибкой cleanup.

Установите причину rename/delete/смены namespace и владельца фактического интерфейса.
Повторная очистка возможна только с исходной identity; новый интерфейс с прежним именем
не заменяет её. Если исходный fd потерян, требуется проверить остатки правил и настройки
хоста перед завершением процесса и ручным восстановлением. Не удаляйте весь firewall,
чужие правила или sysctls.state только для обхода reservation. Краш не создаёт доказанного
владения для нового процесса.

Эти проверки не атомарны с внешней командой. Общий sysctl backend пока проверяется только
на входе/выходе API: его внутренние ожидания lock/prune/read/write, stale recovery и
identity физических WAN требуют отдельной проверки. Самостоятельные операции kill-switch
тоже не покрываются gateway-контекстом. [Отчёт и тесты](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md).

---


### 6.54 Сервер: поколение не перезапускается после ошибки очистки

Если профиль оставил неподтверждённые NAT/DNS/sysctl ресурсы или очередь TUN не
завершилась, worker сообщает ошибку завершения и останавливается. Запуск следующего
поколения внутри него запрещён. Проверьте исходную ошибку firewall/sysctl/TUN в логе;
успешная запись статистики не означает успешного освобождения сетевых ресурсов.

Точные правила NAT/FORWARD/MSS/DNS REDIRECT сохраняются в памяти до подтверждённого
удаления. Повторная очистка возможна, пока worker жив; отсутствие firewall-утилиты
не считается доказательством отсутствия правил. После SIGKILL этот реестр теряется,
а historical sweep не гарантирует восстановление на неперечисляемых mixed nft цепочках.

При штатной остановке всего worker освобождается и его IPv4 forwarding lease;
исходное значение восстанавливается, только если нет других владельцев и настройка
по-прежнему имеет управляемое значение. Stop одного профиля глобальную lease не снимает.
INI-параметров для этого не требуется. [Отчёт](../reports/audit-0.8.2/AUDIT-Q14-RETAINED-CLEANUP.md).


### 6.55 Linux: sysctl journal отказал в чтении или ожидании lock

`sysctls.state` должен быть обычным файлом без дополнительных hardlink, без записи
для группы/остальных и не больше 128 КиБ. Symlink/FIFO, рост, усечение или изменение
snapshot во время чтения приводят к отказу до восстановления kernel sysctl.
Сохранённые оригинальные значения при этом не удаляются. Проверьте файл и владельца
каталога состояния; не заменяйте журнал пустым ради успешного запуска.

`timed out waiting for ... host sysctl journal lock` / `timed out waiting for lock`
означает, что бюджет ожидания mutex/flock 15 секунд исчерпан. Найдите удерживающую
операцию/процесс и завершите её штатно. Удаление активного `.lock` создаёт другой inode
и разрушает взаимное исключение; оно не освобождает уже удерживаемую блокировку.
Изменение namespace во время ожидания тоже останавливает recovery до записи sysctl.
Этот бюджет не является deadline всей сетевой настройки или файлового I/O.
[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-JOURNAL-IO.md).


### 6.56 Linux: потеря identity kill switch или ошибка проверки reconnect

`kill-switch namespace identity lost` останавливает команды в текущем namespace и
сохраняет исходного владельца/правила. Не очищайте чужую одноимённую цепочку.
Вернитесь в исходный namespace для повторной проверяемой очистки либо установите
точного устаревшего владельца и используйте процедуру [Getting started](GETTING-STARTED.md).
`allow_ipv4_leak` / `allow_ipv6_leak` не обходят ошибку identity.

`kill-switch verification/address refresh failed` прекращает reconnect до следующего dial.
Проверьте указанное правило OUTPUT/FORWARD/DROP или недоступный firewall-инструмент.
Оставшаяся защита сохраняется; post_down получает reason `kill_switch_failed` и error code
`kill_switch`. При неудачном добавлении нового адреса прежнее разрешение сохраняется.
Восстановите инструмент/доступ и точные правила перед перезапуском. Не очищайте всю
таблицу filter. Корректная остановка IPv6-only не требует IPv4-инструмента, который
не использовался. Очистка без живого владельца внутри процесса не подтверждает crash recovery.
[Отчёт и границы](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-IDENTITY.md).


### 6.57 Linux: интерфейс существует, но проверка NDP/TAP не удалась

NDP proxy, MAC TAP, ifindex hooks, проверка наличия интерфейса для sysctl и автоматический
выбор TUN в панели теперь запрашивают текущий network namespace через сокет ядра.
Унаследованный `/sys/class/net` больше не служит источником этих сведений. При
`cannot inspect NDP interface` проверьте интерфейс именно в namespace Qeli, его тип
Ethernet/unicast MAC и доступ к управляющим/пакетным сокетам. `required` по-прежнему
отказывает в старте при ошибке проверки/bind; `auto` сообщает ошибку и продолжает.

Ответственность режимов `off`, `manual`, `route` и `nat66` не меняется. В частности,
`manual` с обязательным NDP инициализируется без remount sysfs, а forwarding/routing/firewall
остаются ответственностью администратора. Проверка флагов TUN/TAP `dev_attach` всё ещё
требует соответствующего sysfs mount. Снимок интерфейса не разрешает восстановление
подменённого интерфейса по имени.
[Отчёт и оставшиеся границы](../reports/audit-0.8.2/AUDIT-Q25-LINK-OBSERVATION.md).


## 7. Справочник

### 7.1 Статусы туннеля (клиенты)
`Disconnected` (серый) · `Connecting` (жёлтый, включая реконнект и «TUN ещё не
поднят») · `Connected` (зелёный, **только после поднятия TUN**) · `Error` (красный,
текст ошибки — из серверного `EXTRA_ERROR` / последней причины).

### 7.2 Цвета точки доступности (карточка профиля)
Reachable → зелёный (`N ms`) · Unreachable → красный (`offline`) · Checking →
жёлтый (`…`) · Unknown → **серый** (ещё не проверяли).

Android sentinel'ы `reach`: `-1` = недоступен (красный), `-2` = проверяется
(жёлтый), `≥0` = мс (зелёный), `null` = серый. Автоопрос — opt-in и по
умолчанию выключен; серый индикатор до ручной проверки не означает ошибку подключения.

### 7.3 Префиксы строк лога (клиенты)
`ERR:` — ошибка цикла · `WARN:` — предупреждение (не фатально) · `NOTE:` —
информационная заметка · `[SECURITY]` — крипто/MITM (**терминально**, без ретраев) ·
`  <- …` — вложенная причина исключения.

### 7.4 Уровни лога сервера
`info` (дефолт) — старт, `New TCP connection`, `AUTH OK`, все `AUTH FAIL/DENIED/
BLOCKED` (WARN). `debug` — причины отказа **до** аутентификации (`handshake timeout`,
`Client … disconnected: …`, `UDP handshake failed`, REALITY-bridging). `RUST_LOG`
переопределяет `[logging] level`.

---

## 8. Чеклисты команд

### 8.1 Сервер
```bash
# статус, версия, слушатели
systemctl is-active qeli
/usr/bin/qeli --version
ss -ltnp | grep qeli ; ss -lunp | grep qeli

# лог: только проблемы / реального времени
journalctl -u qeli --since '10 min ago' -p warning --no-pager
journalctl -u qeli -f

# включить debug и смотреть решающую строку
mkdir -p /etc/systemd/system/qeli.service.d
printf '[Service]\nEnvironment=RUST_LOG=debug\n' > /etc/systemd/system/qeli.service.d/zz-debug.conf
systemctl daemon-reload && systemctl restart qeli && journalctl -u qeli -f

# личность сервера (public key для пиннинга)
qeli show-identity --config /etc/qeli/server.conf

# брутфорс-локи
qeli list-blocked ; qeli unblock <ip>

# перевыпуск клиентской ссылки
qeli add-client <user> --password '<pw>' --link --host <ip>:<port> --link-profile <profile> --config /etc/qeli/server.conf

# REALITY-серт сервера снаружи (маскировка)
echo | openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com 2>/dev/null | openssl x509 -noout -subject

# PMTU-фикс (обе стороны)
iptables -t mangle -A PREROUTING -p tcp --dport <port> --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -A OUTPUT     -p tcp --sport <port> --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
ip6tables -t mangle -A PREROUTING -p tcp --dport <port> --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
ip6tables -t mangle -A OUTPUT     -p tcp --sport <port> --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
```

### 8.2 Клиент Android
```bash
adb logcat -s VpnSvc VpnMain            # лог сервиса + активити
# сброс профилей/согласия VPN при залипании:
adb shell pm clear com.qeli
adb shell appops set com.qeli ACTIVATE_VPN allow   # если поддерживается
```

### 8.3 Десктоп (Windows/macOS)

- `Refusing untrusted service storage` / `refusing default DLL search` — отказ защиты,
  а не повод копировать DLL рядом с EXE. Начиная с 0.8.2 Windows проверяет владельца,
  все разрешения на запись и reparse points; сервисный профиль доступен только
  SYSTEM/Administrators. Старые небезопасные файлы автоматически не принимаются.
  Сначала остановите VPN/службу и завершите восстановление DNS/маршрутов/firewall.
  Затем сохраните резервную копию для диагностики, пересоздайте защищённое хранилище
  из elevated GUI и заново сохраните профиль из доверенного источника. Не удаляйте
  активные recovery journals и не «исправляйте» только ACL поверх непроверенных файлов.
- `Legacy or untrusted Qeli storage requires migration` в разработке **0.8.3**:
  старое Windows-хранилище подготавливается через подтверждаемый
  диалог при ручном запуске GUI от администратора. Сначала штатно отключите VPN,
  завершите восстановление сети, остановите `QeliWinSvc` и закройте другие клиенты.
  При `previous tunnel task did not stop within 8s` миграция запрещена: дождитесь
  завершения задачи и повторите отключение; ошибка сама по себе не означает recovery.
  Служба и автозапуск не перемещают старые данные автоматически. Старый каталог
  сохраняется в приватной уникальной резервной копии, профиль службы затем нужно
  заново выбрать из доверенных пользовательских данных. DLL находятся в
  `%ProgramData%\QeliWin\native\<SHA256-комплекта>`, закрытые данные службы —
  `%ProgramData%\QeliWin\service`; `%APPDATA%\QeliWin` и recovery-журналы не переносятся.
  Проверка консервативно блокирует переход при любом Wintun-адаптере, даже другого VPN;
  не удаляйте чужие адаптеры/firewall и не обходите отказ. Подтверждение пользователя
  о завершении DNS/route recovery обязательно; проверки не доказывают его автоматически.
  [Подготовка старого хранилища](../../../qeli-win/README.md#подготовка-старого-хранилища-при-переходе-на-083).
- `Tunnel cleanup remains incomplete` означает, что очистка ещё не закончена:
  служба сохраняет Error вместо Disconnected. Повторите остановку и проверьте журнал.
- `TLS traffic key budget exhausted; reconnect required` — защитное завершение
  REALITY-TLS после 2^24 записей или 64 GiB ciphertext на одном ключе в одном направлении.
  Клиент использует обычную политику переподключения; KeyUpdate пока не реализован.

- Вкладка **Log / Журнал** → **Copy log** — прислать при разборе.
- Windows требует **администратора** (манифест `requireAdministrator`); macOS —
  **root** (`sudo`) или включённый launchd-демон.
- Kill-switch остался после краша? Windows:
  `Remove-NetFirewallRule -Group qeli_ks; Set-NetFirewallProfile -All -DefaultOutboundAction Allow`;
  macOS: запустить Qeli от root для проверенного recovery умершего владельца. Для явного ручного вмешательства остановить все экземпляры и очистить только anchors qeli/com.apple/qeli; глобальный pf и чужие политики сохранить. См. [kill-switch macOS](CONFIG.md#macos-pf).
- `kill-switch is owned by another live Qeli process` означает, что второй Windows-туннель
  пытается захватить общесистемное состояние firewall. Сначала остановите другой клиент/сервис.
- `[SECURITY] kill-switch disengage failed; egress remains blocked` — fail-closed режим:
  recovery state и владение сохранены, чтобы тот же процесс (или следующий запуск) повторил
  полное восстановление трёх профилей firewall. Не удаляйте recovery state вручную.

---

*Документ основан на текущем коде (`qeli/src/**`, `qeli-shared`, `qeli-win`,
`qeli-mac`, `qeli-android`) на ветке `dev`. Строки ошибок сверены с исходниками;
если поведение расходится — доверяйте коду и обновите этот файл.*

### Ошибки очистки gateway или порядка kill-switch

`gateway cleanup failed` сохраняет записи TUN/семейства для повтора в работающем
процессе. Разберите указанную ошибку firewall; успешная очистка другого профиля не
подтверждает чистоту этого. Ошибка восстановления sysctl сообщается вместе с ошибками
правил. Не снимайте сохранённый kill-switch только потому, что forwarding восстановлен.

`cannot inspect router kill-switch protection` или ошибка порядка jump запрещает
вставку либо повторное использование permit без проверенной защиты. Проверьте доступ
к iptables/ip6tables и фактический порядок FORWARD. После краша процесса журнал правил
в памяти теряется; перед ручным восстановлением разберите оставшиеся `qeli-gw-nat`
для нужного интерфейса/подсети.
[Доказательства и ограничения](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md).

### NAT exit-node или конфликт kill-switch

Если policy routing направляет пересылаемые пакеты из exit-TUN через WAN,
отличный от выбранного Qeli, они блокируются правилом `qeli-exit-node`,
а не выходят с исходным адресом клиента. Проверьте `ip rule`, маршрут
`ip route get <адрес> from <адрес-клиента> iif <tun>` и выбранный WAN в логе.
После ошибки очистки правило `qeli-exit-node:lockdown` сохраняет блокировку
до успешного повтора; не удаляйте его отдельно от оставшихся MARK/NAT-правил.
`exit_node` несовместим с `gateway_nat`, `forward` и `dev_attach` в одном профиле.

Если физический WAN был переименован или заменён во время работы exit-node,
остановите профиль и проверьте очистку `qeli-exit-node` перед повторным запуском:
новое устройство со старым именем может унаследовать допуск старых правил.
[Доказательство и граница](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md).

Если отдельный exit WAN сменился без изменения пути к VPN-серверу,
exit-node проверяет default route раз в 5 секунд и устанавливает правила
нового WAN. До успешной установки guard блокирует трафик. При ошибке в
журнале будет `exit-node WAN refresh failed`; проверьте default route,
`iptables` и выбранный WAN, если связь не восстанавливается. При нескольких
default routes Qeli выбирает наименьшую метрику; индивидуальная policy
route может выбрать другой WAN и останется заблокированной guard.
[Монитор и его границы](../reports/audit-0.8.2/AUDIT-Q25-EXIT-WAN-MONITOR.md).
Ошибка `no unique default WAN` означает отсутствие однозначного внешнего
интерфейса: проверьте `ip route show default` и `ip -6 route show default`.
При ECMP или равной минимальной метрике на разных WAN задайте один
приоритетный WAN; `route get` для одного адреса не представляет все
клиентские потоки. [Проверка ECMP](../reports/audit-0.8.2/AUDIT-Q25-WAN-ECMP.md).

На общем WAN проверяйте точные комментарии NAT `qeli-exit-node:<tun>` в каждой семье.
Старый MASQUERADE без суффикса сохраняется при очистке; не удаляйте его, пока на него
может полагаться старый exit-процесс. Отсутствие запомненного WAN запрещает автоматическое
удаление firewall, но не доказывает отсутствие остатков предыдущего процесса.

`kill-switch conflict` означает, что до установки найдена чужая per-TUN или старая
общая Qeli chain. Штатно остановите её живого владельца либо подтвердите, что цепочка
осталась после сбоя, и восстановите именно её по процедуре
[Getting started](GETTING-STARTED.md). Не очищайте всю filter-таблицу.
Неполный/нечитаемый снимок также блокирует допуск. Разрешения утечек не устраняют
конфликт политик. [Доказательства и ограничения](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md).

### Linux: занято владение kill-switch или неизвестно состояние IPv6

`cannot exclusively own this network namespace` означает, что резервирование
kill-switch не удалось. При `Address already in use` остановите другой защищённый
клиент в этом network namespace, включая экземпляр с тем же `dev`. При другой
ошибке проверьте ограничения AF_UNIX/sandbox и ресурсы процесса. До этого отказа
новый клиент не восстанавливает DNS и не изменяет firewall. Leak overrides его не обходят.

Lease освобождается при закрытии клиента, но сам по себе не удаляет firewall после
краша. Сначала установите, кому принадлежат оставшиеся цепочки; используйте точечное
восстановление из [GETTING-STARTED.md](GETTING-STARTED.md). У lease нет lock-файла,
который нужно удалять. Старые версии и ручные изменения firewall требуют отдельной
координации при обновлении.

`IPv6 can become active` после ошибки установки IPv6-части означает, что запуск без
`ip6tables` мог бы дать утечку при позднем появлении адреса. Установите/исправьте
`ip6tables` или глобально отключите модуль IPv6; `allow_ipv6_leak = true` — явное
принятие утечки. Если указан сбой rollback IPv4,
не считайте оставшийся firewall очищенным.
[Проверки и ограничения](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV6.md).

### Linux: имя TUN уже зарезервировано

`cannot reserve TUN` при `Address already in use` означает, что другой новый Linux-клиент
уже использует это `dev` в том же network namespace, даже если сейчас переподключается
и интерфейса временно нет. Остановите владельца или выберите другое имя. Правило действует
и при `kill_switch = false`, и при `dev_attach = true`: общий multi-queue интерфейс
не предназначен для двух независимых Qeli-сессий. AF_UNIX/sandbox/resource ошибки тоже
запрещают startup; отказ происходит до восстановления DNS и изменения сети.
При конфликте kill-switch временная резервация TUN неудачного запуска освобождается.

Если IPv6 выключен через `ipv6.disable=1`, доступное точное значение `1` в
`/sys/module/ipv6/parameters/disable` позволяет не обращаться к IPv6 firewall.
Если файл недоступен или модуль просто не загружен, Qeli не делает вывод «IPv6 выключен».
Не подменяйте sysfs и не отключайте IPv6 ради обхода проверки: восстановите доступ
к диагностике и разберите исходную ошибку.
[Отчёт и ограничения](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md).


### 6.58. Панель: занятый конфиг, истёкший preflight и отмена restore

`network preflight is busy`, `config is busy` или `network preflight expired`
означают, что эта попытка сохранения/restart не прошла до записи/dispatch. Дождитесь
окончания предыдущей операции, обновите конфиг в панели и повторите действие.
Сетевые пробы делят 15 секунд; после наблюдения пять секунд отведены на ожидание
config lock и подготовку кандидата. Это не срок всех операций с файлами.

После закрытия вкладки или отмены запроса уже начатый restore может продолжиться.
Блокировка остаётся у фоновой операции до её окончания. Проверьте фактические файлы
и список snapshots перед повторным восстановлением. Не считайте отмену rollback.

`could not confirm systemctl restart` означает неизвестный результат. Проверьте
`systemctl status <unit>` и journal: systemd мог уже принять запрос. Повторять
restart автоматически по одному timeout нельзя. Занятая очередь worker restart
возвращает ошибку сразу; после освобождения очереди действие можно повторить.

[Разбор](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md).


### 6.59. Backup/restore: timeout, лимит архива и неполный snapshot

Подготовка download/restore делит 60 секунд между ожиданием config lock, командами
архивации, проверками и extraction. `archive operation timed out before publication`
означает, что замена live-файлов этим restore не начиналась. После начала публикации
блокировка удерживается до завершения файловых операций; это не жёсткий срок I/O.

Portable gzip ограничен 16 МиБ, как загрузка панели; pre-restore snapshot — 64 МиБ.
`system command output limit exceeded` означает отказ от частичного результата.
Проверьте, нет ли в `/etc/qeli` посторонних крупных файлов. Если полный комплект
не укладывается в лимит, сделайте ручную полную копию перед обслуживанием.

`could not take the pre-restore snapshot` при нечитаемом файле останавливает restore.
Проверьте доступ именно от имени пользователя сервиса. Не продолжайте замену файлов,
пока не получена полная резервная копия. При ошибке уже начавшейся публикации используйте
сохранённый `.pre-restore-*.tgz`; автоматический rollback всего дерева не обещается.

[Разбор и проверки](../reports/audit-0.8.2/AUDIT-Q05-ARCHIVE-BUDGET.md).


HTTP 409 означает реальную конкуренцию или timeout ожидания FileLock. Ошибки открытия lock на read-only storage, ENOSPC при upload/extraction и сбой snapshot возвращают HTTP 500; malformed archive — HTTP 400. До публикации ответ указывает `publication_started=false`, `rollback_snapshot=null`. Если запись запретилась после распаковки, приватный `.restore-staging-*` может остаться: после возврата записи и завершения restore проверьте и удалите его вручную. Такие операционные пути исключены из backups и не используются следующим restore. [Проверки Q07](../reports/audit-0.8.2/AUDIT-Q07-BACKUP-RESTORE.md).

### 6.60. Sysctl: namespace изменился во время транзакции

`host sysctl namespace changed during the journal transaction` или `transaction lost
its namespace context` запрещает дальнейшую запись этой транзакцией. Сохраните
`sysctls.state`; не удаляйте журнал для обхода ошибки. Вернитесь к исходным network,
PID/time namespace и корректному procfs, затем повторите cleanup отдельной операцией.
Ошибка после записи не означает, что sysctl остался прежним: в журнале сохраняется
исходное значение для проверки/восстановления. Смена контекста назад не возобновляет
уже отказавшую транзакцию. [Разбор](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-CONTEXT-IO.md).

### 6.61. `published ... persistence is uncertain`

Новые байты уже опубликованы, но синхронизация каталога завершилась ошибкой. Это
не откат: перечитайте файл и его revision перед повторным сохранением. Проверьте
состояние файловой системы, свободное место и I/O-ошибки. При аналогичной ошибке
удаления имя уже может отсутствовать; повторная операция всё равно выполнит fsync.
Не удаляйте `sysctls.state` для обхода ошибки. Ошибки до rename сохраняют прежний
файл, а незавершённый временный файл удаляется, если файловая система это позволяет.
[Разбор и пределы гарантий](../reports/audit-0.8.2/AUDIT-Q25-ATOMIC-STATE.md).

### 6.62. Небезопасный sysctl state directory или заменённый lock

`unsafe sysctl state directory` означает отказ до чтения/восстановления журнала.
Используйте абсолютный реальный `STATE_DIRECTORY` без symlink и `..`; не выдавайте
каталогу или журналу group/world write. Штатный `/var/lib/qeli` может принадлежать
пользователю сервиса; root CLI сохраняет эту совместимость. Root не принимает
чужой каталог непосредственно под общим sticky `/tmp`. Не используйте `chmod 777`.

`lock changed while waiting` означает, что имя lock больше не соответствует
дескриптору ожидавшего процесса. Сохраните журнал, проверьте сторонние операции
с каталогом и повторите после завершения конфликтующей операции. Не удаляйте
lock для «разблокировки»: это создаёт новую независимую группу flock.
[Разбор и поддерживаемая политика](../reports/audit-0.8.2/AUDIT-Q25-STATE-DIRECTORY.md).

### 6.63. Sysctl: удержание namespace требует свободных fd

Транзакция теперь открывает и удерживает network, PID и доступный time namespace
до окончания работы с журналом, начиная до ожидания блокировок. Отказ открытия
(например, `Too many open files` или `Permission denied`) не разрешает продолжить
восстановление без подтверждения identity. Проверьте лимит fd и доступ к собственному
procfs от имени сервиса; не удаляйте журнал для обхода отказа. Это не постоянная
резервация namespace после завершения процесса.
[Гарантия и ограничения](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-PIN.md).

### 6.64. Потерян исходный sysctl интерфейса

`lost live per-interface sysctl evidence/witness`, `per-interface sysctl object changed`
или `cannot inspect saved sysctl ... No such file` означают, что автоматическое
восстановление исходного `rp_filter`/`accept_ra` нельзя безопасно продолжить. Даже
прежнее имя и ifindex не подтверждают исходный объект. При rename старый fd тоже может
вернуть ENOENT. Qeli сохраняет оригинал, продолжает независимую очистку и сообщает ошибку.

Остановите автоматические перезапуски и участников, использующих этот журнал. Сохраните
приватную копию `sysctls.state` и логов. По административной истории сети установите,
какому исходному интерфейсу принадлежало значение; вручную восстанавливайте только
подтверждённый исходный объект. Журнал сам по себе не доказывает тождество текущего
интерфейса. Если подтвердить его нельзя, используйте плановую перезагрузку хоста:
следующий запуск распознает валидный журнал прежнего boot-id и не воспроизведёт его.
Автоматической команды, которая безопасно угадывает соответствие и очищает такую запись,
нет. Обычный restart, переименование обратно или удаление журнала не заменяют проверку.

Лимит 256 удерживаемых per-interface объектов действует на процесс. Каждый удерживает
sysctl fd и ссылки на namespace fd; это не общий лимит в 256 дескрипторов. При
`per-interface sysctl descriptor limit reached` завершите подтверждённую очистку,
проверьте fd и оставшиеся записи. Не повышайте лимиты вместо выяснения причины.
[Разбор, миграция v2 → v3 и тесты](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md).

### 6.65. Панель: не удалось проверить наличие iptables

`Could not verify iptables availability` появляется в Status/Transport health, если
проверка через PATH завершилась ошибкой: истёк срок, нет прав на запуск, получен
ненулевой exit либо слишком большой вывод. Проверьте установку/доступ к утилите
от имени службы и повторите диагностику. Это warning; critical об отсутствии
iptables выдаётся отдельно при подтверждённом отсутствии.

На async-пробы `iptables/ip6tables --version` выделены четыре общих слота и 15 секунд
на запрос вместе с очередью. Вывод ограничен 64 КиБ отдельно для stdout/stderr.
Отмена запроса останавливает принадлежащую ему группу процессов; обычный timeout
ждёт завершения ребёнка. Kill/reap и синхронные проверки файлов не получают жёсткой
верхней границы, поэтому это не обещание времени всего HTTP-запроса. Наличие утилиты
также не подтверждает правильность firewall. [Разбор](../reports/audit-0.8.2/AUDIT-Q05-HEALTH-PROBES.md).

### 6.66. Linux: истёк общий срок очистки kill-switch

`kill-switch cleanup deadline expired; ownership retained for retry` означает, что
15 секунд попытки отключения исчерпаны ожиданием блокировки или командами обеих семей.
Проверьте зависший backend, конкурирующие операции firewall и их логи. После устранения
причины повторная очистка в том же процессе получает новый срок и проверяет остатки.
При timeout часть jump/chain могла уже удалиться; не считайте защиту подтверждённой
и не выдавайте остановку за успешную. После выхода процесса owner в памяти утрачен:
нужно проверить точные `QELI_KS_<tun>` в исходном namespace и выполнить подтверждённое
восстановление. Не удаляйте чужие цепочки. [Разбор](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-BUDGET.md).

### 6.67. Linux: обновление kill-switch остановило reconnect

`kill-switch server-address refresh deadline expired; ownership retained for retry`
означает, что время resolver, очереди или firewall-команд исчерпало общий срок 15 секунд.
Проверьте DNS/NSS, конкурирующие операции firewall и ответы iptables/ip6tables.
Ожидание DNS ограничено сроком; поздний результат системного вызова отбрасывается.
`firewall inspection failed` при проверке разрешения IP не разрешает его вставку.
Connect-loop прекращает reconnect, сохраняя защиту. Не удаляйте DROP ради обхода ошибки:
сначала устраните причину, затем выполните контролируемое восстановление/перезапуск.
Частично добавленный новый адрес может остаться вместе с прежним. Отдельный вызов refresh
в том же процессе получает новый срок, но автоматический повтор здесь не реализован.
[Разбор](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REFRESH.md).

### 6.68. Linux: установка kill-switch или её откат завершились ошибкой

`kill-switch setup deadline expired` означает, что resolver, очередь или команды
исчерпали общий срок установки 15 секунд. Проверьте DNS/NSS, конкурирующие операции
и ответы firewall. После позднего ответа новые команды установки не запускаются;
начатые изменения требуют отката, у которого отдельный общий срок 15 секунд.

`kill-switch setup rollback incomplete; ownership retained` означает, что очистка
записанных семей не подтверждена. `allow_ipv4_leak`/`allow_ipv6_leak` не обходят этот
отказ. Не считайте ни установку, ни защиту, ни полную очистку успешной: часть правил
могла уже удалиться. Устраните причину и выполните проверенную очистку. В живом процессе
она использует прежний namespace и сохранённые пути утилит; после его выхода проверьте
точные `QELI_KS_<tun>` и jumps в исходном namespace перед ручным восстановлением,
сохраняя чужие правила. Сам deadline до привязки owner не означает, что появились
новые правила. Это не жёсткий срок подключения и не автоматическое восстановление
после краша. [Разбор](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-SETUP.md).

### 6.69. Сервер: истёк срок очистки NAT

`NAT cleanup deadline expired; unresolved ownership retained for retry` означает,
что одна попытка очистки исчерпала 15 секунд на очередь или последовательность команд.
Проверьте задержки iptables/ip6tables, конкурирующие изменения firewall и число правил.
Отдельная попытка в том же worker получает новый срок и проверяет остатки. Применённое,
но поздно подтверждённое удаление остаётся pending; это не доказательство, что правило
всё ещё существует. Ошибка завершения профиля/worker не должна считаться успешной остановкой.

После выхода worker точных реестров в памяти уже нет: до восстановления проверьте
правила с точным комментарием `qeli-nat:<profile>`, DNS INPUT и журнал sysctl в исходном
namespace. Сохраняйте чужие правила; не заменяйте проверку общей очисткой firewall или
удалением журнала. Deadline не отменяет уже начатый sysctl/I/O и не гарантирует время
всей остановки. [Разбор](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP-BUDGET.md).

### 6.70. Сервер: истёк срок DNS INPUT setup/cleanup

`DNS firewall setup deadline expired` относится к 15 секундам одного набора разрешений:
очередь, очистка старых записей, UDP/TCP и проверка INPUT. Ошибка после частичной
установки запускает откат с отдельным сроком 15 секунд.

`DNS INPUT cleanup deadline expired` сохраняет запись как pending ещё до ожидания
блокировки. После устранения задержки profile/setup/final cleanup может повторить
проверку. Drop сообщает ошибку в лог; итог остановки определяется последующей
подтверждённой очисткой. `DNS INPUT cleanup still pending` запрещает признание финальной
очистки успешной, а при setup — регистрацию поверх наблюдаемого pending-поколения.
Проверьте mutex/конкурирующие операции и ответы iptables/ip6tables; не удаляйте чужие
INPUT-правила. После выхода worker требуется отдельная проверка остатков: отметка
в памяти не заменяет crash journal. DNS REDIRECT порта 53 имеет отдельную незакрытую
границу setup. [Разбор](../reports/audit-0.8.2/AUDIT-Q14-DNS-INPUT-BUDGET.md).

### 6.71. Сервер: NAT setup / rollback deadline

`NAT setup`, `IPv4 routing setup` и `IPv6 routing setup deadline expired` учитывают
ожидание firewall/registry mutex и всю последовательность команд одного setup.
Откат имеет отдельный общий срок; `NAT rollback incomplete` сохраняет точные записи
и запрещает успех установки. После устранения задержки lifecycle cleanup проверяет
остатки заново. Не очищайте чужие правила и не считайте timeout доказательством отсутствия
мутации. [Разбор](../reports/audit-0.8.2/AUDIT-Q14-NAT-SETUP-BUDGET.md).

### 6.72. Sysctl: namespace generation или legacy v3

`host sysctl network namespace generation mismatch` сохраняет журнал и отказывает
до проверки владельцев и sysctl I/O. Совпавшего inode недостаточно; не присваивайте
старому журналу текущий cookie. `SO_NETNS_COOKIE is required` требует ядра с поддержкой
этой socket option для управления sysctl. `legacy v3 host sysctl journal lacks durable
namespace generation` требует подтверждённой очистки в исходной сети до обновления
либо плановой перезагрузки. Сохраните журнал, не меняйте cookie/version/boot-id ради
запуска. [Подробности](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-GENERATION.md).

### 6.73. Router operation deadline expired

Gateway/exit-node не успел закончить команды или дождаться operation mutex. Сведения об оставшихся правилах и sysctl удерживаются для verified cleanup с новым сроком. Проверьте доступность firewall tools; не удаляйте правила по общему префиксу. Внутренний I/O может вернуться позже срока. [Контракт](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-BUDGET.md).

### 6.74. Route operation deadline expired

Проверка/изменение маршрутов или ожидание mutex превысили общий срок. Не считайте timeout доказательством отсутствия изменений. Сохранённый owner допускает verified cleanup; при неизвестном откате COMMIT останавливается. Не удаляйте чужие маршруты и не освобождайте pending-записи вручную без проверки. [Подробности](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-BUDGET.md).

### 6.75. DNS: systemd-resolved is not the active system resolver

Для `dns = tunnel` проверяется содержимое `/etc/resolv.conf`, включая цель symlink. Ссылка на upstream-файл, комментарий с адресом stub и смешанный список DNS не подходят. Используйте действующий stub или `dns = off`/`system` для управления DNS платформой. Qeli не переписывает файл автоматически. [Проверка и её границы](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONFIG.md).

### 6.76. DNS: bus/service context changed или different network namespace

Клиент отказывается менять DNS по ifindex в чужой сети или через заменённый экземпляр
службы/шины. Проверьте, что resolved обслуживает сеть клиента, брокер находится в том же
PID namespace, `busctl` установлен, `/proc` доступен, а `DBUS_SYSTEM_BUS_ADDRESS` указывает
на одну локальную Unix-шину. Не копируйте host bus в контейнер с отдельной сетью для
управления DNS. Для внешнего управления используйте `dns = off`/`system`.

После замены службы сохранённый lease не передаётся новому владельцу автоматически.
Проверьте интерфейс и состояние через `resolvectl status`; сохраните evidence перед
ручным recovery (§6.50). `LinkBusy` означает управление интерфейсом через другой менеджер;
скрытого fallback к networkd нет. Ошибка `SetLinkDNSEx` при нестандартном порте требует
resolved с поддержкой этого API: Qeli не подменяет порт на 53.
[Разбор и проверки](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONTEXT.md).

### 6.77. Server worker network namespace already owned

Другой worker или процесс удерживает `qeli.server.worker` в этой сети. Изменение
control socket, state directory либо mount/PID namespace не устраняет конфликт.
Используйте существующий worker с несколькими профилями либо выделите другому
network namespace и отдельные файловые пути. Если прежний worker ещё выполняет
`post_down`, дождитесь его выхода. После фактического SIGKILL kernel lease исчезает;
удалять для него файлы не требуется. Не удаляйте control lock живого процесса.

Неизвестный владелец не обходится автоматически; локальный процесс также способен
занять abstract-имя. Ошибка reservation unavailable может означать иной отказ bind,
который указан в сообщении. [Проверки и ограничения](../reports/audit-0.8.2/AUDIT-Q14-WORKER-NETWORK-LEASE.md).

### 6.78. Server firewall recovery incomplete

Worker не запускает профили, если точные правила из `server-firewall.state` не удалось удалить или проверить. Сохраните журнал и `.lock`, используйте прежние state/network namespace/backend, устраните отказ iptables или проблему прав и повторите запуск. Сообщение `iptables backend changed` требует возврата исходного nft/legacy backend; `server firewall journal requires SO_NETNS_COOKIE` — ядра с поддержкой этой опции. Файл с повреждённым/неподдерживаемым содержимым нельзя автоматически сбрасывать. Пустой журнал после успеха нормален. [Порядок восстановления](OPERATIONS.md#восстановление-серверного-firewall).

### 6.79. Linux: kill-switch rebuild guard остаётся после отказа

Правила `-m comment --comment qeli-ks-rebuild:<tun> -j DROP` закрывают OUTPUT и при
необходимости FORWARD на время замены прежнего kill-switch. Новый запуск с тем же
`dev` в том же namespace/backend сначала проверяет guards, затем перестраивает
обычные цепочки. Guards снимаются только после готовности всех требуемых семей.
При отказе установки или ещё одном SIGKILL защита сохраняется; `allow_ipv*_leak`
не обходят отказ восстановления. Ошибка снятия guard не удаляет готовые новые цепочки.

Временные guards строже обычного allow-list: до готовности новой цепочки они могут
блокировать DNS и loopback. Если guard остался после отказа, запуск по имени сервера
может остановиться на resolve; используйте проверенный IP либо ручное восстановление.
Сначала устраните исходную ошибку firewall и повторите запуск того же клиента.
Для ручного снятия остановите владельца, проверьте точные OUTPUT/FORWARD правила
обеих семей в исходном namespace и сознательно выберите восстановление прямого выхода.
После очистки обычной `QELI_KS_<tun>` удалите только найденные точные guard-правила:

```bash
# Пример для dev = vpn0; выполнять только для подтверждённых оставшихся правил.
sudo iptables  -D OUTPUT  -m comment --comment qeli-ks-rebuild:vpn0 -j DROP
sudo iptables  -D FORWARD -m comment --comment qeli-ks-rebuild:vpn0 -j DROP
sudo ip6tables -D OUTPUT  -m comment --comment qeli-ks-rebuild:vpn0 -j DROP
sudo ip6tables -D FORWARD -m comment --comment qeli-ks-rebuild:vpn0 -j DROP
```

Не очищайте таблицу целиком и не удаляйте guards другого TUN. Комментарии этого
префикса зарезервированы за Qeli. `kill-switch conflict` может означать guard другого
клиента даже без его обычной цепочки. При первой установке без прежней защиты guards
не создаются: контракт относится к замене существующего барьера.
[Воспроизведение утечки и проверки](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REBUILD.md).

### 6.80. Linux: owned route changed; preserving replacement

Qeli обнаружил изменение физического обходного маршрута или blackhole и оставил
его администратору. Даже при тех же destination/gateway/device смена `proto`, metric,
source или дополнительных атрибутов прекращает прежнее ownership. Это может объяснять
оставшийся маршрут после штатной остановки. Проверьте таблицу в исходном namespace;
не удаляйте все записи по одному совпадению адреса. После SIGKILL постоянный журнал
восстанавливает подтверждённые физические записи при следующем запуске; для
неопределённых intent действует процедура §6.81.
[Порядок эксплуатации](OPERATIONS.md#linux-физические-маршруты-после-изменений-администратором).

### 6.81. Linux: восстановление журнала физических маршрутов

`client route recovery incomplete` означает, что подтверждённая очистка не завершена.
`unresolved physical route intent without delete authority` — команда могла изменить
маршрут, но подтверждения владения нет. Совпадение destination не разрешает удаление.

1. Остановите владельца и проверьте исходный network namespace, boot ID и `dev`.
   Сохраните копию журнала и снимки `ip -4 route show table main` /
   `ip -6 route show table main`. Не переносите журнал в другую сеть.
2. При недоступном `ip`, отказе прав или ошибке state I/O устраните причину и повторите
   запуск. Не ослабляйте права каталога и не удаляйте стабильный lock.
3. Для pending определите происхождение конкретной записи. Удаляйте только точный
   маршрут, который администратор подтвердил как аварийный остаток Qeli. После его
   отсутствия повторный запуск снимет reservation. Если маршрут нужен другому владельцу,
   сохраните его и согласуйте план; автоматического присвоения pending нет.
4. `refuses a live or persistent TUN` требует остановить владельца и разобраться с
   существующим устройством. Не удаляйте чужой TUN по совпадению имени. `still live`
   означает занятую kernel lease; смена state path не обходит её.

Повреждённый/неизвестный формат, превышение лимитов, unsafe owner/symlink или
`context was lost` прекращают операции. Не исправляйте boot/cookie/version вручную
для обхода проверки. После смены boot ID сбрасывается только валидное прежнее состояние.
Новый журнал обязателен в managed режиме и при отключённом DNS; требуются доступный
`SO_NETNS_COOKIE` и доверенный writable `/var/lib/qeli`. Пустой журнал и `.lock`
после штатной очистки нормальны.
[Контракт восстановления](OPERATIONS.md#восстановление-физических-маршрутов-клиента).

### 6.82. Linux: persistent TUN/TAP пережил остановку клиента

Сообщение `client route recovery refuses a live or persistent TUN` означает, что
устройство с прежним `dev` ещё существует. Для обычного непостоянного TUN закрытие
последнего queue fd удаляет устройство; флаг persistence оставляет его после SIGKILL.
Совпадение имени и ifindex не доказывает право нового процесса удалить устройство.
Qeli сохраняет журнал и отказывает в таком recovery. Per-link DNS живого индекса
также не сбрасывается по одному оставшемуся маркеру.

1. Остановите прежний клиент и его автоматические перезапуски. В исходном network
   namespace установите, кто создал устройство и кто держит его очереди; остановка
   одного PID сама по себе не доказывает отсутствие другого владельца.
2. Сохраните журнал, DNS-маркеры, `ip -d link show dev vpn0`, адреса, IPv4/IPv6
   маршруты и правила firewall. Проверьте `ip tuntap show dev vpn0`, состояние
   `resolvectl status` и текущий ifindex. Здесь `vpn0` — пример, используйте свой `dev`.
3. Если устройство нужно другому процессу или его происхождение неизвестно,
   сохраните его и разберите конфликт. Не удаляйте журнал и не меняйте cookie/boot ID
   ради запуска. `dev_attach = true` не является командой аварийного восстановления.
4. Только для подтверждённого бесхозного остатка, который больше не нужен, удалите
   **именно это устройство в исходной сети**: `ip tuntap del dev vpn0 mode tun`;
   для проверенного TAP используйте `mode tap`. Перед командой повторно сверьте
   устройство и владельцев. Это ручное решение администратора, не действие Qeli.
5. Убедитесь, что устройство отсутствует, затем запускайте исходный INI с тем же
   `dev`, namespace и каталогом состояния. Qeli восстановит подтверждённые физические
   маршруты и снимет DNS-маркер отсутствующего link; неподтверждённый intent требует
   отдельного разбора (§6.81). Проверьте новый интерфейс, связь и DNS.

Удаление интерфейса не снимает оставшийся kill-switch. Сохраняйте барьер до готовности
нового подключения; для намеренного перехода на прямой выход применяйте §6.79.
Не очищайте общие таблицы firewall/маршрутов. Автоматическое присвоение persistent
устройства или чужих DNS-настроек не поддерживается.
[Проверка SIGKILL и ручного восстановления](../reports/audit-0.8.2/AUDIT-Q25-PERSISTENT-TUN.md).

### 6.83. Linux: mixed nft/legacy/firewalld recovery

Backend выбирается отдельно для `iptables` и `ip6tables`. При восстановлении
серверного firewall-журнала после смены backend Qeli оставляет записи затронутого
семейства и прекращает startup;
независимые подтверждённые удаления другого семейства могут уже завершиться.
Верните исходный backend каждого семейства. Общий flush таблиц не нужен.

Нативное nft-выражение в совместно используемой цепочке может мешать не только `-S`,
но и проверке отсутствующего правила через `-C`. В проверенном случае после успешного
`-D` возвращаются `Parsing nftables rule failed` и exit 3. Тогда правило уже может
отсутствовать в ядре, однако журнал правильно остаётся: ошибка разбора не доказывает
отсутствие. Повторный запуск будет отказывать, пока проверка остаётся неоднозначной.

Остановите автоматические перезапуски, сохраните журнал и снимок `nft -a list ruleset`
в исходном namespace. Владелец сторонних nft-правил должен восстановить совместимость
цепочки, сохранив нужную фильтрацию: например, перенести своё выражение в отдельную
нативную таблицу с проверкой hook/priority и порядка правил. Удаляйте только специально
подтверждённые ненужные правила, а не весь FORWARD. После устранения ошибки повторите
запуск Qeli; он завершит точные проверки и снимет соответствующие записи журнала.
Не заменяйте exit 3 на «правила нет» и не удаляйте state для обхода отказа.

Успех firewall recovery не означает завершения всех подсистем. Для
`lost live per-interface sysctl evidence` на WAN `accept_ra` действует §6.64:
исходный интерфейс и значение требуют отдельного административного подтверждения.

Reload firewalld с nftables backend проверяется отдельно от Qeli recovery. Сохранение
правил Qeli не доказывает, что зоны и политики firewalld пропускают VPN-трафик: это
зависит от настройки администратора. [Матрица и её границы](../reports/audit-0.8.2/AUDIT-Q14-MIXED-FIREWALL.md).

### 6.84. Linux: клиент отказывает при предупреждении о legacy-таблицах

Строка `# Warning: iptables-legacy tables present, use iptables-legacy to see them`
(или соответствующая `ip6tables-legacy`) означает, что одновременно существуют
таблицы другого backend. Сама по себе она не означает поломку выбранного backend.
В прежней реализации это предупреждение перед `No chain/target/match by that name`
приводило к ложному отказу при проверке отсутствующей цепочки `QELI_KS_<dev>`.
Исправление Q25-F102 разрешает только точные advisory-строки вместе с известной
диагностикой отсутствия и подходящим exit. Обновите бинарник с этим исправлением;
не удаляйте сторонние legacy-правила ради устранения предупреждения.

Permission/backend errors, неизвестные дополнительные сообщения и nft parse errors
по-прежнему требуют диагностики. Exit 1 сам по себе не означает «правила нет».
Для `Parsing nftables rule failed` применяйте §6.83, не стирая journal/цепочки.
Сохраняйте исходный backend **каждого семейства** между запуском, crash recovery и
остановкой клиента: автоматическая миграция между nft/legacy не подтверждена.
Reload firewalld не заменяет проверку трафика, DNS и оставшегося kill-switch.
[Причина, тесты и границы](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-MIXED-FIREWALL.md).

### 6.85. Клиент: задержка DNS и остановка

`system DNS resolver queue expired` означает, что запрос не дождался свободного слота;
`system DNS resolution timed out` / `deadline expired` — истёк срок ожидания DNS/NSS.
Kill-switch включает это ожидание в свои 15 секунд; подключение и UDP-диагностика
используют собственные сроки. Установка/refresh и начальное подключение Linux
реагируют на SIGTERM/SIGINT во время ожидания DNS. Очистка сети выполняется обычным
путём; ошибка очистки по-прежнему требует восстановления.

Проверьте разрешение имени в том же сетевом и mount namespace, `/etc/hosts`,
`/etc/nsswitch.conf` и состояние системного resolver. Максимум четыре зависших вызова
могут занять все слоты; повторные попытки ждут в общей очереди, числовые IP её обходят.
Системный вызов нельзя безопасно прервать: до его завершения он удерживает поток/слот,
но не задерживает уничтожение Tokio runtime и не получает права изменять firewall,
маршруты или TUN. Это не общий жёсткий срок остановки всех сетевых операций.
[Проверки и границы](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-RESOLVER.md).

### 6.86. Linux: resolver-файл и разрешения DNS в kill-switch

Если DNS не проходит при активной защите, проверьте содержимое обоих resolver-файлов
из того же mount/network namespace. Обычный symlink разрешён; FIFO, каталог, файл
более 64 KiB, NUL/неверный UTF-8 или некорректная `nameserver`-директива не дают
разрешений из этого файла. Пишите `nameserver 192.0.2.53 # comment`, с пробелами.
Scoped IPv6 (`%wan0`/`%2`) не разрешается адресным правилом без scope; остальные
корректные записи сохраняются. Не расширяйте правило до произвольного `--dport 53`.

Чтение до установки использует очередь §6.85, включая случай числового сервера.
При её timeout новая установка не начинается; существующая защита требует обычного
recovery/cleanup. SIGTERM прерывает ожидание read-only worker; синхронные сетевые
мутации сохраняют свои прежние границы. После изменения системных DNS нужен новый
цикл установки: refresh адресов VPN-сервера не перечитывает список DNS-разрешений.
[Причины и лабораторная проверка](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-FILES.md).

### 6.87. Linux: остановка в состоянии awaiting_network

При остановке во время создания TUN/адресов/маршрутов/DNS клиент продолжает принимать
сигналы и выполнять соседние async-задачи, но ждёт начатую системную операцию. Затем
непринятые настройки откатываются в исходном контексте. Если команда или ядро зависли,
не запускайте конкурирующий профиль с тем же `dev`: внешний lease должен оставаться
занятым до завершения очистки. Наличие сигнала в логе не означает завершение отката.

`network transaction ... namespace changed` означает отказ от результата из изменившегося
NET/mount-контекста; `worker panicked` — ошибку worker, а не успех настройки. Сохраняйте
журналы при неподтверждённой очистке. Для уже установленного туннеля и kill-switch
по-прежнему действуют прежние ограничения синхронных участков.
[Устройство операции и тесты](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-TASK.md).

### 6.88. Linux: ошибка очистки после работающего соединения

Во время штатной остановки DNS/маршрутов/forwarding соседние async-задачи продолжают
работать, но TUN и сетевой lease освобождаются только после очистки. Сигнал остановки
не является подтверждением, что интерфейс уже можно повторно использовать.

Категория `network transaction` в ошибке очистки означает отказ создания/контекста
или panic worker. Причина хука `network_cleanup_failed` и код `network_cleanup`
сохраняются. Включённый kill-switch нельзя считать снятым после такого выхода;
не удаляйте его автоматически по факту закрытия окна клиента. Ранние ошибки и
принудительный Drop по-прежнему могут выполнять fallback синхронно.
[Подробности](../reports/audit-0.8.2/AUDIT-Q25-TUN-TEARDOWN.md).

### 6.89. Linux: stop во время firewall-команды или chain retained

Ожидание DNS можно отменить до мутации. После начала iptables/ip6tables-операции клиент
сохраняет namespace/TUN lease и ждёт её результата, даже если сигнал уже принят.
Соседние async-задачи продолжают работать. Общего жёсткого срока shutdown пока нет.

При `firewall unhook failed; chain retained` изучите ошибку OUTPUT/FORWARD и точное
IPv4/IPv6-семейство. Цепочка с неподтверждённым unhook не очищается автоматически.
Сохраните логи и устраните причину команды перед новым запуском; статус `failed`
сам по себе не подтверждает ни отсутствие, ни полное сохранение всей защиты.
[Сценарии отмены и восстановления](../reports/audit-0.8.2/AUDIT-Q25-FIREWALL-TASK.md).

### 6.90. UDP: ServerHello отсутствует при подключении ко второму IP сервера

В старых сборках wildcard listener мог отвечать с основного IP вместо адреса назначения.
Сравните IP запроса и ответа в захвате: открытый UDP-порт сам по себе не подтверждает
правильный источник. Исправление сохраняет локальный адрес каждого пакета. Для старой
сборки возможна явная `bind.address` на нужный адрес; это не исправляет wildcard-режим.
Ошибка `UDP destination packet info missing`/`truncated UDP packet info` означает отказ
получения адресного контекста; сохраните журнал и сведения об ОС/сокете.
[Воспроизведение и исправление](../reports/audit-0.8.2/AUDIT-Q15-UDP-LOCAL-ADDRESS.md).

### 6.91. Linux: остановка ждёт startup recovery или journal lock

Пока другой процесс держит `client-routes.state.lock`, уже допущенное восстановление
остаётся владельцем TUN/namespace lease. Heartbeat и обработка stop продолжаются,
но выход ждёт результата. Ошибка ожидания, повреждённый journal или legacy global DNS
сохраняют `failed`, даже если stop уже отправлен. Сохраните evidence и устраните
причину блокировки/ошибки; не удаляйте lock-файл действующего владельца.

После успешного recovery остановленный клиент не начинает handshake. `dev_attach = true`
не является обходом DNS-проверок. [Сценарии](../reports/audit-0.8.2/AUDIT-Q25-STARTUP-RECOVERY-TASK.md).

### 6.92. Linux: TUN packet pump startup failed

Сохраните полный error chain: fcntl может вернуть ошибку дескриптора, а создание
packet worker — ошибку ресурсов ОС. Уже запущенный reader присоединяется перед
освобождением исходного TUN. Отказ очистки маршрутов/DNS/forwarding сохраняет `failed`
и kill-switch даже после SIGTERM. Устраните причину и выполните новый явный запуск;
не считайте наличие `post_up` подтверждением работающего data plane.
[Воспроизведение fcntl/thread failures](../reports/audit-0.8.2/AUDIT-Q25-PUMP-START.md).

### 6.93. Linux: статус панели задерживается или не обновился после выхода

Проверьте ошибки `cannot publish client diagnostics`, доступность хранилища и права
каталога `QELI_CLIENT_STATUS`. `cannot start client diagnostics writer` означает, что
поток диагностики создать не удалось; VPN может продолжать работу без обновления файла.
Ошибка записи итогового статуса не меняет код выхода VPN и может оставить старый снимок.

При медленном fsync штатный выход ждёт writer; принудительное освобождение владельца
также ждёт поток. Не считайте отображаемый `running` доказательством живого процесса,
а отсутствие промежуточного состояния — потерей соединения: очередь объединяет снимки.
[Устройство и проверки](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md).

### 6.94. Linux: повреждённый known_hosts или временный device-id

`cannot read known_hosts store`, `known_hosts exceeds 1 MiB`, `invalid known_hosts pin`
и `SERVER KEY MISMATCH` требуют проверки существующего файла и ключа сервера.
`allow_unpinned_tofu = true` не отключает эти проверки. Не удаляйте всё хранилище ради
повторного запуска: сохраните копию и исправьте конкретную запись после проверки ключа.

`device id will be per-run` означает ошибку чтения/lock; `device id could not be persisted`
— отказ записи. Этот запуск использует один временный ID, но он может не сохраниться
после перезапуска. Проверьте тип файла, права и владельца lock; не удаляйте lock живого
процесса. [Подробности](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-FILES.md).

### 6.95. Linux: TOFU timeout и поздняя ошибка сохранения

`server identity verification timed out` означает, что handshake прекратил ожидание.
Клиент всё ещё ждёт принятую файловую операцию перед reconnect/выходом; не считайте этот
тайм-аут общим пределом остановки. `unobserved identity verification failure` сообщает
об отказе, пришедшем после отмены handshake: запуск завершится ошибкой, даже при SIGTERM.
Проверьте состояние хранилища и причину I/O; не удаляйте lock работающего процесса.
[Подробности](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md).

### 6.96. Сервер: установка профиля превысила 120 секунд

`setup exceeded its 120 second budget before all listeners bound` означает, что
поколение не достигло готовности в срок. Проверьте более ранние сообщения о
TUN/NAT/NDP, `post_up`, DNS и bind каждого `listen`. Ошибка `listener bind failed`
указывает на конкретный отказ порта; освободите адрес/порт и дождитесь
успешного отката перед retry. Появление `post_up` ещё не подтверждает bind.

Срок относится только к установке. Отмена может ждать уже начатый worker
или очистку дольше 120 секунд; не запускайте параллельно второе поколение с
тем же TUN/сетевыми правилами. [Проверка](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-BUDGET.md).

<!-- normative-sync: manual-ws-write-v1 -->

При fronting=websocket общий core завершает отправку каждого protocol record через flush,включая handshake/ACK/heartbeat. При backpressure непереданные байты остаются в bounded writer и не теряются при отмене следующей операции. Ошибка после частичной отправки закрывает этот поток; восстанавливать его с прежним cipher state нельзя — требуется новое соединение. [Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md).

<!-- normative-sync: manual-ws-read-v1 -->

При отказе WebSocket Upgrade проверьте,что промежуточный HTTP endpoint передаёт GET/HTTP/1.1,Host,Sec-WebSocket-Version13 и не дублирует ключ/accept. Body,Transfer-Encoding,незапрошенные extensions/subprotocol и head свыше4096 байт не поддерживаются. UnexpectedEof может означать незавершённый кадр или fragmented message. Ошибка следующего кадра возвращается после уже полученных данных и требует нового соединения. Настройки конфигурации не изменились;формат INI. [Отчёт Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md).

<!-- normative-sync: manual-ws-control-v1 -->

При front=websocket Ping обслуживается без отправки данных приложением. Корректный Close завершает соединение после echo; дополнительные данные после Close не принимаются. Ошибка Close payload означает неверную длину, status или UTF-8 причину. После terminal error нужен новый carrier. `reality` — имя Quick Start: INI использует fake-tls с REALITY proxy; mode=reality-tls обозначает настоящий TLS. AWG jc должен совпадать для TCP obfs; на UDP это junk datagrams. Конфиги остаются INI. [Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md).

<!-- normative-sync: manual-macos-forwarding-v1 -->

### macOS: ошибка владельца или очистки forwarding

Для обычного utun с forward=true допускается один Qeli forwarding owner на весь Mac.
При Another live Qeli forwarding owner exists остановите текущий профиль до запуска
следующего. Исходно включённый forwarding также требует lease. Новых INI-ключей нет.
Root startup восстанавливает журнал мёртвого владельца; живого не трогает.

Forwarding cleanup remains pending или Owned forwarding journal disappeared означают,
что очистка не подтверждена. Повторите штатную остановку после устранения ошибки sysctl
или доступа к защищённому каталогу /Library/Application Support/Qeli. Повреждённый либо
подменённый forwarding-state.json требует проверки администратором; не удаляйте файл
вслепую. Ошибка восстановления не разрешает закрытие TUN. Журнал — внутренний JSON DTO,
пользовательские конфиги остаются INI. Это не механизм полного crash recovery сети и не
координация с независимыми инструментами, меняющими sysctl.
[Проверки и ограничения](../reports/audit-0.8.2/AUDIT-Q28-MACOS-FORWARDING.md).

<!-- normative-sync: manual-macos-guardian-v1 -->

### macOS per-app: guardian readiness и обновление bundle

Служебная схема per-app — v5. Обновляйте host/helper/extension одним подписанным bundle
после остановки старых профилей и завершения guardian. Версия v4 не доказывает ownership
и автоматически не перехватывается. Если старый state мешает claim, подтвердите stop старых
Qeli managers/guardian, сохраните копию per-app-state.json и удалите только этот устаревший
файл в Qeli app-group container. Активный/неизвестный state вслепую не удаляйте.

Ошибка readiness означает отсутствие точного token acknowledgement после claim в течение
5 секунд либо exit/неправильный ack. Самого живого PID недостаточно; завершите cleanup
перед retry. Join error после подтверждённого stop повторяет только join и блокирует
reconfiguration до завершения. Чужой живой owner не изменяется. Completed owner state
сохраняется как tombstone; новый token допускается после подтверждённого stop.
Конфиги остаются INI, JSON state — служебный DTO.
[Объём проверок и ограничения](../reports/audit-0.8.2/AUDIT-Q28-MACOS-GUARDIAN.md).

<!-- normative-sync: manual-macos-relay-budget-v1 -->

### macOS per-app: relay timeout и остановка sockets

TCP connect имеет общий бюджет 10 секунд с DNS и всеми кандидатами; первый blackhole
может исчерпать его до fallback. TCP send и весь UDP batch ограничены 5 секундами,
DNS query — 2 секундами внутри внешнего бюджета. Framework-write watchdog через 10 секунд
закрывает текущий relay; после частичной TCP отправки требуется новое соединение.
Stop сначала отказывает новому I/O, затем очередь/cancel handlers освобождают fd;
сам возврат stop не подтверждает завершённый kernel release. Пустая UDP датаграмма
не означает EOF. Новых INI-параметров нет. Эти изменения проверены по исходникам;
Swift/macOS runtime исключён пользователем, managed tests его не заменяют.
[Объём проверки и ограничения](../reports/audit-0.8.2/AUDIT-Q28-MACOS-SOCKETS.md).


<!-- normative-sync: q28-macos-identity-halfclose-v1 -->

### macOS: старые DNS/PF journals и TCP EOF

Новые DNS journals: schema 2/UTC; PF stamps: clock=utc. Старые stamps с живым PID не
считаются stale только из-за несовпадения локальных ticks. Перед upgrade остановите
старые профили/guardian. Если legacy PID занят другим процессом, проверьте ownership
вручную; не удаляйте journal вслепую. Downgrade с активным новым state не поддержан.
TCP EOF завершает только соответствующее направление: app FIN сохраняет ответ сервера,
remote FIN сохраняет app-to-server. Полный stop — оба EOF или error/cancel/write timeout.
[Сверка критериев, проверки и исключения](../reports/audit-0.8.2/AUDIT-Q28-MACOS-INTEGRATION.md).


<!-- normative-sync: q29-android-legacy-backup-v1 -->

### Android: нечитаемые legacy-профили и восстановление

Ошибка legacy migration не создаёт пустой default store и не разрешает обычную запись.
Старая encrypted-копия сохраняется. При временном отказе перезапустите процесс приложения;
при утрате Keystore key используйте ранее экспортированный backup и явное подтверждение
восстановления в UI. Stale restore отказывает; автоматического удаления app data нет.
Cloud/device-transfer не копируют app state по явным правилам; перенос профилей выполняется
экспортом/импортом backup. Без backup потерянный ключ не восстановить.
[Проверки и границы Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md).


<!-- normative-sync: android-private-dns-q29-v1 -->

### Android: исключённое приложение не работает / DNS не разрешается

При включённом «Блокировать подключения без VPN» исключённые per-app приложения
тоже блокируются. Если им нужен прямой выход, отключите системный lockdown осознанно;
профиль с `kill_switch=true` после этого не сможет подтвердить требуемую защиту.

При ошибках имён проверьте Android Settings → Network & internet → Private DNS.
В проверенном API34 неверное имя strict provider ломало системный DNS и при
действующем VPN; автоматического fallback на открытый DNS не было. Убедитесь, что
provider доступен и вне VPN, и внутри него. `Automatic` допускает обычный DNS,
а успешная raw UDP-проба не доказывает работоспособность Private DNS/DoT.
[Матрица, точные артефакты и ограничения](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-APP-POLICY.md).
Проверка доверенного CA, отказа при неверном CA/SAN и восстановления выполнена
на API34 для TCP/UDP/QUIC: [strict DoT](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-DOT.md).

### Reload службы и конфигурация владельца root

`systemctl reload qeli` отправляет SIGHUP supervisor: он проверяет и перечитывает пользователей/аутентификацию, затем просит worker перечитать их без замены процессов. Неверные INI/users отвергаются до публикации нового auth state. Profile/listener/TUN и startup settings панели требуют полного restart службы. SIGHUP сохраняет блокировки входа в панель. [Аудит systemd](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).

Режим root читает приватные файлы qeli, но публикация конфига через панель по-прежнему требует доверенного файла: владелец root или пользователь процесса, без group/other write и без symlink. Поэтому root отвергнет сохранение qeli-owned INI через панель. Проверьте конфиг от администратора, затем выполните `sudo chown root:root /etc/qeli/server.conf` и `sudo chmod 600 /etc/qeli/server.conf`, если служба должна работать от root. Не передавайте password receipts пользователю qeli. Старый root drop-in обновляется повторным `sudo qeli set-service-user root` текущим бинарником и restart службы. Добавляются три filesystem capabilities, а не неограниченный набор. [Systemd audit](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).

### Linux: TCP работает, но скорость падает при одновременном upload/download

<!-- normative-sync: q36-tun-counter-boundary-v1 -->

Нулевые client tcp_uplink_drops/tcp_downlink_drops и server dropped не исключают
потерь в TUN ядра: это прикладные счётчики Qeli. Снимите до/после одинакового
интервала `ip -s -s link show dev vpn0` и `tc -s qdisc show dev vpn0` на сервере
и клиенте. Замените vpn0 фактическим TUN именем; команды выполняются в namespace
процесса. Сравнивайте дельты RX/TX errors/dropped для того же ifindex и отдельно
qdisc drops. При mq не складывайте root и children — root уже агрегирует их.
Нулевой backlog после теста не показывает пиковую очередь во время нагрузки.
Рост TUN tx_dropped при нулевых qdisc drops указывает на потери устройства TUN,
но сам по себе не устанавливает причину driver drop или потерянный TCP flow.
Не увеличивайте очереди без сравнения задержки: больший буфер может её увеличить.
[Ограниченный эксперимент и границы доказательства](../reports/BENCHMARK.md).

Переполнение внутреннего кольца TUN возможно до чтения пакета Qeli; native handoff counters не охватывают этот этап. Сам агрегат TX dropped не определяет причину произвольного отказа на другом стенде. Лабораторные численные наблюдения разработки не публикуются.


<!-- normative-sync: q29-process-death-troubleshooting-v2 -->

### Android: VPN не вернулся после смерти процесса

После аварийного завершения процесса Always-on VPN зависит от перезапуска сервисов Android. Исправленный ordinary R8 Qeli в проверенном Android14/API34 автоматически восстановил аутентифицированное соединение после SIGKILL за2,985с с одной новой generation через guarded sticky recovery; прежний отказ сохранён как результат старого control. Это проверка конкретного стенда, не гарантия для каждого OEM. Force stop,отзыв VPN и явный Disconnect намеренно не возобновляли соединение в30с контролях. Если автоматического старта нет,проверьте активный профиль/Always-on,сохраните ActivityManager/Vpn/VpnSvc logcat и dumpsys activity services; доступен ручной запуск Qeli. Generic/null DNS остаётся отдельным незакрытым пунктом. [Проверенный restart и границы](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md).

[Audit details](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md).


<!-- normative-sync: q29-publication-troubleshooting-v1 -->

### Android: APPLIED / CONNECTED

При подключении Android запись `Native NetworkPlan APPLIED` означает применение плана и передачу TUN ядру; публикация VPN системой ещё может продолжаться. Дождитесь статуса «Подключено» / `Android VPN CONNECTED` перед проверкой трафика. При включённой блокировке соединений без VPN ранние сокеты во время подключения могут быть отклонены. Если новый запрос после CONNECTED не проходит, сохраните его время начала и logcat VpnSvc/ConnectivityService: это уже отдельная неисправность, а не основание отключать блокировку. Лабораторные выборки подтвердили передачу после CONNECTED, но не гарантируют нулевую задержку каждого сокета на всех устройствах.

[Audit](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).


### Android: восстановление после смерти процесса

Восстановление Qeli после SIGKILL проверено на обычном production R8 APK; отключение/отзыв запрещают возврат служб в 30-секундных окнах. Generic/null DnsResolver ENONET на проверенном API34 принят как неисправленное ограничение; Q29 закрыт в согласованном объёме. [Подробности](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md).


<!-- normative-sync: q29-dns-compatibility-troubleshooting-v1 -->

### Android: ENONET в одном приложении

Если VPN уже показывает «Подключено», обычные DNS-запросы работают, а одно
приложение сообщает `DnsResolver` / `resNetworkQuery failed: ENONET`, сохраните
версию Android, время запроса и сообщение этого приложения. На проверенном
Android14/API34 автоматический выбор семейства адресов без явно выбранной
сети отказал до отправки DNS; тот же отказ воспроизвёл минимальный VPN без Qeli.
Это отдельное наблюдение одного образа, не общий отказ DNS в туннеле.

Для исправления именно этого вызова разработчик приложения может явно
передать VPN-сеть в DnsResolver.query либо использовать запросы A/AAAA.
Эти варианты и обычный DNS прошли отдельные проверки на данном стенде.
Параметр network относится к вызывающему приложению —
[контракт Android API](https://developer.android.com/reference/android/net/DnsResolver).
Сохраняйте системные Always-on VPN и «Блокировать подключения без VPN».
Отдельного режима разрешения обхода VPN в Qeli нет.

[Факты, воспроизведение и границы](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).

### Linux: размер клиентской TUN-очереди не применился

`tun.tx_queue_len` задаётся в `[qeli]` клиентского файла, не в новой секции `[tun]`
и не только на сервере. В поддерживающей доработку сборке отсутствие ключа означает
`1000` пакетов для собственного Linux TUN/TAP. Сохраните INI, остановите/запустите
именно клиент и проверьте `qlen` через `ip link show dev vpn0` в его namespace.
Имя берётся из `dev`; подтверждающая строка лога —
`Client TUN TX queue length: <N> packets`. Перечитывание сервера не меняет очередь клиента.

Если ключ неизвестен, проверьте установленный **клиентский бинарник**: прежние
сборки с тем же номером 0.8.2 не обязаны содержать доработку. Обновление одного
сервера не помогает. Если ошибка возникает при сохранении через панель, проверьте
также поддержку ключа её локальным редактором. Если значение отвергнуто, допустимы
только целые `1..32767`;
`0` и `auto` не включают автоматический режим. С `dev_attach=true` удалите ключ
полностью и настраивайте очередь у внешнего владельца интерфейса.

`failed to set client TUN TX queue length` — отказ установки в ядре: настройка
соединения прерывается, без скрытого fallback на старую длину. Проверьте `ip`,
права процесса, имя/владение интерфейсом и namespace; не обходите ошибку ослаблением
общей проверки конфига. Большая очередь не исправляет любую асимметрию: сравнивайте
kernel TX drops отдельно от qdisc/прикладных drops, а также retransmits и RTT.
[Полный контракт](CONFIG.md#client-tun-tx-queue),
[операционная проверка](OPERATIONS.md#client-tun-tx-queue).
[Отчёт с измерениями потерь, retransmits и задержек](../reports/TUN-QUEUE-SIZE-2026-10-16.md)
и [рекомендации по выбору размера очереди](../reports/TUN-QUEUE-SIZE-2026-10-16.md#как-выбирать-размер).

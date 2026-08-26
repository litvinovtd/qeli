# Qeli 0.8.0 Reality/H2 — повторный PCAP/DPI-тест

Дата: 2026-08-26  
Бинарник: `qeli 0.8.0`, SHA-256 `97ef2526e818ba30bd0da92b6df79c16373925c2fa96095b1bd0eeabbfbe1b74`

## Итог

Новый carrier действительно работает: 6/6 полностью новых сессий прошли `AUTH OK`, runtime подтвердил
`genuine HTTP/2 stream`, tunnel ping прошёл без потерь, inner UDP 4 Мбит/с прошёл в обе стороны.
Шесть control-flow отдельно подтверждены curl как реальный `HTTP/2 200`.

Главный старый load-инвариант существенно сломан: средний TCP payload изменился с 952 B до
1037 B, а доля full-MTU DATA — с 0.028% до 44.6% (у текущих HTTP/2 controls
68.8%). Средний DATA gap: старый Reality-TLS 1.915 ms, новый H2 2.841 ms,
controls 1.395 ms.

Переподогнанный на старом corpus shape-классификатор (те же 22 transport/rate-independent признака)
распознал новый Qeli в 0/6 случаях, false-positive на новых controls 0/6; средняя
Qeli-score старой модели 0.00020 против 0.00002. Nearest-centroid:
Qeli 0/6, controls false-positive 0/6. Это прямое сравнение с прежним отпечатком, но не
оценка промышленного DPI и не универсальная «вероятность обнаружения».

## Чистота и воспроизводимость

- Перед тестом выполнен полный reboot `.10` и `.11`; после boot: `emulator=0`, `qeli=0`, лишних
  TUN/TAP и искусственных qdisc нет, CPU steal 0%.
- На обеих ВМ exact SHA совпал. Capture point для Qeli и controls одинаков: `.11`, `ens18`.
- Для wire capture выключены GRO/GSO/TSO/rx-gro-hw; после теста исходное состояние восстановлено.
- Финальная гигиена: emulator=0, qeli=0, лишних интерфейсов/qdisc нет.

## PCAP corpus

- Reality-TLS + genuine H2: 6 handshake PCAP + 6 symmetric-load PCAP.
- Idle cover: 35 секунд после 5-секундного quiet guard.
- Реальный HTTP/2: 6 control PCAP, каждый `HTTP/2 200`.
- Qeli workload: inner UDP 4 Мбит/с upload + download; все 12 направленных замеров успешны.

## TLS/H2 наблюдения

- Qeli ClientHello SNI: `{'www.microsoft.com': 6}`.
- Qeli ALPN: `{('h2', 'http/1.1'): 6}`; control ALPN: `{('h2', 'http/1.1'): 6}`.
- Qeli JA3 hashes: `{'e36d6a2c0b2d149bfc3c71c185fe0f6a': 1, 'c184922429f7f75dc2488cc9d1f230a8': 1, '2b70d5353f441cdb2cd6ecf9be4c650b': 1, 'c983539f447fe7dacab8a39b58f4289f': 1, '05183a3acb788882cac2fd459944f1b7': 1, 'cc93e65ff4e31c04f71a86f463dce8b3': 1}`; control JA3 hashes: `{'32e4b8812cda0c0d50783b438492a769': 6}`.

ALPN `h2` и настоящее HTTP/2 framing устраняют старую двойную fake-TLS choreography. Статического JA3
в этой выборке нет: все шесть Qeli ClientHello дали разные hash из-за anti-fingerprinting randomization,
тогда как curl-control повторил один hash. Это убирает постоянный идентификатор, но произвольные синтетические
комбинации сами могут быть out-of-distribution. Curl-control не является browser-control, поэтому различие
JA3 здесь нельзя превращать в численную вероятность; следующий этап должен проверить, что каждый профиль
реально принадлежит corpus Chrome/Firefox/Edge/Safari, а не просто отличается от соседней сессии.

## Idle

- client→server: 52 DATA events, mean gap
  0.690 s, CV 0.958,
  range 0.000–3.761 s.
- server→client: 54 DATA events, mean gap
  0.635 s, CV 1.055,
  range 0.000–3.083 s.

Фиксированный 30-секундный heartbeat старой сборки не наблюдается; idle остаётся случайным cover-потоком.

## Что ещё нужно для максимального скрытия

1. Заменить произвольную JA3-ротацию несколькими настоящими browser TLS profiles, для каждого из которых
   весь ClientHello воспроизводится согласованно, а не только случайно переставляются расширения.
2. Сделать H2 поведение target-specific: browser-like SETTINGS, PRIORITY/priority-update, WINDOW_UPDATE,
   stream concurrency и request/response choreography; один вечный POST остаётся семантическим признаком
   для active/terminating observation.
3. Расширить controls одинаковым workload: браузеры, обычные H2 upload/download/streaming, gRPC/WebTransport,
   а также WireGuard/OpenVPN/HTTPS proxy; текущий corpus всё ещё мал.
4. Отдельно проверить active probes, replay, malformed TLS/H2, reconnect/timeouts и long-lived flow.
5. UDP `quic-shape` не считать настоящим QUIC/H3: до реального QUIC state machine максимальный stealth —
   только TCP Reality-TLS/H2.

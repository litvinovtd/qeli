# Роуминг клиента: план полной реализации
<!-- normative-sync: roaming-v5-safe -->

> Статус: проектирование завершено; этапы 0–2A и общие исходники этапа 2B вплоть до
> PathUpdate-driven TCP make-before-break реализованы под `experimental-roaming`.
> Hard resume и explicit close прошли изолированный Linux live e2e; новый handover-срез
> прошёл lab source/unit gates, но ещё требует live-матрицу гонок и устройств. Ограниченные
> UDP registry/migration state, cross-worker dispatch и atomic writer-egress этапов 3A–3C
> готовы по исходникам; ingress/session actor и оставшиеся вспомогательные egress-пути ещё
> впереди.
> Production-адаптеры и оставшиеся работы этапов 3–6 ещё впереди.
> На лабе `.10` прошли финальные default/feature suites (862/901 library tests,
> 4 CLI и 7 integration), а также strict Clippy обеих сборок. Целевая версия — 0.8.x.
>
> План повторно сверен с текущей архитектурой ветки dev после перехода всех приложений
> на единое Rust-ядро. Документ задаёт обязательные инварианты реализации. Номера строк
> исходников намеренно не фиксируются: после рефакторинга они быстро устаревают.

## 1. Что считается полным роумингом

Роуминг — смена внешней сети или пути без создания новой VPN-сессии. При успешном
переходе сохраняются:

- идентификатор сессии, пользователь и device id;
- назначенные внутренние IPv4/IPv6-адреса;
- TUN/TAP и применённый NetworkPlan;
- серверные маршруты, iroute, DNS и внутренний MTU;
- счётчики квоты и ограничения скорости;
- криптографическое состояние UDP-сессии;
- логические TCP-слоты multipath.

Успешный роуминг не запускает Argon2 и полную AUTH повторно. Полный reconnect остаётся
обязательным fallback, если peer не поддерживает роуминг, сервер перезапущен, grace-период
истёк, сессия отозвана или проверка нового пути не завершилась.

Роуминг должен работать независимо для следующих комбинаций:

| Внутренний трафик | Внешний путь | Устройство |
|---|---|---|
| IPv4, IPv6, dual-stack | IPv4 или IPv6 | TUN или TAP |

Поддержка по транспортам:

| Транспорт | Целевое поведение |
|---|---|
| TCP во всех поддерживаемых режимах | make-before-break, при жёстком обрыве — authenticated JOIN в пределах grace |
| UDP с qeli QUIC-конвертом и DATA_FRAG_V1 | полная миграция адреса, сокета и PMTU |
| UDP без QUIC-конверта | полный reconnect; роуминг не объявляется |
| raw plain | только TCP; отдельного UDP plain в текущем протоколе нет |

Не являются целью первой версии: MPTCP, downstream replay buffer, межузловая миграция
сессии, гарантированная нулевая потеря пакетов при жёстком handover.

### Инварианты приёмки

После успешного перехода не должны меняться session id, адреса туннеля, generation
NetworkPlan и сам TUN/TAP. Не должны сбрасываться AEAD-счётчики или replay-window.
Временные host routes, allowlist, CID aliases, candidate sockets и orphaned sessions
должны удаляться ровно один раз при commit, abort, revoke или timeout.

## 2. Совместимость и согласование возможностей

Новые возможности включаются только через существующий аутентифицированный capability
trailer. Нужны раздельные биты:

- CONTROL_V2 — двунаправленный versioned control channel;
- UDP_ROAM_V1 — CID routing и проверка нового UDP-пути;
- TCP_RESUME_V1 — authenticated JOIN существующей сессии;
- TCP_HANDOVER_V1 — замена логического потока make-before-break.

Сервер объявляет только возможности, реально доступные конкретному профилю. UDP_ROAM_V1
нельзя объявлять для UDP-профиля без QUIC-конверта и DATA_FRAG_V1. Клиент в режиме
**required** отказывает до передачи credentials/полной AUTH, если нужной capability нет.

Legacy client/server продолжают использовать обычный reconnect. Поэтому обновление можно
выполнять постепенно; синхронное обновление сервера и всех клиентов не требуется.

Пользовательские конфиги qeli остаются только flat INI. JSON, используемый внутри FFI/ABI
или serde-моделей, является внутренним payload и не должен появляться в пользовательской
документации или примерах конфигурации.

## 3. Ключевой материал и защита resume

Текущая выработка направленных C2S/S2C ключей должна остаться побитово совместимой.
Поверх исходного IKM для classic, hybrid и bound-режимов вводится SessionKeyMaterial,
который domain-separated HKDF выводит:

- resume secret;
- C2S CID secret;
- S2C CID secret;
- при необходимости отдельный control secret.

Требования:

- секреты хранятся в zeroizing-контейнерах;
- запрещены Debug, сериализация и логирование секретов, токенов и полных CID;
- токен сессии служит только locator и не является доказательством владения;
- UDP-миграция сохраняет исходные PacketCodec и единую replay-window — codec нельзя
  клонировать или создавать заново с тем же ключом;
- TCP JOIN всегда выполняет новый key exchange и создаёт новые AEAD-ключи;
- proof TCP JOIN связывает resume secret, transcript hash, locator сессии, широкий
  resume epoch, logical slot id и флаг handover;
- повтор proof, proof для другого слота/epoch или изменённого transcript отклоняется.

Resume epoch должен быть как минимум u64 и не зависеть от существующего u8 stream index.

## 4. CONTROL_V2

Текущий control-формат с однобайтовой длиной недостаточен для роуминга и крупных
сообщений. Кроме того, клиентский downlink сейчас в основном ожидает IP-пакеты. До
роуминга нужен общий двунаправленный dispatcher и versioned control frame:

- magic и версия;
- type, flags и message id;
- длина u16 либо bounded varint;
- part index/part count для фрагментации больших сообщений;
- порядок, идемпотентность, ACK и явная ошибка;
- строгие лимиты размера, числа частей и времени сборки.

Минимальные сообщения для роуминга:

- PATH_INIT;
- PATH_CHALLENGE;
- PATH_RESPONSE;
- PATH_COMMIT;
- PATH_ABORT;
- CLOSE_SESSION;
- SESSION_REVOKED/KICK.

CONTROL_V2 передаётся только внутри аутентифицированных AEAD-записей и только после
согласования capability. Полный live PUSH_CONFIG может использовать тот же транспорт,
но не является обязательным условием первой версии роуминга. Обязателен сам надёжный
двунаправленный dispatcher.

## 5. Динамическая смена пути в едином Rust-ядре

Текущий runtime получает параметры соединения при запуске. Для роуминга нужен
generation-scoped command channel от платформенного адаптера к уже работающему ядру.

PathUpdate должен содержать:

- platform path id и причину события;
- устойчивый token физической сети или interface index;
- доступные локальные адреса;
- результаты A/AAAA, полученные через нужную физическую сеть, и TTL;
- признак смены default route, wake и same-network NAT failure.

Команды bounded, дедуплицируются и отменяют устаревший candidate. Команда от старой
generation не может изменить новый runtime.

Смена пути выполняется транзакционно:

1. **PREPARE_PATH:** платформа ставит candidate host route до сервера, расширяет kill-switch
   и per-app allowlist, выполняет DNS через точную физическую сеть.
2. Ядро создаёт candidate socket и требует точный bind/protect к выбранному пути.
3. Новый UDP-путь проходит challenge/response либо TCP-путь проходит authenticated JOIN.
4. **COMMIT_PATH:** active path меняется атомарно.
5. Старый путь дренируется ограниченное время.
6. Временные правила старого пути удаляются; при ошибке выполняется **ABORT_PATH**.

При успешном роуминге состояние клиента остаётся Running, TUN/TAP и NetworkPlan не
пересоздаются. В статистике roam и full reconnect учитываются раздельно.

## 6. UDP: новый short header и CID

Существующий четырёхбайтовый формат handshake/long header и известный legacy path сохраняются
для совместимости. Для согласованного UDP_ROAM_V1 обычная форма QUIC short header сохраняет
стандартные short flags, но DCID расширяется до восьми байтов. Отдельный постоянный qeli-marker
запрещён: он создал бы простой DPI-отпечаток. При miss по source address сервер пробует извлечь
восьмибайтовый CID и выполнить bounded lookup в profile-wide registry; известный legacy path
продолжает использовать сохранённую четырёхбайтовую форму.

CID:

- выводится из направленного CID secret, session id и epoch;
- имеет не менее 64 бит locator space;
- атомарно регистрируется с проверкой коллизии;
- имеет ограниченное окно current/previous/future aliases;
- удаляется при drain, timeout, kick, quota, reload и закрытии сессии;
- проверяется клиентом и в направлении server-to-client при нескольких сокетах.

Packet number в наружном заголовке можно рандомизировать на новом пути, но это не
разрешает сбрасывать внутренние AEAD counters. Активный путь определяется монотонным
path epoch. Пакет со старого пути не может откатить active path после commit.

## 7. UDP: серверная архитектура

Текущий UDP data plane адресует клиентов исходным SocketAddr, разделён между workers и
захватывает конкретные socket/address/family в writer. Этого недостаточно для смены
адреса. Нужны:

1. **UdpHalfOpen** для неаутентифицированного handshake.
2. **ProfileUdpRegistry**, общий для всех SO_REUSEPORT workers и всех bind.listen одного
   профиля.
3. Реестр по CID, заполняемый только после успешной AUTH.
4. Per-session actor, единолично владеющий:
   - PacketCodec и replay-window;
   - reassembly DATA_FRAG;
   - active/candidate paths;
   - PMTU state;
   - heartbeat, cover traffic и reaper coordination;
   - egress writer.

ActiveUdpPath должен включать peer address, фактический receiving/egress socket, local
listener/family, CID и epoch. Lookup CID выполняется до new-session rate limiting, иначе
валидный migrated packet может быть ошибочно принят за новый handshake.

На сессию допускается не более одного candidate; также нужны глобальный лимит и rate
limit candidate paths. Один session actor исключает дубли heartbeat/cover/reaper при
нескольких workers.

На клиенте UDP-сессия также должна иметь единственного владельца PacketCodec, replay-window,
active/candidate sockets и очереди TUN. Шифрование пакетов со старого и нового пути нельзя
разнести по независимым writer-задачам: это создаёт гонку AEAD counter и порядка commit.
Candidate socket принимает только control/probe до PATH_COMMIT; после commit новый egress
меняется атомарно, а старый socket остаётся только на ограниченный receive drain.

Межпроцессный и межузловой роуминг не поддерживается первой версией. При балансировке
нескольких процессов требуется sticky routing либо внешний state store — это отдельный
этап.

## 8. UDP: проверка пути и PMTU

Проверка владения новым обратным путём обязательна уже в первой версии:

1. Клиент с candidate socket отправляет зашифрованный PATH_INIT с следующим CID и
   монотонным path epoch.
2. Сервер находит сессию по CID, проверяет AEAD/replay и создаёт bounded candidate.
3. Сервер отправляет PATH_CHALLENGE, не превышая anti-amplification budget 3× от байтов,
   полученных с непроверенного адреса.
4. Клиент отвечает PATH_RESPONSE с challenge.
5. Сервер атомарно фиксирует active path и подтверждает PATH_COMMIT.

До корректного PATH_RESPONSE сервер не переключает downstream на новый адрес. Stale epoch,
неверный CID, duplicate challenge и параллельный candidate отклоняются предсказуемо.

После commit внешний UDP payload budget в обоих направлениях сбрасывается к безопасному
минимуму для нового outer family. Затем запускается живой двунаправленный PMTU probe.
Старый измеренный PMTU переносить нельзя.

PMTU state machine живёт внутри session actor и не вызывает отдельный socket.recv, который
может украсть data/control datagram у основного loop. ACK связывается с path epoch, точным
source и egress socket. Запоздалый ACK старого пути не может увеличить бюджет нового.

DATA_FRAG_V1 обязателен: внутренний MTU TUN/TAP и NetworkPlan остаются прежними, а
зашифрованная запись режется под новый внешний бюджет. Reassembly либо сохраняется до
ограниченного expiry при drain, либо очищается с отдельным drop reason; AEAD и replay
при этом не сбрасываются.

Нужно отдельно проверить достаточность текущего replay-window на высокоскоростном
make-before-break с переупорядочиванием. Если окно расширяется временно, переход и
обратное сужение должны быть bounded и покрыты тестами.

## 9. TCP: lifecycle сессии на сервере

Для TCP нужен lifecycle:

- Active;
- Orphaned;
- Resuming;
- Closing;
- Revoked.

Неожиданная потеря последнего transport stream переводит сессию в Orphaned на grace.
Ручной CLOSE_SESSION, kick, quota, expiry, shutdown и protocol violation немедленно
переводят её в Revoked и освобождают ресурсы.

Orphaned-сессия удерживает внутренние IP, routes/iroutes, token/resume secret, лимиты,
quota counters и считается в max_clients/per-user. Нужны max_orphaned и
max_orphan_bytes, чтобы разрыв сети нельзя было превратить в DoS памяти.

JOIN должен атомарно зарезервировать сессию и logical slot до ответа JOINOK. Reaper
проверяет session id и generation, чтобы гонка JOIN/reap/kick/quota не освобождала
восстановленную сессию. Любое владение ресурсом освобождается ровно один раз.

Новая полная AUTH того же device id немедленно отзывает старую orphaned-сессию. Одного
знания session token для JOIN недостаточно — требуется proof из раздела 3.

## 10. TCP: стабильные потоки и клиентский supervisor

Текущая работа с потоком через позицию в Vec и modulo непригодна для handover: добавление
или удаление элемента меняет распределение пакетов. Нужна таблица стабильных логических
слотов:

~~~text
Slot { id, generation, state: Ready | Draining, transport }
~~~

Новый transport сначала проходит KE/JOIN для того же slot id, затем атомарно становится
Ready, а предыдущий переводится в Draining. Scheduler отправляет новые пакеты только в
Ready-слоты и не перенумеровывает остальные.

Один клиентский supervisor должен сериализовать:

- adaptive ramp-up/ramp-down;
- замену погибшего потока;
- roaming handover;
- полный reconnect fallback;
- ручную остановку.

При нуле живых TCP streams в пределах grace TUN/TAP и NetworkPlan сохраняются, а uplink
имеет строгий bounded queue или fail-closed drop. Бесконечное накопление пакетов запрещено.
Downstream replay buffer не требуется: потерянные внутренние TCP-сегменты восстановит
внутренний транспорт.

Make-before-break:

1. подготовить candidate network path;
2. открыть transport и выполнить новый KE;
3. authenticated JOIN того же logical slot;
4. получить подтверждение reservation;
5. атомарно переключить scheduler;
6. ограниченно дренировать старый stream.

При жёстком обрыве выполняется JOIN в пределах grace, затем — полная AUTH fallback.
Если **reconnect = false**, успешный roam разрешён, но после неуспешного roam клиент
останавливается без full reconnect. **persist_tun** применяется только к полному reconnect
fallback, а не к успешному роумингу.

Ручной stop отправляет best-effort CLOSE_SESSION и отменяет candidate. Политика Trusted
Wi-Fi имеет приоритет над автоматическим roam. После sleep дольше grace ожидается full AUTH.

## 11. Платформенные адаптеры

Общий порядок для всех платформ: prepare route/allowlist → DNS на нужном пути → точный
bind/protect socket → protocol validation/JOIN → commit → drain → cleanup.

### Android

- сохранять точный Network/path id, а не только факт доступности сети;
- получать A/AAAA через Network.getAllByName;
- для initial и candidate socket выполнять Network.bindSocket(fd), затем protect(fd);
- Connectivity callback преобразовать в PathUpdate, а не безусловный reconnect;
- Trusted Wi-Fi остаётся policy stop;
- детектировать same-network NAT rebinding/dead mapping без смены Network.

### Windows

- до connect поставить временный host route /32 или /128 до сервера;
- одновременно разрешить old и candidate endpoint в kill switch;
- привязать source address и interface через IP_UNICAST_IF/IPV6_UNICAST_IF;
- WinDivert должен горячо обновлять carrier set, сохраняя flow/fragment state и tunnelUp;
- при abort/commit атомарно удалить только правила своей generation.

### macOS

- временный host route к candidate endpoint;
- old/new allowlist в kill switch на время drain;
- IP_BOUND_IF/IPV6_BOUND_IF и DNS через физический интерфейс;
- Network Extension не должна пересоздавать utun при успешном roam.

### iOS

- NWPathMonitor внутри Packet Tunnel Extension;
- DNS и NAT64 synthesis через текущий физический path;
- привязка к интерфейсу там, где NetworkExtension API это допускает;
- обязательный device-lab: симулятор не подтверждает поведение cellular/Wi-Fi handover.

### Linux и OpenWrt

- netlink watcher RTM_NEWADDR/route вместо периодического полного reconnect;
- bind source/interface с сохранением строгой семантики client local;
- динамические server bypass routes и kill-switch allowlist;
- для exit-node на commit обновлять WAN/NAT/MARK/accept_ra правила обоих семейств.

## 12. Конфигурация

Новые пользовательские параметры добавляются в существующий flat INI. Отдельный JSON
конфиг не вводится.

Сервер, внутри конкретного профиля:

~~~ini
[profile:mobile-udp]
roaming.enabled = true
roaming.grace_secs = 30
roaming.max_orphaned = 256
roaming.max_orphan_bytes = 67108864
~~~

Клиент:

~~~ini
[qeli]
roaming = auto
~~~

Допустимые значения клиента:

- **off** — всегда обычный reconnect;
- **auto** — использовать согласованный roam, иначе reconnect;
- **required** — отказать, если профиль/peer не поддерживает безопасный roam.

На первом rollout серверный default — off, клиентский — auto. Не следует выводить в
конфиг низкоуровневые переключатели crypto, path validation или CID rotation: они являются
инвариантами протокола, а не настройками администратора.

Валидация должна отклонять:

- required для UDP без QUIC/DATA_FRAG;
- required при отсутствии серверной capability;
- невозможный cross-interface roam при жёстком client local;
- нулевые/чрезмерные grace и memory limits.

Новые ключи обязаны пройти единый round-trip во всех Rust/C#/Kotlin/Swift моделях,
редакторах профиля, raw editor, встроенных quick-start режимах, примерах установки и
qeli share. В share следует писать только значения, отличные от default. Внутренние
JSON-структуры FFI/ABI также обновляются, но не становятся пользовательским форматом.

## 13. Панель, API и эксплуатация

Сессия больше не должна идентифицироваться внешним peer address. SessionShared и control
API получают additive поля:

- session_id и lifecycle state;
- current_peer и outer family;
- roam_count и last_roam_secs;
- число ready/draining streams или active/candidate paths;
- текущий внешний payload budget;
- причина последнего fallback.

Dashboard использует session_id как ключ строки. Успешный roam не создаёт события
disconnect/connect и не запускает обычные пользовательские уведомления. Допустимо отдельное
низкошумное roam event. Окончательный disconnect фиксируется только при revoke/reap.

Метрики должны быть low-cardinality:

- attempts/success/failure по transport и нормализованной причине;
- orphan gauge/reap;
- validation latency и candidate gauge;
- CID miss/collision;
- PMTU reset/probe;
- reconnect fallback.

В логах запрещены resume proof, session token, secrets и полный CID.

## 14. Порядок реализации

Ни один production-этап не допускает небезопасный роуминг без proof, path validation,
anti-amplification и PMTU reset.

### Этап 0. Протокольная спецификация — ✅ исходники

- зафиксировать capability bits и wire constants;
- KDF labels и known-answer vectors для всех auth modes;
- CONTROL_V2 и лимиты reassembly;
- TCP JOIN transcript/proof;
- UDP short header/CID/path messages;
- feature flags с default off.

Результат: спецификация и тестовые векторы, но feature недоступна пользователю.

### Этап 1. ABI и транзакция пути — ✅ исходники

- generation-scoped PathUpdate/command channel;
- PREPARE/COMMIT/ABORT contract;
- platform socket binding hooks;
- отдельная телеметрия roam/reconnect;
- mock adapter с fault injection.

Результат: ядро умеет безопасно запросить и откатить candidate path без изменения
текущего data plane.
ABI 1.12 и stats V3 сохраняют старые префиксы; mock fault injection покрывает отказы
PREPARE/BIND/COMMIT/ABORT. Production-адаптеры не рекламируют path capability до этапа 4;
платформенный PathUpdate e2e ещё не выполнялся.

### Этап 2A. TCP lifecycle — ✅ исходники

Общее default-off ядро реализует состояния Active/Orphaned/Resuming/Closing/Revoked,
двойной лимит orphan-сессий и retained bytes, generation-tagged reaper ownership,
монотонное потребление resume epoch, стабильные logical slots, атомарную JOIN reservation
и make-before-break drain. Unit-тесты покрывают stale proof/transcript/epoch/locator,
гонки JOIN/reaper и revoke/JOIN, исчерпание лимитов, abort, exact-once release и поздний
drain ACK. Интеграция state machine с сервером описана в этапе 2B; обычные сессии и
production-сборка без feature gate сохраняют прежний data plane.

### Этап 2B. TCP resume и handover — 🟡 общие исходники готовы, live-приёмка ожидается

Linux handler и общий client supervisor под default-off feature выводят и обнуляют resume
secret исходной сессии, строго разбирают authenticated resume JOIN и резервируют lifecycle/slot
до JOINOK. Каждый attach выполняет свежий KE и получает свежие per-carrier data keys.
Feature-клиент умеет объявить `CONTROL_V2`, `TCP_RESUME_V1` и `TCP_HANDOVER_V1`, но negotiation
удаляет handover без полного platform `ROAMING_PATH`; production-адаптеры его пока не объявляют.
Потеря последнего carrier до 30 секунд сохраняет прежние TUN
и NetworkPlan; supervisor раз в секунду восстанавливает тот же stable logical slot, а sibling
reader/writer завершаются общим сохраняющим состояние stop-сигналом.

Сервер допускает один bounded authenticated candidate сверх stream cap, поэтому hard resume
атомарно заменяет stale carrier даже тогда, когда клиент уже увидел обрыв, а сервер ещё не получил
EOF/RST. После commit старый transport переводится в draining и закрывается. Если все server-side
carrier уже отсоединились, остаются 30-секундный orphan grace, точные session/retained-byte limits
и generation-scoped reaper. Для legacy/non-negotiated сессий прежние JOIN и scheduler не изменены.

При намеренной остановке клиент отправляет строгий пустой односоставной `CLOSE_SESSION` внутри
аутентифицированного PacketCodec/`PACKET_MUX_V1`. Клиент принудительно flush-ит ожидающий batch
recordizer и не более 750 мс ждёт завершения записи в сокет; сервер атомарно запрещает новые
JOIN/resume, закрывает все bonded streams, сразу освобождает lease и не входит в orphan grace.
Linux SIGINT/SIGTERM теперь использует этот cooperative cancel path вместо обхода data-plane
destructors через `process::exit`.

Основа make-before-break теперь связывает authenticated resume proof с явным handover-флагом
и считает перекрывающиеся carrier каждого stable logical slot через refcount. Поэтому завершение
старого draining carrier не может ошибочно пометить replacement отсутствующим. Сервер также
требует, чтобы authenticated client capabilities одновременно объявляли TCP handover core bits
и полный platform-контракт `ROAMING_PATH` (`PATH_TRANSACTIONS + PATH_SOCKET_BINDING`): одного
core-bit недостаточно для вытеснения живого transport.

Общий supervisor теперь забирает один ACK-подтверждённый PREPARE candidate, создаёт отдельный
unbound socket, до connect требует точный platform `BIND_SOCKET` и использует только A/AAAA из
данного PathUpdate. Fresh-KE authenticated handover JOIN проверяется до `COMMIT_PATH`; только
после его ACK новый carrier заменяет stable slot 0. Перекрывающиеся carrier удерживают slot через
refcount, а committed-набор адресов становится источником восстановления остальных bonded slots.
BIND/COMMIT/ABORT имеют коррелированные oneshot-результаты, 45-секундный предел и отмену при
supersede/stop.

Если peer не поддерживает handover, временный path проходит ACK-подтверждённый ABORT до обычного
full-reconnect fallback. Ошибки candidate connect/JOIN также откатывают platform-состояние.
Отказ COMMIT остаётся fail-closed: сервер к этому моменту уже аутентифицировал и переключил
carrier, поэтому клиент восстанавливается существующим hard resume, не публикуя локально
неподтверждённый path. Production platform bits остаются выключенными до этапа 4 и live-приёмки.

На lab `.10` финальные default/feature suites прошли с 862/901 library tests, 4 CLI и
7 integration tests (по одному privileged test ignored), а strict all-target Clippy — в обеих
конфигурациях. Изолированный Linux netns e2e с односторонним TCP RST прошёл 13/13: resume занял
2 секунды, внешний carrier сменился, TUN ifindex/IP сохранились, ping восстановился, а password
AUTH выполнилась ровно один раз. Отдельный live e2e `.11 → .10` с обязательным
`PACKET_MUX_V1` прошёл 3/3 tunnel ping, подтвердил оба close-маркера, отсутствие established
carrier и клиентского TUN после остановки и отсутствие перехода сервера в resume grace.

Эти результаты `.10/.11` относятся к hard resume и explicit close, а не к новому
make-before-break пути. Новый общий path прошёл указанные source/unit gates и точную Windows FFI
feature matrix, но ни один production/Linux adapter пока не рекламирует `ROAMING_PATH`. Поэтому
live-приёмка этапа 2B следует за platform adapter этапа 4 и его lab race matrix.

### Этап 3. UDP migration

Статус 3A–3C: под default-off feature готовы registry/migration и writer-egress основы.
Profile-wide bounded-модель владеет
generation-tagged сессиями, не более чем тремя deterministic CID aliases, directional zeroized
secrets, одним authenticated candidate, точной привязкой PATH_CHALLENGE/RESPONSE к path/epoch/token,
трёхкратным anti-amplification budget, атомарной collision-safe CID rotation, generation-tagged
PMTU reset и точным cleanup. Generic bounded cross-worker fabric закрепляет неизменяемого
home-worker владельца session codec, не вводит общий decrypt-lock, не делает channel hop для local
ingress и использует fail-closed `try_send` между `SO_REUSEPORT` workers. Unknown CID, invalid
worker, full и closed mailbox различаются, а rejected payload сохраняет точное ownership без
`Debug`.

Аутентифицированный server UDP writer теперь один раз на полную зашифрованную запись получает
snapshot точных socket, peer, framing, path epoch и согласованного PMTU budget. Экспериментальный
guarded commit может атомарно опубликовать следующий IPv4/IPv6 path и восьмибайтовый CID без замены
PacketCodec, replay window, rate buckets и TUN ownership. Stale commit не откатывает путь;
запоздалый `EMSGSIZE` старого пути не перезаписывает безопасный бюджет нового семейства;
DATA_FRAG вычитает фактическую длину legacy- или roaming-заголовка. Legacy wire с четырёхбайтовым
CID остаётся byte-identical. Тринадцать focused unit-тестов покрывают последовательные ротации,
stale/collision/anti-amplification, local/cross-worker/full/closed routing и atomic writer publish.

Ingress fabric и guarded commit ещё не подключены к session actor, а `UDP_ROAM_V1` не рекламируется.
Heartbeat, cover, reverse PMTU probe, полная DATA_FRAG/reassembly/replay интеграция,
cross-listener/family races и mock/Linux live-приёмка остаются следующими срезами.

- восьмибайтовый CID и profile-wide registry;
- per-session actor и dynamic egress;
- PATH_INIT/CHALLENGE/RESPONSE/COMMIT;
- anti-amplification и candidate limits;
- двунаправленный live PMTU reset/probe;
- DATA_FRAG/reassembly/replay интеграция;
- cross-worker/listener/family tests.

Результат: безопасный UDP роуминг на mock/Linux path.

### Этап 4. Платформы

- Android;
- Windows;
- macOS;
- iOS;
- Linux/OpenWrt и exit-node.

Каждая платформа проходит prepare/bind/commit/rollback тесты до включения capability.

### Этап 5. Конфиги, приложения и панель

- flat-INI parsing/defaults/validation/round-trip;
- GUI editors и встроенные quick-start режимы;
- API/dashboard/metrics/logging;
- русская и английская документация;
- install/deb/examples в /etc/qeli.

### Этап 6. Лаба, soak и rollout

- полный transport/family/platform matrix;
- длительные flap, suspend/resume и NAT rebinding;
- canary профили;
- staged enablement;
- проверка fallback на legacy peers.

## 15. Проверки и release gates

### Протокол и криптография

- capability downgrade и неизвестные биты;
- fuzz discriminator 4/8 bytes, truncation и CID collision;
- KDF known-answer tests для classic/hybrid/bound;
- replay/wrong transcript/wrong slot/wrong epoch TCP JOIN;
- CONTROL_V2 больше 255 байт, reorder, duplicate, timeout и лимиты.

### Гонки и ресурсы

- CID lookup между SO_REUSEPORT workers, listeners и outer families;
- registry lookup до new-session rate limit;
- spoofed source и anti-amplification 3×;
- параллельные candidates и stale commit;
- reaper против JOIN/kick/quota/new AUTH/reload;
- запрет JOINOK до atomic reservation;
- stable slots без перенумерации;
- adaptive multipath против roam;
- отсутствие u8 epoch exhaustion;
- отсутствие double free и утечек aliases/routes/sockets.

### PMTU и фрагментация

- live probe не забирает data datagram;
- stale ACK не расширяет новый путь;
- reset IPv4→IPv6 и IPv6→IPv4;
- asymmetric C2S/S2C PMTU;
- fragments в момент drain;
- reorder/loss/duplicate/conflict/expiry;
- неизменный inner TUN MTU при DATA_FRAG_V1.

### End-to-end матрица

- inner IPv4, IPv6, dual-stack на outer IPv4 и IPv6;
- TUN и TAP;
- все TCP режимы;
- UDP fakeTLS/obfs/AWG с QUIC и DATA_FRAG;
- max_streams 1, fixed и adaptive;
- full/split/per-app routing;
- kill switch, Trusted Wi-Fi и жёсткий local pin;
- reconnect false и persist_tun;
- NAT rebinding без смены интерфейса;
- sleep меньше и больше grace;
- A/AAAA reorder и DNS64/NAT64;
- legacy peer fallback;
- отрицательный тест multi-process/multi-node.

Soak: не менее 10 000 смен пути с контролем памяти, fd, sockets, routes, firewall rules,
CID aliases и orphaned sessions. Допустимая регрессия throughput/CPU на включённом
роуминге — не более 3–5% относительно того же транспорта без него.

Release запрещён, если хотя бы одна поддерживаемая платформа:

- объявляет capability без точного socket binding;
- переключает downstream до path validation;
- переносит старый PMTU;
- сбрасывает UDP codec/replay state;
- оставляет bypass route/kill-switch hole после abort;
- принимает TCP JOIN только по token;
- пересоздаёт TUN/TAP при успешном roam.

## 16. Оценка трудоёмкости и риски

Полная реализация для сервера, единого ядра, пяти клиентских платформ, панели,
документации и лаборатории: ориентировочно 20–30 инженерных недель.

Практическая оценка:

- server + Linux/Android MVP: 10–14 инженерных недель;
- один разработчик: около 5–7 календарных месяцев;
- два опытных разработчика: около 12–18 календарных недель с учётом интеграции и lab.

Главные риски:

1. server UDP state, общий между workers/listeners;
2. гонки TCP orphan/reaper/JOIN;
3. точная platform binding и атомарный kill-switch rollback;
4. PMTU при смене outer family;
5. iOS cellular/Wi-Fi поведение, проверяемое только на устройствах;
6. сочетание adaptive multipath, roam и reconnect supervisor.

## 17. Rollout

1. Серверный default off, клиентский auto.
2. Capability negotiation допускает rolling upgrade.
3. Сначала canary TCP и UDP профили с отдельными метриками.
4. Затем по одной платформе после её полной lab-матрицы.
5. При любой неподдерживаемой или ошибочной ситуации — обычный full reconnect.
6. После перезапуска сервера, смены node или истечения grace — только full AUTH.

Feature не считается готовой, пока не пройдены все обязательные release gates, даже если
happy-path смены Wi-Fi/cellular уже визуально работает.

# Роуминг клиента: план полной реализации
<!-- normative-sync: roaming-v46-tiered-soak-accepted -->

> Статус: проектирование завершено; этапы 0–2A и общий TCP handover этапа 2B реализованы
> под `experimental-roaming`. Linux in-process и Android feature adapters объявляют полный
> `ROAMING_PATH` для TCP и всех поддерживаемых UDP camouflage modes только при наличии реализации
> в ядре; default-сборки и unsupported platforms сохраняют обычный reconnect. Linux TCP прошёл live e2e 15/15, hard resume и
> explicit close. Android API 34 emulator прошёл Wi-Fi → cellular (198/200 ping), cellular →
> Wi-Fi (200/200) и sleep/wake на неизменном пути (160/160): сохранились PID, TUN и NetworkPlan,
> полная AUTH выполнилась один раз, underlying Network сменился атомарно, DNS после переходов
> продолжил разрешать имена. Повторный hard-loss/make-before-break race-gate принял ровно один
> authenticated JOIN на каждый переход (76/80 и 80/80 ping). Этапы UDP 3A–3E: ограниченные
> registry/migration
> state, cross-worker dispatch, atomic data/auxiliary egress, negotiated bootstrap,
> authenticated ingress/control boundary, guarded PATH_RESPONSE/PATH_COMMIT transaction и
> post-commit UDP DATA/DATA_FRAG ingress вместе с общими клиентскими validation state machine,
> wire framing и exact-bound candidate-socket dialer готовы по исходникам. Live client actor теперь
> не только переводит все post-auth data/control/PMTU пути epoch 0 на directional CID framing, но и
> валидирует отдельный candidate socket, обрабатывает PATH_INIT/CHALLENGE/RESPONSE/COMMIT/ABORT,
> ждёт точный platform COMMIT ACK и атомарно переключает socket, receive pump, CID framing и
> консервативный PMTU budget. Ошибка после peer PATH_COMMIT приводит к fail-closed reconnect.
> В feature-сборке Linux UDP согласует `UDP_ROAM_V1` для fake-TLS, QUIC masking, obfs и AWG только
> при полном platform `ROAMING_PATH` и аутентифицированном `DATA_FRAG_V1`; fixed-source и
> default-сборки бит не получают.
> Двухмаршрутный UDP netns live e2e прошёл 17/17: PATH_INIT/CHALLENGE/RESPONSE/COMMIT перенёс
> authenticated session, carrier `/32`, socket и receive pump до выключения старого интерфейса,
> сохранив PID, TUN и отсутствие top-level reconnect. Отдельный rollback-сценарий прошёл 20/20:
> путь B был избирательно заблокирован, bounded PATH_INIT retries истекли, exact platform ABORT
> удалил подготовленный кандидат и оставил действующий carrier `/32` на пути A; туннель сохранил
> тот же PID/TUN и не вошёл в top-level reconnect. Трёхмаршрутный supersede-сценарий прошёл 24/24:
> blackholed B успел отправить PATH_INIT, затем platform выполнила `ABORT(B) → PREPARE(C)`, actor
> удалил старый socket до retry-expiry, а сервер challenge/commit увидел только путь C и ровно один
> commit. PID/TUN и трафик сохранились без reconnect. Windows/macOS C# и iOS Swift path executors
> теперь готовы по исходникам; впереди их device/race-приёмка и этапы 4–6. iOS Rust slice проходит
> строгий cross-target Clippy для `aarch64-apple-ios`, но Xcode- и physical-device
> NetworkExtension-приёмка ещё не выполнены. Детерминированный commit-race-сценарий прошёл 24/24:
> после server PATH_COMMIT(B)
> локальная route-мутация COMMIT(B) была задержана, detector увидел C, но сериализованный executor
> не позволил C отменить или обогнать B. Exact ACK и публикация B завершились до PREPARE(C), после
> чего C также был подтверждён ровно один раз; PID/TUN и трафик сохранились без reconnect.
> Детерминированный control-loss-сценарий прошёл 18/18: firewall counters подтвердили потерю ровно
> первого PATH_CHALLENGE и первого PATH_COMMIT, свежие PATH_INIT/PATH_RESPONSE восстановили оба
> обмена, а сервер повторил PATH_COMMIT без второй публикации пути и без reconnect.
> Оба Linux IPv4 roaming PMTU-среза прошли по 19/19. Bare probes и ACK обрабатываются после точной
> классификации committed CID/epoch/socket/peer, а не отбрасываются как не прошедшие AEAD records.
> Симметричный переход MTU 1500 → 1280 независимо пересертифицировал оба направления с 1461 до
> 1161 байта, сохранил внутренний TUN MTU 1400 и передал payload 1350 байт через DATA_FRAG.
> В асимметричном gate C2S 1500 / S2C 1280 uplink остался 1461, сервер спустился по общему PMTU ladder
> и сертифицировал downlink 1161; reverse DATA_FRAG, PID/TUN и сессия сохранились.
> Детерминированный Linux IPv4 receive-drain gate прошёл 26/26. На старом пути A оба направления
> работали с MTU 1280, трёхсекундной задержкой и gap-reorder; путь B был закоммичен, пока обе
> DATA_FRAG-записи по 1350 байт оставались неполными. Точный прежний epoch/peer/socket/CID оставался
> только принимающим на один reassembly timeout, завершил обе записи и истёк; control и PMTU старого
> пути отклонялись. Duplicate DATA_FRAG на активном пути B остался идемпотентным без замены PID/TUN
> и без reconnect.
> Dual-listener Linux outer-family gate прошёл 32/32. Одна authenticated session переместилась
> IPv4 → IPv6 → IPv4 через разные receiving workers без новой AUTH и reconnect, сохранив codec owner,
> PID и TUN. Оба направления независимо пересертифицировали PMTU 1461 → 1341 → 1461, через IPv6
> прошёл DATA_FRAG-sized пакет, а каждый commit оставил ровно один активный qeli-owned `/32` или
> `/128`. Generation-scoped discovery A/AAAA теперь переживает точный pin активного peer только для
> будущей authenticated PathUpdate; bypass и bonded carriers остаются ограничены committed peer.
> Двунаправленный Linux gate deliberate DATA_FRAG-loss прошёл 25/25. При outer MTU 1280 firewall
> отбросил ровно первый полноразмерный фрагмент каждой 1350-байтной записи, но пропустил её хвост;
> ни одна неполная запись не попала в TUN. Путь B закоммитился без новой AUTH, замены PID/TUN или
> reconnect. После пятисекундного reassembly timeout и удаления старого пути A следующие
> фрагментированные записи завершились в обе стороны. Focused unit-регрессия фиксирует удаление
> просроченной записи перед выделением и завершением её замены.
> Детерминированный Linux gate same-network NAT dead mapping прошёл 21/21. Stateless translation
> сменила наблюдаемый сервером peer с `10.41.3.1` на `10.41.3.254`, тогда как интерфейс, локальный
> адрес, default/carrier routes, endpoint, PID и TUN клиента не изменились. Authenticated RX silence
> запросил один ограниченный `SameNetworkNatFailure` PathUpdate для active epoch; observer остался
> единственным владельцем наблюдения пути и update id, а candidate закоммитился ровно один раз без
> второй AUTH или reconnect. Policy one-attempt/grace/fallback теперь находится в общем Rust core;
> platform controllers дают только bounded-запрос свежего snapshot того же пути. ABI 1.13 теперь
> передаёт этот запрос Android как generation-scoped событие `PATH_REFRESH` без payload. Kotlin
> возвращает `SameNetworkNatFailure` snapshot неизменной `Network` и не владеет retry timer;
> единая Rust policy по-прежнему задаёт одну попытку, 15-секундный grace и reconnect fallback.
> Source/JVM-регрессии и полная UDP-матрица NAT-rebinding на API 34 emulator с feature APK готовы.
> Для fake-TLS, QUIC, obfs и obfs-AWG двусторонне потерянный старый 5-tuple вызвал
> `PATH_REFRESH`, `PATH_CHALLENGE` и `PATH_COMMIT` на новый source port без второй AUTH,
> NetworkPlan, замены процесса/TUN или reconnect. Android `Network` handle остался прежним,
> tunnel ping прошёл 5/5 до и после миграции в каждом режиме. NAT-rebinding на реальных
> устройствах остаётся отдельным gate.
> Повторный gate после чистой сборки текущего feature core и APK `0.8.0` (`versionCode=720`,
> SHA-256 `710185c288ac0d19e1adfd843d409d8f450270239a5bd241dd91764d996d9ead`) снова закрыл
> 44/44 инварианта по четырём режимам: новый исходный UDP-порт, единственные AUTH/NetworkPlan,
> неизменные PID/TUN и tunnel ping 5/5 до и после commit.
> Общий feature core готов к Windows socket handle: `PATH_COMMAND` передаёт заимствованный signed
> 64-bit Unix descriptor или Windows `SOCKET`, а native TCP candidate dialer и единый UDP migration
> actor компилируются на Windows. Общий C#-адаптер реализует optional ABI 1.12/1.13 bindings для
> path update/result и строгий ограниченный JSON-контракт коррелированных
> PREPARE/BIND/COMMIT/ABORT и событий PATH_REFRESH без payload. Conformance-тесты отклоняют
> неизвестные поля, stale generation и несовместимые семейства адресов, сохраняя Windows socket
> values шире `Int32`.
> Windows C#-адаптер теперь выполняет сериализованную path-транзакцию. PREPARE устанавливает только
> привязанные к точным interface/source candidate routes `/32` или `/128` и расширяет kill switch и
> WinDivert carrier allow-set до old+new. BIND применяет `IP_UNICAST_IF`/`IPV6_UNICAST_IF` к
> заимствованному 64-bit `SOCKET` и связывает выбранный local address до connect в Rust core.
> COMMIT передаёт candidate routes в session cleanup, удаляет только stale Qeli-owned carrier rows
> и сужает policy до нового пути; ABORT удаляет candidate state и восстанавливает старый путь.
> Обычный TCP и все поддерживаемые UDP camouflage profiles используют один executor. Явные `local`
> или `lport`, default/старое ядро либо unsupported peer сохраняют существующий reconnect fallback.
> Shared/Windows builds и managed route/socket/policy self-tests проходят без предупреждений.
> До rollout остаются Windows real-device, race, kill-switch и soak acceptance.
> macOS C#-адаптер теперь выполняет ту же сериализованную path-транзакцию для обычного TCP и всех
> поддерживаемых UDP camouflage profiles. PREPARE проверяет точный работающий physical
> interface/source и создаёт только точные Darwin `RTF_IFSCOPE` carrier routes, не присваивая
> operator-owned routes. BIND применяет `IP_BOUND_IF` либо `IPV6_BOUND_IF` и выбранный source address
> к заимствованному fd до connect в Rust. COMMIT сохраняет scoped route для мигрировавшего socket,
> транзакционно переключает обычный Qeli host route для последующего ремонта bonded TCP и сужает PF
> с old+new до нового carrier-набора; ABORT удаляет только candidate-owned state и возвращает старый
> PF-набор. Disconnect повторяет незавершённую очистку и восстанавливает как committed Qeli routes,
> так и исходные operator routes. Явные `local`/`lport`, default/старое ядро или unsupported peer
> сохраняют reconnect. Cross-platform Release build и macOS route/socket/capability self-tests
> проходят без предупреждений. До rollout остаётся live macOS-приёмка route-команд, PF, per-app,
> device/race и sleep/soak; этот source-only gate не выдаётся за проверку на реальном macOS.
> Общий Linux exit-node roaming gate прошёл TCP 35/35 и UDP-матрицу 4/4: `quic`, `fake-tls`,
> `obfs`, `obfs-awg` дали по 35/35 каждый. Реальный full-tunnel consumer передал трафик через
> server → exit → WAN A, после чего authenticated carrier и физический default выхода переместились
> на WAN B без повторной полной AUTH, замены PID/TUN или top-level reconnect. Ровно две исходные
> полные AUTH соответствуют exit и consumer; после handover их число не изменилось. Точные
> MARK/MASQUERADE/FORWARD rules и NAT counters проверены на обоих WAN; прежнее поколение осталось
> доступным для fail-safe drain. После полного завершения SIGTERM-cleanup exit-процесса rules обоих
> поколений отсутствовали, а исходные `ip_forward`/`rp_filter` были восстановлены. Владение exit WAN
> теперь привязано к TUN, поэтому обычный соседний профиль в том же daemon не может получить exit
> rules. IPv4 и IPv6 независимо обновляют свои фактические default uplink, не предполагая совпадения
> с интерфейсом qeli carrier. Identity, TOFU, device-id и control socket теста изолированы в его
> рабочем каталоге; TCP и все UDP-маскировки проходят один общий exit-node COMMIT path.
> Текущие lab gates: 972 feature library tests при трёх ignored, 881 default tests при
> одном ignored, strict default/feature Clippy, базовый Linux netns 26/26, exit-node TCP 35/35,
> exit-node UDP 4/4 режима по 35/35 и TCP matrix 6/6 режимов: `reality-tls` 19/19,
> остальные пять режимов по 15/15,
> UDP roaming netns success 17/17, rollback 20/20, supersede 24/24, commit-race 24/24 и
> control-loss/replay 18/18, symmetric IPv4 PMTU 19/19, asymmetric IPv4 PMTU 19/19 и
> receive-drain/reorder/duplicate 26/26, outer-family round-trip 32/32, DATA_FRAG-loss 25/25 и
> same-network NAT dead-mapping 21/21,
> Android x86_64 NDK release с
> `-D warnings` и Gradle unit/assemble. Полная platform/race/soak matrix остаётся release gate. Целевая версия — 0.8.x.
> TCP matrix покрывает `fake-tls`, `reality-tls`, `plain`, `obfs-ws`, `obfs-none` и `obfs-awg`
> одним runner. REALITY-срез использует настоящий локальный TLS target и проверяет заимствованные
> TLS shape/цепочку сертификатов, прозрачный decoy bridge, точный pinned identity и настоящий
> HTTP/2 carrier до того, как проходит тот же make-before-break handover.
> Отдельный `roaming_wire` fuzz-target теперь проверяет произвольные UDP CID-заголовки, TCP resume
> JOIN/proof и PATH control bodies, валидные round-trip инварианты и tampered-proof path. Он включён
> и в обязательный CI smoke loop, и в nightly matrix с сохраняемым corpus. Лабораторный
> ASan/libFuzzer smoke выполнил 1 324 437 запусков за 31 секунду при coverage 515, corpus 22 и
> peak RSS 371 MiB без падений или ошибок санитайзера.
> Каждый live Linux TCP/UDP netns-профиль явно включает server rollout и использует client
> `required`, поэтому reconnect fallback не может дать зелёную миграцию. Вынесенные UDP case
> helpers загружаются fail-closed; отсутствие helper проверено как `rc=2`, а не ложный `0 failed`.
> Клиентская политика `off|auto|required`, transport-specific capability negotiation и
> flat-INI/`qeli://` round-trip теперь source-complete в Rust, Kotlin, C# и Swift. `off` не
> допускает TCP resume/handover, а все UDP camouflage modes используют тот же policy gate;
> `required` fail-closed до credentials/полной AUTH. Все четыре клиентских GUI и профильные
> настройки серверной панели/API, worker-lifetime метрики/logging и явные безопасные packaged
> examples готовы. Этап 5 source-complete, а device/soak gates этапа 6 не закрыты.
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
| UDP fake-TLS / QUIC masking / obfs / AWG с согласованными UDP_ROAM_V1 и DATA_FRAG_V1 | полная миграция адреса, сокета и PMTU через единый directional-CID envelope |
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

Сервер объявляет только возможности, реально доступные конкретному профилю. UDP_ROAM_V1 требует
DATA_FRAG_V1, но не требует включённого legacy-параметра `quic`: после взаимного аутентифицированного
opt-in все UDP camouflage modes переключаются на один roaming CID envelope. Клиент в режиме
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

Существующий handshake и известный legacy path сохраняются для совместимости: QUIC-masked legacy
профиль имеет четырёхбайтовый CID, fake-TLS/obfs без masking до AuthOK CID не имеют. После
согласованного UDP_ROAM_V1 все режимы переключаются на общую форму roaming short header со
стандартными QUIC-shaped flags и восьмибайтовым DCID. Он находится снаружи session PacketCodec,
чтобы сервер мог выбрать сессионный ключ, но внутри profile-wide UDP obfs transform: fake-TLS и
QUIC masking оставляют CID-shaped header видимым, а obfs/AWG закрывает его ключом профиля до выхода
на физический провод. Отдельный постоянный qeli-marker запрещён:
он создал бы простой DPI-отпечаток. При miss по source address сервер пробует извлечь восьмибайтовый
CID и выполнить bounded lookup в profile-wide registry; известный legacy path продолжает использовать
свою исходную форму.

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

Текущий feature-gated TCP adapter уже:

- сохраняет точный `Network.networkHandle`, отбрасывает stale generation и superseded Network;
- получает A/AAAA через точный `Network.getAllByName`, ограничивает набор адресов и удаляет
  локальные IPv6 zone id из ABI-представления;
- выполняет `Network.bindSocket(fd)`, затем `VpnService.protect(fd)` для candidate socket;
- преобразует Connectivity callback и смену пути во время сна в ограниченный `PathUpdate`;
- применяет новый `setUnderlyingNetworks` только после COMMIT и сохраняет прежний TUN/NetworkPlan;
- при hard loss выбирает уже доступный физический replacement вместо обнуления current Network;
- Trusted Wi-Fi остаётся policy stop;
- **остаётся:** детектировать same-network NAT rebinding/dead mapping без смены Network.

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

- required для UDP без согласованного DATA_FRAG/UDP_ROAM;
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
PREPARE/BIND/COMMIT/ABORT. ABI 1.13 добавляет capability-gated same-path refresh request без
изменения фиксированных event/stats prefixes. Linux исполняет его in-process, Android возвращает
snapshot неизменной `Network`. Остальные native adapters не объявляют новый bit и сохраняют
reconnect fallback.

### Этап 2A. TCP lifecycle — ✅ исходники

Общее default-off ядро реализует состояния Active/Orphaned/Resuming/Closing/Revoked,
двойной лимит orphan-сессий и retained bytes, generation-tagged reaper ownership,
монотонное потребление resume epoch, стабильные logical slots, атомарную JOIN reservation
и make-before-break drain. Unit-тесты покрывают stale proof/transcript/epoch/locator,
гонки JOIN/reaper и revoke/JOIN, исчерпание лимитов, abort, exact-once release и поздний
drain ACK. Интеграция state machine с сервером описана в этапе 2B; обычные сессии и
production-сборка без feature gate сохраняют прежний data plane.

### Этап 2B. TCP resume и handover — 🟡 Linux и Android feature live приняты

Linux handler и общий client supervisor под default-off feature выводят и обнуляют resume
secret исходной сессии, строго разбирают authenticated resume JOIN и резервируют lifecycle/slot
до JOINOK. Каждый attach выполняет свежий KE и получает свежие per-carrier data keys.
Feature-клиент умеет объявить `CONTROL_V2`, `TCP_RESUME_V1` и `TCP_HANDOVER_V1`, но negotiation
требует полный platform `ROAMING_PATH`. Linux объявляет его только для feature TCP без fixed source;
Android — только для TCP и только когда загруженное feature-ядро подтверждает path transaction ABI.
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
неподтверждённый path. Android включает `ROAMING_PATH` для feature TCP и всех UDP-режимов, а
`PATH_REFRESH` объявляет только если ядро ABI 1.13 сообщает парный core capability.
Windows, macOS и iOS объявляют оба path capability для обычных профилей, когда feature core
предоставляет соответствующий ABI. На iOS ту же транзакцию исполняют `NWPathMonitor`,
interface-scoped endpoint resolution, Darwin socket binding и точные carrier `excludedRoutes`.
Явные `local`/ненулевой `lport`, default/старое ядро и unsupported peer сохраняют reconnect fallback.

На lab `.10` финальные default/feature suites прошли с 865/910 library tests, 4 CLI и
7 integration tests (по одному privileged test ignored), а strict all-target Clippy — в обеих
конфигурациях. Изолированный Linux netns e2e с односторонним TCP RST прошёл 13/13: resume занял
2 секунды, внешний carrier сменился, TUN ifindex/IP сохранились, ping восстановился, а password
AUTH выполнилась ровно один раз. Отдельный live e2e `.11 → .10` с обязательным
`PACKET_MUX_V1` прошёл 3/3 tunnel ping, подтвердил оба close-маркера, отсутствие established
carrier и клиентского TUN после остановки и отсутствие перехода сервера в resume grace.
Постоянный `resume` netns case теперь воспроизводит server-side carrier reset на неизменном path A:
ровно один authenticated JOIN завершается внутри grace без второй AUTH, top-level reconnect или
замены PID/TUN; live результат — 18/18. Парный `grace-expiry` case задаёт server grace 3 секунды,
держит replacement carriers в blackhole до reap locator, требует точные `unknown locator` отказы без
JOIN commit, затем ждёт исчерпания 30-секундного client resume budget и принимает только обычный
full reconnect со второй AUTH и восстановлением трафика; live результат — 18/18. Это
детерминированная transport-проверка short/expired grace, а не замена physical-device suspend gate.

Эти результаты `.10/.11` относятся к hard resume и explicit close. Новый двухмаршрутный Linux
feature e2e также прошёл 15/15: path B завершил authenticated JOIN/COMMIT, path A был выключен,
те же PID/TUN сохранились, а 150/150 ping прошли без top-level reconnect. Android API 34 emulator
с feature `.so` прошёл оба направления Wi-Fi/cellular: hard loss Wi-Fi подготовил candidate на уже
доступном cellular Network и сохранил 198/200 ping, обратный make-before-break переход сохранил
200/200. PID приложения, VPN Network, `tun0` и `NetworkPlan 1` не менялись, `Auth OK` появился
ровно один раз. Sleep/wake на прежнем Network сохранил 160/160 ping без лишнего handover; после
обоих переходов и сна системный DNS продолжил разрешать имя.

`scripts/roaming_android_sleep_wake_gate.py` теперь делает эту same-network приёмку повторяемой и
fail-closed для любого уже подключённого TCP- или UDP-профиля, не сохраняя профиль или credentials.
Он запоминает и восстанавливает флаги Doze и состояние экрана AVD, требует реальный deep `IDLE`,
ведёт непрерывный tunnel ping, а после wake сравнивает PID приложения, идентичность `tun0` из
`/proc/net/if_inet6` и его адрес, запрещая новую AUTH или NetworkPlan. Полная матрица API 34 с
feature APK 0.8.0 прошла для `fake-tls`, `quic`, `obfs` и `obfs-awg`: каждый режим оставался в deep
idle 20 секунд, сохранил 180/180 ping и тот же PID/`tun0`, разрешил `example.com` через серверный
tunnel-resolver после wake и записал только same-network keep-маркер. После каждого режима
временный сервер останавливался без оставшегося порта или TUN. Parser-регрессии покрывают реальный
однострочный формат флагов `dumpsys deviceidle`. Этот повторяемый emulator gate не заменяет приёмку
suspend/NAT rebinding на физическом устройстве.

`scripts/roaming_android_udp_grace_expiry_gate.py` добавляет отдельную credentials-free
fail-closed приёмку истечения UDP roaming grace для любого уже подключённого experimental-профиля.
Она принимает только исполняемый `apply|restore` fault hook, не запускает его через shell и всегда
восстанавливает fault, Doze и экран при любом исходе. Gate требует реальный deep `IDLE`, держит
прежний путь недоступным дольше согласованного grace, а затем проверяет строгий порядок
same-network soft recovery → transport fallback → ровно одна новая AUTH → ровно один применённый
NetworkPlan. После полного reconnect replacement TUN определяется по точному назначенному адресу,
а не по нестабильному имени `tun0`; PID приложения должен сохраниться.

Полная API 34 матрица feature APK прошла для `fake-tls`, `quic`, `obfs` и `obfs-awg`: старый
UDP-путь блокировался в обе стороны на 40 секунд при общем grace 15 секунд без рестарта endpoint.
Во всех четырёх режимах восстановились tunnel ping 5/5 и DNS через серверный tunnel-resolver.
Этот emulator gate подтверждает единую policy для всех UDP adapters, но не заменяет
physical-device suspend/NAT acceptance.

Общий TCP supervisor теперь всегда уступает generic-восстановление слота уже подготовленному
exact-path candidate, а после исчезновения последнего carrier даёт handover-enabled платформе
ограниченное окно в одну секунду на подготовку PathUpdate. Если candidate за это время не появился,
обычный hard-resume продолжает работу; восстановление не откладывается бесконечно. Это устраняет
наблюдавшуюся Android-последовательность, где generic hard-resume и exact-path handover подряд
заменяли slot 0. Повторный API 34 race-gate зарегистрировал ровно один authenticated JOIN для
hard loss Wi-Fi→cellular и один для обратного make-before-break, сохранил соответственно 76/80 и
80/80 ping, тот же PID/VPN Network/`NetworkPlan 1`, единственную AUTH и работающее разрешение DNS.
Полный Rust library suite прошёл 931 тест при трёх ignored; strict all-target Clippy и Android
release-сборка с `-D warnings` прошли.

Впереди остаются реальные устройства, platform-specific same-network NAT rebinding,
Windows/macOS/iOS device/race-приёмка, iOS Xcode/NetworkExtension-сборка и расширенная
transport/family/NAT64/per-app/race/soak matrix.

### Этап 3. UDP migration

Статус 3A–3D: под default-off feature готовы registry/migration, server egress и client validation основы.
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
Heartbeat и shaping-cover записи теперь получают тот же per-record snapshot активного egress,
поэтому после commit используют точные актуальные socket, peer и CID. Уже получившая snapshot запись
может завершить отправку по draining path, но следующие записи увидят commit. Reverse PMTU probe
строится под active framing, отправляется с активного socket точному peer и связывается с path epoch
и адресом. Pending marker разделяется с timeout-задачей, поэтому смена ключа сессии в address map не
оставляет retry gate занятым. При сертификации ACK проверка epoch/peer удерживает read guard активного
пути, поэтому ACK старого пути не может расширить бюджет нового.

UDP bootstrap-контракт теперь fail-closed и аддитивен. Вход требует явного authenticated opt-in
обеих сторон к `CONTROL_V2 + UDP_ROAM_V1 + UDP_DATA_FRAG_V1`: клиент не может активировать
зарезервированную возможность, которую сервер не рекламировал. Для согласованной QUIC-сессии
зашифрованный AuthOK передаёт `udp_roaming_session` как ненулевой `u64` ровно из 16 hex-символов.
После успешного negotiation клиент отклоняет отсутствующий или некорректный идентификатор, а legacy
AuthOK builder полностью исключает поле. Три focused-теста покрывают negotiation, каноническую
выдачу/legacy omission и строгий parsing.

Feature UDP-handshake теперь использует общий `SessionKeyMaterial`: существующие data keys остаются
идентичными, а directional C2S/S2C CID secrets выводятся теми же hybrid/static-bound KDF и хранятся
с zeroization. До того как AuthOK сможет объявить полностью согласованную сессию, сервер записывает
её точный initial worker/path, epoch-zero CIDs и family-safe payload budget в единый profile-wide
registry; клиент независимо выводит совпадающие directional CIDs из session id. Очисткой владеет
non-cloneable generation-scoped registration guard, поэтому поздний teardown старой сессии не удалит
aliases замены. Worker IDs теперь уникальны между всеми `bind.listen` профиля, что готовит однозначную
cross-listener/cross-family доставку. Два focused lifecycle-теста фиксируют гонки stale owner и
replacement.

Server hot path теперь создаёт один bounded fabric на все workers/listeners профиля и выдаёт
каждому worker отдельный non-cloneable mailbox. Восьмибайтовый short header проверяется до
new-session rate limit, но переключение в roaming path происходит только после успешного lookup
полного CID: совпадающий первый байт legacy QUIC не является discriminator, поэтому неизвестный CID
известного address продолжает legacy-обработку и не ломает повтор AUTH после потерянного AuthOK.
Pooled datagram без копирования и точный receiving socket доставляются immutable home worker.
Generation-safe индекс `session_id → address` публикуется только после AUTH и очищается вместе с
address map; stale teardown старой generation не может удалить replacement.

Owner boundary теперь передаёт encrypted record через существующие session-wide `PacketCodec`,
replay window и bounded DATA_FRAG reassembler. Строгий CONTROL_V2 decoder пропускает только
одночастные клиентские `PATH_INIT` и `PATH_RESPONSE` без flags. Replay, malformed/fragmented
control, server-direction messages, обычные data records и неаутентифицированные байты
отбрасываются до TUN и до изменения path state. Candidate liveness обновляется только после
успешной AEAD-проверки. Два focused-теста фиксируют direction/shape gates и общий replay window.

Authenticated `PATH_INIT` теперь одной операцией profile registry проверяет next epoch, future
C2S CID, ожидаемый S2C CID и новый socket/peer. Затем он создаёт или идемпотентно находит
единственный candidate с non-zero 128-bit token. `PATH_CHALLENGE` шифруется общим TX PacketCodec,
получает проверенный восьмибайтовый destination CID и отправляется через точный receiving socket.
Cumulative budget резервируется до send, включает roaming header и obfs overhead и не превышает
3× от консервативно посчитанного authenticated candidate ingress. Generation-scoped ticket
сохраняется в session actor для следующего PATH_RESPONSE-среза.

Guarded commit state transaction теперь готовит полный следующий CID/PMTU outcome до изменения
реестра и вызывает синхронный publisher внешнего socket/address state, удерживая lock profile
registry. CID aliases, active epoch, PMTU generation и candidate ownership меняются только после
успешной публикации. Ошибка publisher оставляет candidate пригодным для повтора, а неверный
challenge больше не увеличивает anti-amplification budget. Focused regression-тест фиксирует
rollback. Последний успешный commit хранится как один bounded exact ticket/path/epoch/token outcome
на сессию. Свежезашифрованный повтор этого PATH_RESPONSE возвращает то же решение PATH_COMMIT без
повторного publisher, ротации CID и сброса уже уточнённого PMTU; несовпадающий token или path
по-прежнему отклоняется fail-closed. Второй focused-тест фиксирует идемпотентный replay.

Live server handler теперь аутентифицирует PATH_RESPONSE по сохранённому candidate, проверяет
старые epoch и peer и синхронно помещает PATH_COMMIT в candidate socket до публикации новых socket,
peer, CID, epoch и family-safe PMTU. `WouldBlock` и любая другая ошибка socket publication оставляют
registry и writer state неизменными, а candidate — пригодным для повтора. После успеха address map
и generation-safe owner index переносятся вместе под directory lock. Очистка при session limit,
supersede и teardown находит текущего владельца по session id, а не по connect-time address. Точный
свежезашифрованный повтор PATH_RESPONSE снова отправляет PATH_COMMIT без ротации CID и сброса PMTU;
другой token, path, старый peer, занятый destination или stale epoch отклоняются fail-closed.

Post-commit DATA и DATA_FRAG теперь входят в существующий authenticated UDP uplink. До AEAD owner
классифицирует routed CID по writer snapshot под directory lock: previous и farther-future epoch
отбрасываются без изменения replay state, current epoch требует точные committed socket и peer, а
только next epoch может попасть в candidate control. После единственного session-wide decrypt обычные
records используют существующие bounded DATA_FRAG reassembler, recordizer, source guard, destination
ACL, bandwidth pacing, accounting, MTU/client-info control и TUN forwarder. Candidate DATA
отклоняется; этот путь может нести только аутентифицированный path control. Commit, teardown и DATA
не могут увидеть частично перенесённое directory/egress state.

Полностью согласованная epoch-zero сессия теперь сразу публикует initial server-to-client CID в
`UdpActiveEgress`, поэтому writer с первой post-auth записи рассчитывает PMTU/recordizer budget для
13-байтового roaming header. AuthOK и его cached retransmit намеренно сохраняют legacy 4-byte QUIC
framing: клиент должен получить AuthOK до того, как узнает session id для вывода обоих directional
CID. Ingress owner отклоняет любой routed CID, пока не отправлены все фрагменты AuthOK и не
опубликован `auth_ok_sent`; ранний candidate не может обогнать epoch-zero bootstrap. Default и
non-negotiated wire остаются неизменными.

Candidate validation теперь независимо ограничена на уровне профиля. Candidate живёт фиксированные
10 секунд, профиль хранит не более `min(max_clients, 1024)` candidates, а скользящее секундное окно
admission допускает не более 64 новых candidates. Идемпотентный повтор того же authenticated
PATH_INIT увеличивает только bounded ingress accounting: он не продлевает TTL и не расходует новый
rate slot. Истёкшие tickets отклоняются до egress/commit, а существующий maintenance tick удаляет
молчащие candidates. Commit, abort, CID collision, session teardown и expiry точно обновляют общий
счётчик.

Cross-listener IPv4→IPv6 regression теперь направляет future CID с чужого receiving worker к
неизменяемому codec owner, коммитит точные candidate socket/family и PMTU generation, а затем
проверяет возврат post-commit ingress тому же исходному owner.

Общий клиентский state machine теперь владеет directional CID derivation/rotation, next epoch,
корреляцией platform candidate и CONTROL_V2 message id, а также полной последовательностью
`PATH_INIT → PATH_CHALLENGE → PATH_RESPONSE → PATH_COMMIT/PATH_ABORT`. Нулевой challenge,
неверные CID/epoch/direction, параллельный candidate и stale platform completion отклоняются
fail-closed. Точный повтор challenge идемпотентно повторяет response. Повторная отправка ограничена
четырьмя datagrams с интервалом 500 мс внутри того же фиксированного десятисекундного lifetime, что
и server candidate. Полученный wire commit остаётся только предложением: active epoch/CID не
меняются до подтверждения платформой `COMMIT_PATH`, поэтому поздний completion после ABORT не может
опубликовать старый путь. Восемь focused-тестов фиксируют эти инварианты; strict feature Clippy и
полный feature library suite (943 passed, три ignored) проходят.

Общий клиентский wire-слой теперь формирует полный конверт `CONTROL_V2 → PacketCodec →
eight-byte CID` и разбирает authenticated packets через единое session replay window. Обычные data
остаются data, а помеченный `PATH_*` обязан быть полным одночастным control без flags. Поэтому
Android, Apple и desktop adapters не могут получить разные CID/control grammar. Round-trip,
разделение data/control, запрет fragmented control и replay закреплены тестами.

Платформенный transport-контракт теперь называется нейтрально `PathController`. Общий Unix UDP
candidate dialer создаёт отдельный unbound socket, ждёт ACK `BIND_SOCKET` именно этого candidate и
только затем подключает первый family-compatible адрес, разрешённый через данный PathUpdate.
Linux-тест фиксирует одинаковый bind-before-connect порядок для TCP и UDP.

Общий client actor теперь создаёт roaming state epoch 0 сразу после AuthOK и атомарно выбирает один
post-auth framing snapshot. Обычные data, DATA_FRAG, recordizer output, heartbeat/cover,
authenticated reports, startup/live PMTU probes и ACK обоих направлений PMTU используют этот
snapshot. Roaming ingress требует точный server-to-client CID до расходования PacketCodec/replay
state; egress использует client-to-server CID. DATA_FRAG и PMTU budgets вычитают фактический
13-байтный roaming header вместо девятибайтного legacy header. Legacy masked/unmasked wire остаётся
byte-for-byte совместимым. Три focused-теста фиксируют passthrough, legacy compatibility и отказ
при CID неверного направления.

Под `experimental-roaming` live UDP actor теперь получает подготовленный `PathUpdate`, выполняет
точный BIND-before-connect через общий Unix candidate dialer и запускает для candidate отдельный
bounded receive pump. PATH_INIT и ограниченные повторы используют общий PacketCodec; только
аутентифицированные PATH_CHALLENGE/PATH_COMMIT/PATH_ABORT с точными CID, message id и epoch могут
изменить state machine. После peer PATH_COMMIT actor сначала ждёт точный ACK платформенного
`COMMIT_PATH`, затем одной actor-транзакцией публикует новый socket, receive pump, directional CID
framing и консервативный family-aware PMTU/record budget. Уже поставленные в очередь пакеты старой
epoch отклоняются, а candidate DATA не становится active до публикации новой epoch. Истечение,
ошибка send, peer abort и teardown освобождают socket и выполняют точный platform ABORT. Поскольку
сервер уже переключился к моменту получения PATH_COMMIT, любая локальная ошибка после него
fail-closed завершает actor для полного reconnect, а не оставляет ложный старый путь. Focused-тест
фиксирует переход receive-классификации candidate → active и отказ старой epoch; strict default и
feature Clippy, default suite 871 passed/1 ignored и feature suite 952 passed/3 ignored проходят.

`UDP_ROAM_V1` теперь включается в `experimental-roaming` для всех UDP camouflage modes, когда сервер
рекламирует тот же бит, аутентифицирован `DATA_FRAG_V1`, а платформа даёт полный `ROAMING_PATH`.
Linux и Android больше не имеют отдельного QUIC-only platform gate. Live-матрица
QUIC/fake-TLS/obfs/obfs+AWG прошла 4/4 режима и 68/68 проверок, сохранив PID, TUN и authenticated
session без top-level reconnect. Fixed-source, legacy peers и default-сборки сохраняют прежний
reconnect. Исходный двухмаршрутный Linux UDP+QUIC
netns e2e прошёл 17/17 с выключением старого пути без замены PID/TUN или top-level reconnect;
парный rollback-сценарий прошёл 20/20 с blackhole только candidate-пути B, bounded expiry,
exact platform ABORT, сохранением carrier `/32` на A, PID/TUN и трафика без reconnect.
Трёхмаршрутный supersede-gate прошёл 24/24: B пересёк BIND/PATH_INIT, затем exact ABORT старого
candidate предшествовал PREPARE C, а actor не принял поздний proof B и опубликовал ровно один C.
Первый adversarial race-срез завершён. Общий client state machine отвергает поздние challenge/commit
старого message id после ABORT и не позволяет stale platform completion изменить replacement.
Path transaction теперь заменяет без ABORT только действительно незабранный PREPARE: незабранный
BIND уже означает применённый PREPARE и проходит exact ABORT. После начала COMMIT последний новый
PathUpdate ждёт linearized ACK, а не отменяет команду, поскольку сервер уже мог переключить путь.
Linux in-process executor сериализует emit/consume/OS mutation, поэтому concurrent detector не может
украсть BIND/COMMIT event. Детерминированный live commit-race прошёл 24/24 с exact B→C order, двумя
однократными commit, неизменными PID/TUN и без reconnect. Первый packet-loss-срез также завершён:
fixed-length firewall gate отбросил ровно первые PATH_CHALLENGE и PATH_COMMIT, свежие зашифрованные
повторы восстановили оба обмена, а live gate 18/18 сохранил PID/TUN и опубликовал один commit.
Симметричный и асимметричный Linux IPv4 PMTU-срезы завершены. Negotiated bare PMTU-control
обрабатывается до PacketCodec decode только после разрешения directional CID в сессию и точного
совпадения committed epoch, receiving socket и peer; candidate-путь по-прежнему принимает только
authenticated PATH-control. На epoch 0 оба направления сертифицировали payload budget 1461 байт.
Двунаправленный carrier MTU 1280 пересертифицировал оба направления до 1161, сохранил внутренний
TUN MTU 1400 и передал payload 1350 через DATA_FRAG. В асимметричном gate C2S остался 1461, а
S2C-only blackhole 1280 заставил сервер спуститься по тому же общему ladder до 1161; reverse payload
1350 прошёл через DATA_FRAG. Один exact pending marker удерживается на всём спуске, поэтому duplicate
report не запускает второй scheduler, а смена epoch/peer отменяет старый.
Linux IPv4 срез in-flight receive-drain также завершён. После PATH_COMMIT точный непосредственно
предыдущий epoch/peer/socket/CID остаётся только принимающим на один DATA_FRAG reassembly timeout;
control и PMTU старого пути отклоняются, а по expiry освобождаются прежние receive task/socket snapshot.
Детерминированный gate 26/26 применил MTU 1280 и трёхсекундный gap-reorder в обоих направлениях
старого пути A, закоммитил B при двух неполных записях по 1350 байт, затем завершил обе записи через
ограниченный drain. Duplicate DATA_FRAG на активном B остался идемпотентным, PID/TUN сохранились,
reconnect не возник. Linux outer-family срез также завершён: dual-listener gate 32/32 перенёс одну
authenticated session IPv4 → IPv6 → IPv4, сохранил codec owner/PID/TUN, пересертифицировал оба
направления 1461 → 1341 → 1461, передал DATA_FRAG-sized пакет и удалил stale qeli-owned route после
каждого commit. Непрерывный трафик сохранил не менее 245 из 260 ping без top-level reconnect.
Deliberate DATA_FRAG-loss срез также завершён: gate 25/25 отбросил по одному полноразмерному фрагменту
в каждом направлении при сохранённых хвостах записей, закоммитил путь B с обеими незавершёнными
reassembly и после пятисекундного timeout и удаления пути A завершил новые фрагментированные записи
в обе стороны. PID/TUN и authenticated session не изменились, reconnect не возник. Детерминированный
Linux same-network NAT dead-mapping срез также завершён: stateless-translation gate 21/21 изменил
только наблюдаемый сервером внешний peer, сохранил неизменными путь клиента/PID/TUN/session, после
authenticated RX silence выпустил один `SameNetworkNatFailure` update и закоммитил один candidate
без новой AUTH или reconnect. Policy request/wait/grace/fallback теперь является общим Rust-state;
platform controllers предоставляют только bounded hook snapshot того же пути и сохраняют ownership
update id. Остаются real-device NAT rebinding и soak.
Linux/OpenWrt adapter этапа 4 теперь получает из общего core ordered-проекцию только family-compatible кандидатов:
должна существовать хотя бы одна пара local/resolved одного семейства, а первый неподходящий
AAAA/A не скрывает следующий пригодный адрес. Native runtime Android/Windows/macOS/iOS теперь
делегируют получение prepared candidate, запросы BIND/COMMIT/ABORT, завершение correlated ACK
и отмену одному общему Rust `CorePathController`. Linux in-process adapter теперь использует
тот же контроллер и общее bounded-состояние `ClientCore`: он исполняет PathCommand вне core-lock,
коррелирует ACK и немедленно обрабатывает обязательный ABORT, не удаляя из очереди посторонние
lifecycle-события. Source-complete read-only PREPARE требует, чтобы каждый carrier разрешался через
точную пару
`from <source> oif <interface>`, а FIB должен вернуть тот же физический интерфейс. Изолированный
netns regression подтвердил, что source bind вместе с `SO_BINDTODEVICE` выбирает candidate
default route несмотря на активные туннельные `/1` и старый carrier `/32`; временный маршрут
или policy rule до аутентифицированного proof не нужен. Затем примитив candidate socket применяет
`SO_BINDTODEVICE` для валидированного interface index и bind адреса того же семейства (включая
scope для IPv6 link-local). Примитив COMMIT теперь выполняет ownership preflight полного набора
адресов до мутации: совпадающий операторский маршрут остаётся чужим, конфликтующий отклоняет
commit, а `replace` разрешён только для маршрута из journal qeli. После каждого `add/replace`
выполняется обычный source-aware FIB lookup; ошибка следующей IPv4/IPv6 семьи восстанавливает
предыдущие маршруты в обратном порядке. После проверки нового пути COMMIT удаляет только прежние
qeli-owned carriers, которых нет в desired family-set; ошибка очистки откатывает новый маршрут и
восстанавливает уже снятые старые маршруты вместе с ownership journal. Активный pin отделён от
generation-scoped discovery A/AAAA: альтернативы доступны только будущей authenticated candidate-
транзакции и заранее не попадают в активный bypass или bonded-набор. Все TCP wire-mode
(`reality-tls`, `obfs`, `fake-tls`, `plain`) уже создают отдельный unbound candidate-сокет,
получают BIND ACK до connect и используют только первый совместимый адрес данного PathUpdate.
После authenticated JOIN COMMIT сначала применяет маршруты, затем переключает закреплённый
набор carrier-адресов для последующих bonded-streams. Непривилегированный тест доказывает,
что dialer игнорирует недоступный адрес конфига в пользу candidate-адреса и связывает сокет
до connect. Linux network detection, capability activation и начальная live-приёмка завершены;
Linux IPv4 packet delay/reorder/duplicate, in-flight receive-drain, outer-family PMTU round-trip и
deliberate DATA_FRAG-loss приняты live-gate; детерминированный Linux same-network NAT dead mapping
принят в netns. Остаются Windows/macOS/iOS device/race-приёмка, real-device NAT rebinding и soak.

- Linux UDP real-device NAT rebinding и soak;
- Windows/macOS/iOS device/race-приёмка, конфигурация/rollout и полная platform matrix;

Результат: безопасный feature-gated UDP роуминг прошёл Linux live success/rollback/supersede,
commit-race, control-loss/replay, PMTU, receive-drain/reorder/duplicate, outer-family,
deliberate DATA_FRAG-loss и same-network NAT dead-mapping приёмку.

### Этап 4. Платформы — 🟡 Linux/Android live, Windows/macOS/iOS executors source-complete

- Linux/OpenWrt in-process TCP: detector/capability/live netns и общий exit-node gate готовы;
  TCP прошёл 35/35, а `quic`, `fake-tls`, `obfs` и `obfs-awg` — по 35/35 каждый;
  real-device/soak впереди;
- Android TCP: exact Network DNS/bind/protect, PREPARE/BIND/COMMIT/ABORT, stale/supersede guards,
  Wi-Fi↔cellular и sleep/wake emulator live готовы; real-device/race/soak/NAT rebinding впереди;
- Android UDP: тот же exact-Network transaction включён для fake-TLS/QUIC/obfs/AWG; общий Rust core
  через ABI 1.13 запрашивает same-network NAT snapshot без Android retry policy. Полная API 34
  feature-APK matrix для fake-TLS/QUIC/obfs/AWG закрыта для same-Network, same-session NAT rebind
  без AUTH/reconnect; real-device NAT-rebinding впереди;
- Windows: общий core сохраняет 64-битный `SOCKET` и запускает ту же TCP/UDP migration state
  machine; C# executor реализует routes, kill switch/WinDivert allow-set и bind через
  `IP_UNICAST_IF`/`IPV6_UNICAST_IF`. Capability включается для обычных TCP и всех UDP profiles;
  default/старое ядро и явные `local`/`lport` используют reconnect. Device/race acceptance впереди;
- macOS: C# executor реализует exact `RTF_IFSCOPE` candidate routes, bind fd через
  `IP_BOUND_IF`/`IPV6_BOUND_IF`, old+new/new-only PF-транзакцию и переключение Qeli-owned обычного
  host route для будущего ремонта bonded TCP. Обычный TCP и все UDP profiles используют общий
  Rust state machine; default/старое ядро и явные `local`/`lport` используют reconnect.
  Cross-build и managed self-tests готовы; device/race/PF/per-app/sleep/soak acceptance впереди;
- iOS: `NWPathMonitor` наблюдает только физические пути, path-scoped UDP `NWConnection` получает
  effective local/remote endpoint после DNS/NAT64, PREPARE держит точные old+new `/32`/`/128`
  NetworkExtension `excludedRoutes`, BIND применяет `IP_BOUND_IF`/`IPV6_BOUND_IF` и source address
  к borrowed fd, COMMIT сужает маршруты до new-only, ABORT возвращает old-only. Обычный TCP и все
  UDP profiles используют общую Rust-транзакцию; явные `local`/ненулевой `lport`, default/старое
  ядро и unsupported peer используют reconnect. Feature Rust slice прошёл strict
  `aarch64-apple-ios` cross-target Clippy; Xcode 16 compile и real-iPhone Wi-Fi/cellular, wake,
  NAT64, rollback, per-app/MDM и soak acceptance впереди.

Каждая платформа проходит prepare/bind/commit/rollback тесты до включения capability.

### Этап 5. Конфиги, приложения и панель — 🟢 source-complete

- flat-INI parsing/defaults/validation/round-trip;
- GUI editors и встроенные quick-start режимы;
- API/dashboard/metrics/logging;
- русская и английская документация;
- install/deb/examples в /etc/qeli.

Flat-INI defaults/validation, все Rust/Kotlin/C#/Swift модели, non-default `qeli://` share
и основной RU/EN config reference реализованы. Общий fixture фиксирует `required` round-trip
и отказ от неизвестного значения. Все четыре редактора Windows/macOS/Android/iOS явно предлагают
`Автоматически / Обязательно / Отключено`, сохраняют выбор через общую платформенную модель и
отклоняют `required` при скрытом source pin. Серверная панель/API показывает профильный
default-off rollout switch, grace period и ограниченные бюджеты ожидающих сессий/памяти. Read-only
control/status и transport-aware dashboard показывают worker-lifetime попытки, commit, финальные
ошибки, TCP grace expiry и ожидающие пути без идентификаторов/секретов. Каждый поставляемый
серверный профиль явно сохраняет безопасные default-off бюджеты, а каждый клиентский шаблон
явно выбирает `auto`, включая installer multiprofile, Reality release, Keenetic и OpkgTun.

### Этап 6. Лаба, soak и rollout

- полный transport/family/platform matrix;
- длительные flap, suspend/resume и NAT rebinding;
- canary профили;
- staged enablement;
- проверка fallback на legacy peers.

Live netns-матрица реальных бинарников 0.8.0↔0.7.14 прошла 24/24 проверки для TCP и UDP.
Current-server/legacy-client и legacy-server/current-`auto` создают TUN, передают трафик и
выполняют ровно одну полную AUTH без входа в roaming. Current-`required` с legacy server при
повторных попытках остаётся до TUN и полной AUTH. Репрезентативный Linux TAP gate прошёл TCP
fake-TLS 17/17 и UDP QUIC 19/19 с сохранением того же TAP, процесса и authenticated session;
повторный default-TUN gate прошёл те же 17/17 и 19/19. Harness сверяет фактический kernel kind,
а оба типа устройства используют одну TCP/UDP roaming state machine. Открытыми остаются полный
10k и платформенные gates.
TCP harness дополнительно закрывает `max_streams=1`, fixed и adaptive bonding. Live regression
воспроизвёл black-hole: после переноса slot 0 старые secondary writers продолжали принимать
flow-pinned пакеты на исчезнувшем пути. COMMIT теперь закрывает весь старый carrier set, а общий
stable-slot maintainer восстанавливает изученную ширину через новый route. Single прошёл 17/17,
fixed 21/21, adaptive 22/22 после роста до трёх потоков под реальной tunnel-нагрузкой;
восстановленные secondary JOIN пришли с path B, TUN/сессия сохранились без reconnect. Feature
suite прошёл 973 теста при трёх ignored, strict feature/default Clippy прошёл.

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
- reset IPv4→IPv6 и IPv6→IPv4 — ✅ Linux dual-listener netns;
- asymmetric C2S/S2C PMTU — ✅ Linux IPv4 netns; outer-family round-trip — ✅ Linux netns;
- fragments в момент drain — ✅ Linux IPv4 netns, оба направления;
- reorder/duplicate — ✅ Linux IPv4 netns; conflict/expiry — ✅ bounded core unit;
  deliberate DATA_FRAG loss и device/soak gates остаются;
- неизменный inner TUN MTU при DATA_FRAG_V1.

### End-to-end матрица

- inner IPv4, IPv6, dual-stack на outer IPv4 и IPv6;
- TUN и TAP — ✅ representative Linux TCP fake-TLS 17/17 и UDP QUIC 19/19 для обоих типов,
  с проверкой фактического kernel `tun_flags` и сохранения экземпляра устройства;
- все TCP режимы;
- UDP fakeTLS/QUIC/obfs/AWG с DATA_FRAG;
- max_streams 1, fixed и adaptive — ✅ Linux TCP single 17/17, fixed 21/21 и adaptive 22/22;
  adaptive вырос до трёх потоков под реальной нагрузкой, а fixed/adaptive восстановили secondary
  slots с path B без замены TUN/сессии или reconnect;
- full/split/per-app routing;
- kill switch, Trusted Wi-Fi и жёсткий local pin;
- reconnect false и persist_tun;
- NAT rebinding без смены интерфейса;
- sleep меньше и больше grace;
- A/AAAA reorder и DNS64/NAT64;
- legacy peer fallback — ✅ source regression для TCP/UDP, absent trailer и pre-`AUTH_EXT_V1`;
  ✅ live 0.8.0↔0.7.14 netns-матрица прошла 24/24 проверки: совместимые TCP/UDP пары выполняют
  одну полную AUTH и передают трафик без roaming, а `required` с legacy server остаётся до TUN/
  полной AUTH при повторных попытках;
- отрицательный тест multi-process/multi-node — source harness направляет path A в исходный процесс,
  а path B в независимый процесс с теми же identity/users, но отдельным registry; foreign JOIN
  обязан получить unknown locator без commit, после чего потеря A должна привести `auto` к full
  reconnect, второй AUTH и рабочему трафику через B. Live gate прошёл 26/26 на неизменном бинарнике:
  двусторонний TCP RST детерминированно зафиксировал потерю carrier на клиенте и исходном сервере,
  после 30-секундного resume budget supervisor выполнил full AUTH во втором процессе, заменил tunnel
  host-route `10.88.0.2/32` на `10.89.0.2/32`, установил bypass через path B и восстановил трафик без
  foreign roaming commit.

Soak: не менее 10 000 смен пути для одного representative TCP и одного representative UDP режима
с контролем памяти, fd, sockets, routes, firewall rules, CID aliases и orphaned sessions. Остальные
UDP wire adapters проходят по 1000 последовательных смен каждый: они используют тот же UDP actor,
поэтому повторять полный 10k для каждой camouflage-обёртки не требуется. Допустимая регрессия
throughput/CPU на включённом роуминге — не более 3–5% относительно того же транспорта без него.
Конфигурируемый same-session harness теперь по умолчанию выполняет 10 000 последовательных A↔B
commit для отдельного TCP или UDP запуска. Он контролирует PID/TUN, AUTH/reconnect,
exact route, независимые client/server commit, все fd, отдельное число socket-дескрипторов и sampled
RSS. Sockets ограничены baseline + 2 финально и baseline + 8 на выборках. Агрегаты control socket:
TCP требует точные attempts/commits, одну session и ноль failures/grace/orphaned state; UDP — точные
attempts/commits, одну session, ноль failures/candidates и три CID aliases после первого commit.
Ни сами CID, ни locator/proof через этот интерфейс не раскрываются. UDP all-modes wrapper передаёт
один выбранный case, включая `soak`, через QUIC, fake-TLS, obfs и obfs+AWG. Smoke на 100 TCP-миграций и
по 100 миграций во всех четырёх UDP wire modes прошли с сохранением одной аутентифицированной
сессии, исходных PID/TUN, точных client/server commit и fd 14/10; полный 10k и platform gates
остаются открытыми.
Старый диагностический TCP 10k прошёл все functional/fd проверки, но превысил RSS budget 32 MiB.
Кодовый аудит нашёл lifecycle-причину: 2–3 завершённых Tokio task handles каждого заменённого
carrier оставались в generation registry до полного teardown туннеля. Регистрация следующего
carrier теперь удаляет только `is_finished()` handles; активные и ещё закрывающиеся задачи остаются
доступны teardown. Async regression фиксирует bounded registry; полный 10k исправленного
release+jemalloc бинарника теперь также прошёл live gate.
Server-resource probe TCP/UDP soak также исправлен. Старый
`ip netns pids ... | head -n1` выбирал supervisor `qeli server`, хотя fd, sockets и RSS настоящего
data plane принадлежат дочернему `qeli _worker`. Живой аудит показал 10 fd, 3 sockets и около
22 MiB у ошибочно измеряемого supervisor против 16 fd, 6 sockets и около 57 MiB у worker. Общий
probe теперь требует ровно один PID с тем же canonical executable, ролью `_worker` и точным
аргументом `-c/--config` текущего server.conf. TCP и UDP также закрепляют start ticks клиента и
worker из `/proc/<pid>/stat`, поэтому исчезновение, неоднозначность или PID reuse дают fail-closed.
Linux contract matrix прошла 4/4, helper и оба soak case прошли ShellCheck. На фиксированном SHA-256
`b8add83126dd1b6c608fa6288b7d227bf377ff3d27ce577db2dab5e114b265dc` исправленный representative
TCP fake-TLS 10k прошёл 15/15 с client/server fd 13/16, sockets 4/6, sampled RSS
47 284/57 764 KiB и нулевым orphan state. Исправленный representative UDP QUIC 10k прошёл 15/15
с fd 14/16, sockets 5/6, sampled RSS 37 176/70 896 KiB, нулём candidates и тремя CID aliases.
Во всех 20 000 representative commit сохранились исходные client/server worker PID, TUN и одна
аутентифицированная сессия без reconnect; SHA совпал после обоих gate.

Tiered UDP adapter matrix на том же SHA также завершена: fake-TLS, obfs и obfs+AWG прошли по
1000/1000 commit и 15/15 проверок каждый. Их финальные client/server sampled RSS составили
43 388/66 596, 45 316/68 412 и 35 844/78 288 KiB соответственно; fd остались 14/16, sockets 5/6,
candidates — 0, CID aliases — 3. Общий `CORRECTED_WORKER_UDP_SHORT_ALL_PASS` получен, фоновый PID
завершился, а тестовые network namespaces удалены.
Отдельный TCP performance gate теперь переиспользует тот же netns runner и бинарник для baseline
с `roaming=off` и согласованного `roaming=required`. Он берёт настраиваемые медианы нечётного числа
замеров upload, download и суммарного CPU qeli client/server и по умолчанию отклоняет относительную
регрессию больше 5%. Policy overrides принимаются только case `perf`, поэтому success/soak нельзя
случайно понизить до reconnect. Live gate на отдельной lab `.11` прошёл на фиксированном SHA-256
`b8add83126dd1b6c608fa6288b7d227bf377ff3d27ce577db2dab5e114b265dc`: baseline `off` дал медианы
518/648 Мбит/с upload/download и 160.255% суммарного CPU, а `required` — 528/648 Мбит/с и 161.131%
CPU. Оба варианта прошли 10/10 функциональных проверок без reconnect, итоговое сравнение — 3/3 при
бюджете 5%. TCP 10k продолжался на отдельной `.10`, поэтому два gate не разделяли CPU, namespaces
или процессы.
Единый `roaming_resource_release_gate.sh` закрепляет fail-closed порядок resource-приёмки на одном
неизменном бинарнике: TCP/UDP all-mode smoke, TCP resume/grace, TCP 10k, representative UDP QUIC
10k, UDP fake-TLS/obfs/obfs+AWG по 1k, performance и multi-node fallback. SHA-256 проверяется до и
после каждого этапа, а его PASS-маркер печатается
только после нулевого exit code. Любая ошибка или замена бинарника запрещает запуск последующих
этапов; contract-тесты фиксируют порядок, hash pin и отсутствие ложного финального PASS.
Короткие фазы повторно прошли fail-closed на одном исправленном бинарнике SHA-256
`b8add83126dd1b6c608fa6288b7d227bf377ff3d27ce577db2dab5e114b265dc`: TCP smoke — 6/6 режимов
(`reality-tls` 21/21, остальные по 17/17), UDP smoke — 4/4 по 19/19, hard resume и grace-expiry —
по 18/18, multi-node fallback — 26/26. SHA совпал после каждой фазы; после финала процессы и
network namespaces теста отсутствовали.

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

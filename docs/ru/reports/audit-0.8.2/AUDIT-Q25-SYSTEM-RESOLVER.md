# Q25-F103: ожидание системного DNS и остановка клиента

24 сентября 2026. База `c8b4cccf`. Частичное закрытие D05/D09; общий transport core и Linux-клиент.

## Дефекты и исправление

Kill-switch синхронно вызывал системный DNS/NSS. Его 15-секундный бюджет отвергал
поздний ответ, но не ограничивал ожидание самого вызова и не позволял отменить его
через сигнал остановки. В подключениях/UDP-диагностике `tokio::net::lookup_host`
переносил NSS в blocking pool: отмена async future не завершала этот вызов, а
уничтожение runtime могло ждать его неограниченно. Прежний `shutdown_timeout(50 ms)`
в диагностике обходил ожидание, но не ограничивал накопление зависших DNS-потоков.

Новый модуль `transport_core/resolver` обслуживает kill-switch, Linux TCP/UDP,
системный fallback native-адаптеров и UDP-диагностику. Общий semaphore допускает
максимум четыре незавершённых NSS-вызова. Ожидание слота входит в срок запроса;
поток получает permit до запуска и удерживает его до фактического завершения,
включая отменённый запрос. Поздние ответы отбрасываются. Числовой IP обходит очередь,
но не проверку истёкшего срока; адреса от платформенных адаптеров сохраняют приоритет.

Это отдельные ограниченные `std::thread`, не blocking pool runtime. Работник владеет
только входом DNS, permit и каналом результата; у него нет сетевых callback или
владельцев firewall/routes/TUN. Linux наследует контекст создающего потока.
Kill-switch закрепляет свой контекст до DNS и повторно проверяет его перед мутациями.
Бюджеты setup/refresh и безопасное поведение ошибок firewall сохраняются.

Реальное сравнение выявило дополнительный пробел: Linux без kill-switch вообще
не проверял stop token до завершения начального carrier connect. Добавлена отмена
этой фазы для TCP/UDP, до применения NetworkPlan. Уже созданные TCP/H2 задачи
остаются у TaskGroup и завершаются через обычный join. Отмена не оборачивает
синхронную сетевую транзакцию в detach/timeout. Конфиги остаются INI; ABI не менялся.

## Проверка

Новые регрессии: **9 обычных + 1 privileged** — IP/localhost, работа соседней задачи
на current-thread runtime, timeout/admission, удержание слота после отмены, отказ от
позднего результата, ошибка/panic worker, уничтожение runtime, отмена до/во время
carrier connect и наследование NET/mount namespace. Контрольная замена worker на
`spawn_blocking` воспроизводит отказ теста завершения runtime (exit 101); исходный
resolver в отдельном контрольном crate даёт PASS. Рабочие исходники не изменялись.

`audit_system_resolver.py` задерживает выбранный `getaddrinfo` на 45 секунд через
test-only LD_PRELOAD, только для `qeli-audit-delay.invalid`. Проверяются setup и refresh
kill-switch, начальные TCP и UDP без kill-switch. **4/4 baseline не остановились за
3 секунды** и были завершены тестом через SIGKILL. **4/4 fixed завершились с exit 0
за 0,003–0,165 секунды**, сохранили исходные operator firewall/routes, не оставили
журналы или TUN. Это измерение данных сценариев, не общий SLA.

Финальная матрица использует `qeli-matrix.test` через настоящий NSS и приватный
`/etc/hosts`: IPv4=nft/IPv6=legacy без firewalld и IPv4=legacy/IPv6=nft с реальным
приватным firewalld. **38/38 сетевых ячеек, 34 SIGKILL/recovery,
1220 основных утверждений и 806 вложенных проверок PASS**.
Все **1088** прямых UDP-попыток под защитой заблокированы: EPERM,
рост DROP-счётчиков, ноль полученных пакетов. Все **656** разрешённых
проб получили ответ. Вложенные проверки не добавляются к числу независимых тестов.
TCP/UDP/QUIC, обе семьи carrier/tunnel, split, TAP, DNS A/AAAA и MTU/PMTU/PTB сохранены.

Host: **1537 unit + 71 config integration**, все 9 feature/cross/lint проверок PASS.
Linux: **2089 обычных + 44 privileged + 8 worker lifecycle PASS**. Python compilation,
bash syntax и 8 contract-тестов матрицы PASS. RU/EN документация проверена отдельно.

Первый native-прогон сохраняется как evidence: DNS-потоки уже были ограничены, но
TCP/UDP без kill-switch ещё не реагировали на stop; эти два FAIL не считаются PASS.
Именно они привели к исправлению начального carrier connect. Матрица v1 проходила
на промежуточном бинарнике; приведённые выше итоги относятся к финальному **v2**.

## Evidence и границы

Стенд `.11`, изолированные NET/mount/PID; работающий `.10` не изменялся.
Проверены хеши всех 343 Rust/conformance файлов и 17 сценариев.
Worker SHA256: `effe784cc0bd6a1d40c2feff90eea9aa7c0f6da1bf85aadd74f79d7446b8602a`.
Source archive SHA256: `b0808c29bf5fe336ff5a378689492bda0305bc13be69d51c50785ce3a7e0d6af`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/resolver-budget-phase/`,
`resolver-shutdown-v2/`, `resolver-hostname-matrix-v2/`, `resolver-counterfactual-v1/`,
`lifecycle-resolver-budget-v2/` + `.tar.gz`; logs/exits: `resolver-linux-final-v2`,
`resolver-shutdown-v2`, `resolver-hostname-matrix-v2`, `resolver-counterfactual-v1` (`.log/.rc`).
Commands: `run_checks.py`, `linux-final-v2.sh`, `resolver-repro-v2.sh`,
`hostname-matrix-v2.sh`, `counterfactual.sh`; manifests/results: `evidence.json`,
`linux-source-final-manifest.json`, `scripts-manifest.json`.
Matrix archive SHA256: `706a2fca29117c33545e3e713225fd668bf2d84e060808c2771076aa038108e4`.
Shutdown archive SHA256: `56e5ab1fcfc9eb3983ceae877a7970d6b8f4359ec0e8d0d730b0141e6d3c21a7`.

Сам libc/NSS нельзя безопасно принудительно прервать. Зависший вызов удерживает
поток, слот и унаследованный контекст до завершения; четыре таких вызова блокируют
новые hostname-запросы до их собственного срока. Числовые адреса продолжают работать.
Это ограничение ресурсов и ожидания, а не обещание успешного DNS или общего срока
всего подключения/остановки. Серверный notification DNS — отдельный путь, он здесь
не переводился на клиентский резолвер.

D05 остаётся **IN_PROGRESS**: синхронные мутации DNS/routes/gateway/kill-switch,
внутренние locks/I/O и цельный срок NetworkPlan/shutdown требуют отдельного переноса
с сохранением ownership. D06/D10/D13 также не закрыты этой фазой. Бенчмарк,
certification и поставляемые платформенные бинарники не обновлялись. Windows VM,
Mac/iOS и physical-router runtime остаются **SKIPPED по решению пользователя**.
Итог техдолга: **4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO**.

[Реестр](../../plans/AUDIT-DEBT.md) · [Мануал](../../manuals/CONFIG.md#kill-switch-kill_switch).

Продолжение: [Q25-F104](AUDIT-Q25-RESOLVER-FILES.md) переносит чтение DNS-файлов до firewall, делит ограниченную очередь с NSS и объединяет reader/parser с проверкой stub. Исторические результаты выше не изменены.

Продолжение: [Q25-F105](AUDIT-Q25-NETWORK-TASK.md) переносит применение NetworkPlan и откат непринятого результата в присоединяемый поток. Штатная очистка активного туннеля остаётся отдельным D05; исторические результаты выше сохранены.

# Q34: зависимости Rust, политика CI и PEM TLS

<!-- normative-sync: q34-dependency-policy-v1 -->

8 октября 2026. Закрыты F451–F454 / Q34-F005–F008 в указанном ниже объёме. Q34 целиком остаётся IN_PROGRESS: 30/37 пунктов полного аудита DONE (81,1%), 7 осталось. Этот пакет не квалифицирует выпуск.

## Найденные проблемы и исправления

| Finding | До исправления | Теперь |
|---|---|---|
| F451 / Q34-F005 | Единственные два вызова `rustls-pemfile` читали PEM панели; crate архивирован, RustSec выдавал RUSTSEC-2025-0134. Cargo.lock также содержал отозванный der0.8.0 | Используется `PemObject` уже подключённого rustls-pki-types1.15.0; wrapper удалён из feature/dependencies/lockfile. der обновлён точечно до0.8.1 |
| F452 / Q34-F006 | CI вызывал только `cargo deny check bans sources`; лицензионной политики не было, metadata ядра не объявляла существующую AGPL-лицензию | `cargo deny --all-features --locked check licenses bans sources`; разрешены необходимые permissive SPDX, исключение AGPL ограничено крейтом qeli. Cargo metadata отражает существующую `AGPL-3.0-only`, лицензии файлов/клиентов не изменены |
| F453 / Q34-F007 | `cargo audit` разрешал предупреждения; версия инструмента устанавливалась без pin | `cargo audit --deny warnings`, cargo-audit0.22.2/cargo-deny0.18.4/Rust1.97.0 закреплены |
| F454 / Q34-F008 | Прежний log fixture не проходил whole-tree rustfmt | Исправлено только форматирование этого теста |

Обновление lockfile удалило rustls-pemfile2.2.0 и заменило der0.8.0 на0.8.1. Все остальные dependency records побайтно/структурно сохранены. По upstream changelog der0.8.0 отозван из-за minimal-versions CI; это не объявленная криптографическая уязвимость. Более новый patch0.8.2 здесь не квалифицирован: данный проход устраняет подтверждённый yank и не заявляет все зависимости последними версиями.

PEM-reader сохраняет лимит4MiB, nonblocking open FIFO, regular-file проверку и поддержку ссылок для ротации сертификатов. Certificate iterator сохраняет порядок цепочки и отказывает на повреждённом следующем блоке; key reader выбирает первый подходящий PKCS#1/SEC1/PKCS#8. Реальная TLS-пара дополнительно проверяется rustls при сборке ServerConfig.

## Реальные проверки

| Проверка | Результат и предел |
|---|---|
| Свежая RustSec DB | Git SHA `5701a6d2a6158d5d4a933df5141a0415c285075d`,1294 advisories. Baseline237 packages:0 vulnerabilities,1 unmaintained+1 yanked. Current236:0 vulnerabilities,0 warnings; строгий gate PASS |
| Лицензии | Baseline standalone gate отклоняет190 requirements при отсутствии allow-policy. Current all-features/locked:0errors/0warnings,211notes. Реальные отрицательные fixtures: сторонний AGPL не получает исключение qeli; неожиданный GPL ядра отклоняется |
| Bans/sources | PASS;20 предупреждений multiple-versions намеренно остаются warnings. Проверка advisories с0warnings не означает отсутствие этих отдельных диагностик |
| Linux debug Rust |10 TLS tests;2445 default library tests PASS,60ignored не запускались;5 CLI tests PASS. Clippy `-D warnings` и whole-tree fmt PASS |
| Features | no-features/client-only/server-only/transport-core-ffi checks PASS.47/1/24 прежних dead-code warnings в урезанных сборках сохранены; это не доказательство неиспользуемости кода в поддерживаемых сборках |
| Release settings | release check без jemalloc ожидаемо отклонён compiler guard; release check с jemalloc PASS. Здесь не собран/не запущен новый Linux release payload |
| HTTPS runtime |14 assertions PASS на настоящем новом CLI: trusted HTTPS/API для auto/reused пары и PKCS#1/PKCS#8/SEC1; операторские bytes сохраняются, auto key0600; private network восстановлена |
| Windows driver files | Две Wintun0.14.1 копии: pinned version/hash/signer/thumbprint/license PASS. Драйвер не загружался, маршруты ОС не менялись |
| Обвязка release/native |70 native и48 release Python tests PASS.67 literal Actions references закреплены SHA/local. Это не проверка runner images/SDK или успешный Actions run |
| Native qualification | Fresh independent A/B4targets/6compiler batches PASS; panic-unwind/jobs1/offline/private targets and per-command caches; exports6realtls+22client(+21JNI Android),14SHA/copies/provenance PASS; fresh Windows C ABI22PASS. Within-own-CargoHome reproducibility only; Mac cross-link missing-SDK warnings retained,physical runtime USER_EXCLUDED. |

Product source `1751a44f686dc2212284b72180bf74a2b9ec06de`. Linux debug ELF SHA256 `ef8c71496f2f13afec52dc62d5ccf3db312e5d727dd15fd7d054ae41ef3b4e3a`,78,756,672bytes. HTTPS загруженный ELF и итоговый сохранённый CLI совпадают по SHA.

## Отказы обвязки и сохранность стенда

Первый formatter run действительно отказал на прежнем logs.rs fixture. Desktop source upload остановлен до компиляции; незавершённый каталог сохранён в verified recoverable archive и удалён после proc/mount guards. Первый полный unit run:2444PASS/1FAIL/60ignored; DNS capacity fixture потребовал больше унаследованных1024 fd (оба конца512 соединений). Повтор с4096 только для test-process:2445PASS/0FAIL/60ignored. Это не изменение системного/service лимита и не скрытый skip. Исходные logs/progress сохранены.

Первый Windows file-signature запуск отказал из-за execution policy, второй — из-за наследованного module path другого PowerShell runtime. Итоговый gate прошёл в штатном системном Windows PowerShell с child-process-only policy/module path; глобальные настройки не менялись. Два внешних native helper прерваны до SSH, чтобы исправить quoting и дождаться исправления fmt; все harness corrections отражены в raw packet.

Linux tests/HTTPS работают в private mount/net/pid namespaces, с private `/etc/qeli`, `/var/lib/qeli`, `/tmp` там, где это необходимо. Cargo/targets/caches принадлежат отдельным каталогам, jobs1/offline после точечного fetch. Исходные .11 service/777/845 и installed ELF75bc сохранены; .10 исходные745/901 сохранены. Перед cleanup: локальный downloaded SHA-verified recoverable archive, затем resolved-prefix/cwd/exe/root/fd/mount guards.

`q34-dependencies-20261008`: SEALED 148 files / 217225967 bytes; manifest SHA256 `9337f372ece61476968f431f7de55f60e2fa8dfc405043cb661ade0f57f926be`.

## Оставшийся объём

Последний [удалённый CI37598403060](https://github.com/litvinovtd/qeli/actions/runs/37598403060) проверял SHA83c07f5c, завершился failure (macos-build/native-libs/ios-build). Текущий exact-SHA admission правильно отказывает по mismatch и failure. Эти результаты не подменены локальными PASS; workflow не запускался и push/deploy/release не выполнялись.

Q34 ещё требует полной сверки остальных зависимостей/SDK/пакетов, подписей текущих release payloads и текущего CI/source-cut в согласованном объёме. Новый Android полный runtime/soak, Mac/iOS runtime, VPN/benchmark и остальные release packages этим пакетом не заявлены. Mac/iOS/router/Windows network VM USER_EXCLUDED; D06 ACCEPTED_LIMITATION; Q29 SIGKILL FAIL/ENONET, Q30 Apple/callback OPEN и Q31 capacity/source-cut/current Actions остаются в прежнем статусе. Старые14 debt DONE и41 certification cases/71 предыдущий supplement сохраняют исторические результаты; новый supplement добавляет только этот scoped packet.

Политика Rust лицензий: [LICENSING](../../../../LICENSING.md),[cargo-deny documentation](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html). Миграция PEM: [RustSec](https://rustsec.org/advisories/RUSTSEC-2025-0134.html).

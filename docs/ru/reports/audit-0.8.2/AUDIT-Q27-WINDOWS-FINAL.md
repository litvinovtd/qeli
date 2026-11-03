# Q27: Windows GUI, служба и драйверы — DONE/PASS в согласованном объёме

5 октября 2026. База `39863933`; Windows, .NET SDK 10.0.300.
**27/37 разделов DONE/PASS (73,0%), осталось 10; следующий Q28.**

<!-- normative-sync: audit-q27-windows-final-v1 -->

## Итог критериев

| Критерий | Evidence и статус |
|---|---|
| Review, конфигурация и мёртвый код | Общий INI/parser/editor контракт Q02/Q26; Windows storage, GUI/service transitions и settings, registration/status/log и driver lifecycle рассмотрены. Удалены старый DLL path shortcut, отдельный LoadLibrary и дублированный filter literal. PASS. |
| Штатные, граничные и негативные сценарии | 325 Windows selftest и 549 shared conformance, без FAIL/SKIP; 52 новые Windows и 6 shared проверок в этом этапе. PASS. |
| Отказы и конкуренция | Partial Open, thread start/receive fault, joined shutdown timeout и retry, native/interop close refusal, concurrent module loading, retained multi-generation gates, journal ordering, failed pre-dispose/TUN Dispose, prewarm readiness. PASS на production paths с injected OS adapters. |
| Доступная интеграция | Реальная загрузка embedded DLL/export/FFI, DPAPI и atomic private files, isolated child processes, read-only SCM/Task Scheduler; Release Windows/shared/Mac compile, signatures/checksums/provenance. PASS в указанном scope. |
| Целевая платформа VM | Реальные Windows adapter/driver open, routes/DNS/firewall/LocalSystem boot/sleep и service reload — **SKIPPED пользователем**, не PASS. Эти результаты не подменены fake adapters. |
| Исправления и повторные проверки | Три предыдущих этапа + этот пакет, 12 контрольных baseline отказов, sealed raw, artifact/source hashes и certification reconciliation. PASS. |

Предыдущие этапы: [storage F222–F224](AUDIT-Q27-WINDOWS-STORAGE.md),
[GUI/control F225–F228](AUDIT-Q27-WINDOWS-CONTROL.md),
[registration/status/log F229–F232](AUDIT-Q27-WINDOWS-OBSERVATION.md).
Их промежуточный IN_PROGRESS — исторический статус. Q27 закрыт по доступным критериям
и согласованным исключениям; это не подтверждение настоящего Windows VPN runtime.

## Находки последнего пакета

| Находка | Исправление |
|---|---|
| Q27-F233: cache trust и неограниченное чтение | Shortcut возвращал ранее извлечённый путь без повторной проверки, disk hash использовал ReadAllBytes произвольного файла. Теперь каждый extraction request проверяет directory/file trust и hash; seekable oversized сразу отказывает, streaming budget — embedded length + sentinel, buffer 64 КиБ. Trusted embedded images кешируются, не доверенные disk paths. Не заявляется новая эскалация через защищённый cache без нарушения его ACL. |
| Q27-F234: DLL reference growth | EnsureDriverLoaded вызывал LoadLibrary при каждом ensure без FreeLibrary. Единственный process-lifetime module cache сериализует загрузку, не кеширует ошибку/нулевой handle, сохраняет DLL для P/Invoke и Rust GetModuleHandle. Это намеренная lifetime reference, не unbounded reference count. |
| Q27-F235: потерянный partial adapter | WinDivert cancellation после Open и Wintun ResolveInterface могли бросить до назначения _tun. Теперь ownership опубликован до throwing stage. Incomplete Wintun prewarm возвращает owned объект для cleanup, readiness запрещает применять его; unused-prewarm cleanup errors не скрываются. |
| Q27-F236: скрытый Dispose в общем слое | CloseTransports и persisted rebuild проглатывали BeforeTunDispose/Dispose, затем забывали TUN. Ошибка теперь останавливает teardown до clear; Stop публикует Error, сохраняет adapter для retry и не снимает guard. Поведение одинаково в Windows/Mac shared C#. |
| Q27-F237: неверный DROP и потерянные gates | DROP был 0x0001 (SNIFF) вместо 0x0002. Исправлен pinned API contract. Закрытие gate проверяется, handle сохраняется при отказе; прежние поколения отслеживаются после replacement. Journal/owner освобождаются после успешного закрытия всех gates. |
| Q27-F238: driver lifecycle | WinDivert закрывал handle до join, игнорировал false join и close errors; Wintun ставил disposed до успешного interop close. Теперь WinDivert Shutdown(BOTH) → общий 2-секундный join budget → synchronized close; timeout/close error удерживает ресурсы для retry. Open/Dispose сериализованы и partial Open откатывается. Wintun close retry сохраняет exact handle/identity. |
| Q27-F239: worker/observer faults | Direct log callback мог прервать Open или packet thread. Observer errors изолированы, worker exceptions завершают packet channel, отказавшая generation не может снова стать tunnel-up. Capture fault проверен на настоящем managed worker с injected receive; native driver open не выполнялся. |

DROP/SNIFF, shutdown BOTH=3, network layer, queue/checksum constants и 80-byte layout
сверены с [официальным заголовком WinDivert 2.2.2](https://github.com/basil00/WinDivert/blob/v2.2.2/include/windivert.h).
Причина F237 следует из кода и API: передавался SNIFF, не kernel DROP; фактический
сетевой транзит на Windows VM не измерялся. Семантика shutdown/queue EOF:
[WinDivert documentation](https://reqrypt.org/windivert-doc.html#divert_shutdown).
Повторная загрузка увеличивает process reference count:
[Microsoft LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw).

Rust Wintun ownership review: independent adapter/session, release packet до Arc session
Drop, EndSession перед CloseAdapter, TunWorkers удерживает потоки до join. Rust/native
source digest и 14 artifacts не изменились; прежний Q22/Q25 runtime scope сохраняется.
Новая native A/B/Linux/JNI/benchmark/soak серия не требуется и не заявляется.

## Проверки и границы

- **325/325 Windows + 549/549 shared PASS**, 0 FAIL/SKIP; Release Windows/shared/Mac
  builds — 0 warnings/errors. Mac compile-only. Все четыре текущие Shared DLL byte-equal.
- Production lifecycle с настоящими managed threads: thread-start faults, pending
  workers, shutdown/close errors, combined Open+rollback error, retry и exact handle,
  receive exception, blocked packet channel, rejection of reactivation. Fake driver
  handles означают проверки ownership протокола, не работающего Windows драйвера.
- Реальные native DLL load/export (включая WinDivertShutdown), bounded streams,
  32 concurrent module ensures, Wintun collisions/readiness/interop close retry,
  retained gates и journal ordering. Пробные DLL extraction используют штатный cache;
  пользовательские profile/settings/service storage и OS networking не изменяются.
- **12/12 baseline ожидаемых FAIL**, exit 1: прежние Dispose/CloseTransports тела с
  injected dependencies, private 8 MiB cache allocation и прежние loader/Open/gate
  решения. Последние являются адаптированными fault models, не запуском старого
  Windows kernel path. Старый false join воспроизведён на реальном managed thread.
- Wintun version/hash/AuthentiCode signer+thumbprint/license PASS для обеих копий;
  WinDivert64.sys Authenticode Valid, thumbprint сохранён в raw. Это не доказательство
  live driver installation/compatibility. PowerShell 5 verification отказал из-за
  отсутствующего Get-FileHash; повтор в доступном PowerShell 7.6.5 PASS, failure сохранён.
  ExecutionPolicy Bypass только в дочернем процессе, системная политика не менялась.
- Docs/panel/generated bindings/native provenance/14 checksums/diff PASS.

Deadline относится к join, не принудительному прерыванию native Shutdown/Close,
Wintun CreateAdapter, SCM/RPC или OS I/O/locks. При отказе требуется Stop retry или
согласованное ручное восстановление; успешный fake close не доказывает OS cleanup.
WintunCloseAdapter — void API: сохраняются наблюдаемые interop exceptions, не
обещается обнаружение всех внутренних driver errors. Cached embedded bytes/module
references живут до конца процесса. Совпадение resource SHA не аттестует уже работающий
чужой service process. Внешнее изменение защищённых файлов администратором и прямой
обход координации storage не поддерживаются. Конфиги INI, internal JSON API/DTO остаются.

Evidence: `release/certification/evidence/q27-windows-final-20261005.json`.
Raw: `audit-debt-20260924/q27-windows-drivers-20261005-r2` (final); прежний raw сохранён отдельно в общем workspace.
Изменения пользователя сохранены, installed services/driver opens/lab/push/deploy не выполнялись.

При pending retirement повторный refresh сначала пытается закрыть прежнее поколение и отказывает до нового native Open при ошибке. Число retained generations ограничено; refinement проверен отдельно, первоначальные 324 PASS и seal сохранены.

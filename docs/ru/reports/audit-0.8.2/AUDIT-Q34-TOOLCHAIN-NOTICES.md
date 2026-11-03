# Q34: notices стандартных библиотек и runtime toolchain

<!-- normative-sync: q34-toolchain-notices-v1 -->

## F473 / Q34-F027

Общий Cargo/NuGet комплект не покрывал notices Rust std и runtime-компонентов
toolchain. Добавлен единственный embedded слой `rust/toolchains`: 65 оригинальных
ресурсов семи component/version групп, 69 файлов /3999768 bytes с метаданными.
Весь native bundle теперь содержит 533 файла /6557892 bytes. Все 462 прежних
Cargo resources/metadata сохранены побайтно; изменены только внешний INDEX/SCOPE.
Политика и maintenance: [LICENSING](../../../../LICENSING.md).

Rust1.97.0, nightly-2026-06-10, compatibility1.89.0 и Zig0.13.0 взяты из четырёх
official tar archives с полным SHA256. 39 installed Rust/doc ресурсов совпали
с official archives. Для каждого Rust сохранены MIT/APACHE, COPYRIGHT-library
и 12 license-pool texts с оригинальной структурой каталогов. Для Zig
сохранены 12 ресурсов libc/musl/MinGW/WASI/libc++/libc++abi/libunwind.
NDK26.3.11579264: три notices из official ZIP совпали с обоими серверами;
квалифицированы также identity/version members. HTTP ranges/ZIP CRC проверены,
полный ZIP SHA256 не заявлен. GCC14.2/MinGW12: пять legal resources из exact Git
commit/tree/blob, фактические dpkg source versions и ownership зафиксированы.

Checker/generator offline, original bytes и пути сохранены, output только новый.
Source catalog и current pins связаны BINDING/index/SHA; missing/extra/corrupt,
consistent-reindex drift и unsafe source отказаны. Общий native checker включает
этот слой; CI требует отдельную toolchain policy проверку. Android Gradle имеет
InputFile для external catalog и сравнивает embedded SOURCES до копирования:
policy drift не скрывается cached legal task. Остальные packaging recipes уже
копируют весь bundle и не требуют отдельных client implementations.

## Проверки и границы

- 47 final-source focused fixtures PASS (16 toolchain,17 native,14 APK).
- Actual final-source offline regeneration:69 toolchain/533 native files byte-identical;65 original upstream resources independently compared. Three Rust HTML documents retain embedded notices and36 companion pool texts, with no relative href/src targets in these exact documents.
- Four actual Release desktop publishes PASS: win-net,win-standalone,osx-arm64,osx-x64. Each contains533 exact native files,187 .NET files and client MPL. Published checker:4 positives,6 missing/corrupt/consistent-reindex stdlib refusals and byte-identical restoration.
- Actual debug/default unsigned R8 release APKs PASS,90 tasks executed, including release lintVital. Each has562 indexed legal assets (533 native),63 Maven archives/76 coordinates/24 embedded notices; existing arm64/x64 JNI SHA unchanged. Four actual APK missing-stdlib/index refusals; downloaded backup APKs independently checked locally.
- Actual cached Gradle legal task:baseline UP-TO-DATE,external catalog reorder invalidates cache and fails with inventory drift,restored PASS;corrupt stdlib refused by checksum,restored PASS. No additional full rebuild needed.
- Actual Debian package/extraction with /bin/true fixture and actual OpenWrt install-body host fixture preserve533 files. Deterministic Keenetic export preserves533 files. These are packaging checks, no install/SDK firmware/router runtime claim. iOS folder resource remains SOURCE REVIEW/USER_EXCLUDED.
- 704 Markdown/9 checks PASS;CI source gate reviewed,text assertions only,no Actions/YAML parser execution. Both labs original services/processes/installed CLI preserved; owned .11 root removed only after recoverable backup SHA and /proc/mount guards. Nativee3/14artifact SHA and protected files unchanged.
- Kotlin deprecation/safe-call and Gradle deprecation warnings remain recorded; assembly/lintVital success does not assert full lint or future Gradle10 compatibility. No Mac/iOS physical,Windows network VM or fresh VPN/device runtime qualification.

Это conservative notices superset, а не per-binary linkage или полная юридическая
квалификация. Extra pool texts не меняют лицензию Qeli. Old native metadata не
pin GCC minor; observed lab sources не доказывают linkage конкретного старого
артефакта/downstream patches. Rust1.89 относится к ранее проверенному OpenWrt SDK
compatibility fixture, immutable published SDK source cut остаётся OPEN.
Matching source publication, dynamic system runtime, MicroCom exact binding,
final-source Actions/signatures/release OPEN. Initial capture/guessed-path harness
FAIL сохранены, не переписаны в PASS. Q29 SIGKILL FAIL/ENONET, Q30/Q31/F459 braces,
D06 ACCEPTED_LIMITATION и USER_EXCLUDED сохранены. Native e3fb/14 artifact SHA и
protected файлы неизменны; нет новой core/native A/B/JVM/device VPN квалификации.
Q34 IN_PROGRESS, полный план 30/37 DONE (81,1%), осталось 7.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-toolchain-notices-20261008`: SEALED 2650 files / 379846049 bytes; manifest SHA256 `f2faf9852b55fd442953779570a95662474dc7e25eefc99c4484b64cbb0a9883`.

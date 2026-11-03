# Q34: .NET notices и лицензия встроенных шрифтов

<!-- normative-sync: q34-managed-notices-v1 -->

## F471 / Q34-F025: общий комплект NuGet/runtime notices

Windows/macOS publish сохранял зависимости, но не имел общего комплекта их
upstream LICENSE/NOTICE/copyright. Добавлен `qeli-shared/third-party-notices/dotnet`:
67 пакетов (63 из35 reviewed lockfiles +4 default runtime packs10.0.12),
187 файлов /4659411 bytes. Сохранены67 original nuspec,65 original archive legal
resources,48 copies of9 reviewed upstream receipts и один decoded font notice.
Это полный reviewed desktop graph superset (Debug/tools/Linux/otherRID), не
утверждение linkage каждого executable. License expressions не переписаны.

67 архивов /358040771 bytes сверены с свежим official NuGet catalog SHA512 и
SHA256. Все67 signed: API NuGet из SDK10.0.401 проверил CMS cryptographic integrity
и contentHash;63 hashes совпали с locks, четыре runtime hashes закреплены в
reviewed TSV. Raw SHA512 signed nupkg не равен contentHash; cache metadata не
используется как доказательство проверки архива. Certificate trust/revocation
не квалифицировались.

Генератор работает offline, требует exact SDK, пишет только новый каталог,
проверяет ZIP paths, nuspec и receipts. SDK-only helper без PackageReferences
собирается вне checkout с пустым packageSources. Validator без SDK/сети связывает
bundle с35 locks, global.json/runtime TSV, проверяет index/SHA/origins/metadata,
missing/extra/duplicate resources и font completeness. Git сохраняет original bytes.
Desktop csproj включает visible Legal/DotNet в single-file и обычный publish.
CI проверяет оба Windows distribution и оба macOS RID; build_app.sh проверяет
оба common bundles и MPL до app assembly. Maintenance: [LICENSING](../../../../LICENSING.md).

## F472 / Q34-F026: Inter имеет отдельную OFL

Avalonia.Fonts.Inter11.3.20 declares MIT для кода, но шесть встроенных TTF имеют
copyright2020 The Inter Project Authors, Version3.019;git-0a5106e0b и SIL OFL1.1.
Все шесть TTF из точного Avalonia nuspec commit984c3b83… сверены по Git blob/SHA;
точные bytes находятся во всех трёх packaged TFM DLL. Сохранены decoded SFNT
name records0/5/13/14 и полный LICENSE.txt из Inter commit0a5106e0bde18df09374066bf3a7998e3546307d.
Это отдельная лицензия шрифта; MIT package expression сохранён без изменений.

## Проверки и границы

- Independent direct ZIP extraction: все67 nuspec/65 archive legal texts и48 exact supplement copies совпадают с bundle; все9 receipts использованы. Font byte/name proof сохранён отдельно.
- 19 focused fixtures PASS: SDK/lock/runtime drift, actual helper result mismatch, unsafe ZIP, missing/extra/corrupt resource, nuspec drift, exact-VCS and unbound receipt refusal. Первичная fixture ожидавшая binding error для invalid empty TSV исправлена; FAIL сохранён.
- Actual generation окончательными helper sources PASS;187 файлов побайтно совпадают при повторной генерации.
- Четыре actual Release publish PASS: win-net, win-standalone, osx-arm64, osx-x64 на Windows host. Каждый содержит187 exact DotNet resources,464 NativeRust и client MPL. Apple runtime/signing не заявлены.
- Final CLI:4 published positives,4 missing/corrupt refusals и отдельный semantic OFL refusal даже при consistent reindexed metadata; restoration byte-identical. Фактические новые shell commands build_app.sh:2 positives/1 missing-index refusal/restored. Это проверка publish-gate, не full signed app execution.
- MSBuild legal target и docs/CI text qualification приведены в raw evidence. Git diff check и документация проверены; Actions execution/YAML parser не заявлены.

MicroCom.Runtime0.11.0 не содержит nuspec VCS commit. Historical upstream LICENSE
2021-11-14 совпадает с publisher MIT/copyright; supplement честно обозначен
publisher-declaration, точная source-to-binary привязка остаётся ограничением.
Avalonia/Tmds supplements включают source/sample/test texts как conservative
superset; наличие notice не означает linkage этих частей в клиенте.

Отдельный inventory toolchain: desktop rustc1.97.0 commit2d8144b78, Zig0.13.0,
cargo-zigbuild0.23.0, MinGW binutils2.44, rcodesign0.29.0. Их runtime/stdlib
notices не входят автоматически в Cargo/NuGet graphs и требуют отдельной
проверки вместе с Android NDK/runtime assets. Matching source publication,
OpenWrt immutable source cut, final-source Actions/signatures/release остаются OPEN.
Native Rust sources/recipes и14 artifact SHA неизменны (e3fb04a8…). Нет новой
native A/B/JVM/device VPN проверки. Q29 SIGKILL FAIL/ENONET, Q30/Q31, F459 braces,
D06 ACCEPTED_LIMITATION и USER_EXCLUDED сохранены. Лаба не затронута.
Q34 IN_PROGRESS; общий план30/37 DONE81,1%, осталось7.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-managed-notices-20261008`: SEALED 1115 files / 34492726 bytes; manifest SHA256 `1f0b212530fe7876f20418132dd1446127fe3cc4edb60feaa6a060dcb8c65cac`.

[Уточнение от 9 октября](AUDIT-Q34-SOURCE-BINDING.md): ограничение MicroCom publisher-only устранено совместимым pin0.11.2, точной VCS-привязкой и новой квалификацией. Исторический пакет выше не изменён.

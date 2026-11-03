# Q29: Android storage, profile editor, backup and Release package

<!-- normative-sync: q29-android-storage-package-v2 -->

**5 October 2026: stage PASS; Q29 IN_PROGRESS. Plan28/37(75.7%),9 sections remain.**

| Finding | Fix |
|---|---|
| F273 | specialUse used an unknown manifest property instead of android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE. Correct name and purpose description added. API34 PackageManager checks property, privacy/permission and service types. Old APK reproduces NameNotFoundException; this does not prove startForeground fails on every OS. |
| F274 | Failed legacy Tink migration aborted open: Activity could not capture a revision or explicitly restore a backup. Partial keysets could resemble an empty store. Revision remains available; ordinary reads/writes refuse, explicit backup restore authorizes a CAS replacement. Legacy ciphertext survives; failed encrypted migration cannot trigger plaintext/default save. Failed deletion after a verified migration does not block the usable new store. |
| F275 | BigInteger.intValueExact requires API31 despite minSdk28. Direct BigDecimal.intValueExact is available sinceAPI1 and still rejects fractions/overflow. Release lint NewApi error resolved. Old call confirmed in source/initial lint; no Android9–11 runtime claim. |
| F276 | allowBackup=false alone does not cover every OEM D2D transfer. Nine credential/device-protected domains explicitly excluded from cloud/device-transfer; fullBackupContent=false for older OS. Packaged manifest/XML checked; physical OEM/cloud/D2D backup not executed. Explicit user backup export remains available. |

Removed five unreachable SDK<26/<28 branches in boot/tile/widget/Activity. minSdk28 unchanged; no new INI settings. Internal JSON archives/journals are not JSON configuration support; native core still rejects JSON configs.

## Checks/evidence

- **167 JVM PASS,0 failures/errors/skips**, production host ConfigCore JNI. Debug/androidTest and unsigned R8/resource-shrunk Release builds and lintRelease complete. Lint **0 errors,55 warnings**, no new-error baseline/suppression. Warning triage covers dependency notices, UI/layout/plurals, legacy attributes and intentional host-JNI override. AAB language splits unqualified; current distribution uses APK.
- **18/18 debug instrumentation PASS** on temporary Android14/API34 x86_64 AVD. Six new tests against preceding12: specialUse property, private service/types, packaged cloud/D2D rules, unreadable/partial legacy recovery and lost Keystore key. Exact ciphertext preservation, ordinary write/editor refusal, explicit restore, stale restore rejection and reopen checked. Actual JNI INI round-trip/JSON rejection and split/full/dual TUN establish repeated.
- Old production APK baseline: **3 tests,2 expected FAIL**, service privacy/type case PASS. Only tests added; product source unchanged.
- First full run:16 PASS; TUN case failed because the harness omitted ACTIVATE_VPN. Preserved; isolated AVD setup repaired,then18 PASS. Two new-test compile errors (nullable SDK return/hidden ApplicationInfo field), offline lint-cache failure and NewApi lint failure retained; these are not product regression claims.
- A debug test APK against minified Release is not a qualified Release test variant. Crash retained/diagnosed separately from production UI smoke; no3 Release instrumentation PASS claimed.
- Unchanged native digest/14actual hashes and183 preceding managed/Swift inputs/7DLLs. Prior1248 .NET checks reused, not rerun or called fresh Android results. Exact JNI.so hashes packaged; no Rust/native AB rebuild needed.

R8 production UI smoke: **PASS on Android14/API34 x86_64: resolved production launcher, cold start, process alive and not debuggable, no fatal logcat errors. The first launch opens Android battery-optimization permission UI; application startup is checked, not a complete Activity interaction or VPN traffic scenario.**. Release fixture uses only the debug test key in a temporary AVD; no production signing/published APK.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-20261005.
Evidence: release/certification/evidence/q29-android-storage-package-20261005.json.

## Operation and remaining Q29

Unreadable legacy profiles must not trigger automatic app-data/ciphertext deletion. Restart the process to retry transient migration; a lost device-bound key requires a usable previously exported backup. Restore uses the existing explicit UI confirmation and rejects stale revisions. A lost key cannot be recreated without a backup. System encrypted-preference transfer does not transfer the Keystore key; explicit user export/import is the supported path.

Only separate read-only AVD sessions; original userdata SHA/mtime/size preserved. Working qeli.service and host routes/firewall/resolver/.10 unchanged; no push/deploy; primary human WIP retained.

Remaining: full connect/reconnect/cancel/revoke/process-death/always-on/lockdown/Doze, JNI/TUN generation/protect races and TCP/UDP traffic; Release lifecycle, older Android API,arm64/physical LTE and other backup/migration failures. D12 network evidence remains historical. The whole section stays open.

Contracts: [specialUse property](https://developer.android.com/reference/android/content/pm/ServiceInfo), [BigDecimal exact/API1](https://developer.android.com/reference/java/math/BigDecimal), [BigInteger exact/API31](https://developer.android.com/reference/java/math/BigInteger), [Android backup/D2D](https://developer.android.com/identity/data/autobackup).

Release test-variant diagnostic: NoClassDefFoundError for kotlin.jvm.internal.Intrinsics in AndroidJUnitRunner/MonitoringInstrumentation. The debug test APK depends on unminified target classes; ordinary production launcher succeeds without instrumentation. Retained diagnostic is not a Release instrumentation PASS or a client launch defect.

## 6 October: F284–F285 profile editor and backup export

| Finding | Fix |
| --- | --- |
| F284 | Export read failures escaped the Activity error handler; null output streams could report success, and KDF/provider writes ran on the UI thread. Read failures now report an error without replacing ciphertext. Encryption and write/close run on Dispatchers.IO; success follows completion, null/write/close failures propagate. Temporary output bytes are cleared. |
| F285 | Save during enumeration could erase the configured application list; saving after enumeration discarded unavailable packages; changing mode during loading left checkbox state stale. Save is disabled until rows are published, missing configured packages remain as labelled rows, and row state uses the current mode. Dismissal cancels the enumeration job; per-package permission lookup tolerates concurrent removal. |

The package-name row is intentionally retained until explicitly unchecked. Empty selection
continues to normalize to the existing all-apps policy; no INI key/default is changed.
Internal archive JSON remains a container for profiles; configurations remain INI.

### Fresh checks and boundaries

- **188 JVM PASS, six new exporter cases**: exact UTF-8/close/temporary-byte clearing,
  encrypted round-trip and wrong passphrase, null sink, failed write, failed close,
  and oversized UTF-8 rejection before opening the sink. Lint: **0 errors,54 warnings**.
  Fresh debug/androidTest and default R8/resource-shrunk Release builds succeed.
- **Same corrected test APK: old product 5 tests/4 expected FAIL, fixed product 5 PASS**.
  Actual Activity, PackageManager and Keystore exercise early Save, absent package retention,
  mode switching during enumeration, unreadable encrypted store export, and exact plaintext/
  encrypted exports into real private `file:` destinations. Test-only dialog-root reflection
  is used on Android14/API34 x86_64. No external SAF/cloud provider or UI latency benchmark
  is claimed. IO placement is reviewed in source; failure cases above use JVM sinks.
- The first baseline had 3 FAIL/2 PASS; one test read the profile before Android delivered
  its posted Save listener. That result, original test source and APK are preserved as a
  harness diagnostic. The early missing-package PASS is unqualified. Waiting for idle
  produces the qualified four failures; the positive export case passes in both products.
- Release TCP recheck, independent packet analysis and final cleanup qualification are
  recorded with their exact results below. Debug profile tests generate no VPN payload.
  No matching Release instrumentation was run in this batch.
- Native/server/service/managed inputs are unchanged. The preceding UDP/QUIC and service
  results retain their own scope. The standalone Java Release probe is reused. Source
  proof covers306 Android inputs (three new, two existing changed),23 auxiliary inputs
  (one changed),five unchanged regression inputs,14 native hashes,seven managed artifacts,
  and eight APKs including the two initial diagnostic artifacts. Fifteen helper checks
  and six CLI rejection guards cover the extended lab runner.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-profile-ui-20261006.
Evidence: release/certification/evidence/q29-android-profile-ui-20261006.json.

Q29 remains IN_PROGRESS,28/37(75.7%). SIGKILL auto-redelivery FAIL and generic auto/null
DnsResolver ENONET remain open; this UI/storage fix does not establish their cause or
accept them. Older/API-OEM/arm64/physical coverage limits and user skips/D06 are unchanged.

First fixed-product attempt: all five tests PASS, overall runner FAIL because its old
traffic guard expected TCP/UDP receipts from the profile-only suite. Preserved as a harness
diagnostic; the suite now requires zero echo receipts and continues through Android cleanup.
Baseline and initial-debug executed helpers are pinned to the preserved pre-guard source;
the final debug/Release helper inputs are pinned separately. No product APK changed.

### Qualified final runtime

Default production R8 Release TCP **PASS**: actual UI INI import and OS lockdown, two
Wi-Fi→Cellular→Wi-Fi transitions,12 ordinary-UID IPv4/IPv6 TCP/UDP full payloads with exact
sink SHA and independent tagged packet reconstruction. Native connection plans/auth
advance after each TCP transition while PID/TUN remain the same. All288 socket samples
are analysed,48 post-stop probes blocked;physical new requests0,capture drops0 in the
qualified windows. Transient loss during handover/force-stop is retained, not called
288 successful replies. Profile-only debug **5/5 PASS**,zero VPN receipts.

Five attempts (two old baselines,first fixed debug with obsolete harness traffic guard,
qualified debug,Release) preserve host/service baseline and AVD userdata SHA/mtime/size,
restore namespace addresses and exit the private server cleanly. Successful final runs
also verify no Android Qeli service/TUN/fatal exception remains. .10 is untouched.
No new native matrix or UDP/QUIC repetition; no push/deploy.

# Q28: per-app bridge, Swift policy and build paths

<!-- normative-sync: audit-q28-macos-perapp-v1 -->

**5 October 2026: C#/shell stage PASS; Swift SOURCE REVIEW / USER SKIPPED. Q28 IN_PROGRESS; plan 27/37 (73.0%), 10 sections remain.**

## Changes

| ID | Defect and change |
|---|---|
| F256 | down/stop swallowed errors; stop/failed rollback forgot ownership and killed the guardian before confirmed cleanup. Failures now propagate; Started and guardian remain retryable. BeforeTunDispose refuses before closing utun; CleanupPlatform retains an active controller. Guardian release requires kill and confirmed join. Missing helper means unknown cleanup. |
| F257 | Internal state was placed directly in shared temp; helper output/pipe EOF had no shared bound. Exclusive private handoff directory (700 on Unix) and file 600, payload cap 1 MiB, same directory for recovery rewrites. ToolProcess caps each pipe at 64 KiB and shares a 190-second process/EOF deadline. |
| F258 | UsesAppFilter accepted uppercase INCLUDE but Swift only recognized exact include. Wire mode is now canonical lowercase before invoking the helper. |
| F259 | Prefix guard accepted dist/../victim and arbitrary leaves, permitting removal outside the intended scope. Per-app build accepts only exact dist/per-app-ARCH and refuses symlinked parents/leaves; app build refuses symlinked dist/outputs. Fixed paths are checked before build/removal. Trusted-workspace path mistakes are covered; concurrent malicious root changes are outside this contract. |
| F260 | Empty Swift CIDR indexed an empty array; split discarded leading/trailing slashes. Empty subsequences are retained and empty address rejected; malformed prefixes cannot become host routes. Native policy cases added. |
| F261 | Delayed relay registration could survive closeAll for an old policy. Shared RelayRegistry accepts only the snapshot generation; retire and state publication are coordinated under the provider lock, callbacks close outside locks. Late monitors cannot revive a stopped provider. Removed the redundant FlowLifetime and unreachable UDP force-cast. |

## Validation

- perapp-selftest **22/22 PASS** on production controller methods: down/stop failure/retry, partial activation/rollback, missing helper, failed update, platform refusal, oversized state and private handoff cleanup. Real local child processes check guardian join and stdout/stderr caps; no NetworkExtension, service or network operation.
- Production build.sh shell fixture **10/10 PASS** with uname/Xcode/build/copy/rm tools mocked. No real recursive deletion, Xcode build, signing or publish. Original build.sh reproduces **5 failures in 10 cases**; other 5 cases correctly pass. Windows symlink fixture unavailable: **SKIP**; corresponding guards source-reviewed.
- Original C# bridge: **6/6 expected FAIL**. Only platform/helper/guardian boundary and namespace adapted; original transitions retained. Original Run independently executes a real local output-overflow child.
- Mac network **117**, control **83**, storage **54**, Windows **325**, shared **549 PASS** after builds; C# Release 0 warnings/errors. Docs/bindings/panel/diff, shell syntax, unchanged native digest and 14 hashes PASS.
- Ten new Swift policy/registry regression cases **not executed**. Xcode/Swift typecheck, actual app group, entitlements/signing/notarization, Darwin sockets/NE callbacks and Unix permissions remain **USER SKIPPED**, not PASS. Initial harness crash on an uncaught InvalidDataException is retained; corrected harness then freshly rebuilt and passed 22 checks.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-perapp-20261005.
Evidence: release/certification/evidence/q28-macos-perapp-20261005.json.

## Remaining scope and boundaries

Stop/join refusal or missing helper retains Error/ownership for cleanup retry. Restore the signed build or manually disable Qeli managers if the helper disappeared; there is no automatic cleanup success. This deliberately replaces best-effort stop. JSON state remains an internal DTO; external configuration is INI only.

Q28 still needs forwarding ownership/crash recovery, guardian ready/owner-generation and native socket lifetime serialization/connect-write bounds. Helper deadline cannot interrupt arbitrary Darwin calls or qualify SystemExtensions. Mac runtime was user-excluded; no fresh Linux/JNI/soak/benchmark claim. Historical release evidence/physical rows remain intact; no push/deploy/lab service/user-profile mutation.

Primary contracts: [.NET private temp directory](https://learn.microsoft.com/en-us/dotnet/api/system.io.directory.createtempsubdirectory?view=net-10.0), [Swift split empty subsequences](https://developer.apple.com/documentation/swift/string/split%28separator%3Amaxsplits%3Aomittingemptysubsequences%3A%29).

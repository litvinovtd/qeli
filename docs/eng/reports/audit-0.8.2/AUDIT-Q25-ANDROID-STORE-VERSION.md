# Q25-F179: Android profile store rejects stale writes

1 October 2026. Base: c7687fb7. D08 remains **IN_PROGRESS**.

Q25-F177 introduced a UI revision within one MainActivity, but another Activity instance could load the same profiles and later save a stale list. Manifest singleTop does not guarantee one instance across every task/intent scenario. Shared encrypted preferences accepted both writes without version checks. A confirmed backup Restore could also replace a profile changed after its dialog appeared.

SecureStore now exposes an opaque version of the encrypted value, including damaged values, and compares it before commit under a SharedPreferences lock common to instances. MainActivity captures the observed version at load and advances it only after successful writes. A stale commit changes no profiles and an EN/RU message asks the user to restart the window. Explicit repair of a damaged store remains possible, but refuses to replace a value that appeared after load. README describes this contract.

compileDebugKotlin, assembleDebug and assembleDebugAndroidTest passed; 156 JVM tests passed with the verified host DLL. Three Android instrumentation regressions were added: sequential conflict between instances, concurrent writes and damaged-value Restore. They were not run on the emulator because .11 rejected the previous root password before APK upload; .10 was untouched. Prepared APKs and a one-off read-only AVD scenario are in audit-debt-20260924/android-cas-20261001. Once SSH works, nine expected tests and unchanged userdata images must be checked.

The lock covers instances in the Android app process sharing SharedPreferences. External processes writing the XML directly are outside this contract. iOS UserDefaults and runtime reconnect remain in D08; final Android lab verification remains in D12.

Reconciliation on 2 October: [Q25-F210](../../plans/AUDIT-DEBT.md) closes available D08 with iOS single-writer/read-only ownership and explicit external-writer boundaries; 511 .NET, 167 JVM and 12 instrumentation PASS. Earlier counts and pending statements above are historical; Apple runtime is SKIPPED by user decision, not PASS.

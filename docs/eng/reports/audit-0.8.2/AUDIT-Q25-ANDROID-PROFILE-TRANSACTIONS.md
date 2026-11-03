# Q25-F174: confirmed Android profile writes

1 October 2026. Base: c2e211a1. D08 remains **IN_PROGRESS**.

Android MainActivity changed profiles or the active index before storage and used asynchronous SharedPreferences.apply(). Write failures could not be observed: UI displayed unconfirmed add/edit/import/duplicate/delete/move/per-app/selection changes. Backup Restore reported success after apply and reread even when the new version had not been durably saved. Legacy plaintext migration also deleted plaintext immediately after apply, risking loss of both copies.

Every profile mutation now prepares and validates proposed state and writes it through a checked commit before changing the UI. On failure, the visible list and selection remain unchanged and the user sees an error. Backup Restore uses the same path and normalizes the internal container to current cfg/INI entries. Legacy plaintext is deleted only after commit and read-back of the encrypted copy; an unreadable existing encrypted entry does not trigger plaintext deletion. Unused SecureStore.Editor.apply was removed. JSON remains an internal store/backup format, not a user config format.

Android compileDebugKotlin and 154 JVM tests passed with the previously verified host DLL; git diff --check passed. An initial run without the DLL produced UnsatisfiedLinkError, and the retry with QELI_CONFIG_NATIVE_LIBRARY passed. UI fault injection and instrumentation were not run. Synchronous commit on the UI thread may add latency for a store up to 8 MiB and needs separate performance evaluation. D08 remains open for concurrent editing and runtime checks.

# Q29: Android foreground service commands and lifecycle

<!-- normative-sync: q29-android-service-v1 -->

**5 October 2026. Stage PASS; Q29 IN_PROGRESS. Plan:28/37(75.7%),9 sections remain.**

## F278: rejected command replaced the existing connection status

An ACTION_CONNECT without configuration or with invalid parameters made rejectForegroundConnect publish ERROR before checking the existing controller. Transport remained alive, but the UI received an error and live connection properties were cleared, contradicting the promise to preserve a running/waiting service when rejecting a new command.

Owner checks now run under the shared service monitor before publishing status. Active transport/TUN, trusted-WiFi pause and pending teardown retain their state; rejection is logged. Initial invalid starts retain foreground promotion, ERROR and service shutdown. No new INI parameters or Rust/JNI changes.

## Verification

Five new tests start the **actual framework-owned service**, without reflection or replacement transport core. A local TCP peer receives the JNI ClientHello and stalls the handshake without a response. Cases cover:

- preserving CONNECTING, foreground and connection_desired after missing/invalid configuration;
- three start → manual handshake cancellation → service/native socket shutdown cycles;
- stopService → actual onDestroy, native socket closure and preserved connection intent; then a fresh start;
- server EOF with reconnect disabled → service shutdown, ERROR and diagnostic reason;
- an initial invalid foreground start → ERROR, service shutdown and no connection intent.

Old APK with unchanged product code: **5 tests, 1 reproducible FAIL** (CONNECTING replaced by ERROR), four PASS. Fixed APK: **28/28 instrumented PASS**, including these five and the previous23. Android14/API34 x86_64, separate readonlyAVD.167 JVM PASS;Release/R8/resource shrink builds;lint0errors55precedingwarnings. Debug runtime does not qualify Release runtime.

After force-stop no TUN or active app service remains;AndroidRuntime contains no FATAL EXCEPTION. Persistent AVD userdata SHA256/mtime/size preserved;host .11 network and working qeli.service match before/after;.10 untouched. Both packaged ABIs match qualified JNI;arm64 not executed. Prior1248 .NET results reused only for183 unchanged managed/Swift inputs and7DLLs, not a fresh run.

## Limits

New tests qualify framework lifecycle **before authentication**, without VPN payload traffic. stopService is not process death, system revoke or automatic redelivery. Three restarts occur after preceding teardown completes; concurrent start during teardown is not qualified. Trusted-WiFi/CONNECTED rejection branches reviewed, fresh runtime covers CONNECTING. Remaining:TCP/UDP traffic,roam/protect,always-on,process death/revoke/Doze,Release runtime,older APIs andphysicalLTE/OEMbackup. The preceding [TUN/JNI stage](AUDIT-Q29-ANDROID-LIFECYCLE.md) retains its own results and limits.

Raw:C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-service-20261005.
Evidence:release/certification/evidence/q29-android-service-20261005.json.

# Q29: concurrent Android TUN and JNI teardown

<!-- normative-sync: q29-android-lifecycle-v1 -->

**5 October 2026. Stage PASS. Q29 IN_PROGRESS; full plan28/37(75.7%),9 sections remain.**

## F277: late NetworkPlan after stop begins

Coroutine cancellation does not interrupt synchronous Builder.establish(). The handler checked only activeConfig and core identity: between stop beginning and those fields being cleared it could still apply a plan. Separate teardown concurrently read/closed vpnInterface. Independent onDestroy did not set stopping. A stale handler could change routing/interface state after shutdown began.

NetworkPlan application/publication, startVpn, stopVpn, onRevoke, onDestroy and forceReconnect now share the service monitor. Java descriptor detach and generation reset use it too. A late plan with stopping set is rejected before Auth OK logging or carrier selection. onDestroy sets terminal stopping while preserving persisted connection desire for normal redelivery.

runner.join remains **outside the monitor**: waiting for the worker must not prevent its access to the service. DISCONNECTED still follows runner completion. This change does not guarantee maximum system Binder latency.

## Checks and limits

Five instrumentation tests exercise packaged JNI: reject a late plan, block at handler entry rather than carrier selection, reject stale/cancelled ACK, own the native descriptor duplicate, and stop/free a runner awaiting socket protection.

Two tests invoke the production adapter on a service object attached to Context through reflection; this is **not** complete system onRevoke/onDestroy E2E. The duplicate-FD case uses a pipe, not a real TUN. The separate preceding TUN test establishes Android split/full/dual interfaces. Runner cancellation uses actual JNI before protect ACK, without a VPN server or payload traffic.

167 JVM tests pass. R8/resource-shrunk Release builds; lint0errors/55 preceding warnings. No fresh Release/UI launch or Release instrumentation is claimed here. Prior1248 .NET results are reused only for unchanged managed/Swift inputs and DLLs.

First AVD stopped after waiting for the new APK timed out; disk preserved. Invalid test auth JSON/incomplete capabilities and an insufficiently specific initial lock assertion are retained as harness failures, not defect confirmation. Final old APK:5tests, **2 expected FAIL** — carrier selected after stopping and locking only inside selectPhysicalCarrierNetwork. Fixed APK: **23/23 PASS**, including five new cases and preceding18. Android14/API34 x86_64, separate readonly AVD; userdata SHA/mtime/size and host network/service preserved.

Rust/JNI sources unchanged; provenance,14 actual hashes and both packaged ABIs checked. Prior evidence remains immutable. Working .11 service and .10 unchanged; no publication.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-lifecycle-20261005.
Evidence: release/certification/evidence/q29-android-lifecycle-20261005.json.

Remaining: full connect/reconnect/revoke/process-death/always-on/Doze and TCP/UDP traffic, additional protect/roaming races, Release lifecycle, older APIs and physical LTE/OEM backup. The preceding [storage/package stage](AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md) retains its own results and limits.

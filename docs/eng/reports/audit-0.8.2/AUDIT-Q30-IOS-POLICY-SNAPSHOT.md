# Q30: MDM numeric policies and asynchronous provider snapshots

<!-- normative-sync: q30-ios-policy-snapshot-v1 -->

6 October 2026. Q30 IN_PROGRESS. This is a scoped source review of managed policy
conversion and the container app's provider-message callbacks, not completion of
PacketTunnel, Keychain, roaming, memory or the whole iOS section.

## F290: MDM values were truncated or implicitly bridged

`ManagedConfigurationReader` accepted `NSNumber.intValue` for policy Booleans and
schema versions. Fractional values could be truncated to 0/1; a Boolean could be
bridged to an integer version. Malformed input therefore became a valid policy.
The reader now distinguishes CFBoolean, checks representable integer boundaries
before conversion, and requires a decimal round trip. Actual Booleans and legacy
exact numeric 0/1 remain compatible; fractional/nonfinite/wrong-type Boolean
values and Boolean/nonfinite/fractional/overflow versions return nil. Integral
floating representation (1.0) remains accepted. No new schema-version enforcement
or default/fail-closed semantics is introduced; the app's existing optional-policy
fallback remains unchanged. An invalid activeProfileID still fails closed.

Three added XCTest cases cover both policy fields, exact numeric compatibility,
Int boundaries, Boolean versions, fractions, NaN/infinity and overflow.

## F291: late provider replies could resurrect stale UI state

`requestProviderSnapshot` decoded and published every response. A response issued
before Disconnect or a status transition could arrive afterwards and restore
Connected/privateUpdatePath. Out-of-order responses could also overwrite newer
accepted counters and connection facts. The container now invalidates response
ownership on connect, managed fail-closed, Disconnect and system-status changes.
Only running/reasserting sessions outside Disconnecting request/accept snapshots.
An epoch/sequence gate rejects obsolete or already accepted responses. An older
valid reply remains usable while a newer request is pending, avoiding starvation
when responses take longer than the polling interval. Decoding precedes the
MainActor ownership check; status checks and publication occur together on MainActor.

Three added XCTest cases cover reordered/duplicate replies, slow pending requests
and stop/restart epochs. They exercise the production gate, not an emulated VPN.

## Verification and remaining work

- Six Python IPA-verifier regression tests PASS using generated archive fixtures.
  This proves the verifier's structural checks, not signing or a real candidate IPA.
- Documentation checks, generated config bindings and diff checks PASS.
- The six new Swift XCTest cases, Swift compilation, simulator build, signed IPA,
  actual provider callback races and physical iOS/MDM runs are NOT_RUN. Xcode/Apple
  runtime is unavailable on this Windows host; the user excluded Mac/iOS runtime.
  These source fixes are not labelled runtime-qualified.
- Rust, native, Android and other client inputs are unchanged against the previous
  commit; prior checks retain their original artifacts, dates, failures and limits.
  No Android or Linux matrix was rerun for these Swift-only changes.

Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-policy-snapshot-20261006.
Evidence: release/certification/evidence/q30-ios-policy-snapshot-20261006.json.
Q29 SIGKILL FAIL/auto-null DnsResolver ENONET remain open; D06 and user skips unchanged.
Overall 28/37 DONE/PASS (75.7%), 9 remain. Continue Q30 engine/lifecycle/storage review.

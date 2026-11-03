# Q30: memory bounds, probe lifetime and source reconciliation

<!-- normative-sync: q30-ios-source-memory-v2 -->

**12 October: Q30 complete within agreed SOURCE REVIEW and portable-check scope. Swift/Xcode/Apple runtime USER_SKIPPED by direct user decision. XCTest and real Apple scenarios remain NOT_RUN.**

Historical checkpoint: 6 October 2026. Scoped fixes F303–F306. The Q30 **Review and dead code**
criterion is complete for source review; Q30 remains IN_PROGRESS. Runtime checks
and the other four checklist criteria are not promoted to PASS.

## F303: probe cancellation depended on a later OS callback

The physical path probe cancelled NWConnection but waited for its cancelled callback
or ten-second timer to finish Swift. Cancellation before continuation registration
could still be followed by handler installation/start. Its completion implementation
duplicated AsyncResultCompletion; TCP reachability used a second gate without a Task
cancellation handler. Both handlers captured the connection they belonged to.

CancellableProbeCompletion serializes resource start against terminal completion.
Cancellation completes Swift immediately, including before park/start. Every terminal
path clears the handler, cancels the connection and releases cleanup captures before
resuming Swift. Exactly one outcome/cleanup survives late callbacks and synchronous
reentry. The duplicate IOSPathProbeCompletion and ProbeGate are removed. Existing
10s path/4s TCP timeouts remain. This does not join OS callbacks or prove real Apple
object release; delayed timer closures retain only the small completion outcome.

## F304: deleted/edited profiles retained queued ping work and stale results

Every probe copied a profile into the queue; archive mutations did not prune queue,
reachability or outstanding IDs. An old result could repopulate a deleted profile's
reachability or describe its previous config. Repeated delete/create could retain
historical profiles in the queue/map despite the archive's 256-profile limit.

Ping accepts only current ID/config text. Archive commit removes obsolete queued
requests and clears removed/changed reachability entries. Only removed queued IDs
are released; active IDs/slots remain owned until their bounded call returns. Result
publication repeats the current ID/config check. Four active workers remain the
limit; native UDP calls are not newly claimed cancellable or joined. Profile rename
with unchanged INI remains a valid request. No network ping runtime was executed.

## F305: a count-only log window did not bound memory

Five hundred arbitrary-length messages could produce a large stored/decoded/encoded
archive. Messages now retain a UTF-8-safe prefix up to4KiB, with a truncation marker;
the actual encoded JSON window is limited to1MiB, retaining a recent suffix and at
most500 entries. Control-character escaping is included in the byte budget.
Oversized legacy archives are rejected before JSON decode; the next append writes
a bounded replacement. Reading UserDefaults may still allocate the legacy Data before
its size can be inspected. Process-local locks do not promise cross-process append
atomicity, and no total extension RSS/leak/device-memory qualification is claimed.

## F306: update timeout bounded time, not HTTP response bytes

URLSession.data buffered a whole releases response before decoding. The update check
now reads URLSession bytes into a collector limited to1MiB, rejecting the first excess
byte and checking Task cancellation. Existing private-path admission,10s time budgets,
ephemeral session and teardown cancellation barrier remain. Session invalidation occurs
on success/error/size rejection. This bounds the collector, not all Foundation/network
internal buffers or measured RSS. Real URLSession streaming/cancellation remains NOT_RUN.

## Source inventory and dead-code disposition

The current inventory contains92 Swift files:33 shared production/support,13 app,
3 PacketTunnel,4 widget,29 test files and10 test-only wire/crypto. Shared source is not
linked into every target: project.yml exclusions/explicit widget sources govern it.
The earlier F302 target-membership fix keeps wire/crypto in XCTest. ABI/native headers
and linked binary provenance remain unchanged; the engine's stale ABI comment now
matches the1.16 compatibility floor.

A reproducible declaration/reference scan plus manual classification leaves12
single-reference declarations: two @main app/widget roots, two NetworkExtension
callbacks, three WidgetKit/control-provider callbacks, four UIViewControllerRepresentable
callbacks and FileDocument.fileWrapper. These are framework entry points, retained.
Name counts are a conservative candidate search, not proof that every branch runs or
that no further dead code can exist. F303 removes the two concrete duplicate owners;
prior F292/F302 removals remain in their sealed packets.

| Layer | Source disposition | Qualification remaining |
| --- | --- | --- |
| INI/models/core policy adapters | Shared ABI/config bindings and prior source review retained | Actual Swift/core integration |
| Profile archive/Keychain/MDM/preferences | F290,F292–F294,F298–F299 | Real entitlements, interprocess races and OS preferences |
| App/UI/widgets/import/export/update | F291,F300–F301,F304,F306; framework roots retained | Presentation, callback scheduling and URLSession cancellation |
| Provider/roaming/packet seam | F295–F297,F303; current ownership and bounded batches | Actual OS drainage, RSS/leaks, native worker joins |
| Wire/crypto conformance support | F302 test-only membership; golden helpers retained | XCTest/Xcode build |

Source limits: native event/uplink/downlink buffers256KiB each,64 packets/batch,
65,535bytes/packet; uplink handoff256 packets/512KiB; one blocking DNS resolver;
profile config256KiB/archive8MiB/backup12MiB/256 profiles; route expansion256 and
snapshot route sample6. These independent caps are not an aggregate memory budget.
Full archive decrypt/validation and temporary encoding can overlap allocations;
real extension memory headroom remains unqualified. Already-issued OS settings/read
operations retain their lease until a real callback; callback-never-returns stays OPEN.

## Checks

Eleven new XCTest:4 cancellable resource-owner cases,4 isolated UserDefaults log cases,
3 bounded update-stream cases (exact limit, early size rejection, precancelled read).
XCTest, Swift/Xcode generation/build, real Network/URLSession/UI/Keychain, simulator,
signed IPA, memory/RSS/leaks and callback/native joins are NOT_RUN. Apple runtime is
user-excluded; no toolchain installed. No surrogate source test is labelled runtime PASS.

Six Python IPA-verifier fixtures,10 XML, all9 documentation checks, config bindings
and diff checks PASS. Unchanged implementation Git hashes retain historical runtime
statuses/dates/artifacts; no Linux/Android matrix repeated. Overall28/37(75.7%),9 remain.
Q29 SIGKILL FAIL/auto-null ENONET,D06 and platform skips unchanged. Source review
criterion completion does not close whole Q30 or resolve those platform observations.

Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-source-memory-20261006.
Evidence: release/certification/evidence/q30-ios-source-memory-20261006.json.

## Agreed-scope reconciliation on 12 October

All original F290–F306 fixes,92 Swift inputs,12 framework entry points and callback/RSS/Keychain/MDM limits remain. Production Swift/MDM/headers have not changed since 6 October; one `exit_node` test profile was corrected and project.yml gained LICENSE/notices resources. Git deltas were reviewed;91 Swift inputs are byte-identical.

Fresh6 IPA-verifier fixtures,10 plist parses, bindings and9 docs checks on a read-only overlay PASS. These checks do not compile Swift. Native iOS build, XCTest, OS settings/read callback drain, signing/entitlements, leaks, sleep/wake/NAT64/MDM remain USER_SKIPPED/NOT_RUN. Future Apple admission requires actual platform qualification.

The direct user decision to skip unavailable Mac/router/VM labs excludes bringing those platforms back into the mandatory queue. The four platform criteria therefore become USER_SKIPPED and this section closes within the available agreed scope. Q29 SIGKILL/ENONET observations, other open sections and D06 remain. Publication is prepared separately from the frozen checkout; the applied plan becomes31/37(83.8%). Raw: `audit-debt-20260924/q30-agreed-scope-20261012`.

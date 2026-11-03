# Q30: application status and managed preference ordering

<!-- normative-sync: q30-ios-app-preferences-v1 -->

Source fixes F298/F299, 6 October 2026. Q30 remains IN_PROGRESS.

## F298: status preassignment bypassed snapshot epoch invalidation

Five preparation/preference reconciliation paths assigned systemStatus before
consume compared old and new status. If reconciliation observed a transition
before its notification, the comparison could not invalidate the old provider
reply epoch. All five now pass the observed status directly to consume; that
method remains the sole systemStatus writer and invalidates before assignment.
This completes these call paths of F291; it does not prove real OS callback timing.

## F299: suspended managed preference work could outlive its intent

Launch, foreground and profile-store events could refresh MDM concurrently, capture
a policy, then suspend while preparing/saving preferences. The preference mutex
serialized writes but did not serialize policy reads; a stale refresh could reach
the write last. Profile application and managed fail-closed work also lacked the
connection generation checks already present in Connect. Profile application carried
settings captured before its suspension, potentially replacing newer UI settings.

AppModel now serializes the entire managed reconciliation and reads MDM after
admission. Profile configuration reads effective settings immediately before mutation.
Profile apply and fail-closed validate connection generation before mutation and
after each preference callback. A newer Connect/Disconnect prevents obsolete work
from issuing its next step; an already-issued OS save cannot be rolled back by a
cancellation check. Preference admission and generation/revision guards check Task
cancellation. Manual disconnect distinguishes task cancellation from a superseding
settings revision, preventing an endless retry loop for an already-cancelled task.

## Checks and remaining scope

Three production PreferenceMutationGate XCTest cover precancelled admission,
cancelled queued work retaining the current owner until completion, and serialized
refresh reading the latest policy at admission. Tests explicitly await owner admission,
without assuming Task creation order. These XCTest and Swift compilation are NOT_RUN.
An unreturned preference callback still holds admission; no cancellation unlock or
Apple callback drainage guarantee is claimed.

Six Python IPA-verifier fixture regressions, ten XML structural reads, generated
bindings, all nine documentation checks and diff checks PASS. These establish only
source/structure consistency. Actual app/MDM preferences, OS notifications, Swift
build, simulator, signed IPA, memory and Apple runtime remain unqualified/user-excluded.
Unchanged native/Android/other client Git inputs retain previous runtime evidence;
no historical status/date/artifact is rewritten as a fresh run.

Provider-message wait/cancellation, backup UI request state and whole-section
memory/dead-code reconciliation remain source-review work. Q29 SIGKILL FAIL and
auto/null ENONET, D06 and platform exclusions are unchanged. Overall28/37(75.7%),
9 remain; no whole Q30 checklist item is closed.

Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-app-preferences-20261006.
Evidence: release/certification/evidence/q30-ios-app-preferences-20261006.json.

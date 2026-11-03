# Q03 — Panel state and load failures

Date: 3 October 2026. Status: **PASS for Q03 panel UI/state**.

Batches covered lockout policy, canonical defaults, logs, transport, dashboard,
client connections, users, layout, Quick Start, notifications and login.
The final config/focus/dirty-navigation batch below closes all five Q03 criteria.
Earlier IN_PROGRESS notes describe their respective intermediate batches.

## Q03-F001 — Unloaded policy looked available for saving

A delayed/failed GET `/api/blocked/settings` left fields and Save active and posted
initial defaults. The backend rejected the initial write without `expected_revision`;
no actual configuration overwrite was reproduced. The UI did not distinguish
loaded settings from its initial placeholder.

Fixed: fields and Save require successfully loaded settings and revision;
overlapping loads/saves are blocked. Errors remain visible and Reload retries.
A disabled fieldset also prevents keyboard editing. Mobile policies stack vertically.

## Q03-F002 — Canonical defaults failure enabled a duplicate JS schema

A failed GET `/api/config/defaults` still let Add profile instantiate a large
embedded object which could drift from Rust defaults. A failed later load could
also retain the previously fetched template.

Fixed: duplicate JS schema removed; common `apiFetch` handles loading and the old
template is cleared. Failure shows a localized message and disables Add.
Successfully loaded configuration remains editable; Reload restores creation only
after the canonical template becomes available.

## Checks

28 actual JS component groups PASS. Three new regressions cover loading, missing
revision, retry, overlapping Save and absence of fallback. The pre-fix regression
reproduced an extra POST; its original log is retained.

Real Edge: eight scenarios, RU/EN × desktop/mobile × two pages. Checked disable
while loading/failed, retry, Enter policy save, Enter canonical profile creation and
retention of its extra field. No JS/resource errors; eight screenshots retained,
RU mobile and RU desktop images visually inspected. APIs use local loopback
fixtures: UI integration, not real server auth/HTTP persistence/network qualification.

Static gate: 11 templates / 1154 RU strings. Native inputs unchanged; A/B provenance
passes without claiming fresh native builds. Linux checks and binary SHA are in
[evidence](../../../../release/certification/evidence/q03-panel-load-20261003.json).

The first Linux build is not accepted: zero archive mtimes let Cargo reuse old
include objects. The repeat invalidates source timestamps, verifies the new message
inside the binary and requires a different SHA. Original evidence retained as
`FAILED_STALE_EMBEDDED_ARTIFACT`. This fixes the test setup; running services are preserved.

## Release checks for the fixes

2257 Linux unit PASS (60 normally ignored). Fresh release SHA `865b7e8ed589fbaca51bd4479d4a1524ae743e1e04e7231cfe30e16295e6e2b8`: 18 namespace cases / 327 checks, aggregate leak, 100 TCP + 100 QUIC / 33 checks and bounded shutdown/recovery passed. Host snapshots and the running .11 service were preserved. Desktop/Android native A/B refreshed with unchanged library hashes; this does not claim fresh platform UI/network tests.

The first Android native attempt refused insufficient disk space. Only the private debug cache was removed after saving unit logs; service files and release cache remained. The retry passed. A fresh Linux unit run found two assertions requiring the old fallback; they were corrected and all units passed. Later formatting of one server-only cfg(test) assertion was verified with rustfmt 1.97.0: canonical output identical. Actual input hashes and original A/B/source identities are retained; format reconciliation is not a new runtime execution.

[Certification](../../../../release/certification/0.8.2.json) binds the new release; prior D15 candidate/benchmark records retain their original SHA. Overall Q03 remains IN_PROGRESS.

Desktop publishing initially refused a source-identity change during A/B; the original FAILED is retained. Composite qualification rechecked actual A/B hashes/exports and the sole formatter-equivalent server-only diff; no additional compilation is claimed by that reconciliation. The original build driver fmt_reused_from label is too broad: 286 Rust files are unchanged and the two changed test files were checked separately, as recorded by fmt_qualification.

## Q03-F003 — Late responses overwrote newer state

Logs, transport and blocked journals allowed a timer/manual request to overlap
another read. Old responses overwrote newer data and cleared a newer spinner.
The pre-fix regression reproduced a third background read over two pending reads.

Fixed: request sequence owns both data and spinner. Background polls skip pending
work; manual reload after a changed log limit or an unblock keeps priority. Late
responses after destroy cannot update journal/transport state. Timers are cleared.
This does not cancel an HTTP request already sent or guarantee a network timeout.

## Q03-F004 — Failures looked like empty journals or disappeared under filters

A blocked-journal GET returning `{ok:false}` cleared both tables and displayed
“No blocked IPs”. A logs error became a line without a severity, hidden by an ERROR
or search filter. A failed read does not establish that records are absent.

Fixed: independent role=alert errors, last successful snapshot preserved and empty
state gated on a successful load without a current error. Log errors are not log
entries. The blocked countdown never removes rows; only a successful GET confirms
removal. Countdown freezes on failure; retained data is the last received snapshot,
and remaining time is an estimate.

## Journal and transport refresh checks

37 JS groups PASS, including nine new groups: reverse response order, old failure
while a newer read is pending, spinner ownership, bounded background polling,
snapshot preservation, filter-independent errors, countdown and timer/destroy cleanup.
12 Edge scenarios PASS: RU/EN × desktop/mobile × logs/blocked/transport, actual
repository templates/assets and loopback fixture APIs. Initial failure, keyboard
Enter retry, background failure and reverse responses covered; no JS/resource errors.
Two RU mobile screenshots inspected. The first browser run required waiting for DOM
visibility after reactive state in the fixture; product code did not change for that
adjustment. A narrow mobile log search field remains a responsive-review candidate;
this does not declare the whole page complete.

Rust, native recipes and library bytes are unchanged. Prior 2257 units and native
A/B are explicitly reused, without a new-execution claim. Fresh release build/checks
for this UI pass are recorded separately in
[evidence](../../../../release/certification/evidence/q03-refresh-20261003.json).
Dashboard, users, client and remaining page/modal scenarios still belong to Q03.

Q03-F003/F004 fresh release SHA `0d61d60402fdce03ddeafff87499691abafe25fb740eaed62cb7b13f6ae1229b`: 18 isolated cases / 327 checks, aggregate leak, 100 TCP + 100 QUIC / 33 checks and bounded shutdown/recovery PASS. Five pre-fix reproductions (two load errors and late responses on all three pages) are preserved separately. Complete snapshots, .11 service PID/start time and its working binary were preserved. Certification 20/20 is refreshed for this artifact; physical rows and older benchmark records are not requalified.

## Q03-F005 — An old write changed a newer modal

Dashboard/client/users completion for write A closed an already opened modal B.
Users could display A's sharing URI/new password in B's modal. Closing the modal
does not cancel an HTTP write already sent; the bug was response ownership.

Fixed: writes retain their original modal object, cannot close a new one or clear
its busy/error state, and duplicate Submit is blocked. Covers bandwidth, client
profile/import, create/edit/group, quota/reset and sharing. Client edit GET also
owns a sequence invalidated by a newer open/close. Later edits in users/dashboard
remain after a successful save. Client fields and Form/INI are disabled during
write: POST does not return a new revision, so UI cannot introduce later edits
with the old revision. A programmatically changed draft is also preserved.
The UI saving flag is omitted from API fields; explicit initial false works in CSP Alpine.

## Q03-F006 — Silent failures and overlapping background reads

Dashboard/client/users ignored API `{ok:false}`, showing initial empty datasets
as absence of clients/profiles/users. Polls and visibility callbacks overlapped;
dashboard/users did not clean them up. The shell started green before first response.

Fixed: separate errors/retry, success-gated empty state, last successful snapshot,
latest-response ownership and busy background skips. Metrics have their own sequence.
Users keeps independent freshness/errors for users/groups/profiles/usage. Current
usage/live failure clears unreliable active addresses; an obsolete failure cannot
clear fresh addresses. Malformed collection replies cannot corrupt the snapshot.
Timers, visibility listeners and delayed post-Connect reload are cleaned up on destroy.
Shell status starts Loading; failure shows Unavailable and an error.

## Q03-F007 — Narrow-screen logs search lost nearly all content width

Before: input outer width 46 px at a 390 px viewport (RU/EN), and 46–58.5 px at
768 px; padding left almost no room for text. Search/select now have a base width
and actions wrap. Eight RU/EN × 320/390/768/1440 checks: input 161–320 px and
select within viewport. CSS source and generated app.css were rebuilt by the locked
Tailwind pipeline. Dependencies installed offline with install scripts disabled;
lockfile unchanged.

## Consolidated checks

71 JS groups PASS (34 new beyond prior 37). Eight pre-fix reproductions are retained;
mobile CSS was measured before the fix too. 24 Edge scenarios PASS: 16 scenarios
on four pages RU/EN × desktop/mobile and eight logs widths. Actual repository
UI/assets and loopback API fixtures; not fresh backend auth/persistence evidence.
Error/retry, reverse reads, Enter Submit, modal ownership and single POST covered.
Initial fixture failures corrected selectors, visibility/focus waits and background
refresh versus manual load; FAILED records retained. Browser also caught a newly
undefined saving flag; initial false fixed before release.

Your uncommitted live-users refresh is separately archived. A merge with readSection,
cleanup and no-store retains its editor protection for live user rows. All 71 groups
also pass against merged WIP, plus four checks of editor/pending refresh/manual
priority/destroy. This extension remains uncommitted; certification covers committed tree.

Rust/manifests/native recipes are unchanged: prior 2257 units and native A/B are
explicitly reused, not executed again. Fresh Linux build/checks are recorded in
[evidence](../../../../release/certification/evidence/q03-remaining-20261003.json).
Q03 remains IN_PROGRESS: notifications/quickstart/login and additional config
keyboard/secret/revision scenarios still need completion.

Q03-F005/F006/F007 fresh release SHA `dadbee830fb8e48279dbd83173dbc8db34b7e5bd4cc77df447a9c53885dc9b21`: 18 isolated cases / 327 checks, aggregate leak, 100 TCP + 100 QUIC / 33 checks and bounded shutdown/recovery PASS. Eight pre-fix UI reproductions are preserved separately. Four additional Edge scenarios passed against merged WIP; live-users changes remain uncommitted. Complete snapshots, .11 service PID/start time and its working binary were preserved. Certification 20/20 is refreshed for this artifact; physical rows and older benchmark records are not requalified.

## Q03-F008 — Quick Start: confirmed inputs and saved result

IP mode was reread after GET and confirmation, so confirmed ipv4 could become
ipv6 in POST. Invalid config.profiles threw outside finally and left busy set.
A restart rejection lost the result of an already saved profile. Copy silently
did nothing without Clipboard API.

IP mode is captured before the first await; the selector is disabled while busy.
One finally covers the whole flow. Configuration, revision and returned profile
are checked before restarting. Collision checks retain existing manual binds
and distinguish TCP/UDP. Cancel, stale revision and destroy stop later actions.
Saved profiles remain visible with restart unconfirmed on a rejected or timed-out
restart. Copy reports failure. Result actions wrap on mobile; visual inspection
found Close outside the left edge, and every action's bounds are now checked.
Unused idx/obfMode/reality/padding/heartbeat/shaping/multipath/fronting/quic/AWG
metadata was removed from all ten cards. Rust builds profiles; JS retains only
display and port-collision metadata.

## Q03-F009 — Notifications: revision, draft and test ownership

Fields were editable before GET. init overlapped reads, missing revisions allowed
write attempts, load errors lacked inline retry, and old successful delivery tests
were displayed against already edited chat IDs or URLs.

Fieldsets disable editing until a successful load and on failure; disabled channels
also block keyboard editing. Toggles respect availability. init is serialized
with reads/writes/tests and applies a successful snapshot atomically. Pending
load edits survive; retry retains an unsaved write-only token. Writes require a
revision; stale revisions and incomplete successful save replies require reload
and preserve the draft. A newer token typed during PUT remains after completion.
Channel tests remain independent with duplicate suppression; results are shown
only for submitted credentials. Nested delivery failure remains an error.
Destroy suppresses late state updates and toasts. No external messages were sent.

## Q03-F010 — Login: duplicate submission and malformed responses

The submit handler lacked a pending guard and could send twice. JSON null was
reported as a network error. One request now stays pending; failures/malformed
replies allow retry, while successful login remains disabled until navigation.
Username trimming is retained; passwords including spaces, # and ; are sent
exactly. The error has role=alert. These frontend fixtures do not requalify
backend auth, rate limits or CSRF.

## Q03-F011 — Shared layout: CSP translations and switch state

Edge reported Undefined variable: qeliT/qeliTf in the Quick Start result.
CSP Alpine resolves helpers through component scope, so window globals were
insufficient. The shared app exposes translators to its descendants. The observer
now syncs aria-checked when a .toggle class changes programmatically, including
GET initialization. A .toggle-wrap added as a root node also receives its role,
tabindex and keyboard handler. Attribute observation is limited to class;
aria-checked updates cannot retrigger it.

## Action-batch checks

Eight defects reproduced on original 92509216. 90 JS groups passed (19 new over
71); 12 Edge scenarios passed: three pages × RU/EN × desktop/mobile. Checked
error/retry, Enter/Space/Escape, exact passwords, pending edits, independent
channels, confirmed IP mode, saved/unconfirmed results and mobile actions.
Actual templates/assets run with loopback API fixtures; no real sends, login or
restart occurred. The first browser run found the CSP defect; the first new JS
fixture was corrected to provide window.location.hostname, present in a browser.

Fresh build and common checks are recorded in
[evidence](../../../../release/certification/evidence/q03-actions-20261003.json).
Q03 remains IN_PROGRESS: config draft/revision/identity races and shared
focus/dirty-navigation checks require the next pass.

Q03-F008/F009/F010/F011: fresh release SHA `91d0b877a4eede2e644b6cf1548fffce9901dbe20810d1bd70b2612531585d57`; 18 isolated scenarios / 327 checks, aggregate leak and 100 TCP + 100 QUIC / 33 checks PASS. All 322 input SHAs verified; .11 snapshots, working service PID/start time and binary preserved. Certification 20/20 refreshed for this artifact. Previous unchanged-Rust budget evidence is explicitly retained as reuse, not re-executed. Physical rows and previous benchmarks were not requalified.

## Q03-F012 — Config reads, review and revision ownership (P2)

Form and INI had separate lifecycle implementations. Pending reads could discard
a newer draft; Save did not reserve the confirmation phase, and the write read
expected_revision after the confirmation. Two pending reviews could both write.

Both views now use common read/write paths. One action owns confirmation, write
and restart. Reads require a valid configuration and nonempty revision, publish
a staged snapshot, and preserve newer edits on failure. Canonical defaults failures
are independent. Save captures the draft/revision before review; a changed owner
or revision cancels the write. Successful replies without a revision require reload.
The submitted snapshot becomes the baseline; newer same-owner edits remain dirty.
Cancelled/failed saves and newer drafts prevent Apply & Restart. Only a confirmed
full restart clears the panel-socket restart requirement. Destroy removes the
exact beforeunload handler and invalidates outstanding reads.

## Q03-F013 — Identity and password-hash results (P2)

Identity reads swallowed failures. Older replies could replace newer keys; key
rotation allowed repeated confirmations. A pending hash erased a newly typed
password and installed a hash for the old plaintext.

Identity has visible failure/retry, retains the last snapshot and accepts only
the latest read. Only explicit public fields are retained. Rotation reserves its
action before confirmation and requires the same key owner. Hashing captures the
exact password and config owner; a changed password retains the new plaintext
and rejects the old result. Clipboard failures are visible.

## Q03-F014 — History and profile removal ownership (P2)

An old History GET could overwrite a reopened window. Restore used a later
revision and reloaded over new edits. Remove used the original array index even
if another profile moved into that position.

History sequence/error/retry belongs to its open window. Restore reserves review,
captures revision and refuses changed drafts. New edits during a successful POST
remain visible and require reload, since disk and draft then differ. A clean
restore reloads canonically without automatic restart. Remove retains the profile
object and its reviewed contents, then locates its current index. Closing a child
confirmation with Escape leaves History open.

## Q03-F015 — Shared confirmation focus (P2)

The shared dialog did not move or trap focus and did not restore it afterwards.
It now declares a named modal dialog, initially focuses Cancel, cycles visible
enabled controls with Tab/Shift+Tab, redirects escaped focus, and restores the
initiating control after the caller clears busy state. Replacement prompts cancel
the previous resolver and retain the original focus owner.

## Completion checks — 3 October

Ten independent baseline reproductions are retained for a81bf03e. 116 actual JS
component groups passed, including 26 new groups. Four real Edge scenarios cover
Config RU/EN × desktop/mobile with the actual CSP: error/retry, public keys,
confirmed draft/revision and single PUT, later edits, Form/INI discard cancellation,
History retry/restore/nested Escape, modal geometry and native beforeunload
dismiss/accept. RU mobile confirmation/editor captures were visually inspected.

The initial Node destroy fixture incorrectly borrowed a function from a separate
VM; it was corrected and microtask waits were bounded. Browser fixtures were fixed
to use CSP-compatible function predicates, the correct dangerous-action selector
and a DOM-render wait. These failures do not establish product defects; raw logs
are retained. No real key rotation, login, external delivery or service restart occurred.

All eleven templates and their ten page wrappers were reviewed across the Q03
batches. Duplicate Form/INI lifecycle paths and the obsolete profile-default
fallback were removed; Quick Start metadata now belongs to Rust. Existing tests
retain exact secret/date/quota behavior. Coverage is panel UI/state; backend auth,
CSRF, persistence and transaction failure injection belong to Q04/Q05/Q07.
User live-users WIP remains separate from the committed-tree qualification.

The final browser run uses the production nonce CSP. Secret fixtures follow the real API: Form omits the admin hash; INI retains <unchanged> through a reviewed save. After dismissed navigation the draft remains editable and Save enabled. Desktop RU/mobile EN captures were also visually checked.

Q03 final qualification: release SHA `f5c4bd0a36ba23dd2ba27ec638b5960b19414281f10fec59122f2f009eced199`; 18 isolated scenarios / 327 checks, aggregate leak and 100 TCP + 100 QUIC / 33 checks PASS. All 322 source input hashes verified; complete .11 host snapshots, running service identity and working binary preserved. Certification 20/20 refreshed on the same artifact. Unchanged Rust unit/native/budget results are reuse only. Physical rows and old benchmarks unchanged. [Final evidence](../../../../release/certification/evidence/q03-config-20261003.json).

# Q25-F163: concurrent notification saves

1 October 2026. Base: 7b18608a. D07 remains **IN_PROGRESS**.

The Notifications tab submitted every field. When two tabs read one notify.ini, a later save from the stale tab overwrote the other's changes, including channel disablement and event selections. The shared lock serialized simultaneous requests but did not detect a stale page. A manual file edit between read and write could also be lost.

GET /api/notify now returns a revision of the exact bytes from the same INI snapshot used to read settings. PUT requires expected_revision and checks it before merging. Immediately before atomic publication, the file is reread under its sidecar lock; changed bytes reject the save and leave the notification cache intact. Successful PUT returns a new revision. The panel sends and updates this token, and a conflict tells the operator to reload settings. Test delivery still reads the current INI without saving. Only INI is persisted; JSON is used by the internal API.

On isolated lab .11, formatting, 5 notification-config tests (including a stale tab and manual comment edit), 9 notification-runtime tests, and strict Clippy for default and client-only builds passed. Log: notifyrev2.log in C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase. Local node --check for the template and git diff --check also passed. HTTP E2E was not run on live .10.

An external editor ignoring the advisory lock can still change the file after the last comparison and before rename. That boundary and other mixed save/reload/import paths remain in D07. Register: **5/15 DONE**.
# Q25-F160: INI revision for lockout-policy saves

1 October 2026. Base: cdde58d8. D07 remains **IN_PROGRESS**.

After requiring expected_revision for Quick Start, form, INI editor, and history restore, the separate POST /api/blocked/settings path still accepted stale data. Two tabs could read the same policy and the second would overwrite the first tab's edit. The second disk read before publication only detected changes during that request; it did not detect a stale tab.

GET /api/blocked/settings now returns a revision of the exact bytes of the same trusted INI snapshot used to read the policy. POST requires expected_revision under the shared write lock and returns the new revision after a save. Stale or missing revisions return config_conflict or config_revision_required without writing. The tab and both API scripts send the token; the legacy flat request body remains accepted only with a revision. This changes the internal JSON API; the on-disk config stays INI.

On isolated lab .11, cargo fmt --all --check, 37 editor tests, 4 status tests, and strict Clippy (-D warnings) passed. Local JS/Python syntax checks and git diff --check passed. Logs: blockedrev1.log and blockedrev2.log in C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase. The E2E script now checks stale and missing revisions, but was not run: it stops the systemd service and therefore was not used on live .10.

An external editor that ignores the advisory lock can still change the file after the final comparison and before atomic replacement. That race and the remaining mixed save/reload/import paths stay in D07. Register: **5/15 DONE**.
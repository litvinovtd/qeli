# Q25-F182: iOS profile snapshots for Edit and Delete

1 October 2026. Base: 6848e3ed. D08 remains **IN_PROGRESS**.

iOS ProfileEditorView retained only a profile UUID. If the profile was deleted while the editor stayed open, AppModel.saveProfile could not find that UUID and took the new-profile branch. If its contents changed, an older form could erase the newer edit. ProfilesView Delete confirmation also retained a stale row while AppModel checked only its UUID before deletion.

The editor now passes the original Profile. Before changing anything, AppModel compares the entire entry with the current one at that UUID. Missing or changed entries produce an explicit localized EN/RU refusal without a store write. New-profile creation remains a separate branch only when the editor had no original entry. Delete likewise compares the confirmed snapshot and refuses to remove a newer version. The Q25-F181 reconnect condition is still evaluated after this check.

Both UI call sites, pre-mutation comparison, localizations and git diff --check were reviewed statically. Xcode/simulator is unavailable under the agreed exclusion; no platform UI test is claimed. Cross-process iOS UserDefaults writes and runtime reconnect remain in D08.

Reconciliation on 2 October: [Q25-F210](../../plans/AUDIT-DEBT.md) closes available D08 with iOS single-writer/read-only ownership and explicit external-writer boundaries; 511 .NET, 167 JVM and 12 instrumentation PASS. Earlier counts and pending statements above are historical; Apple runtime is SKIPPED by user decision, not PASS.

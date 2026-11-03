# Q25-F181: iOS notice when an active profile needs reconnect

1 October 2026. Base: 4d74e72d. D08 remains **IN_PROGRESS**.

iOS AppModel.saveProfile allowed INI changes to the active profile while the tunnel ran. Save updated encrypted storage and the list, but Packet Tunnel Provider kept a snapshot of the old configuration; the editor closed without saying to reconnect. Android already displayed that reminder. Users could believe new routes or security settings were active when they were not.

saveProfile now returns whether the active profile text changed during an active tunnel phase. After a successful write, the editor presents a localized EN/RU instruction to disconnect and reconnect. It stays open until acknowledgement. Name-only edits or changes to inactive profiles need no notice. No automatic restart was added, leaving network-policy changes as an explicit user action.

The sole saveProfile caller, active-phase condition, localizations and git diff --check were reviewed statically. Xcode/simulator is unavailable under the agreed exclusion, so UI/runtime behavior has no platform PASS. D08 remains open for iOS concurrent edits, other runtime transitions and device confirmation.

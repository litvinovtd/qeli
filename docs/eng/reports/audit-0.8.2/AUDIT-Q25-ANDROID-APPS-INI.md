# Q25-F193 — Android per-app editor and INI sections

Status: source fixed and JVM-verified on 1 October 2026; emulator UI awaits lab access.

The app picker removed apps_mode/apps lines with a regex and appended new lines at the end of the INI. If [logging] was the last section, the keys landed under logging and the shared parser rejected the save. The apps_mode prefix match could also remove similarly named lines.

A narrow ProfileAppsEditor now changes only exact keys inside [qeli], inserts them before the next section, and preserves comments and unrelated text. Selected package IDs are sorted for stable INI and to avoid a spurious reconnect notice on an unchanged selection. It does not replace the shared parser: VpnConfig.parse and validate still gate persistence. The dialog now catches edit errors as save failures.

Three targeted JVM tests cover [logging] after [qeli], comments and similar key names, and missing [qeli]. Full Android testDebugUnitTest: 167/167 PASS, zero failed/skipped with host native ABI 1.16. assembleDebug PASS. Physical UI/instrumentation for this version has not run; D08/D12 remain IN_PROGRESS.

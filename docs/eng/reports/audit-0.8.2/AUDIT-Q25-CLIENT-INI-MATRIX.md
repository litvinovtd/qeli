# Q25-F197 — shared INI editor matrix

Status: 1 October 2026; full targeted suite PASS on Windows. Product code did not change in this package: no mismatch was found.

A new integration test takes all 84 fields from the actual schema (81 `[qeli]` and 3 `[logging]`), sets an explicit value for each, and checks `import → runtime → import` for equality of the complete value map. Coupled cases use valid settings: `mode = plain`, `mtu = 1400`, and `exit_node = true` with `gateway = false`. This detects dropped fields during client adapter materialization, including file-only settings.

A second test exercises 1000 deterministic combinations of keys and values, including unknown and repeated keys, quotes, spaces and tabs. Every case must survive `import → export → import` with the same typed values and raw entries; runtime-invalid drafts are intentionally allowed by export. Full `config_editor`: 54/54 PASS (`--no-default-features --offline`), rustfmt PASS. This is not coverage-guided fuzzing or a UI/concurrent-write test; D08 remains IN_PROGRESS.

Reconciliation on 2 October: [Q25-F210](../../plans/AUDIT-DEBT.md) closes available D08 with iOS single-writer/read-only ownership and explicit external-writer boundaries; 511 .NET, 167 JVM and 12 instrumentation PASS. Earlier counts and pending statements above are historical; Apple runtime is SKIPPED by user decision, not PASS.

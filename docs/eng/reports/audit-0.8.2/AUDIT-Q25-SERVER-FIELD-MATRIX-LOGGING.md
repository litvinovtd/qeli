# Q25-F152: INI matrix and full restart for logging

1 October 2026. Base: `8ce31599`. D07 remains **IN_PROGRESS**.

The INI codec has matching read/write coverage for 150 fixed keys: 7 in `[auth]`, 23 in `[web]`, 4 in `[logging]`, and 116 in `[profile:*]`. The existing `exhaustive_round_trip_every_server_key` fixture contains every one and compares parsed structures after serialization. Repeatable `listen` and `route` entries and address-reservation keys appear in that fixture and additional tests. This establishes parse/serialize coverage for fixed fields; runtime behavior for every field remains to be verified.

Runtime review found a mismatch in `[logging]`: `level`, `file`, and `time_format` are read before the main config when both supervisor and worker start. After a save, the panel did not classify changes to these startup-only fields as requiring a full restart. A direct `POST /api/server/restart` could therefore restart only the worker. In a container without systemd, Apply & Restart could also fall back to a worker restart. The supervisor kept its old logging settings while the new worker used the new ones.

`needs_full_restart_for_config` now compares these three fields with the supervisor's startup config. Save responses and the worker-restart API require a full restart, and the container fallback is disabled for these edits. `logging.format` remains a documented inert compatibility field: `json` does not make a JSON config or change log output, so restarting cannot make it effective.

On isolated lab .11, two focused restart-selection and live web reload tests, the exhaustive INI round-trip, 36 editor tests, `cargo fmt`, and strict Clippy passed. Logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/loggingrestart1.log` and `loggingmatrix2.log` in the same directory. No services were started or changed.

The field-to-runtime/validation matrix for other sections, mixed save/reload/import flows, and the external editor race without the advisory lock remain open. Register: **5/15 DONE**.

# Q25-F165: client autostart and diagnostic bounds

1 October 2026. Base: 2b0f294f. D08 remains **IN_PROGRESS**.

At supervisor startup, autostart inspected each client INI through unbounded read_to_string. The Client page checked status.json size through metadata and then reopened the path, allowing replacement between those operations to bypass its 64 KiB limit. Connect and Delete did not share the Save/Import lock, so simultaneous panel requests could start a tunnel during deletion or remove a newly saved file.

Autostart now reads one stable regular file within the shared 256 KiB client INI budget. Status uses one stable snapshot bounded to 64 KiB; invalid or oversized status is ignored and the prior log fallback remains available. Connect and Delete are serialized with Save/Import by the panel mutex; Delete also takes the sidecar lock before removing the file. Deletion still stops the process first even if the profile file has disappeared. A failed Disconnect leaves the file intact.

On isolated lab .11, rustfmt, one autostart test, seven client API tests and strict Clippy for normal and client-only builds passed. Log: clientbounds2.log in C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase. git diff --check passed locally. No live-tunnel HTTP E2E was run; .10 was unchanged.

Stale Delete revisions, application of a changed INI on reconnect and other adapters remained for D08. Manual editing without the advisory lock is an external D07 race.

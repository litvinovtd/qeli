# Q25-F159: stable ordering of dynamic INI fields

1 October 2026. Base: `4c06ad18`. D07 remains **IN_PROGRESS**.

Five `HashMap` iterations in the server INI serializer wrote fields in unpredictable order: group sections in both the main server INI and standalone users database, profile IPv4/IPv6 reservations, and user metadata. Re-saving a semantically identical configuration could change its text, create an unnecessary history entry, or conflict with an editor revision.

All five collections are now sorted by key before writing. User and profile list order is preserved. Two regression tests compare identical configurations built in opposite insertion orders and check both exact output and sorted dynamic keys. On isolated .11, `cargo fmt --all`, both tests, and strict Clippy (`-D warnings`) passed; log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/iniorder2.log`. Installed services were unchanged.

The remaining server-field/path runtime matrix, mixed save/reload cases, and the narrow race against a manual editor between the last revision check and atomic publication remain under D07. Register: **5/15 DONE**.

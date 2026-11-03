# Q25-F162: INI-only notification settings with bounded loading

1 October 2026. Base: 26c98ac1. D07 remains **IN_PROGRESS**.

Review of the separate notification config found residual notify.json parsing and automatic migration to notify.ini, contrary to the established INI-only config contract. notify.ini itself was read without a size or regular-file check: a malformed or substituted path could block reading or consume excessive memory. A save could also create an INI larger than the loader would subsequently accept.

The JSON config is no longer parsed or migrated. If INI is missing while an old notify.json is present, loading reports an explicit error without changing either file. The shared descriptor-stable INI loader now caps reads at 64 KiB, and saves reject larger serialized output before writing. Portable backups omit the old sidecar; archive restore rejects one that contains it. The internal JSON API and webhook messages remain.

On isolated lab .11, 4 notification tests, 27 ordinary backup tests, formatting, and strict Clippy for server and client-only builds passed. Both native root backup/restore tests also passed again inside a separate namespace. Logs: notifyinionly2.log and notifyinionly3.log in C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase. The live .10 service was unchanged.

An existing notify.json is not deleted automatically, so an administrator can transfer any needed credentials to notify.ini before removing it. Concurrent notification saves from two tabs and the external-editor race remain further D07 work. Register: **5/15 DONE**.
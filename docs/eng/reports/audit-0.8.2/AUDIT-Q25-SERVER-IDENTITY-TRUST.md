# Q25-F143: trust boundaries for identity_key and logging.file

1 October 2026. Base: `7be8bd74`. D07 remains **IN_PROGRESS**.

`identity_key` lets a config direct creation or replacement of a private key to an arbitrary path. Worker/supervisor and CLI `show-identity`, `rotate-identity`, `add-client --link`, `share-link` used the path even from a group/world-writable or symlink config; the shell-hook prohibition did not cover it. A safe `.11` lab baseline returned `OK` from `check-config` for mode `0666` with an explicit `identity_key`; the baseline did not write a key. Separately, `[logging] file` was opened before main validation, allowing an untrusted config to control log-file creation.

The new `ConfigSourceSnapshot` carries contents and trust from one opened inode. For explicit `identity_key`, CLI and both startup paths require a regular non-symlink file owned by root or the effective UID, without group/world write. Rejection precedes key writes and, for `add-client --link`, the user write. `check-config` applies the same admission rule. The early logger ignores `logging.file` from an untrusted file, warns on stderr and continues logging there without opening the requested file/directory. Default identity paths derived from safe profile names remain available without an explicit `identity_key`.

Verification: unit tests for trust persistence after chmod and early logger behavior; `cargo fmt --check`, strict Clippy; Linux CLI rejection matrix for `check-config`, `server`, `_worker`, `show-identity`, `rotate-identity`, `add-client --link`, `share-link` at mode `0666`; no key, log or users file created; then a positive mode-`0600` check and a private key with mode `0600`. Logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/identitytrustbaseline.log` and `identitytrustfixed.log`.

This is not a general ban on all filesystem effects from an untrusted INI: `users_file`, TLS and other settings need separate D07 review. The full field matrix and external-write race in panel saves remain open.

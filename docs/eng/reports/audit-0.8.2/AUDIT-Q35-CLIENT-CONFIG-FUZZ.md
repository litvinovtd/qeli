# Q35 — client INI and qeli:// fuzzing invariants

<!-- normative-sync: audit-q35-client-config-fuzz-v1 -->

On 10 October 2026 the `client_config` fuzz target was strengthened. Previously it fed arbitrary bytes to the client INI parser, editor JSON service and `qeli://` decoder but discarded successful results: silent loss on reserialization was not an oracle. The editor's service JSON API remains; INI is still the only configuration format.

For inputs up to 8 KiB, the target now checks the fixed point `parse → canonical INI/URI → strict reparse → reserialize`. Each input also derives structured INI and `qeli://` examples with IPv4/IPv6, TCP/UDP, all three roaming policies, percent-encoded `%`/`:` in the password, and a label. The URI checks the exact user, password, port and roaming policy. Larger inputs still reach the original parsers and editor without the extra serialization. The new oracles can expose silent behavioral drift without making large fuzz inputs expand repeatedly in memory.

The changed target built under pinned `nightly-2026-06-10`, `cargo-fuzz 0.13.2` and ASan in isolated lab .11. Seven initial seeds were replayed, followed by **18,494 fuzz runs in 61 seconds** with no new crash artifacts. Fuzz lock SHA256 remained `cc451c34452ab43cdf475b7a915c8fbdc16b825d2ee262bd3903eeb6f92355f4`; target source SHA256 was `426b5ea87dfa1803de19fdd30480e0c7c91ad501ce20e51d1f557827bdc702c3` and target binary SHA256 was `ada8d0616654d1a2ceb16b9e6900ccb4020c7863c57d87c0bfec6496c2ce664b`. All 701 final corpus files, logs and receipts were preserved as 723 SHA-verified evidence files. A previously sealed source-input archive was reused; the other 14 targets were not rebuilt.

The first local evidence collector stopped with a `SyntaxError` from incorrect `try` indentation after the successful fuzz run and before any server modification. That refusal is retained; the corrected collector preserved the evidence. The owned lab root was removed after process, open-descriptor, mount, service and `/usr/bin/qeli` SHA checks; `/var/tmp` space was recovered. Service PIDs remained 777/845 and the host's initial and final state matched.

This qualifies one strengthened target for a one-minute run, not the complete nightly, a proof of parser safety, or completion of Q35. Overall status remains **30/37 DONE (81.1%)**, Q35 `IN_PROGRESS`. Local out-of-Git raw packet: `audit-debt-20260924/q35-client-config-fuzz-20261010`. `LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE`.

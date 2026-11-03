# Q35 — UDP fragment reassembly fuzz oracles

<!-- normative-sync: audit-q35-fragment-fuzz-v1 -->

10 October 2026. Scope: `qeli/fuzz` targets `data_frag` and `udp_frag`. The production reassemblers and wire formats did not change. Previously `udp_frag` mostly fed arbitrary headers, while `data_frag` discarded reassembly results; its conflict mutation could also miss the first fragment.

`data_frag` now checks exact output under forward/reverse delivery, duplicates, reuse of a completed record ID, a correctly authenticated conflicting first fragment, invalid MAC without poisoning a partial record, and the 32-record/512-KiB limits. It also checks that refusal frees capacity for a subsequent complete record. `udp_frag` derives valid messages of up to 24 fragments, checks reorder/duplicate/exact output, conflicting fragments, the historic 1200-byte receive limit, rejection above that limit, and recovery afterward.

Both changed targets built with pinned `nightly-2026-06-10`, `cargo-fuzz 0.13.2`, and ASan in isolated lab .11. Fourteen initial inputs per target were replayed. `data_frag` completed **9,630 runs in 61 seconds**, `udp_frag` **237,183 runs in 61 seconds**; no new crash artifacts. Independent fuzz lock SHA256 stayed `cc451c34452ab43cdf475b7a915c8fbdc16b825d2ee262bd3903eeb6f92355f4`. Binary SHA256: `data_frag` `e5db62dd7ebce460985ff1c8369ee03ebeda6024c1f19d7c3df351d2183a77c3`; `udp_frag` `722a490e115aa5c3ada46decb4751edec98a087bbe52725679bba29db1537402`.

The first harness run failed with `RecordTooLarge`: it generated a 32-KiB record where the actual maximum is 16,645 bytes. The intermediate retry stopped on an existing corpus directory (`FileExistsError`). Both failures are retained, and neither is counted as a product bug or a passing run. The final run used a valid 16-KiB + 1-byte record. The 300 selected inputs, corpus files, logs and results were archived and SHA verified. The private lab root was removed after process/fd/mount ownership checks; service .11 retained PIDs 777/845 and the binary SHA. Generated Cargo/rustup caches were removed. The other 13 previously qualified fuzz targets were unchanged and not rebuilt.

Limit: this qualifies the two changed targets, not a 10-minute nightly, exhaustive DoS coverage, or extended VPN soak. Q35 stays `IN_PROGRESS`; overall audit remains 30/37 DONE with seven sections open. Local raw evidence: `audit-debt-20260924/q35-fragment-oracles-20261010`. `LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE`.

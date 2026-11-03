# Q25: Linux CLI and network recovery — final

<!-- normative-sync: audit-q25-linux-cli-final-v1 -->

**DONE/PASS. Overall plan: 25/37 (67.6%), 12 remaining; next Q26.** 4 October 2026.
[Evidence](../../../../release/certification/evidence/q25-cli-20261004.json).

Two confirmed [F216/F217](AUDIT-Q25-CLI-BOOTSTRAP.md) defects were fixed: both startup entry points and `check-config --client` use bounded INI reading; client logging uses the shared strict parser and snapshot trust; a shared regular-file sink helper rejects FIFO. The standalone partial parser and duplicate sink opens were removed. The manual was updated. Configs remain INI only, with internal JSON API retained. Shared data plane, wire, config keys and C/JNI ABI are unchanged.

| Layer | Review and evidence |
|---|---|
| Entry points/feature gates | `qeli client`, `qeli-client`, `check-config --client`, shared parser/config_source and early logging; Linux-only wiring, both real builds and all-target Clippy. The dead partial parser was removed; no other confirmed dead production implementation was found in this pass. |
| INI/file contract | 7 new unit regressions; 12 baseline FAIL; 26 final CLI scenarios / 68 checks PASS. INI/log FIFO, exact 262144-byte bound, unknown/malformed, permissions/symlink, mixed-case, missing/directory, nonzero error exit and append. |
| Routes/DNS/firewall/TUN | All 348 compilation inputs match; only 4 bootstrap/entry-point files changed/added. Shared Q24 `client/mod.rs` is an exact prefix; 71 network inputs are unchanged. Closed Q14/Q17–Q24 and D01–D05/D09/D10/D13 applicability was reconciled against source. |
| Failures/concurrency/recovery | Earlier 152 mixed-firewall cells / 136 crash-recovery cases, namespace/TUN identity, leases, joined hooks/writers, 15-second setup/cleanup budgets and honest terminal status retain original dates/scopes. They were not fully rerun. Fresh private NET/mount/PID library suite: 2414 PASS, 60 ignored. |
| Actual integration | The fixed debug daemon passed TCP IPv4 full and dual-stack UDP split: 2 scenarios / 32 checks PASS, real AUTH/TUN/routing/stop and cleanup. Complete private/host snapshots matched. The dedicated full leak matrix/100-cycle soak was not rerun; subset aggregate_leak_passed=false remains explicit. |
| Build contract | 4 fresh independent native A/B pairs PASS, byte-identical to Q24; all canonical/consumer copies, 14 SHA256SUMS and provenance verified. Earlier 22 Windows ABI and 23 actual Android JNI checks therefore apply to the same bytes; no new emulator execution is claimed. |

Final build, CLI, desktop/Android A/B and connected wrappers passed strict host-state comparison without excluding firewall rules. Initial FAIL runs remain: external `vpn-nat` changes three legacy rules while `vpn-obfuscated` cycles through restarts; the current journal identifies the actor. Running Qeli PID/binary were preserved. Those external services were not fixed or stopped.

The private Android SDK was temporarily archived to make build space. Every payload SHA was checked before removing the expanded copy and after restoration; all file SHA/size/mtime and both AVDs were preserved. Only a verified inactive private Cargo cache and temporary archive were removed; sources, CLI candidates and raw failures remain.

Accepted D06 WAN identity and safe manual recovery boundaries for legacy DNS/persistent TUN/lost sysctl witnesses remain. Replacing the selected WAN requires stopping the profile and confirming cleanup. Arbitrary root rewrites are not certified. Router/Mac/iOS/Windows VM network runtime is excluded by the user; missing runtime is not PASS. No new peak benchmark, full release preflight, push/deploy. Raw artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q25-cli-20261004/`.

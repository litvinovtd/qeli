# Q33: final installation, update, file and hook reconciliation

<!-- normative-sync: q33-completion-v2 -->

8 October 2026. Q33 complete within agreed scope. F449/Q33-F052 and F450/Q33-F053 closed; real two-HTTP-restore retained-hook reproduction and fixed startup/later worker generation checks pass. Exact results and limits follow.

## Final fix

An unchanged hook `sh /etc/qeli/../qeli/owned.txt` executes `owned.txt`, but the old collector protected only `..`. An archive keeping INI unchanged while replacing a non-executable-bit script passed this gate. The exact original Linux collector reproduction returns `..` and fails the `owned.txt` protection assertion. This reproduces the collector, not HTTP exploitation or execution of a malicious hook.

Restore now protects top-level entries from the original path, normalized path and resolved existing prefix. This covers outside aliases and missing future files under a linked directory; alias and target are both protected. Quote/space escapes preserve the real filename. An additional raw scan retains direct-literal protection through nested `sh -c`. Unknown variable/glob top-level literals inside `/etc/qeli`, or reads of the entire managed root, conservatively refuse publication.

The Linux gate uses the actual production helper and `vet_staged_dir`: four refused replacements preserve live/staged bytes, while an ordinary external hook permits data-only validation. Unreachable `.conf/.ini` branches in the standalone wrapper have explicit panic seams; server Cargo tests verify integration without those seams. No hook executes in this reproduction.

Limit: static collection is not a shell sandbox. Paths constructed entirely from variables, runtime `cd`, external-program dependencies and unsynchronized concurrent administrator symlink replacement cannot be completely analyzed. Keep executable hooks and their dependencies outside the managed backup tree. [Restore rules](../../manuals/OPERATIONS.md).

## Q33 coverage without repeating unchanged scenarios

| Layer | Qualified coverage | Evidence / limit |
|---|---|---|
| Command source | Same trusted descriptor for INI/owner/mode, snapshot cleanup; bounded password-command/hooks | [Config trust](AUDIT-Q14-Q33-CONFIG-TRUST.md), earlier Linux hooks/file-IO/budget runs in [debt registry](../../plans/AUDIT-DEBT.md). Hooks intentionally execute trusted operator code |
| Installer | Metadata/arch/version/dependencies; private staging, configs/identity/users/panel, secret journals, error propagation, ownership transition | [Admission](AUDIT-Q33-INSTALLER-ADMISSION.md), [secrets](AUDIT-Q33-INSTALLER-SECRETS.md), [config](AUDIT-Q33-INSTALLER-CONFIG.md), [CLI](AUDIT-Q33-INSTALLER-CLI.md), [service user](AUDIT-Q33-SERVICE-USER.md) |
| Update / Debian | Actual dpkg fresh install/upgrade/downgrade/rollback/remove, installed identity and health, retained state | [Updater](AUDIT-Q33-SERVER-UPDATER.md), [lifecycle](AUDIT-Q33-DEBIAN-LIFECYCLE.md), [binary](AUDIT-Q33-BINARY-INSTALLER.md), [real package manager](AUDIT-Q33-PACKAGE-MANAGER.md): 36 actual checks |
| systemd / full installer | Actual manager sandbox/capabilities, reload/root transition, bad-INI recovery, genuine production release ELF/DEB; binary/deb installer 24 + 24 actual checks | [systemd](AUDIT-Q33-SYSTEMD.md), [package manager](AUDIT-Q33-PACKAGE-MANAGER.md). No whole-install/account rollback or power-loss durability claim |
| Kernel / VPN | Partial tuning restores original values/files, failed probing is not PASS; 18-scenario/376-check TCP/UDP4/6/TAP/DNS/MTU/legacy/leak matrix | [Package manager](AUDIT-Q33-PACKAGE-MANAGER.md), real release pipeline gate; original host settings/services preserved |
| Docker | Production runtime image/owned daemon/private NET, volumes/root0600/readonly, pinned H1 VPN fresh/recreate/known-image recovery, 6 graceful exits; publication policy 7 checks | [Docker](AUDIT-Q33-DOCKER-ENTRYPOINT.md): 26 runtime checks. Compiler stage/multiarch/current Actions/registry attestation remain release qualification, no claimed publication |
| Backup / files | Archive trust/integrity/budgets/locks/cancellation, per-file publication/exact prune, separated state keys, filesystem EIO/ENOSPC/EACCES, earlier native/runtime validation | [Q07 completion](AUDIT-Q07-BACKUP-RESTORE.md); F449 adds alias/quote/dynamic-literal protection. No whole-tree atomicity/automatic rollback/fsync certification |
| Dead code / harness | Removed obsolete updater URL/cache branch and four destructive/status-ignoring Docker harnesses; scoped resource ownership/status/cleanup | Updater/admission/Docker reports. Original harness FAILs remain recorded |

## Final-source verification

Targeted helper/gate: Linux 14 PASS. Raw retains original collector expected FAIL, intermediate 12/13 PASS, UTF-8 standalone fixture error and fixed 14 PASS. Two intermediate-source native qualifications were stopped only for owned compiler PIDs after cwd/root guards; rc143 is retained, not a product failure or PASS. Full Cargo failures are retained: missing conformance fixtures in the first transfer, one old test using an incompatible empty set, and an IO test launched without its required private-FS/preload setup. The test adapter and fixture transfer were fixed; IO runs separately with the real shim in private MNT/NET/PID. Initial stop approval review timed out; read-only inventory and safe retry were separate.

Current Linux source e8f5469e: actual CLI build/bin5/backup49 PASS, including two privileged archive tests; standalone14 PASS; the separately isolated IO method passes twice (normal/cancel), heartbeat180/179 and ~2seconds intercepted read each. Full Clippy -D warnings/rustfmt PASS; recipes38 PASS. ELF SHA256 c098a9899ae41042d8ad19ff211aefba1dfed020b753ca33c3dddfbd74f9f289, 78712856 bytes. HTTP exploitation/end-to-end malicious hook execution were not run; publication gate and existing native roundtrip are qualified.
Fresh independent A/B builds PASS for Windows/macOS universal2/Android arm64+x86_64 from e8f5469e, native source digest8d1cc8fa. Six actual compiler commands use fresh separate A/B targets, offline private registries/caches, jobs1 and panic=unwind. Export gates6Reality+22client (+21JNI Android) PASS. All14 SHA/canonical-consumed pairs/provenance PASS; actual refreshed Windows DLL22 C ABI/control/localhost-runner checks PASS (no Wintun/OS routes). New library bytes are recorded; previous ABI results are not relabeled as executions on these files. Mac runtime/iOS/firmware remain USER_EXCLUDED; no new Android full runtime/soak/benchmark claim.
`q33-hook-restore-20261008`: SEALED 133 files / 160469796 bytes; manifest SHA256 `e11346af579035340f8446e1f9917db7ffa9bf87cbd400c827c7b4143fd37c03`.

## Retained hook: F450 / Q33-F053

Real HTTP requests against the e8f5469e ELF confirmed the chain: a ready worker retains `post_down = sh /etc/qeli/owned.txt`; the first overlay restore clears the command in INI, the second publishes another `owned.txt`, and stopping the original worker executes the replacement. The harmless marker reads `replaced`. This is an actual runtime reproduction, in private MNT/NET/PID with private `/etc/qeli`, `/var/lib/qeli` and `/tmp`; the lab service remains intact.

The fix retains commands from the startup snapshot and configurations read by the supervisor before each worker launch. References conservatively live until supervisor exit: removing a command/profile from INI or retiring a worker does not release them. Restore combines retained commands with current INI. The first safe overlay remains allowed; replacement in the second returns HTTP400 before snapshot/publication. Exact restore also refuses deleting a protected top-level entry, including a directory containing a nested script.

Current Linux source aa98f208: actual CLI build/bin5/backup50, retained-generation1, post_down3, separately isolated private-FS/preload IO2 and Clippy -D warnings PASS. Runtime: baseline6 expected-vulnerability checks, fixed8 and fixed-later10 PASS. The last scenario manually changes the command and restarts only the worker through the real API; the supervisor survives, the new generation becomes ready, and after two restores shutdown executes `original`. Checks cover exact refusal before publication, preserved script and successful safe overlay. The marker exists only in the owned fixture. Linux ELF SHA256 `73af3c9e60b23c17f994f87a198184fc6f624fb6f96f90af7ae5b7877bff5b2b`, 78778192 bytes.

The initial baseline fixture failure is retained: inherited `/sys` displayed host interfaces, causing a false ready assertion. Checking actual `ip link` inside private NET fixes the fixture; the first run counts neither as product failure nor PASS. Repeated baseline confirms the full chain. An early Android cleanup invocation before artifact downloads completed refused on missing local result.json before SSH/deletion; it was retried only after PASS. Original root777/845 and installed ELF75bc remain; a SHA-verified recoverable archive was downloaded before guarded cleanup.

Fresh independent A/B PASS for Windows/macOS universal2/Android arm64+x86_64 from aa98f208, native source digest374be1f4. Six fresh build-command batches, separate A/B targets/private offline registry/caches,jobs1,panic=unwind; exports6Reality+22client (+21JNI Android), all14SHA/canonical-consumed pairs/provenance PASS. Actual refreshed Windows DLL22 C ABI/control/localhost-runner checks PASS; no Wintun/OSroutes. New native bytes are recorded, old ABI/runtime results are not relabeled. Mac cross-build emits retained missing-xcrun/SDK warnings; real Mac/iOS runtime remains USER_EXCLUDED, no new Android full runtime/soak/benchmark claim.

`q33-retained-hooks-20261008`: SEALED 112 files / 167439176 bytes; manifest SHA256 `b817b3916307f8b7ad20d6f07dda0bae0ce99fc1430c34337451370d9e4bb3bc`.

## Q33 conclusion and limits

All five Q33 criteria are complete within agreed scope: review/dead code; positive/boundary/negative; failures/concurrency; Linux target integration; fixes/retest/evidence. The table above preserves exact sources and limits of previous installer/package/systemd/Docker/VPN runs: those payloads were not rebuilt for F450, and earlier results are not relabeled as executions on the new ELF.

Q33 DONE. Overall30/37 DONE (81.1%),7 remain. No new mandatory debt from this item. The static hook collector is best-effort for literal paths, not a shell sandbox: entirely variable-built paths, runtime cd/external dependencies and unsynchronized admin edits between supervisor/worker reads are not qualified. Keep hooks outside `/etc/qeli`; conservative protection can last until full supervisor restart. Whole-tree atomic restore, automatic rollback, power-loss/fsync and empty OS bootstrap are not claimed. Multiarch compiler/registry/current Actions/release attestation remain in Q34, not PASS.

Historical debt14 DONE + D06 ACCEPTED_LIMITATION; Q29 SIGKILL FAIL/ENONET, Q30 Apple/callback, Q31 3/5/capacity/source-cut and user platform exclusions are preserved. No push/deploy/release.

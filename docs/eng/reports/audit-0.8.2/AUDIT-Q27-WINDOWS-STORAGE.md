# Q27: Windows archives and service profiles — stage PASS

5 October 2026. Base `e981c8c5`; Windows, .NET SDK 10.0.300.
Full Q27 remains **IN_PROGRESS**; plan total **26/37 (70.3%)**, 11 sections remaining.

<!-- normative-sync: audit-q27-windows-storage-v1 -->

## Confirmed defects

| Finding | Reproduction and fix |
|---|---|
| Q27-F222: unused backup | Windows kept the previous encrypted generation in `.bak`, but corrupt latest data was quarantined and returned an empty list. After successful quarantine it now recovers a structurally valid backup and atomically republishes a DPAPI CurrentUser archive. Legacy backups use the existing migration. Recovery write errors propagate. Stale-revision checks and the sidecar lock remain. |
| Q27-F223: inconsistent service limits | SaveProfile could publish a blob exceeding 4 MiB that LoadProfile refused. The writer now checks plaintext and the final DPAPI envelope before publication. The reader enforces the budget during streaming, replacing initial Length plus unbounded CopyTo. Status is capped at 64 KiB, intent at 16 bytes; status messages at 2048 characters. This is a local protected-storage boundary, not a demonstrated remote attack. |
| Q27-F224: lossy UTF-8 and required nulls | Encoding.UTF8 replaced invalid bytes in authenticated profiles; service deserialization accepted required fields containing null. Strict UTF-8 and shared ProfileStorePayload.Validate reject them before UI/native use. Only cryptographic failure selects legacy; System policy still forbids plaintext. |

The DPAPI codec now has a path-scoped WindowsProfileArchive using the same production
ProfileStoreFile. Tests never open real APPDATA or ProgramData. Temporary decrypted
and serialized byte arrays are cleared in finally; immutable strings and internal
serializer buffers are not claimed to be completely erasable.

ServiceStatus now uses the same directory/owner/DACL/reparse checks as other service
files, reading one handle that permits atomic rename. This is trust-consistency
hardening; an installed-service ACL exploit was not reproduced. Service/autostart
registration require protected executable paths; owned DLL extraction refusal forbids
fallback. Existing guards were reviewed and selftested without installing/changing SCM.

## Checks

- **184/184 Windows selftests PASS**, 0 FAIL/SKIP; 41 added assertions:
  21 archive + 20 service storage. Real DPAPI CurrentUser/LocalMachine;
  corruption/backup/legacy/ID/strict UTF-8/null, stale writer, blocked quarantine and
  migration, exact 4 MiB, envelope overhead, growth stream and status/intent caps.
- **543/543 shared conformance PASS**, mandatory fixtures enabled, 0 FAIL/SKIP.
  Shared structural validation preserves archive behavior.
- Release Windows/shared/Mac builds: 0 warnings/errors. Mac is compile-only on Windows;
  no Keychain/daemon/macOS runtime execution.
- Isolated old production Load/Save/decoder/reader adaptation reproduces **5/5 expected
  FAIL**: backup, encrypted UTF-8, required null, writer limit and streaming limit.
  Paths/System identity become test arguments; original bodies are retained. The
  streaming control reports initial Length=1 then grows; it does not demonstrate a
  normal Windows file-handle race when opened without FileShare.Write.
- Both pinned Wintun 0.14.1 DLLs: hash, Authenticode signer/thumbprint and licenses PASS.
  Initial script execution was denied by local execution policy; the retry used
  process-only ExecutionPolicy Bypass without changing system policy.
- RU/EN docs, panel, generated bindings, diff and native provenance/checksums checked.
  Rust/native inputs unchanged; no new native A/B, Linux network matrix or benchmark.

Raw: `audit-debt-20260924/q27-windows-store-20261005` under the shared workspace;
machine-readable evidence: `release/certification/evidence/q27-windows-storage-20261005.json`.
The first three baseline harness failures (desktop reference/import/native DLL resolver)
remain preserved; only r4 reproduces production regressions, exit 1.

## Remaining Q27 scope

GUI service/profile transitions, autostart/SCM error reporting and remaining driver
adapters need completion of review and available fault checks. Windows VM network,
sleep/wake and boot service runtime are **SKIPPED by user decision**, not PASS.
Selftest loads the Wintun DLL but does not qualify driver installation, live routes,
DNS/firewall or a VPN connection. Running services/native binaries/lab were unchanged;
no push/deploy. Configs remain INI; internal JSON DTO/storage remains authorized.

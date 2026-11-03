# Q25: preserve the legacy DNS recovery record after failed restoration

Date: 23 September 2026. Baseline: `95f4bce6`. Sections 19/25: **IN_PROGRESS**.

**Q25-F006, P2 — legacy resolver recovery could report success without restoring it.**
The absent-original branch ignored remove_file errors and used exists(), which follows
symlinks: an undeletable resolver or dangling symlink could remain while recovery reported
success and removed its backup. The regular-file branch also ignored permission-restoration
errors and interpreted missing content as an explicitly empty original.

Legacy filesystem restoration now lives in one host-testable module, used directly by Linux
DNS recovery. It checks deletion and permission results, accepts only NotFound as an
idempotent unlink success, requires file content, and validates symlink targets before
removing the current resolver. The backup is retired only after successful restoration.
Backup-removal failure is reported separately. Explicit empty files, relative Unix symlink
targets and the existing managed-no-original recovery fallback remain compatible.

This handles existing recovery snapshots from older releases. New sessions continue to use
per-link systemd-resolved configuration and do not write /etc/resolv.conf directly. Client
configuration remains INI; the pre-existing internal recovery record is not a config format.
Unsupported Unix symlink restoration in host tests returns an error before modifying files.

## Validation

Eight Windows host tests exercise real temporary files: successful and empty file recovery,
absent-file removal, a deterministic unlink failure (directory with a sentinel), missing or
invalid payloads, failed atomic replacement, malformed snapshots, fallback compatibility and
unsupported symlink handling. Failures verify that the exact backup bytes remain available.
Three additional Unix tests cover dangling-link removal, relative links and original modes;
they were cross-compiled, not executed here. Existing Linux DNS tests consume the same module.

**842 host unit + 52 editor/policy + 7 examples + 12 server INI = 913 Rust tests PASS.**
Linux all-targets Clippy, client-only, server-only, minimal FFI, rustfmt, nine docs checks and
diff checks pass. The existing chunks_exact_to_as_chunks Clippy allowance and 23 server-only
transport warnings remain. No real resolver, firewall or VPN state was changed; no Linux
E2E, SSH, systemd restart, GitHub Actions or benchmark was run.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/dns-backup-audit-20260923.

## Remaining work

Synchronous DNS/firewall command bounds and legacy recovery concurrency need further audit.
Symlink restoration still has an unlink/recreate window; a later failure preserves the
backup but cannot promise an unchanged resolver. Lower-level TunGuard/NetworkPlan rollback
errors and normal data-plane cleanup errors still need end-to-end propagation to the retry
loop. This pass does not close those lifecycle findings or the full system audit.

Follow-up: [TUN cleanup audit](AUDIT-Q25-TUN-CLEANUP.md) propagates explicit resource and rollback-guard failures to the client stop policy. Live Linux E2E and complete task shutdown remain open.

Follow-up: [Q25-F101](AUDIT-Q25-LEGACY-DNS.md) closes legacy global DNS through refusal of automatic replay and manual migration. An old snapshot does not prove ownership of the current resolver; automatic restore/refcount and their test implementations were removed. Historical results above describe the earlier behavior.

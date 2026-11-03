# Q25 — shared client DNS application deadline

<!-- normative-sync: audit-q25-dns-budget-v1 -->

Date: 24 September 2026. Base: `2d4837b91a7147a3d88b9d5559da2c32b39261c1`.
Partial closure of D05 in the [debt register](../../plans/AUDIT-DEBT.md).

## Q25-F084, P2 — every command renewed the DNS setup deadline

`setup_network_plan_dns` runs `resolvectl dns` followed by `resolvectl domain`. The shared
runner limited each command to 15 seconds, but the second received a fresh deadline.
Time spent checking the original TUN also did not reduce the next budget. Setup could
therefore continue changing resolver state after the expected overall deadline.

The deadline is now created once on DNS setup entry, before validation, file checks
and lease acquisition. Both commands use `output_until` with that deadline. Expiry
before the next target check reports `DNS setup command budget exhausted`; expiry during
a target probe also prevents launching the command. Each stdout/stderr stream retains
its 16 MiB limit, and the shared runner terminates and waits for children. There are
no new INI keys or ABI changes.

Partial failure does not remove the marker or imply that no changes occurred. The
generation owns its lease before the first mutation; only its guard may perform later
`revert`, with a separate 15-second command deadline. Setup expiry does not consume the
rollback budget. Unconfirmed revert keeps the marker under the existing contract.

## Validation

Three new Linux regressions use the existing serialized `resolvectl` replacement fixture;
they never invoke the real resolver or host networking. Application steps use the
production runner with real finite shell/sleep child processes.

1. DNS takes 150 ms and domain takes 700 ms within a shared 600 ms budget. Domain is
   interrupted, success is refused and the marker remains byte-identical. Separate owned
   revert succeeds and removes the marker only after confirmation.
2. An already expired budget starts neither a target probe nor a command.
3. Delaying the second target probe until expiry prevents domain from starting; the
   command log contains only the first DNS application.

A counterfactual restored only the previous `.output()` call in place of
`.output_until(until)`, retaining the new tests and additional pre-step budget check.
Both regressions (shared deadline and delayed target) failed as expected with exit 101;
the original source file was then restored byte-for-byte. This isolates the old behavior,
not a full run of the previous commit. Logs: `dns-budget-counterfactual/`.

**1468 host unit + 71 config integration PASS**, all nine feature/cross/lint commands
PASS. The new DNS tests execute on Linux: **1935 ordinary + 29 privileged PASS**.
**8 worker lifecycle E2E PASS**: TCP/UDP × off/manual/route/nat66. Worker E2E verify the
broader lifecycle regression; the three tests above verify the new DNS deadline,
not the server matrix. Tests ran on `.11` in private namespaces; the running `.10`
server and its configs were unchanged.

Linux Rust 1.97, host Rust 1.98. Linux worker SHA256:
`bfbe2240547d91ef0bff4dd6e9c1968c75952b65f5557945e2e8177a4b8dbddf`.
Source archive SHA256: `422e276ac55e484f5156877e62ca6e410e482e8c6f75143930cde8f676100c7a`
(306 `qeli`/`conformance` files, pre-commit snapshot).

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/dns-budget-phase/`,
`dns-budget-final.log`, `lifecycle-dns-budget/`; commands, manifests and exit codes are saved.

## Remaining boundaries

The 15 seconds bound command admission/waiting in this sequence, not all of connect or
disconnect. Synchronous file I/O, spawn, kill/reap and uninterruptible kernel waits do not
receive a hard wall-clock bound. Actual D-Bus/systemd-resolved context, external DNS
queries and remote resolvers remain D06/D10 work. Whole NAT/routes/kill-switch sequence
budgets and other lock waits remain D05; this result does not close the full section.

[Original command runner](AUDIT-Q25-SYSTEM-COMMANDS.md) ·
[Troubleshooting](../../manuals/TROUBLESHOOTING.md) · [Configuration](../../manuals/CONFIG.md)

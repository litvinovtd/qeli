# Q25-F130: server worker admission after forced cancellation

25 September 2026. Base commit: `1d12549d`. D05 remains **IN_PROGRESS**.

`run_worker` used to hold the abstract network-namespace socket as an ordinary local value. If its future was cancelled after starting host/network work, the socket was dropped while profile descendants could still be aborting and synchronous fallback cleanup might be incomplete. A second worker in the same namespace could then pass admission in the still-running process. The normal systemd worker exits rather than deliberately cancelling this future; the finding concerns the forced-cancellation/library boundary, not a demonstrated ordinary SIGTERM leak.

The new `WorkerLease` is armed immediately before the first NAT recovery mutation. Early validation failures still release it. Successful terminal shutdown disarms it, and Rust's existing drop order keeps the socket alive until the other worker resources are gone. If the future is forcibly dropped or a post-admission result is not confirmed successful, its close-on-exec descriptor remains bound until process exit. This is intentionally fail-closed: an in-process retry is rejected; a new process can perform the existing exact-rule recovery. No INI/API/ABI change.

The change prevents overlapping worker admission; it does **not** turn synchronous `Drop` into an async join or impose a hard shutdown wall-clock limit. Forced cancellation can still abort async children while fallback resource cleanup runs; arbitrary kernel/filesystem I/O and process termination retain their existing limits. Old binaries do not participate in the network lease.

Current-source Linux checks: 7/7 ordinary network-lease tests, including cancellation, pre-mutation error, successful release and SIGKILL recovery; 19/19 profile-task ownership tests; 1/1 explicitly run privileged network-namespace test; Rustfmt and Clippy `--lib --bins -D warnings` PASS. The live TCP/UDP × off/manual/route/nat66 worker matrix on the isolated .11 lab passed 8/8 with saved before/after firewall, route, link and forwarding snapshots. Final binary SHA256: `40a5b9d4c1ec5c3425d3d12fa4ad1d233089d6c6cae5f8fa225a11ce17552abc`. The checked `network_lease.rs` SHA256 is `6ecfd426e7e3d327c3f8dbc330445f2dde597bf3785f7259b50b361699d4e2f1`.

The first final binary build stopped at ENOSPC: the private Cargo incremental cache had grown to 3.2 GiB. Only the verified `/var/tmp/qeli-audit-debt-20260924-d85ead10/target/debug/incremental` cache was removed; no installed service or host data was touched. The final non-incremental build and live run are `forcedlease-buildfinal.log/.rc`; the earlier successful tests and first live matrix are `forcedlease25.log/.rc` and `server-forced-drop-20260925/`. All artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-forced-drop-phase/`.

The remaining D05 work is whole shutdown budgeting and proof of child-task/resource ordering on forced `Drop`. D06 WAN identity and D10 network combinations are unchanged.

Continuation on 2 October 2026: Q25-F206 in the [debt register](../../plans/AUDIT-DEBT.md) closes forced-Drop async-join/host-cleanup ordering; the overall shutdown budget remains open. This report records historical behavior.

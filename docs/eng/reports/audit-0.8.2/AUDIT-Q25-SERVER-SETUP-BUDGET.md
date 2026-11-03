# Q25-F119: shared server profile setup budget and listener readiness

Date: 25 September 2026. Baseline commit: `017b3f2e`. D05/D09/D10: partial closure.

## Confirmed problem

TUN, NAT, NDP, hooks, DNS and listener binds had separate waits but no shared
profile setup deadline. `run_profile_generation` includes both setup and
long-lived client service, so timing out that entire function would terminate a
healthy profile later. UDP also logged `listening` before all `SO_REUSEPORT`
sockets were bound, and extra TCP/UDP listeners could still be binding after
the primary endpoint was serving.

## Change

One 120-second budget runs from entry into `run_profile` until **every** listener
confirms a successful bind. It is removed once ready, leaving healthy service
unlimited. TCP signals after bind; UDP first binds the complete socket group,
then starts workers and signals readiness. Failure of any endpoint stops setup
and lets the ordinary wrapper release services and host resources.

The first lab run exposed a regression in the new barrier: a bind failure was
reported as both a setup error and a listener cleanup failure, so successful
rollback still barred retry. The listener now owns only the readiness message
and finishes its task successfully; the wrapper reports the setup failure and
cleanup no longer receives a false error. This was checked for primary and
extra ports on both transports.

## Validation and limits

Linux `.11`: 2/2 new budget tests, 11/11 worker-order tests, Clippy
`--lib --bins -D warnings`, rustfmt and docs checks PASS. In private
NET/mount/PID namespaces: 8/8 TCP/UDP × IPv6 `off`/`manual`/`route`/`nat66`
ordinary starts; 4/4 TCP/UDP × occupied primary/extra port with exact rollback,
retry and stop; 22/22 recovery/ownership/SIGKILL checks PASS. Source (362
files) was verified before and after. Binary SHA256:
`b89120781c1d8c71c5372328ce250d5608b4c006bbf5cc92b73bafa6e195e3e3`.
The failed first run and corrected rerun are retained in
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-setup-budget-phase/`.

The 120 seconds bound waiting **until readiness**, not shutdown: cancellation
joins admitted host work and cleanup. A non-preemptible kernel/fs call can
exceed wall time. Forced Drop and whole-shutdown deadlines remain D05
IN_PROGRESS.

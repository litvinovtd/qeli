# Q25-F117: server profile DNS firewall setup off the async executor

Date: 25 September 2026. Baseline commit: `540b784a`. D05/D09/D10: partial closure.

## Confirmed problem

`run_profile_generation` installed DNS INPUT/REDIRECT rules synchronously on its
async task, both for the primary address and dual-stack IPv6. iptables/ip6tables
commands and state reads could stall a single-thread executor. A cancelled
worker may produce a `DnsInputLease` whose Drop itself performs blocking cleanup.
Destroying that result on another thread after losing the network namespace
would run cleanup in the wrong context.

## Change

Both DNS firewall installs now run on joined host workers.
`profile_teardown::blocking` releases a result to its caller only after explicit
adoption. Cancellation closes the adoption channel: the worker drops an
unadopted lease in its original namespace and is joined before the outer
profile guard is destroyed. An adopted lease still moves into `ProfileTeardown`.
Setup order and the INI contract are unchanged. The cancellation test checks
the exact thread destroying an unadopted result; the executor-responsiveness
test now uses a causal gate rather than a load-sensitive tick count.

## Validation and limits

Full host lib: 1603 PASS, 1 previously ignored. Linux `.11`: 11/11 targeted
tests; 22/22 recovery/ownership/SIGKILL checks; four TCP/UDP × IPv6
`manual`/`route` dual-stack DNS cases PASS in private NET/mount/PID namespaces.
The cases cover IPv4 UDP/TCP INPUT and REDIRECT, no Qeli-owned IPv6 DNS rules in
`manual`, managed IPv6 rules in `route`, second-worker rejection, rejected
SIGHUP and final removal of rules, TUN, sysctl and control socket. Source SHA
was verified before and after execution. Binary SHA256:
`ff91c374a6107d9859895b4f618be3647f6632ad7343a959e3398c6f40fb6ce3`.
Linux all-targets Clippy, rustfmt, `git diff --check` and docs checks PASS.
Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-dns-setup-phase/`.

NDP bind still runs synchronously on the async task: its `AsyncFd` requires a
separate handoff. There is no whole-setup deadline; arbitrary kernel/fs calls
and forced Drop cannot be preempted. D05 stays IN_PROGRESS.

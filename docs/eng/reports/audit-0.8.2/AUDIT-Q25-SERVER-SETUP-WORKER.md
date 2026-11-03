# Q25-F116: server profile TUN/NAT setup off the async executor

Date: 25 September 2026. Baseline commit: `33c40ff5`. D05/D09: partial closure.

## Confirmed problem

`run_profile_generation` synchronously inspected and created TUN, configured its
addresses, MTU and queue length, then ran stale NAT cleanup, IPv4/IPv6 firewall
setup and sysctl acquisition on the async task. Each external command had its
own deadline, but the sequence blocked the executor. Cancelling that task during
a system call could not safely release an already created TUN before the call
finished.

## Change

`setup_profile_tun` runs on a joined worker. Its `ProfileTunSetup` result holds
the original fds, kernel interface name, device type, subnet and queue count.
Until adoption, closing those fds removes the non-persistent TUN; after adoption,
`ProfileTeardown` owns the queues. A separate NAT/IPv6 worker starts only after
that handoff. Cancelling a waiter joins its worker before the outer profile
guard removes rules and closes fds. Setup order, foreign-device refusal, INI
parameters and wire/API behavior are unchanged.

## Validation and limits

A new cancellation-order test proves worker completion, unadopted-result
release, then outer guard destruction. With previous coverage, 11 targeted
tests PASS on host and Linux. Full host lib: 1603 PASS, 1 previously ignored.
Linux server cross-check, all-targets Clippy and rustfmt PASS.
Lab `.11`, private NET/mount/PID namespaces: 8/8 TCP/UDP × IPv6
`off`/`manual`/`route`/`nat66` starts/stops PASS and 2/2 TCP/UDP bind failures
after `post_up` with exact TUN/NAT rollback, retained worker-lifetime sysctl,
restart and final stop PASS. Installed services were untouched.
Logs, source and hashes:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-setup-phase/`.

DNS INPUT firewall and NDP bind still run synchronously inside the async profile.
Several sequential 15-second component deadlines do not make one setup deadline;
non-preemptible kernel/filesystem calls and forced Drop remain. D05 therefore
stays IN_PROGRESS.

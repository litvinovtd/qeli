# Q25: kill-switch lifetime ownership and IPv6 protection evidence

Date: 23 September 2026. Baseline: `c528d6b5`.
Q25-F046–F047 are fixed in code; Linux lease runtime needs a separate run.
Sections 17/18/25 remain **IN_PROGRESS**.

## Findings

**Q25-F046, P2 — cross-process admission race and same-TUN chain takeover.**
The previous mutex protected only one process. Two clients could both inspect an empty
firewall and install incompatible DROP policies. A new process with the same `dev`
also treated the matching chain as its own and rebuilt it before discovering the
occupied TUN. Matching chain names did not establish live ownership.

**Q25-F047, P2 — failed IPv6 observation permitted an unprotected startup.**
`host_has_global_ipv6` converted every `/proc/net/if_inet6` read error to `false`.
If the IPv6 firewall leg was unavailable or failed installation, startup could
report a successful kill-switch without proving global IPv6 absent. That path
also skipped refusal and rollback of an already installed IPv4 leg.

## Changes

The Linux client claims the fixed abstract AF_UNIX name `qeli.client.kill-switch`
before DNS recovery and the first engage. Binding is atomic in the network namespace
and immediately fails if another participant holds the name. All TUNs, configurations,
versions and state directories use the same name; renaming a profile cannot bypass it.

The descriptor spans reconnect and terminal cleanup/post_down. Its guard is declared
before the adapter so cancellation/unwind releases network objects before the lease.
The socket is close-on-exec; spawned commands cannot retain it after exec. Process
termination releases the name through the kernel. This does not clean up the firewall:
rules left after a crash still need recovery. No lock files, PID lookup or stale-inode
deletion are involved. The lease does not change forwarding/sysctls.

Mechanism references: [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html),
[abstract UNIX sockets](https://man7.org/linux/man-pages/man7/unix.7.html),
[Rust UnixDatagram::bind_addr](https://doc.rust-lang.org/std/os/unix/net/struct.UnixDatagram.html#method.bind_addr).

The lease is cooperative: old versions and external firewall tools do not participate.
Both filter inventories and rejection of foreign/legacy chains therefore remain.
Every acquisition failure refuses startup, including sandbox/resource errors; leak
overrides do not bypass it. Gateway/exit profiles without a kill-switch are outside
this lease's scope.

IPv6 observation now uses the shared bounded executor for
`ip -6 address show scope global`. Only successful empty output permits skipping
protection without `allow_ipv6_leak = true`. Nonempty, unknown or invalid output,
process errors, timeouts and overflow require protection. No new format parser is
needed: any nonempty response conservatively requires protection. The old best-effort
procfs parser is removed. IPv4 rollback and its error reporting remain.

INI keys, service JSON and firewall allowance policy are unchanged.

## Verification

**9 new host tests**: seven through public engage and two at the executor boundary.
Coverage includes observation errors, failing status, IPv6 presence, invalid UTF-8,
failed IPv4 rollback, successful empty output, explicit leak acceptance, and real
runtime/output limits of isolated child commands.

Five regressions: **FAIL on the original logic → PASS after the fix**.
The original procfs probe ran on Windows, where the file is absent; this models unknown
state rather than observing a Linux host. The control retains original logic, renaming
only a private helper so the new tests compile. Firewall commands and address inventory
are intercepted; real host networking is unchanged.

The kernel model now rejects deletion of a nonempty or referenced chain. The first full
run exposed an incorrect old-model expectation with a remaining hook. After correcting
the model, both original and fixed logic were checked against it again. The five
regression bodies are unchanged except formatting.

Added **6 Linux lease tests and one ignored child fixture**: repeated/concurrent claims,
independent test names, drop/unwind release, close-on-exec, another process being refused,
and process-exit release without Rust destructors. These were **compiled by Clippy
all-targets but not executed** in this Windows environment. Tests use unique names rather
than the production lease; actual network-namespace isolation still needs runtime checks.

**1253 host unit + 52 editor/policy + 7 examples + 12 server INI = 1324 Rust tests PASS.**
All nine matrix commands PASS: Linux all-targets Clippy, separate client/server,
minimal FFI, no-roaming, no-features, rustfmt and host regressions.
Rust 1.98.0; the existing `chunks_exact_to_as_chunks` exception is retained.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/kill-switch-lifetime-audit-20260923.

## Open work

Linux lease runtime, two real clients/separate namespaces, iptables-nft/legacy,
IPv6-disabled hosts with ip6tables installed, an overall firewall-operation deadline,
IPv6 appearing after an initially empty inventory, and gateway/exit TUN-generation
ownership. The IPv6 snapshot is not continuous monitoring; link-local without global
addresses allows skipping protection under the current contract. The sysctl journal
is unchanged. Remaining audit work, DNS/carrier globals, native certification and a new
benchmark remain open. This run does not certify leak prevention on a real Linux host.

Follow-up: [Q25-F048–F049](AUDIT-Q25-CLIENT-NAMESPACE.md) adds positive module-wide
IPv6 disablement evidence and moves leases into the shared Linux client module.
Gateway/exit without kill-switch and dev_attach now also reserve the configured TUN.
The limitations above describe this report's baseline.

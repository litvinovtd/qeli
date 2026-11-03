# Q25-F127: exit WAN change without VPN path COMMIT

Date: 25 September 2026. Base: `edc70b93`. D06 remains **IN_PROGRESS**.

## Defect and fix

The exit node refreshed WAN-dependent MARK/NAT/FORWARD rules only at a VPN
path COMMIT. On a dual-uplink host, the path to the VPN server can stay on
WAN A while the default route for forwarded exit traffic changes to WAN B.
The guard blocked that traffic, but B had no rules until a COMMIT.

Linux TCP and UDP data planes now start one monitor only for `exit_node`.
Every 5 seconds it reads an IPv4/IPv6 default-WAN snapshot and calls the
existing `refresh_exit_paths_if_active` when it changes. It remembers success
only after the complete refresh: a WAN name enters cleanup ownership before
its rules finish installing, so partial failures must be retried. Old rules
remain until teardown for existing flows. The monitor belongs to the
connection TaskGroup, which stops and joins its network operation before
NetworkPlan, TUN, DNS and firewall cleanup. Ordinary clients do not start it.

The end-to-end test also exposed a cleanup defect: `iptables -S` prints
`--comment "qeli-exit-node:lockdown"` with quotes. The lockdown-position check
accepted only the unquoted spelling and left protection enabled at stop
(first substantive TCP run: 34 PASS, 1 FAIL). The parser now accepts both
exact forms and still rejects an ACCEPT preceding lockdown.

## Verification and boundaries

On isolated lab `.11`, 116/116 gateway tests and `cargo fmt --check` passed.
Real TCP/fake-tls and UDP/fake-tls scenarios each passed **35 checks, 0
failures**: the carrier/server route stayed on A, the exit default changed
to B, new MARK/NAT/permit appeared without VPN COMMIT, consumer traffic used
B with NAT, and there was no second AUTH or reconnect. Clean stop removed
both WANs' rules and restored `ip_forward` and `rp_filter`.
Script and final logs:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/wan-monitor-e2e.sh`,
`wanmonitortcp5.log`, `wanmonitorudp3.log`. Runs used private
network/mount/PID namespaces and separate `STATE_DIRECTORY` values for all
processes. Installed services and server `.10` were unchanged.

The monitor follows default WAN **names** and does not solve device name reuse
[Q25-A125](AUDIT-Q25-WAN-NAME-REUSE.md). It cannot override per-packet
policy routing: the guard still blocks off-WAN traffic
[Q25-F124](AUDIT-Q25-EXIT-POLICY-ROUTING.md). A missing route or failed
installation leaves traffic blocked and retries at the next tick; inspect
logs and routes if connectivity does not recover. An identity-bound backend
and mixed-backend recovery remain D06/D10.

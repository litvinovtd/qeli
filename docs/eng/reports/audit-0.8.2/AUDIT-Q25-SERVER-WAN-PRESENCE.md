# Q25-F131: WAN presence during managed server routing setup

25 September 2026. Base: `3570d441`. D06 remains **IN_PROGRESS**.

## Defect and change

With `routing.nat.enabled = true` or managed `routing.ipv6.mode = route/nat66`,
an explicitly configured WAN name was previously accepted without checking
whether that device existed. `iptables -o <name>` can retain a rule for an absent
interface: if another device later receives the name, the rule starts matching
without new profile admission. An auto-detected WAN can also disappear between
`ip route get` and rule setup.

`resolve_wan_until` now verifies the selected name with
`network_interface::index` in the calling worker's network namespace.
An absent device or ioctl error rejects setup. The check consumes the shared
operation budget and precedes enabling forwarding/sysctls and adding new rules.
`manual` remains administrator-owned and does not run this managed-rule check.
The default `routing.nat.interface = eth0` still means IPv4 auto-detection.
INI/API formats are unchanged.

## Verification and limits

On isolated Linux `.11`, Rustfmt, one focused unit test covering absent/present
devices on both IPv4 and IPv6 branches, strict Clippy, the build and **8/8**
ordinary TCP/UDP × off/manual/route/nat66 worker lifecycle cases passed.
Two additional runs in private NET/mount/PID namespaces gave **2/2 PASS**:
absent `qeli-miss0` was rejected for IPv4 NAT and IPv6 route before changing
`ip_forward`, IPv6 forwarding or firewall rules; the TUN was removed on stop.
The initial test fixture accidentally exceeded Linux `IFNAMSIZ`; after shortening
the name, the final run passed. Server `.10` and installed `.11` services were
not changed.

Final binary SHA256: `41b4e2229b4509f2976a53f63e2d9c63843353c06c17ce12709435a58f8e7cd8`.
Verified `nat.rs` SHA256: `542912d3a51297e855c577a2b1d54dd7f9ddfe0b85d04a28312192892bfac6e1`.
Logs, exit codes, network snapshots and reproduction scripts:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/wan-presence-phase/`.

This establishes **presence at setup**, not continuous device identity.
Deletion, rename and name reuse after setup can still activate name-based
selectors, as shown in [Q25-A125](AUDIT-Q25-WAN-NAME-REUSE.md).
An identity-bound backend, mixed-backend packet/recovery and other D06/D10
criteria remain open.

# Q25-F128: the exit TUN cannot be its own WAN

Date: 25 September 2026. Base: `a05b6885`. D06 remains **IN_PROGRESS**.

`detect_wan` selects the interface of the default route. If an administrator sends the default route into the exit node's own TUN, the previous name validation accepted it and began installing `-i <tun> -o <tun>` MARK/FORWARD and MASQUERADE rules. That path is not an external WAN and cannot provide internet egress for client traffic.

`engage_exit_on` and `engage_exit_ipv6_on` now reject an exact match with the exit TUN before recording ownership or changing firewall/sysctl state. This applies to initial setup and roaming/background WAN refresh. After IPv6 forwarding changes, the second WAN check also rejects a default route that moved onto the TUN. An error preserves the existing guard and the monitor retries; the operator needs a separate external WAN.

The `exit_rejects_its_own_tun_as_wan_before_mutating` regression checks both families, no new mutations or ownership during setup, and no new mutations during refresh of an active exit node. On isolated Linux lab `.11`, the exact regression passed **1/1**, the entire gateway rollback module passed **102/102**, and `cargo fmt --check` plus `cargo clippy --lib -- -D warnings` passed. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/selfwanexact.log`; installed services and server `.10` were untouched.

Boundary: this rejects an exact name match with the exit TUN; it does not prove physical independence of another interface or solve WAN name reuse [Q25-A125](AUDIT-Q25-WAN-NAME-REUSE.md). D06/D10 remain open.

# Q25-F122: a late IPv4 route cannot bypass the kill switch

Date: 25 September 2026. Base commit: `b1cf0ece`. D06: partial closure.

## Problem and change

When `iptables` was missing or IPv4 rules could not be installed, a single successful empty `ip -4 route show default` result allowed startup without IPv4 protection. DHCP, an administrator or a network change could add a default route later; refresh did not arm a previously unprotected family. IPv4 traffic could then leave outside the VPN.

Startup now refuses an unavailable IPv4 firewall regardless of the current route. Skipping IPv4 protection requires explicit `allow_ipv4_leak = true`. The old route probe and its snapshot tests were removed. Configuration keys, API and ABI are unchanged; an IPv6-only host without `iptables` needs an explicit IPv4 leak override.

## Verification and limits

The model checks refusal before a default route arrives, absence of a route probe, explicit override and cleanup of an IPv6-only profile. Locally, 106 gateway and 17 portable kill-switch tests pass. Linux `.11`: the targeted regression (1/1), 107/107 gateway tests, 45/45 kill-switch tests, `--lib --bins -D warnings` Clippy and 2/2 privileged packet tests pass. The new native test adds an IPv4 address and default route in a private network namespace after dual-family kill-switch setup and confirms that the IPv4 DROP counter increases; the sibling test rechecks late IPv6. All 362 source files were verified; archive SHA256 `2f24a3459c70e7715b4dead97c8210f5a308dcd013a2a0d7b08bc86a7029e9dc`. Other route/WAN races and network backends remain D06/D10. Source and logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/kill-switch-dynamic-ipv4-phase/`.

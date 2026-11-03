# Q25-F121: late IPv6 cannot bypass the kill switch

Date: 25 September 2026. Base commit: `28d61ac8`. D06: partial closure.

## Problem and change

If `ip6tables` was missing or the IPv6 firewall leg failed, a successful empty `ip -6 address show scope global` result allowed the IPv4 kill switch to start without IPv6 protection. This was only a snapshot: DHCPv6, RA or an administrator can add an address later. Refresh did not arm a previously unprotected family, so the continuing session could send IPv6 outside the VPN.

With the IPv6 module enabled and `allow_ipv6_leak = false`, an unavailable IPv6 firewall now always rejects setup. The already armed IPv4 leg is rolled back, retaining any rollback error. Without an IPv6 firewall, only verified global IPv6 disabling or explicit `allow_ipv6_leak = true` admits the session. The address probe and its test fixtures were removed because they cannot prove safety for the session lifetime.

This deliberately tightens behavior on IPv4-only hosts: when the IPv6 module is enabled, `ip6tables` is required even without global IPv6 addresses. INI keys, API and ABI are unchanged. Operator actions are in [CONFIG](../../manuals/CONFIG.md) and [TROUBLESHOOTING](../../manuals/TROUBLESHOOTING.md).

## Verification and remainder

The focused model checks refusal without `ip6tables`, no address probe, IPv4 rollback, rollback-error reporting, explicit override and verified global disabling. Locally, 104 gateway and 20 portable kill-switch tests pass. Linux `.11`: the targeted regression (1/1), 105/105 gateway tests, 48/48 kill-switch tests, `--lib --bins -D warnings` Clippy and 2/2 privileged packet tests pass. The new native test enters a private network namespace, starts the kill switch without global IPv6, then adds an address and default route and confirms the IPv6 DROP counter increases. All 362 source files were verified; archive SHA256 `9f15a779f5dfe87f330cf14310404debb208d970c499cbcc027505f90f732da6`. The first Linux run exposed a missing-tool fixture that depended on whether `/usr/sbin/ip6tables` existed; path substitution made it deterministic, and the counts above are from the corrected run. Lab source and logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/kill-switch-dynamic-ipv6-phase/`.
Dynamic IPv4 default routes, namespace changes and the full network-backend matrix remain D06/D10. One private packet scenario does not replace the whole matrix.

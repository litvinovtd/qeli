# Q25-F120: recheck the IPv6 exit WAN during roaming refresh

Date: 25 September 2026. Base commit: `842890d0`. D06: partial closure.

## Problem and fix

At platform COMMIT, `refresh_exit_paths_if_active` rechecked the IPv4 default route after installing rules. IPv6 was rechecked only after enabling forwarding, **before** the `ip6tables` batch. If the IPv6 default route changed during that batch, refresh could report success with NAT66/FORWARD bound to an inactive WAN.

The IPv6 batch now has the same final check as IPv4. A missing or changed default route makes refresh fail; both old and newly touched WAN names remain recorded for verified cleanup. Deleting old-WAN rules at this point could break active flows and belongs to teardown of the current generation.

## Verification and limits

The firewall model switches the IPv6 default route during a `TCPMSS` command, after NAT66 programming. The regression requires COMMIT failure, retention of both WAN targets and successful removal of their rules. Locally, 108 gateway tests pass. Linux `.11`: the targeted regression (1/1), 109/109 gateway tests and scoped `cargo clippy --lib --bins -- -D warnings` pass; 362 source files verified (archive SHA256 `801f41e64e30a7fd8a5cb2d56e648ecf7a96bd14dbf8a61d8c2b58283af6c73c`). The first filter matched 0 tests; only the corrected run counts here. Source and logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/gateway-ipv6-roam-phase/`.

This closes the observed window between the rule batch and COMMIT, but cannot make WAN selection atomic with a route change after the last query. Firewall selectors still use interface names; rename/reuse and IPv6 address arrival after admission remain D06/D10. INI, API and ABI are unchanged; user-facing syntax is unaffected.

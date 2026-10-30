# Use cases

Practical Qeli deployments: goals, required inputs, complete configs, startup order,
verification and recovery after reboot.

[Documentation map](../index.md) · [Русский](../../ru/scenarios/README.md)

| Use case | Goal | Version and qualification |
| --- | --- | --- |
| [Client → A → B → Internet](CHAINED-SERVERS.md) | Accept clients on A and send their traffic through B, retaining the servers' own routes; built-in client, INI hooks and autostart | Planned 0.8.4 reconnect fix passed candidate testing; root qualified, User=qeli not independently qualified |

To install Qeli itself, start with [GETTING-STARTED](../manuals/GETTING-STARTED.md).
Full parameters are in [CONFIG](../manuals/CONFIG.md); this section describes complete
deployments rather than duplicating the reference.

## Chain qualification results

- [0.8.4 candidate: repeated post_up, autostart and A/B reboot](../reports/CHAINED-SERVERS-084-2026-10-30.md).
- [Historical 0.8.3 INI-hook and cleanup checks](../reports/CHAINED-SERVERS-HOOKS-2026-10-30.md).
- [Original C → A → B qualification](../reports/CHAINED-SERVERS-2026-10-30.md).

Add new use cases as separate files here with matching RU/EN paths. Include version/
privilege requirements, verification steps and qualification limits, then link them
from this catalog. Test reports and raw locations remain in reports/;
the lab raw files themselves are not moved here.

[The previous guide address](../manuals/CHAINED-SERVERS.md) remains for old links;
the maintained document is in this section.

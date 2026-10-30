# A → B through INI hooks: qualification, 30 October 2026

Result: **17 operational scenarios passed**, covering repeated commands, restarts,
transport loss and real A/B reboots. Rules and routes did not accumulate duplicates.
Qeli runs network commands from INI; the init system only starts processes.
No code/binary changes or release publication. Complete INI configs with post_down
also passed 8 checkpoint states and 68 runtime checks without failures.

This report preserves **0.8.3** results. The current
[manual](../scenarios/CHAINED-SERVERS.md) describes planned 0.8.4;
[repeated post_up and native panel autostart were qualified separately](CHAINED-SERVERS-084-2026-10-30.md).

[Four-action guide with startup section](../scenarios/CHAINED-SERVERS.md) ·
[Compact results](../../data/chained_servers_hooks_2026-10-30.json).

## Lab and method

- A — VM300, B — VM301: **2 vCPU / 2 GiB** each.
- Independent client C and target T — VM304/305: 1 vCPU / 1 GiB each.
- Linux amd64 **0.8.3**, SHA-256:
  `9cc1dfb84ccdee3bc0fb23aa3b0745882b0d520a325134112be2575512b62a1d`.
- Reused retained /opt/qeli-chain-e2e-20261030-r08/qeli; no new binary copies/builds.
  VM302 was unused; no computation or software installation on Proxmox.
- TCP FakeTLS on both legs, **Recordizer required**, inner IPv4, MTU 1400.
  Heartbeat 1000 ms, jitter 100 ms; client timeout 3 s.
- Network commands ran as root in isolated namespaces. A/B hooks in the manual
  match saved recipe.json, with only B's WAN interface substituted.
- Server routing.post_up installs A's table/rule and B's NAT; client post_up installs
  A's working route. No route watcher on A.
- A → B client: **reconnect=false**, service **Restart=always / RestartSec=5**.
- Small HTTP probes, not another throughput benchmark. Each recovered state checks
  egress through B and separately checks A/B's own WAN access.

## Scenarios and results

| Scenario | Count | Result |
| --- | --- | --- |
| Initial startup | 1 | Path through B |
| Reapply all three INI commands | 3 times | No duplicates or insertion errors |
| Restart A's ingress server | 2 times | Path through B recovered |
| Restart A's upstream client | 2 times | post_up and route restored |
| Restart B's server | 2 times | Automatic recovery |
| Abrupt upstream process exit | SIGKILL | New PID, route restored |
| Temporary A → B transport loss | 6 s | Recovery after restriction removal |
| Delete A's working route | then restart upstream | Route restored |
| Delete B's NAT | then restart B server | NAT restored |
| Reboot A while B is stopped | then start B | Automatic connection |
| Reboot B | real reboot | Automatic recovery |
| Reboot A while B is ready | real reboot | Automatic recovery |

**17 checkpoint states**, 79 top-level runtime checks without failures.
Every checkpoint had exactly one rule 20800, one working qeli-out default metric 10,
one blackhole default metric 32767, one of each specified IPv4/IPv6 firewall rule on A
and one tagged NAT rule on B. Each condition was checked separately.

**Three real reboots**: A, B, A; changed boot IDs are retained.
A/B's own WAN probes retained their original source addresses, including during
A → B transport loss and A booting before B. The host route to 1.1.1.1 did not change.
A rebooting host is not expected to remain available throughout its own reboot.

## Why reconnect=false

The preceding targeted series showed that reconnect=true recreates qeli-out without
repeating post_up in the same process. The working route disappears.
This is the behavior of the tested 0.8.3 binary. Current dev/0.8.4
[client lifecycle](../../../qeli/src/client/mod.rs) has changed; its sources
are not presented as the sources of the historical binary.

With reconnect=false and Restart=always, a new process executes the hook again.
This combination was verified across restarts, transport loss and reboot and was used
in the previous manual revision. The 0.8.4 reconnect=true recipe passed a new separate series.

## Scope and retained initial failures

- Qualification covers this IPv4 recipe, not every transport, IPv6 transit or arbitrary
  external firewalls. Table 208/priority 20800 must belong exclusively to this recipe.
- Hooks are not a continuous reconciler: after deliberate route/NAT deletion, recovery
  was verified by **restarting the owning process**, not spontaneous repair.
- Package installation and its qeli-user restrictions were not qualified by this namespace
  test. The manual explicitly specifies root network hooks and a service-user setting;
  user creation remains the normal package procedure.
- Earlier r01 contained an unknown INI key, routing=split-tunnel; check-config stopped
  startup. That key was removed; gateway=false/pull_routes=false are retained.
- r02/r03 TUN observers lost 79/35 capture packets respectively; both series stopped.
  These are observer losses, not VPN UDP loss. Throughput raw remains separate.
- r04 established lifecycle/reconnect behavior. Final operational qualification is
  the separate **operational-r01**, not a rewritten earlier result.

## Follow-up: complete configs with post_down

The manual now embeds commands directly in complete B, A and upstream configs.
Post_up is unchanged. Separate **cleanup-r03** verified the new post_down commands
on the same SHA/lab, without resource changes or further reboots:

- Clean A server shutdown removes its additional firewall rules, rule 20800 and
  reserve blackhole; the upstream working route remains owned by the client.
- Clean upstream shutdown removes only its working route, not A server rules.
- B shutdown removes only this recipe's tagged NAT rule.
- Each post_down was also called three times with entries already absent, without errors.
- Starting/restarting each process restored the chain without duplicate entries.
- A/B namespaces used FORWARD DROP: Qeli's routing.forward_private=true allowances
  kept the chain working. No global ACCEPT policy was needed.
- A/B's own WAN probes passed while processes were stopped as well.

8 checkpoint states, 68 runtime checks, all passed. Main-series reboot checks cover
the earlier variant without custom post_down cleanup; this follow-up tested stop/start,
not another reboot matrix. Post_down execution is not promised after SIGKILL/power loss.

Initial raw remains: cleanup-r01 stopped on an incorrect observer condition
(iptables -C normally prints “Bad rule” for an absent rule; the hook itself succeeded).
The observer now enumerates rules with -S. Cleanup-r02 stopped before Qeli startup
on EEXIST while creating C's test VLAN. Cleanup and absence of test processes/namespaces
were verified before r03. These are harness/setup failures, not final successful results.

New raw: /opt/qeli-chain-hooks-cleanup-20261030-r01 … -r03 on A/B/C/T.
R03 retains cleanup-recipe.json, configs, hook logs and results.
All four VMs were restored. A separate read-only audit confirmed networking, services,
full qdisc, no test units/lease and unchanged binary SHA.

## Raw and restoration

Final series: **/opt/qeli-chain-operational-20261030-r01** on A/B/C/T.
Retains recipe.json, private configs and their SHA, runtime logs, boot IDs, header-only
captures, controller and operational-result.json. Keys/private configs are not published.
Earlier /opt/qeli-chain-hooks-20261030-r01 … -r04 and the original full series are unchanged.

300/301/304/305 were restored. A separate read-only audit confirmed addresses,
routes/rules, firewall, namespaces, forwarding/sysctl and original services;
no test unit files or lease locks remain. Full A/B qdisc options match the originals,
including restoring B's original fq after reboot. A/B/C binary SHA is unchanged.

This qualifies network startup/recovery. Throughput results from the original
[full test](CHAINED-SERVERS-2026-10-30.md) are not conflated with this series.

# 0.8.4: post_up on reconnect and native panel autostart

30 October 2026. **Candidate passed 9 scenarios / 53 runtime checks**, including three
real reboots. A has no separate client service: the built-in ClientManager uses
`autostart=true` and the client uses `reconnect=true`.
This is an experimental dev build, **not a published release or release/dist qualification**.

[A → B manual](../scenarios/CHAINED-SERVERS.md) ·
[Compact results](../../data/chained_servers_panel_084_2026-10-30.json).

## Cause and fix

Tested 0.8.3 consumed the command through `self.post_up.take()` on first invocation.
A full reconnect recreated the TUN, losing its route, but no command remained.
Earlier observations/raw remain in the [0.8.3 report](CHAINED-SERVERS-HOOKS-2026-10-30.md).

The 0.8.4 [Linux adapter](../../../qeli/src/client/mod.rs) retains the command and tracks
the last serviced NetworkPlan generation separately. A hook is eligible only after
successful platform apply and ACK. The same generation does not run it twice;
a full reconnect with a new generation reruns post_up. Carrier recovery preserving
the TUN/plan needs no repeat configuration. Post_down remains terminal cleanup,
not a paired action on every reconnect.

Trusted local config, panel/API hook-write prohibition, secret-free context,
30-second deadline and best-effort error handling are unchanged. Post_up must be
idempotent; the manual uses route replace and firewall existence checks.

## Build and lab

- Built **only on VM302**, with no Proxmox commands/computation.
- Dev snapshot HEAD `a56aa7a415f1414e544ac878bccec8d83c3e0681`, plus client/mod.rs changes.
  Cargo fmt also wrapped lines in two existing recordizer.rs/web/pages/config.rs tests;
  no substantive differences in those files. The primary checkout left them unchanged.
- Linux amd64 **qeli 0.8.4**, default server/client + jemalloc.
- SHA-256: `dbcb5717ebb17338542f4b14ba69e0cf25fbd759020ab39859d38a43b5958abb`.
- Native source digest: `26a4059be65d5f37d276174ebca84af630f876bbe700a338e0c6c2615a6ad7a3`.
- A — VM300, B — VM301: **2 vCPU / 2 GiB**; independent C/T — VM304/305.
- Both legs TCP FakeTLS, **Recordizer required**, active PACKET_MUX_V1 confirmed;
  inner IPv4, MTU 1400, heartbeat 1000 ms / jitter 100 ms, timeout 3 s.
- Real server supervisor/ClientManager, authenticated loopback panel,
  API login/Connect/Disconnect. Client is a direct child of the supervisor.
- Private bind mounts isolated /etc/qeli/clients and /var/log/qeli from host files.
  Network namespaces/their setup service are lab infrastructure, not manual dependencies.
  No upstream client service, route watcher or restart wrapper.

## Observations

| Scenario | A client PID | Cumulative post_up calls | Result |
| --- | ---: | ---: | --- |
| Initial panel-manager autostart | 5261 | 1 | OK |
| Three repeated Connect calls | 5261 | 1 | OK |
| B restart #1 | 5261 | 2 | OK |
| B restart #2 | 5261 | 3 | OK |
| B restart #3 | 5261 | 4 | OK |
| Panel Disconnect → Connect | 5878 | 5 | OK |
| Real B reboot | 5878 | 6 | OK |
| A reboot while B is ready | 834 | 7 | OK |
| A reboot before B starts | 828 | 8 | OK |

Across three B restarts, the same PID **5261** reran the hook: **1 → 2 → 3 → 4**.
The table 208 working default returned without manual commands.
Three Connect calls for an already-running client retained one process/one invocation.
Manual Disconnect kept the server rule; the next Connect started a new client.

B reboot retained A client PID 5878 and reran the hook. After A reboot, the panel manager
started the profile itself. When A booted before B, its child already existed and recovered
without changing PID after B started. Changed B/A/A boot IDs are retained.

Every checkpoint confirmed panel autostart=true/connected/up, one client child,
one rule 20800, one working route and one tagged NAT rule. C egress through B
and A/B's own WAN probes passed. A rebooting host is not expected to stay available
throughout its own reboot.

## Automated checks and limits

- lifecycle_adapter_tests: **13 passed**, including two new regressions for new-generation
  invocation, deduplication, absent plans/empty commands, failed-plan nonpublication
  and refreshed context.
- hooks: **3 passed / 3 ignored**; ignored tests are not counted as executed.
- client_manager: **7 passed**. Native, client-only and FFI compilation checks,
  release build and formatting passed.
- Functional IPv4/TCP FakeTLS qualification, not throughput, all 12 profiles or mobile
  hook execution (mobile clients do not execute these hooks).
- Execution was root in isolated namespaces, not separate qualification of package
  installation, directory ownership/UID migration or arbitrary systemd hardening.
- Preserved-TUN carrier recovery is covered by the deduplication unit contract;
  no separate live hard-resume matrix was run.
- Autostart is not a watchdog for an exited process: manual Disconnect stayed disconnected;
  subsequent Connect worked. This changes hook lifecycle, not client management.
- Hooks remain file-only. Autostart in the file is the checkbox's flag, but UI/API
  saves still cannot introduce shell commands.
- No backport to 0.8.3. The candidate implements planned 0.8.4 behavior;
  this task did not publish the release.

## Raw and restoration

Build/logs: `/opt/qeli-client-hook-reconnect-084-20261030-r01` on 302.
Lab raw: **/opt/qeli-chain-panel-084-20261030-r01** on A/B/C/T:
private configs and SHA, native client/server logs, panel state, PID/PPID, hook counts,
boot IDs, controller, header-only captures and before/after snapshots.
Secrets/private configs are not published.

300/301/304/305 were restored. A separate read-only audit confirmed original addresses,
routes/rules, firewall, forwarding/sysctl, services, full A/B qdisc and no test units/lease.
A/B's host profile/log paths also match their original state. Candidate and retained
0.8.3 SHA on A/B/C are unchanged. Old binaries/raw and release/dist were not replaced.
No release publication.

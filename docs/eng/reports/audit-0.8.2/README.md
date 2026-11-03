# Qeli 0.8.2 audit

Q01–Q37 reports are grouped by audit-plan stage. Each report retains its dates, results, limitations and history of intermediate statuses.

[Audit plan](../../plans/FULL-SYSTEM-AUDIT.md) · [Audit debt](../../plans/AUDIT-DEBT.md) · [Documentation](../../index.md)

Current result: 37/37 within the agreed scope. This does not turn every historical scenario into PASS or establish release readiness. API34 ENONET and D06 remain accepted limitations; physical exclusions are retained.

## Q01

- [Q01 — server INI: first audit pass](AUDIT-Q01-SERVER-INI.md)

## Q02

- [Q02 — client parsers: links and import boundaries](AUDIT-Q02-CLIENT-PARSERS.md)

## Q03

- [Q03 — Panel state and load failures](AUDIT-Q03-PANEL-STATE.md)

## Q04

- [Q04: panel authentication and API boundaries](AUDIT-Q04-WEB-AUTH.md)

## Q05

- [Q05/Q07 — backup/restore budget and snapshot completeness](AUDIT-Q05-ARCHIVE-BUDGET.md)
- [Q05 — asynchronous panel firewall-tool discovery](AUDIT-Q05-HEALTH-PROBES.md)
- [Q05: configuration transactions, live reload and restart](AUDIT-Q05-HTTP-TRANSACTIONS.md)
- [Q05 — panel transactions, preflight and cancellation](AUDIT-Q05-PANEL-TRANSACTIONS.md)
- [Q05: deadlines and output limits for preflight host observations](AUDIT-Q05-PREFLIGHT.md)

## Q06

- [Q06: users and access revocation — complete](AUDIT-Q06-USERS-ACCESS.md)

## Q07

- [Q07: backup, restore and history — batches 1–3](AUDIT-Q07-BACKUP-RESTORE.md)

## Q08

- [Q08: cryptography, identity and keys](AUDIT-Q08-CRYPTO-KEYS.md)

## Q09

- [Q09: final handshake/pre-auth audit and KICK retention](AUDIT-Q09-FINAL.md)
- [Q09: TCP authentication and complete ClientHello parsing](AUDIT-Q09-TCP-PARSER.md)
- [Q09: UDP AUTH ownership and pre-authentication PMTU](AUDIT-Q09-UDP-AUTH.md)
- [Q09: UDP handshake, admission publication and cleanup](AUDIT-Q09-UDP-CONTRACTS.md)

## Q10

- [Q10: PacketCodec, replay and CONTROL_V2 receipts](AUDIT-Q10-CODEC-CONTROL.md)

## Q11

- [Q11: REALITY, TLS 1.3 and HTTP/2](AUDIT-Q11-REALITY-TLS-H2.md)

## Q12

- [Q12: transports and wire camouflage](AUDIT-Q12-TRANSPORTS.md)

## Q13

- [Q13: recordizer, padding and shaping](AUDIT-Q13-MORPHOLOGY.md)

## Q14

- [Q14: control socket, API bounds and lifecycle hooks](AUDIT-Q14-CONTROL.md)
- [Q14: supervisor, workers and profiles](AUDIT-Q14-CURRENT-LIFECYCLE.md)
- [Q14 — DNS INPUT lease admission, deadlines and retirement](AUDIT-Q14-DNS-INPUT-BUDGET.md)
- [Q14: DNS rule ownership after failed cleanup](AUDIT-Q14-DNS-OWNERSHIP.md)
- [Q14 — exact server firewall recovery after a crash](AUDIT-Q14-FIREWALL-JOURNAL.md)
- [Q14: server HTTP/2, profile shutdown and pre-auth admission](AUDIT-Q14-H2-TASKS.md)
- [Q14: bounded hook output and hook process cleanup](AUDIT-Q14-HOOKS.md)
- [Q14: partial IPv6 sysctl acquisition and rollback retry](AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md)
- [Q14: mixed nft/legacy/firewalld after SIGKILL](AUDIT-Q14-MIXED-FIREWALL.md)
- [Q14 — shared NAT cleanup deadline](AUDIT-Q14-NAT-CLEANUP-BUDGET.md)
- [Q14: finite NAT rule cleanup and failure diagnostics](AUDIT-Q14-NAT-CLEANUP.md)
- [Q14: deadlines and output limits for server NAT commands](AUDIT-Q14-NAT-COMMANDS.md)
- [Q14 — NAT, forwarding and DNS REDIRECT setup deadlines](AUDIT-Q14-NAT-SETUP-BUDGET.md)
- [Q14: final DNS and IPv6 sysctl verification during worker shutdown](AUDIT-Q14-OWNED-SHUTDOWN.md)
- [Q14: profile task and TUN teardown errors during shutdown](AUDIT-Q14-PROFILE-SHUTDOWN.md)
- [Q14/Q15: worker background services and complete session accounting](AUDIT-Q14-Q15-WORKER-USAGE.md)
- [Q14/Q19 audit: profile shutdown and DNS listeners](AUDIT-Q14-Q19-LIFECYCLE.md)
- [Q14/Q25: shared firewall checks and exact DNS cleanup](AUDIT-Q14-Q25-FIREWALL-CHECKS.md)
- [Q14/Q32: bounded notification delivery and shutdown](AUDIT-Q14-Q32-NOTIFICATIONS.md)
- [Q14/Q33: config snapshot authorization for Linux commands](AUDIT-Q14-Q33-CONFIG-TRUST.md)
- [Q14 — exact NAT cleanup and generation stop outcomes](AUDIT-Q14-RETAINED-CLEANUP.md)
- [Q14 audit: supervisor, worker and control events](AUDIT-Q14-SUPERVISOR.md)
- [Q14: sysctl recovery outcome and repeated lease acquisition](AUDIT-Q14-SYSCTL-RECOVERY.md)
- [Q14 — worker ownership within a network namespace](AUDIT-Q14-WORKER-NETWORK-LEASE.md)

## Q15

- [Q15: sessions, IP pools and limits](AUDIT-Q15-CURRENT-SESSIONS.md)
- [Q15-F002: local reply address for wildcard UDP](AUDIT-Q15-UDP-LOCAL-ADDRESS.md)

## Q16

- [Q16: ACL, push routes and site-to-site](AUDIT-Q16-ACL-ROUTES.md)

## Q17

- [Q17: IPv4 NAT, forwarding and sysctls](AUDIT-Q17-IPV4-NETWORK.md)

## Q18

- [Q18: IPv6 off/manual/route/nat66 and NDP](AUDIT-Q18-IPV6-NDP.md)

## Q19

- [Q19 audit: cache memory, signed exchanges and query headers](AUDIT-Q19-DNS-CACHE.md)
- [Q19 audit: EDNS, RDATA and cache lifetimes](AUDIT-Q19-DNS-EDNS.md)
- [Q19: server and client DNS](AUDIT-Q19-DNS-FINAL.md)
- [Q19 audit: server DNS proxy](AUDIT-Q19-DNS-PROXY.md)
- [Q19/Q22 audit: shared DNS and route planning](AUDIT-Q19-Q22-NETWORK-PLAN.md)

## Q20

- [Q20: DHCP and lease lifecycle](AUDIT-Q20-DHCP-FINAL.md)

## Q21

- [Q21: TUN/TAP, IP and MTU/PMTU](AUDIT-Q21-PACKETS-FINAL.md)

## Q22

- [Q22: transport core, FFI/JNI and memory](AUDIT-Q22-CORE-FFI-FINAL.md)

## Q23

- [Q23: roaming, resume and CONTROL_V2](AUDIT-Q23-ROAMING-FINAL.md)

## Q24

- [Q24: multipath, bonding and shared budgets](AUDIT-Q24-BONDING.md)

## Q25

- [Q25-F186: Android active-profile index](AUDIT-Q25-ANDROID-ACTIVE-INDEX.md)
- [Q25-F193 — Android per-app editor and INI sections](AUDIT-Q25-ANDROID-APPS-INI.md)
- [Q25-F167: byte-faithful Android client INI import](AUDIT-Q25-ANDROID-FILE-IMPORT.md)
- [Q25-F203 — Android Private DNS, VPN traffic, and Wi-Fi change](AUDIT-Q25-ANDROID-NETWORK-IDENTITY.md)
- [Q25-F174: confirmed Android profile writes](AUDIT-Q25-ANDROID-PROFILE-TRANSACTIONS.md)
- [Q25-F176: strict Android profile-store loading](AUDIT-Q25-ANDROID-STORE-DECODING.md)
- [Q25-F179: Android profile store rejects stale writes](AUDIT-Q25-ANDROID-STORE-VERSION.md)
- [Q25 — atomic state publication failures and durability](AUDIT-Q25-ATOMIC-STATE.md)
- [Q25-F216/F217: shared Linux CLI INI bootstrap](AUDIT-Q25-CLI-BOOTSTRAP.md)
- [Q25: bounded client system commands and IPv4 protection checks](AUDIT-Q25-CLIENT-COMMANDS.md)
- [Q25-F166: stale Delete and applying client INI changes](AUDIT-Q25-CLIENT-DELETE-REVISION.md)
- [Q25-F197 — shared INI editor matrix](AUDIT-Q25-CLIENT-INI-MATRIX.md)
- [Q25-F102: legacy-table advice prevented client startup](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md)
- [Q25: disabled IPv6 and TUN reservations for every Linux client](AUDIT-Q25-CLIENT-NAMESPACE.md)
- [Q25-F133: Linux client-only build and exit WAN monitor](AUDIT-Q25-CLIENT-ONLY-BUILD.md)
- [Q25-F165: client autostart and diagnostic bounds](AUDIT-Q25-CLIENT-PROFILE-BOUNDS.md)
- [Q25-F164: panel client INI revisions](AUDIT-Q25-CLIENT-PROFILE-REVISION.md)
- [Q25-F177: client UI revisions and active-profile application](AUDIT-Q25-CLIENT-PROFILE-UI-REVISION.md)
- [Q25-F196 — share URI password contract across adapters](AUDIT-Q25-CLIENT-SHARE-PARITY.md)
- [Q25-F194 — portable password in share links and editor build](AUDIT-Q25-CLIENT-SHARE-PASSWORD.md)
- [Q25-F195 — share-link errors in client UI](AUDIT-Q25-CLIENT-SHARE-UI.md)
- [Q25-F169: preserve client INI text until the shared parser](AUDIT-Q25-CLIENT-UI-INI-INPUT.md)
- [Q25-F198 — direct qeli:// import budget](AUDIT-Q25-CLIENT-URI-BUDGET.md)
- [Q25: core lifecycle failures must reach terminal cleanup](AUDIT-Q25-CORE-LIFECYCLE.md)
- [Q25/Q33: bounded credential commands and early client shutdown](AUDIT-Q25-CREDENTIAL-COMMANDS.md)
- [Q25-F168: file-based client INI in desktop CLI](AUDIT-Q25-DESKTOP-CONFIG-FILES.md)
- [Q25-F189: stable desktop profile IDs](AUDIT-Q25-DESKTOP-PROFILE-IDENTITY.md)
- [Q25-F173: desktop UI profile transactions](AUDIT-Q25-DESKTOP-PROFILE-TRANSACTIONS.md)
- [Q25-F192 — shared Windows/macOS settings storage](AUDIT-Q25-DESKTOP-SETTINGS-STORE.md)
- [Q25-F183: bounded desktop profile-store reads](AUDIT-Q25-DESKTOP-STORE-BOUNDS.md)
- [Q25-F178: cross-process desktop profile-store writes](AUDIT-Q25-DESKTOP-STORE-CONCURRENCY.md)
- [Q25-F184: bounded desktop profile-store lock wait](AUDIT-Q25-DESKTOP-STORE-LOCK-WAIT.md)
- [Q25-F191 — null fields in desktop profile stores](AUDIT-Q25-DESKTOP-STORE-NULL-FIELDS.md)
- [Q25-F172: desktop profile-store recovery](AUDIT-Q25-DESKTOP-STORE-RECOVERY.md)
- [Q25-F185: desktop profile-store structure](AUDIT-Q25-DESKTOP-STORE-STRUCTURE.md)
- [Q25-F171: desktop profile-store encoding](AUDIT-Q25-DESKTOP-STORE-UTF8.md)
- [Q25 — shared client DNS application deadline](AUDIT-Q25-DNS-BUDGET.md)
- [Q25: DNS ownership belongs to a connection generation](AUDIT-Q25-DNS-LEASES.md)
- [Q25 — DNS markers: trusted storage and namespace generation](AUDIT-Q25-DNS-MARKER-STORAGE.md)
- [Q25: preserve the legacy DNS recovery record after failed restoration](AUDIT-Q25-DNS-RECOVERY.md)
- [Q25-F200 — audit report structure and language parity](AUDIT-Q25-DOC-PARITY.md)
- [Q25: exit-node NAT ownership and conflicting kill-switch policies](AUDIT-Q25-EXIT-OWNERSHIP.md)
- [Q25-F124: exit-node under off-WAN policy routing](AUDIT-Q25-EXIT-POLICY-ROUTING.md)
- [Q25-F128: the exit TUN cannot be its own WAN](AUDIT-Q25-EXIT-SELF-WAN.md)
- [Q25-F127: exit WAN change without VPN path COMMIT](AUDIT-Q25-EXIT-WAN-MONITOR.md)
- [Q25-F107/F108: asynchronous kill-switch operations and retained DROP after unhook failure](AUDIT-Q25-FIREWALL-TASK.md)
- [Q25 — shared gateway/exit-node operation deadline](AUDIT-Q25-GATEWAY-BUDGET.md)
- [Q25: gateway ownership during setup, roaming and cleanup](AUDIT-Q25-GATEWAY-IDENTITY.md)
- [Q25-F120: recheck the IPv6 exit WAN during roaming refresh](AUDIT-Q25-GATEWAY-IPV6-ROAM.md)
- [Q25: gateway rollback, scope isolation and firewall inspection](AUDIT-Q25-GATEWAY-ROLLBACK.md)
- [Q25: gateway WAN discovery and cleanup](AUDIT-Q25-GATEWAY-WAN.md)
- [Q25: HTTP/2 workers and client-generation shutdown](AUDIT-Q25-H2-TASKS.md)
- [Q25-F112/F113: bounded identity files and fail-closed TOFU](AUDIT-Q25-IDENTITY-FILES.md)
- [Q25-F114: owned TOFU worker, handshake cancellation and late errors](AUDIT-Q25-IDENTITY-WORKER.md)
- [Q25-F187: active-profile index on iOS Restore](AUDIT-Q25-IOS-ACTIVE-INDEX.md)
- [Q25-F181: iOS notice when an active profile needs reconnect](AUDIT-Q25-IOS-ACTIVE-PROFILE-RECONNECT.md)
- [Q25-F180: empty iOS profile archives are not replaced by a template](AUDIT-Q25-IOS-EMPTY-ARCHIVE.md)
- [Q25-F182: iOS profile snapshots for Edit and Delete](AUDIT-Q25-IOS-PROFILE-SNAPSHOT.md)
- [Q25 — shared standalone kill-switch cleanup deadline](AUDIT-Q25-KILL-SWITCH-BUDGET.md)
- [Q25-F122: a late IPv4 route cannot bypass the kill switch](AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV4.md)
- [Q25-F121: late IPv6 cannot bypass the kill switch](AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV6.md)
- [Q25 — standalone kill-switch ownership and reconnect checks](AUDIT-Q25-KILL-SWITCH-IDENTITY.md)
- [Q25: kill-switch lifetime ownership and IPv6 protection evidence](AUDIT-Q25-KILL-SWITCH-LIFETIME.md)
- [Q25 — kill-switch protection across crash restart](AUDIT-Q25-KILL-SWITCH-REBUILD.md)
- [Q25 — kill-switch refresh budget and unknown inspections](AUDIT-Q25-KILL-SWITCH-REFRESH.md)
- [Q25 — kill-switch setup deadline and verified rollback](AUDIT-Q25-KILL-SWITCH-SETUP.md)
- [Q25: refuse unscoped legacy global DNS recovery](AUDIT-Q25-LEGACY-DNS.md)
- [Q25 — link observations in the calling namespace](AUDIT-Q25-LINK-OBSERVATION.md)
- [Q25: Linux CLI and network recovery — final](AUDIT-Q25-LINUX-CLI-FINAL.md)
- [D09: Linux lifecycle and system-failure evidence](AUDIT-Q25-LINUX-LIFECYCLE-CLOSURE.md)
- [Q25-F170: mobile client INI size budget](AUDIT-Q25-MOBILE-CONFIG-BUDGET.md)
- [Q25-F188: mobile store and backup bounds](AUDIT-Q25-MOBILE-STORE-BOUNDS.md)
- [Q25-F175: protect mobile profiles after load failure](AUDIT-Q25-MOBILE-STORE-LOAD-FAILURE.md)
- [Q25 — network namespace generation in sysctl journal v4](AUDIT-Q25-NAMESPACE-GENERATION.md)
- [Q25 — pinning namespaces during sysctl transactions](AUDIT-Q25-NAMESPACE-PIN.md)
- [Q25-F199 — reproducible native build inputs](AUDIT-Q25-NATIVE-BUILD-INPUTS.md)
- [Q25-F202 — reproducible native cores and Android runtime](AUDIT-Q25-NATIVE-REBUILD.md)
- [Q25: retain the kill-switch when forwarding cleanup fails](AUDIT-Q25-NETWORK-CLEANUP.md)
- [Q25-F105: applying NetworkPlan outside the async executor](AUDIT-Q25-NETWORK-TASK.md)
- [Q25/Q14: bounded password files and final client status](AUDIT-Q25-PASSWORD-FILES.md)
- [Q25-F201 — archived patch applicability and evidence age](AUDIT-Q25-PATCH-RECONCILIATION.md)
- [Q25: bounded Linux path-monitor commands](AUDIT-Q25-PATH-MONITOR.md)
- [Q25: persistent TUN/TAP after SIGKILL](AUDIT-Q25-PERSISTENT-TUN.md)
- [Q25-F110: TUN pump startup and early rollback on a joined worker](AUDIT-Q25-PUMP-START.md)
- [Q25 — system resolver configuration validation](AUDIT-Q25-RESOLVER-CONFIG.md)
- [Q25 — DNS service context and direct D-Bus calls](AUDIT-Q25-RESOLVER-CONTEXT.md)
- [Q25-F104: resolver-file reads before kill-switch installation](AUDIT-Q25-RESOLVER-FILES.md)
- [Q25: Linux route ownership after administrator changes](AUDIT-Q25-ROUTE-ATTRIBUTES.md)
- [Q25 — shared deadline for client route transactions](AUDIT-Q25-ROUTE-BUDGET.md)
- [Q25: original TUN and namespace during route cleanup](AUDIT-Q25-ROUTE-IDENTITY.md)
- [Q25: physical client route recovery after a crash](AUDIT-Q25-ROUTE-JOURNAL.md)
- [Q25: failed carrier-route mutation outcomes](AUDIT-Q25-ROUTE-OUTCOME.md)
- [Q25: route deletion specifications and verified cleanup](AUDIT-Q25-ROUTE-OWNERSHIP.md)
- [Q25: unknown route outcomes and release of orphaned reservations](AUDIT-Q25-ROUTE-PENDING.md)
- [Q25: verified carrier-route retirement and restoration](AUDIT-Q25-ROUTE-POSTCONDITIONS.md)
- [Q25: route ownership scoped to a connection lifetime](AUDIT-Q25-ROUTE-SCOPE.md)
- [Q25-F161: directory-enumeration errors during archive restore](AUDIT-Q25-SERVER-ARCHIVE-SCAN.md)
- [Q25-F135: refuse NAT auto-WAN without a usable default-route listing](AUDIT-Q25-SERVER-AUTO-WAN-FAILURE.md)
- [Q25-F158: saved versus active lockout policy](AUDIT-Q25-SERVER-BLOCKED-LIVE.md)
- [Q25-F160: INI revision for lockout-policy saves](AUDIT-Q25-SERVER-BLOCKED-REVISION.md)
- [Q25-F141: consistent server INI admission across CLI, panel and runtime](AUDIT-Q25-SERVER-CHECK-CONFIG-PARITY.md)
- [Q25-F115: server cleanup without blocking the async executor](AUDIT-Q25-SERVER-CLEANUP-WORKER.md)
- [Q25-F146: concurrent server INI writes](AUDIT-Q25-SERVER-CONCURRENT-WRITES.md)
- [Q25-F117: server profile DNS firewall setup off the async executor](AUDIT-Q25-SERVER-DNS-SETUP-WORKER.md)
- [Q25-F152: INI matrix and full restart for logging](AUDIT-Q25-SERVER-FIELD-MATRIX-LOGGING.md)
- [Q25-F130: server worker admission after forced cancellation](AUDIT-Q25-SERVER-FORCED-DROP-LEASE.md)
- [D07: global server INI fields](AUDIT-Q25-SERVER-GLOBAL-FIELDS.md)
- [Q25-F142: profile names cannot escape the server key directory](AUDIT-Q25-SERVER-IDENTITY-NAME.md)
- [Q25-F143: trust boundaries for identity_key and logging.file](AUDIT-Q25-SERVER-IDENTITY-TRUST.md)
- [Q25-F190 — server INI history errors](AUDIT-Q25-SERVER-INI-HISTORY.md)
- [Q25-F159: stable ordering of dynamic INI fields](AUDIT-Q25-SERVER-INI-ORDER.md)
- [Q25-F140: private permissions after panel writes server INI](AUDIT-Q25-SERVER-INI-PERMISSIONS.md)
- [Q25-F138: one size limit for server INI](AUDIT-Q25-SERVER-INI-SIZE.md)
- [Q25-F136: NAT44 off-WAN boundary with private LAN access](AUDIT-Q25-SERVER-NAT44-EGRESS.md)
- [Q25-F134: NAT66 blocks transit through another WAN](AUDIT-Q25-SERVER-NAT66-EGRESS.md)
- [Q25-F118: NDP proxy bind off the async executor](AUDIT-Q25-SERVER-NDP-BIND-WORKER.md)
- [Q25-F162: INI-only notification settings with bounded loading](AUDIT-Q25-SERVER-NOTIFY-INI.md)
- [Q25-F163: concurrent notification saves](AUDIT-Q25-SERVER-NOTIFY-REVISION.md)
- [Q25-F151: panel saves cannot promote an untrusted INI](AUDIT-Q25-SERVER-PANEL-SAVE-TRUST.md)
- [Q25-F150: INI trust in panel identity, Share, and users](AUDIT-Q25-SERVER-PANEL-SNAPSHOT-TRUST.md)
- [D07: foundational server profile fields](AUDIT-Q25-SERVER-PROFILE-FOUNDATION.md)
- [D07: server profile obf.* fields](AUDIT-Q25-SERVER-PROFILE-OBF.md)
- [Q25-F154: Quick Start and lockout-policy saves](AUDIT-Q25-SERVER-QUICKSTART-BF-SAVE.md)
- [Q25-F119: shared server profile setup budget and listener readiness](AUDIT-Q25-SERVER-SETUP-BUDGET.md)
- [Q25-F116: server profile TUN/NAT setup off the async executor](AUDIT-Q25-SERVER-SETUP-WORKER.md)
- [Q25-F137: SIGHUP refusal without partial VPN-auth changes](AUDIT-Q25-SERVER-SIGHUP-AUTH.md)
- [Q25-F155: SIGHUP restart hints for unapplied changes](AUDIT-Q25-SERVER-SIGHUP-RESTART-HINTS.md)
- [Q25-F148: TLS file validation in check-config](AUDIT-Q25-SERVER-TLS-CHECK-CONFIG.md)
- [Q25-F149: TLS path trust and Let's Encrypt panel saves](AUDIT-Q25-SERVER-TLS-PATH-TRUST.md)
- [Q25-F147: panel TLS PEM input and incomplete auto pair](AUDIT-Q25-SERVER-TLS-PEM.md)
- [Q25-F144: trust boundary for custom auth.users_file](AUDIT-Q25-SERVER-USERS-PATH-TRUST.md)
- [Q25-F145: SIGHUP and restart parity for users_file](AUDIT-Q25-SERVER-USERS-SIGHUP-RESTART.md)
- [Q25-F132: ambiguous auto-WAN for server profiles](AUDIT-Q25-SERVER-WAN-ECMP.md)
- [Q25-F131: WAN presence during managed server routing setup](AUDIT-Q25-SERVER-WAN-PRESENCE.md)
- [Q25-F153: panel authentication validation before saving INI](AUDIT-Q25-SERVER-WEB-AUTH-SAVE.md)
- [Q25-F156: panel hash validation at admission and live reload](AUDIT-Q25-SERVER-WEB-HASH-VALIDATION.md)
- [Q25-F139: panel live state after saving INI](AUDIT-Q25-SERVER-WEB-LIVE.md)
- [Q25-F157: truthful panel live-reload result](AUDIT-Q25-SERVER-WEB-RELOAD-RESULT.md)
- [Q25: initial physical-route setup and verified interface flush](AUDIT-Q25-SETUP-FLUSH.md)
- [Q25: owner evidence during setup and roaming](AUDIT-Q25-SETUP-IDENTITY.md)
- [Q25-F109: startup recovery on a joined worker](AUDIT-Q25-STARTUP-RECOVERY-TASK.md)
- [Q25 — state-directory trust and lock identity](AUDIT-Q25-STATE-DIRECTORY.md)
- [Q25-F111: ordered diagnostics writes outside the async executor](AUDIT-Q25-STATUS-WRITER.md)
- [Q25 — namespace checks at internal sysctl boundaries](AUDIT-Q25-SYSCTL-CONTEXT-IO.md)
- [Q25 — safe sysctl journal reads and lock waits](AUDIT-Q25-SYSCTL-JOURNAL-IO.md)
- [Q25: namespace isolation for the sysctl journal](AUDIT-Q25-SYSCTL-NAMESPACE.md)
- [Q25: sysctl owner evidence and preserving recovery](AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md)
- [Q25 — ownership of the original interface sysctl](AUDIT-Q25-SYSCTL-TARGET.md)
- [Q25: TUN and DNS system-command deadlines](AUDIT-Q25-SYSTEM-COMMANDS.md)
- [Q25-F103: system DNS waiting and client shutdown](AUDIT-Q25-SYSTEM-RESOLVER.md)
- [Q25: TCP task ownership and Linux path-monitor shutdown](AUDIT-Q25-TCP-TASKS.md)
- [Q25: safe Linux TUN/TAP admission and creation](AUDIT-Q25-TUN-ADMISSION.md)
- [Q25-F123: sysfs context during TUN dev_attach](AUDIT-Q25-TUN-ATTACH-CONTEXT.md)
- [Q25: attach without creating a TUN and preserve device framing](AUDIT-Q25-TUN-ATTACH.md)
- [Q25: propagate TUN, route and DNS cleanup failures](AUDIT-Q25-TUN-CLEANUP.md)
- [Q25: retain original TUN descriptors through cleanup](AUDIT-Q25-TUN-LIFETIME.md)
- [Q25-F106: asynchronous teardown of an established tunnel](AUDIT-Q25-TUN-TEARDOWN.md)
- [Q25: cancelled shutdown and TUN worker ownership](AUDIT-Q25-TUN-WORKERS.md)
- [Q25: shared TUN/TAP route installation and removal of obsolete implementations](AUDIT-Q25-TUNNEL-ROUTES.md)
- [Q25: UDP task ownership and path-rollback ordering](AUDIT-Q25-UDP-TASKS.md)
- [Q25-F129: ambiguous ECMP default WAN](AUDIT-Q25-WAN-ECMP.md)
- [Q25-F126: select the default WAN by route metric](AUDIT-Q25-WAN-METRIC.md)
- [Q25-A125: WAN name reuse](AUDIT-Q25-WAN-NAME-REUSE.md)
- [Q25-F204 — Linux worker resource churn](AUDIT-Q25-WORKER-RESOURCE-CHURN.md)

## Q26

- [Q26: shared C# and managed/native boundary — DONE/PASS](AUDIT-Q26-MANAGED-FINAL.md)

## Q27

- [Q27: service transitions, SCM, autostart and settings — stage PASS](AUDIT-Q27-WINDOWS-CONTROL.md)
- [Q27: Windows GUI, service and drivers — DONE/PASS within agreed scope](AUDIT-Q27-WINDOWS-FINAL.md)
- [Q27: service registration, status and logs — stage PASS](AUDIT-Q27-WINDOWS-OBSERVATION.md)
- [Q27: Windows archives and service profiles — stage PASS](AUDIT-Q27-WINDOWS-STORAGE.md)

## Q28

- [Q28: macOS daemon, helper and observation](AUDIT-Q28-MACOS-CONTROL.md)
- [Q28: macOS forwarding ownership and recovery](AUDIT-Q28-MACOS-FORWARDING.md)
- [Q28: guardian readiness and generation ownership](AUDIT-Q28-MACOS-GUARDIAN.md)
- [Q28: final macOS integration](AUDIT-Q28-MACOS-INTEGRATION.md)
- [Q28: macOS network cleanup and firewall ownership](AUDIT-Q28-MACOS-NETWORK.md)
- [Q28: per-app bridge, Swift policy and build paths](AUDIT-Q28-MACOS-PERAPP.md)
- [Q28: native socket lifetime and I/O budgets](AUDIT-Q28-MACOS-SOCKETS.md)
- [Q28: macOS storage and profile keys](AUDIT-Q28-MACOS-STORAGE.md)

## Q29

- [Q29: per-app UID and Private DNS](AUDIT-Q29-ANDROID-APP-POLICY.md)
- [Q29: CONNECTED after Android VPN publication](AUDIT-Q29-ANDROID-CONNECTED-GATE.md)
- [Q29 F282–F283: socket-protection ownership and trusted-Wi-Fi failures](AUDIT-Q29-ANDROID-CONTROLLER.md)
- [Q29: current VPN integrations and Android fixture reliability](AUDIT-Q29-ANDROID-CURRENT-VPN.md)
- [Q29: Android VPN payload and post-auth lifecycle](AUDIT-Q29-ANDROID-DATA.md)
- [Q29: bounded Doze and repeated carrier switching](AUDIT-Q29-ANDROID-ENDURANCE.md)
- [Q29: IPv4/IPv6 TCP/UDP after Android network switching](AUDIT-Q29-ANDROID-HANDOVER-PAYLOAD.md)
- [Q29: Android carrier-network handover](AUDIT-Q29-ANDROID-HANDOVER.md)
- [Q29: packets crossing carrier transitions and force-stop](AUDIT-Q29-ANDROID-LEAK-BURSTS.md)
- [Q29: concurrent Android TUN and JNI teardown](AUDIT-Q29-ANDROID-LIFECYCLE.md)
- [Q29: Android Release on an IPv6-only DNS64/NAT64 network](AUDIT-Q29-ANDROID-NAT64.md)
- [Q29: Android connection permission ownership](AUDIT-Q29-ANDROID-PERMISSIONS.md)
- [Q29: Android screen, deep idle and TCP recovery](AUDIT-Q29-ANDROID-POWER.md)
- [Q29: Android VPN recovery after process death](AUDIT-Q29-ANDROID-RECOVERY.md)
- [Q29: Android Release sleep and transport recovery](AUDIT-Q29-ANDROID-RELEASE-FAULTS.md)
- [Q29: instrumented Release runner](AUDIT-Q29-ANDROID-RELEASE-RUNNER.md)
- [Q29: minified Release and Android network runtime](AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md)
- [Q29: comparing Android DNS APIs](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md)
- [Q29: Android foreground service commands and lifecycle](AUDIT-Q29-ANDROID-SERVICE.md)
- [Q29 F289: apply LAN settings to an active connection](AUDIT-Q29-ANDROID-SETTINGS.md)
- [Q29 F286–F288: bounded input and final Android source review](AUDIT-Q29-ANDROID-SOURCE.md)
- [Q29: system DNS and cold Android Release enable](AUDIT-Q29-ANDROID-STARTUP-DNS.md)
- [Q29: VPN publication during cold startup](AUDIT-Q29-ANDROID-STARTUP-STATE.md)
- [Q29: Android storage, profile editor, backup and Release package](AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md)
- [Q29: Android system Always-on, lockdown and process death](AUDIT-Q29-ANDROID-SYSTEM.md)
- [Q29: TCP across Android Wi-Fi/Cellular switching](AUDIT-Q29-ANDROID-TCP-HANDOVER.md)
- [Q29: authenticated Private DNS / DoT](AUDIT-Q29-ANDROID-TRUSTED-DOT.md)
- [Q29 F281: trusted Wi-Fi with active lockdown](AUDIT-Q29-ANDROID-TRUSTED-LOCKDOWN.md)
- [Q29: trusted Wi-Fi service runtime](AUDIT-Q29-ANDROID-TRUSTED-WIFI.md)
- [Q29: Android UDP and QUIC masking recovery](AUDIT-Q29-ANDROID-UDP-RECOVERY.md)

## Q30

- [Q30: application status and managed preference ordering](AUDIT-Q30-IOS-APP-PREFERENCES.md)
- [Q30: first-writer ownership of Keychain identity and trust](AUDIT-Q30-IOS-KEYCHAIN.md)
- [Q30: provider ownership, stop/start and late OS completions](AUDIT-Q30-IOS-LIFECYCLE.md)
- [Q30: provider messages and backup UI request state](AUDIT-Q30-IOS-MESSAGES-BACKUP.md)
- [Q30: MDM numeric policies and asynchronous provider snapshots](AUDIT-Q30-IOS-POLICY-SNAPSHOT.md)
- [Q30: memory bounds, probe lifetime and source reconciliation](AUDIT-Q30-IOS-SOURCE-MEMORY.md)

## Q31

- [Q31: LuCI control, INI publication and firewall failures](AUDIT-Q31-OPENWRT-CONTROLS.md)

## Q32

- [Q32: bounded log reads and trace publication](AUDIT-Q32-LOGS-TRACE.md)
- [Q32: metrics across missing samples and worker changes](AUDIT-Q32-METRICS.md)
- [Q32: trusted notification INI and delivery correctness](AUDIT-Q32-NOTIFICATIONS.md)
- [Q32: usage reset at the atomic publication boundary](AUDIT-Q32-USAGE.md)

## Q33

- [Q33: binary installer payload and state preparation](AUDIT-Q33-BINARY-INSTALLER.md)
- [Q33: final installation, update, file and hook reconciliation](AUDIT-Q33-COMPLETION.md)
- [Q33: Debian package lifecycle and state protection](AUDIT-Q33-DEBIAN-LIFECYCLE.md)
- [Q33: Docker entrypoint configuration and first-run publication](AUDIT-Q33-DOCKER-ENTRYPOINT.md)
- [Q33: installer dependency and Debian package admission](AUDIT-Q33-INSTALLER-ADMISSION.md)
- [Q33: actual installer CLI and version compatibility](AUDIT-Q33-INSTALLER-CLI.md)
- [Q33: installer preflight and staged INI publication](AUDIT-Q33-INSTALLER-CONFIG.md)
- [Q33: installer secret and web-config publication](AUDIT-Q33-INSTALLER-SECRETS.md)
- [Q33: actual portable DEB, update and rollback](AUDIT-Q33-PACKAGE-MANAGER.md)
- [Q33: server updater package transactions](AUDIT-Q33-SERVER-UPDATER.md)
- [Q33: service-user transitions and installer secret ownership](AUDIT-Q33-SERVICE-USER.md)
- [Q33: real systemd sandbox, SIGHUP and root service mode](AUDIT-Q33-SYSTEMD.md)

## Q34

- [Q34 — native libraries after adopting the panel fixes](AUDIT-Q34-ADOPTED-NATIVE.md)
- [Q34: Android dependency locks and checksum verification](AUDIT-Q34-ANDROID-DEPENDENCIES.md)
- [Q34: project licenses and Maven notices in Android APKs](AUDIT-Q34-ANDROID-NOTICES.md)
- [Q34 — Android build recipe and runtime evidence](AUDIT-Q34-ANDROID-RUNTIME.md)
- [Q34: artifact provenance and atomic checksums](AUDIT-Q34-ATTESTATION-CHECKSUMS.md)
- [Q34: client build dependencies and Windows signatures](AUDIT-Q34-CLIENT-SUPPLY.md)
- [Q34: Rust dependencies, CI policy and TLS PEM](AUDIT-Q34-DEPENDENCY-POLICY.md)
- [Q34: full amd64 Docker build and release admission](AUDIT-Q34-DOCKER-BUILD.md)
- [Q34: immutable Docker frontend and APT inputs](AUDIT-Q34-DOCKER-INPUTS.md)
- [Q34: complete CI fuzz target inventory](AUDIT-Q34-FUZZ-INVENTORY.md)
- [Q34: reproducible fuzz CI and complete ASan smoke](AUDIT-Q34-FUZZ-TOOLCHAIN.md)
- [Q34/Q25 — Linux packet matrix and roaming soak](AUDIT-Q34-LINUX-MATRIX.md)
- [Q34: .NET notices and embedded font licensing](AUDIT-Q34-MANAGED-NOTICES.md)
- [Q34: Android Maven graph security](AUDIT-Q34-MAVEN-SECURITY.md)
- [Q34: common Cargo legal resources](AUDIT-Q34-NATIVE-NOTICES.md)
- [Q34: exact local OpenWrt source cut](AUDIT-Q34-OPENWRT-SOURCE-CUT.md)
- [Q34: Git trust flags in OpenWrt source admission](AUDIT-Q34-OPENWRT-SOURCE-FLAGS.md)
- [Q34: release source admission and Docker notices](AUDIT-Q34-PUBLICATION-GATES.md)
- [Q34/Q25 — memory across 100 release handovers](AUDIT-Q34-RELEASE-SOAK.md)
- [Q34: .NET SDK and dependency locks](AUDIT-Q34-SDK-LOCKS.md)
- [Q34: exact MicroCom.Runtime source identity](AUDIT-Q34-SOURCE-BINDING.md)
- [Q34: standard-library and toolchain runtime notices](AUDIT-Q34-TOOLCHAIN-NOTICES.md)
- [Q34: permanent GitHub Actions semantic gate](AUDIT-Q34-WORKFLOW-LINT.md)

## Q35

- [Q35 — client INI and qeli:// fuzzing invariants](AUDIT-Q35-CLIENT-CONFIG-FUZZ.md)
- [Q35 — final fuzz, fault, concurrency, DoS and soak review](AUDIT-Q35-FINAL.md)
- [Q35 — UDP fragment reassembly fuzz oracles](AUDIT-Q35-FRAGMENT-FUZZ.md)
- [Q35 — concurrent extended TCP and UDP roaming soak](AUDIT-Q35-LONG-SOAK.md)
- [Q35 — full release-soak admission](AUDIT-Q35-RELEASE-ADMISSION.md)

## Q36

- [Q36: current data-plane statistical population](AUDIT-Q36-CURRENT-STATISTICS.md)
- [Q36 — benchmark audit completion](AUDIT-Q36-FINAL.md)
- [Q36: matched-total P1/P4 load and TUN boundary counters](AUDIT-Q36-MATCHED-LOAD.md)
- [Q36 — actual TUN boundary diagnostics and observer effects](AUDIT-Q36-TUN-STAGE.md)
- [Q36-F018: UDP shutdown and retained task failures](AUDIT-Q36-UDP-SHUTDOWN.md)

## Q37

- [Q37: documentation and test harnesses — 11 October 2026](AUDIT-Q37-DOCUMENTATION.md)

## Documentation reconciliation

[Post-audit 0.8.2 documentation review — 16 October](DOCUMENTATION-REVIEW.md)

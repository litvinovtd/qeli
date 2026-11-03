# Q25 — DNS service context and direct D-Bus calls

<!-- normative-sync: audit-q25-resolver-context-v1 -->

24 September 2026. Base `76ff2df3`. Partial D06/D09/D10 closure.

## Q25-F094, P1 — a numeric ifindex could target another network

The isolated `resolver-context-probe-v2` reproduced the defect: `resolvectl dns 2`
from a child network namespace over a shared bus changed DNS on the parent service's
`foreign0`, which also had ifindex 2. The change was reverted in that private fixture.
Checking the TUN and `/etc/resolv.conf` did not establish the receiver's context.
Additionally, `resolvectl` can forward DNS/domain/revert to networkd on `LinkBusy`;
checking resolved before/after does not bind the receiver.
CLI behavior: [systemd v257 resolvectl](https://github.com/systemd/systemd/blob/v257/src/resolve/resolvectl.c).

The client now holds a namespace fd and resolver context with the DNS lease:

- one local Unix bus (`path` or `abstract`); the broker and caller share a PID
  namespace, so foreign-namespace PID numbers are not interpreted locally;
- AUTH EXTERNAL checks the endpoint and captures its GUID; every `busctl` uses
  that GUID in its address, `--auto-start=no`, and the service's specific unique name;
- separate `GetId`, unique owner, PID, resolved network namespace, repeated owner
  reads and calling-thread context checks;
- the context is checked before/after DNS, domain and revert. A replacement service
  or bus fails while retaining the lease; no automatic adoption of a new owner and
  no implicit forwarding to networkd;
- authentication is bounded to 128 bytes and the remaining total deadline; identity
  replies to 1024 bytes after the bounded command runner. Setup shares its existing
  15 seconds; cleanup gets separate 15 seconds. Internal file I/O is not made interruptible.

The AUTH GUID and message-bus `GetId` are distinct identities. Checking the GUID on
connection prevents unique-name reuse after a bus restart between inspection and
method delivery. [D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html),
[sd-bus v257 GUID check](https://github.com/systemd/systemd/blob/v257/src/libsystemd/sd-bus/bus-socket.c).

## Q25-F095, P2 — a nonstandard DNS port was passed as a server name

For a NetworkPlan port other than 53, the adapter passed `address#port` to
`resolvectl`: the suffix denotes the DNS/TLS server name, not its port. Addresses
are now typed byte arrays, and ports separate `uint16` values in `SetLinkDNSEx`,
with an empty server name. Lists using only port 53 use `SetLinkDNS`. There is no
fallback to an API silently losing a custom port. INI and shared NetworkPlan formats
are unchanged. [CLI contract](https://github.com/systemd/systemd/blob/v257/man/resolvectl.xml).
A separate real fixture read the old call back as `DNSEx` port 0 and server name `5353`; the fixed adapter read back `192.0.2.53:5353`. The server still advertises port 53 and redirects it to its listener; this fix covers arbitrary valid NetworkPlan ports.

## Supported configuration

Linux `dns = tunnel` requires `busctl`, an already running systemd-resolved, its stub
in `/etc/resolv.conf`, accessible procfs, a shared client/service network namespace,
and a shared caller/broker PID namespace. A custom local `DBUS_SYSTEM_BUS_ADDRESS`
is supported and captured at setup. TCP buses, fallback address lists and foreign
PID namespaces are refused. Non-53 ports require `SetLinkDNSEx`. On `LinkBusy`, adjust
external manager ownership of the TUN or delegate DNS through `dns = off`/`system`.
Services are not autoactivated and the persistent resolver file is not rewritten.
`resolvectl` remains useful for manual diagnostics.

## Validation and boundaries

Added 11 ordinary Linux regressions, one privileged foreign-network check and a
separate real dbus-daemon/resolved child fixture. **1491 host + 71 config,
9 feature/cross/lint checks PASS; 2023 Linux + 33 privileged + 8 worker E2E PASS**.
The real service confirmed default/custom ports, domain/revert and refusal of a
foreign network or wrong AUTH GUID. An additional nested PID namespace was refused
before DNS mutation; the parent service's per-link state remained empty.

Disabling context guards reproduced 3 FAILs (owner replacement, new bus, foreign
network), separately restoring the well-known destination another 1 FAIL. Sources
were restored: **29 DNS + 1 privileged PASS**. Full packet matrix: **17/17,
301 assertions PASS**; Bash syntax and 8 Python harness checks PASS. All 325 source
files were verified before/after runs. Later changes only update comments in three
Rust files and the INI example: equality of all other lines was verified separately;
no repeat runtime test of those comments is claimed.

Source archive: `93bec3ea6a769da24ae5156cec57e40e68f7cfd0e76d31f23d2d1f76b8b20912`.
Debug worker: `6b6f6eda9975cffe5dc52f451ee5b791e6a62a360999be02a0f10b3e2cfda018`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/resolver-direct-phase/`,
`resolver-direct-final.log`, `resolver-direct-native/`, `resolver-direct-counterfactual/`,
`resolver-pidns-native/`, `resolver-port-baseline/`, `lifecycle-resolver-direct/`,
`packet-matrix-resolver-direct/`. Comment changes: `post-test-comment-changes.json`.
Rust Linux 1.97 / host 1.98; existing Clippy exception `chunks_exact_to_as_chunks`.
The intermediate `resolver-service` snapshot and its 17/17 matrix remain separate;
the results above refer to the subsequent `resolver-direct` snapshot.

Lab `.11`, private network/mount/PID namespaces; live server `.10` was unchanged.
The matrix no longer treats a successful stub log as proof of applied DNS: it runs
real dbus-daemon/resolved, reads per-link state, sends A/AAAA through 127.0.0.53,
and checks DNS removal after stop while the service is still alive.

Observations are not an atomic lock against external root moving a live service or
replacing a link after inspection. External managers' previous per-link state is not
saved for automatic recovery. Persistent recovery remains D04; whole NetworkPlan
limits D05. D06 remains open for process-global DNS/carrier state and other register
criteria. This run is not final release benchmarking or platform certification.
Windows VM/Mac/iOS/router runtime is skipped by the user's decision.

[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/CONFIG.md)

Follow-up: [Q25-F096/F097](AUDIT-Q25-DNS-MARKER-STORAGE.md) moves DNS markers to v2 with SO_NETNS_COOKIE and a trusted held directory, testing SIGKILL/restart with real resolved. Counts and the v1 contract above describe the historical snapshot; current operations are in TROUBLESHOOTING §6.50.

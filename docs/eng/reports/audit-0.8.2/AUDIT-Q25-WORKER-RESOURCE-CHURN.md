# Q25-F204 — Linux worker resource churn

<!-- normative-sync: audit-q25-worker-resource-churn-v2 -->

Date: 1 October 2026. Current Rust source previously synchronized to
lab .11; `cargo build --offline --locked --bin qeli` with
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=1` passed.
Tested debug binary SHA-256:
`ae59962eebe483ad4d312bda34cb5634bf66bcd2ca372869b17b15e8c95e66d9`.
Complete `qeli/src`: 308 files with the same digest
`64be415e454438fe2b90129168069e0be9a9caf4a7a467bca24398fd4a6250aa`
in the checkout and on .11.

The existing `scripts/audit_worker_lifecycle.py` gained bounded
`--resource-reloads 10`. Every case runs in fresh network, mount,
and PID namespaces with a private bind mount for `/etc/qeli`.
After worker readiness, a second owner is rejected and malformed
SIGHUP is rejected; ten valid SIGHUPs follow, with a control request
between them. Snapshots of `/proc/<pid>/fd`, socket fds, `task`,
and `VmRSS` are saved before and after every reload. Predetermined
criteria: final fd/socket fd/task growth no more than two, sampled
peak RSS no more than +32 MiB. After SIGTERM, TUN, routes, firewall,
sysctl, control socket, and journal are checked.

| Modes | Result | Δ fd/socket/tasks | Largest Δ RSS |
|---|---:|---:|---:|
| TCP: off/manual/route/nat66 | 4/4 PASS | 0/0/0 in each | 15,520 KiB |
| UDP: off/manual/route/nat66 | 4/4 PASS | 0/0/0 in each | 15,472 KiB |

Overall **8/8 cases and 80 valid reloads PASS**. All eight second-worker
rejections and eight malformed reloads preserved the live worker.
After every stop, the control socket, TUN, Qeli rules, and
`sysctls.state` are gone; full before/after network snapshots match
under the documented checks. The RSS limit is a sampled peak, not
a continuous maximum between samples. `py_compile` and
`git diff --check` passed.

Raw evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/d13-resource-20261001/`
(`results.json`, eight `resource-samples.json` files,
network-before/after, active firewall dumps, and worker logs).
Identity keys were not copied from the isolated lab.

## TCP same-session churn and strict `rp_filter`

The first current-source Linux client run with the lab's
`net.ipv4.conf.all.rp_filter=1` could not receive replies on the standby
path: the old `/32` server route remained on A until COMMIT while the new
carrier's reply arrived on B. Changing only
`net.ipv4.conf.qrm-b.rp_filter=2` in the isolated lab confirmed the cause:
handover passed. The client now acquires a managed lease on the IPv4
candidate interface at PREPARE and releases it at COMMIT/ABORT. Its original
value and journal entry are restored; the global sysctl is unchanged. The
harness temporarily checks path B with a loose filter and restores strict
mode **before** the client starts, so preflight cannot mask the fix.

The first 100-handover debug soak confirmed all 100 COMMITs and no orphan
or socket accumulation, but retained a real FAIL: client fds grew 18→26
and server RSS grew by 54,216 KiB. The generation-length interface lease
accounted for the extra fds; limiting it to COMMIT/ABORT removed that
retention. Debug RSS must not be substituted for the production allocator's
release result.

Final `qeli/src`: **308 files**, matching digest
`f3626d47535f5cb73286adcd2e50de7ab88f466158b291fbfc22947045cda124`.
`cargo build --offline --locked --release --features jemalloc --bin qeli` PASS;
release SHA-256 `a526c03bf0bae927828e91f11ac5d751c3a82e560a7f12ada3a6ab6b410cedb0`.
This exact binary passed **20/20** single-handover and **16/16**
100-handover TCP fake-tls soak checks. One session, original processes/TUN,
and 100 client/server COMMITs remained; orphan=0 and there was no repeat
AUTH. Client fds 18→18, socket fds 6→6, RSS 51,712→54,104 KiB
(sampled peak +2,524 KiB). Server fds 21→21, socket fds 7→7,
RSS 52,100→56,764 KiB (sampled peak +4,664 KiB). All values are below
the fixed +32 MiB RSS and fd limits. `cargo fmt --all -- --check`
passed. The full `cargo test --offline --locked --lib` at the lab's initial
1024-fd soft limit gave 2,237 PASS / 1 FAIL (`EMFILE`): the DNS capacity
test holds 512 client and 512 server TCP sockets at once. At soft limit
4096 with `--test-threads=2`, the same suite gave **2,238 PASS / 0 FAIL**
(59 ignored); both complete logs are retained. Namespaces, test listeners, and
processes were absent afterward; .10's `qeli-server.service` remained
active on :443.

Raw evidence in the same directory: `qeli-d13-product-rpf2.log`,
`qeli-d13-product-soak100.log` (debug FAIL),
`qeli-d13-final-success.log`, `qeli-d13-final-soak100.log`,
`qeli-d13-fmt.log`, `qeli-d13-unit.log`, and `qeli-d13-unit-fd4096.log`.

## UDP same-session and two-profile stop/fault

The same `a526c03b` release binary completed **100/100** UDP QUIC
same-session COMMITs: **17/17** checks PASS. Original client/server
processes and TUN survived; no repeat AUTH, candidate, or CID accumulation.
Client fds 18→19, socket fds 6→7, RSS 51,532→60,660 KiB
(sampled peak +13,048 KiB); server fds 21→21, socket fds 7→7,
RSS 59,792→74,728 KiB (sampled peak +14,936 KiB). Both peaks stay
below the predefined +32 MiB budget. After COMMIT, both `rp_filter`
values returned to their original strict value 1 and the sysctl lease
left the journal. The first run is retained as **FAIL 14/15** solely
because preflight probed B with its source address while the default
still selected A under strict reverse-path filtering. The corrected
preflight temporarily uses a candidate-compatible filter and
`ping -I qru-b`, restoring strict mode **before** Qeli starts. No
product change was needed.

New `scripts/audit_worker_multiprofile_resource.py` isolates network,
mount, and PID namespaces and exercises concurrent TCP `alpha` and UDP
`beta` profiles. **14/14** assertions PASS: malformed SIGHUP retained both
profiles; ten valid reloads held fd/socket/task counts at
26/11/7→26/11/7 and sampled RSS peak at 54,224→54,352 KiB (+128 KiB).
Graceful stop ran both `post_down` hooks exactly once and restored the
original firewall, routes, links, forwarding, control socket, and
journal. After SIGKILL both profiles' rules and journal remained for
recovery; restarting only `alpha` removed orphan rules/device for the
deleted `beta`, and final clean stop restored the original snapshot.
The first version of this new harness falsely detected second-run
readiness from the old hook file; waiting for a new `up` entry fixed it.

Three other UDP wire modes used the same binary for 20 transitions
each: `fake-tls`, `obfs`, and `obfs-awg` all passed **17/17** checks.
Each retained one session and the original processes/TUN, counted
20 COMMITs, avoided fd/socket accumulation, and restored `rp_filter`
and the sysctl lease. The largest sampled RSS increase in those three
runs was +12,428 KiB server and +5,660 KiB client. These are bounded
20-transition adapter checks, not a 100-transition endurance run for
each adapter.

D13 is **DONE** within the available Linux scope: bounded worker
reload/stop, TCP and UDP same-session churn, two-profile SIGKILL/recovery,
and network-object restoration met the recorded criteria. This does not
claim a continuous RSS maximum between samples or unavailable platform
runtime checks.

Raw evidence: `udp-quic-100.log` (initial harness FAIL),
`udp-quic-100-fixed.log`, `multi-profile.log` (early false-ready FAIL),
`multi-profile-02.log`, `multi-profile-02/` (14 results, snapshots,
resource samples, and logs), plus `udp-fake-tls-20.log`,
`udp-obfs-20.log`, and `udp-obfs-awg-20.log`. Earlier 100 release handovers at
`ea87fd49` remain separate evidence.

[Debt register](../../plans/AUDIT-DEBT.md) ·
[Earlier release soak](AUDIT-Q34-RELEASE-SOAK.md)

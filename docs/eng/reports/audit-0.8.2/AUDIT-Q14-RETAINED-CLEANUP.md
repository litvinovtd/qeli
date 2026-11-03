# Q14 — exact NAT cleanup and generation stop outcomes

<!-- normative-sync: audit-q14-retained-cleanup-v1 -->

Date: 24 September 2026. Baseline: `d85ead10`. Closes D01 in the
[debt register](../../plans/AUDIT-DEBT.md); the full audit remains open.

## Fixes

**Q14-F027: generic NAT and retired generations within a live worker.** Previously,
tagged-sweep failures were only logged. A failed teardown could enter backoff and
its error disappear after a replacement generation. The worker now retains exact
IPv4/IPv6 NAT, FORWARD, MSS and DNS REDIRECT specifications before `-A/-I`. A failed
or interrupted command cannot discard them. Cleanup checks each rule with `-C/-D`,
continues after individual failures and releases only verified absent rules. Missing
tools retain evidence for retry. The limit is 32768 unique specifications; capacity
exhaustion refuses new untracked mutations, while repeats use no additional slots.
DNS INPUT keeps its existing lease registry. Historical tag sweeps remain additional
best-effort recovery, including transitions from older configurations.

`run_profile` distinguishes operational failure from cleanup failure. Ordinary startup
errors can be retried after successful cleanup. Incomplete teardown prevents another
profile generation in the same worker: the failure reaches the worker, which stops its
remaining tasks and returns an error. This preserves a TUN queue timeout after the
three-second grace period and prevents replacement over retained resources. Another
thread’s raw descriptor is never forcibly closed.

**Q14-F033, P2: IPv4 forwarding remained enabled after successful stop.** The
`server-ipv4` scope was acquired for the worker lifetime but never released on a clean
stop. Final cleanup now releases it after all profiles and exact firewall retries;
release failure becomes part of the stop result. The sysctl journal still respects
shared owners. Stopping one profile does not disable forwarding beneath another live profile.

## Verification

- Host: **1421 unit + 71 config integration PASS**; nine feature/cross/lint commands PASS.
- Linux, Rust 1.97.0, Debian kernel 6.12.105: **1862 ordinary tests PASS**.
- Separately, **18 privileged tests PASS**: seven route identity, seven TUN/TAP ioctl,
  exact IPv4/IPv6 firewall, carrier bind/source, physical-path observation and chown.
  Two ignored child fixtures are invoked by their parents, never independently.
- **8 E2E PASS**: TCP/UDP × `off/manual/route/nat66`. A real `_worker`, INI
  `check-config`, malformed config/reload, rejection of a second worker by the control
  lease, one post_up/post_down, SIGTERM, disappearance of TUN/socket/rules, restored
  forwarding/accept_ra and retirement of the released sysctl journal. `manual` starts
  with NDP `required`; no Qeli IPv6 rules or forwarding change are allowed. This does
  not demonstrate delivery of actual NDP packets.
- The same E2E on the original `d85ead10` binary fails in the first TCP/off case with
  `IPv4 forwarding lease leaked`; the corrected snapshot passes all eight cases.
- Fixed the earlier native rename fixture: `link down` can remove its route before
  cleanup. The test now reseeds the route on the renamed interface and verifies its
  presence before the operation under test.

Reproducible runner: `scripts/audit_worker_lifecycle.py --qeli /path/to/qeli
--artifacts /new/absolute/directory`. Requires root, unshare, iproute2, iptables/ip6tables,
/dev/net/tun and an existing /etc/qeli mount point. It creates private network, mount
and PID namespaces, enables loopback, mounts the matching sysfs and replaces /etc/qeli
only in its private mount namespace. Test-process fd limit must be at least 8192.
The complete E2E deadline is 420 seconds; its child namespace is tied to the runner.

Local evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`:
`checks.json`, `linux-tests-v6.log`, `native-extra-v2.log`, `lifecycle-final/`,
`baseline-build.log`, source manifests and binary SHA256 values. Unsuccessful initial
runs are retained: disabled loopback, RLIMIT_NOFILE=1024, an incorrect child-fixture
filter and the rename fixture are not reported as successful product verification.

## Limits

Exact firewall registries remain in worker memory. SIGKILL/crash, previous workers,
unlistable mixed nft chains without saved specifications and persistent recovery
remain D04. This does not add atomicity against privileged external changes, a whole
cleanup deadline, new benchmarks, native release certification or device tests.
Individual command deadlines are unchanged. INI/API/ABI/wire contracts are unchanged.

Follow-up: [Q14-F034 — shared cleanup deadline](AUDIT-Q14-NAT-CLEANUP-BUDGET.md)
covers profile/startup/final cleanup admission and commands; the earlier results above
refer to their own snapshot. NAT setup/rollback, DNS lease Drop/setup admission and
persistent recovery remain open.

Follow-up: [Q14-F037](AUDIT-Q14-WORKER-NETWORK-LEASE.md) prevents bypassing the control lease through another path/filesystem namespace. A new kernel lease scopes server-worker admission to the network; SIGKILL/deleted-profile recovery was tested for listable tagged rules. Persistent exact-rule journaling and mixed nft remain open.

Later follow-up: [Q14-F038](AUDIT-Q14-FIREWALL-JOURNAL.md) adds a persistent exact server firewall journal and verifies recovery with listing failures. Client crash recovery and the general mixed nft/firewalld matrix remain open.

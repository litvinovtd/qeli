# Q25: persistent TUN/TAP after SIGKILL

Date: 24 September 2026. Verified code: `25688fe8`.
This validates existing protection at runtime; **no new defect was found**.
The persistent TUN portion of D04 is closed within safe refusal and explicit manual
removal of a verified orphan. D04 remains **IN_PROGRESS** for the mixed firewall matrix.

## Contract under test

An ordinary nonpersistent device disappears when its last queue fd closes.
A persistent TUN/TAP survives SIGKILL. A fresh managed client cannot claim it by name:
route recovery refuses before DNS/handshake and preserves the device, addresses,
routes and journal. A retained marker does not authorize clearing DNS for a live index.

After confirming all owners have stopped, an administrator may remove an unwanted
orphan in its original namespace. Only then does an ordinary restart with the same
`dev` recover confirmed physical records, retire the absent link's DNS marker, create
a new interface and restore connectivity. This does not automatically delete a
persistent TUN. See [troubleshooting §6.82](../../manuals/TROUBLESHOOTING.md#682-linux-persistent-tuntap-survives-client-termination).

## Scenario and evidence

Added `scripts/audit_persistent_tun_shim.c` and `scripts/audit_persistent_tun.py`;
extended `scripts/ipv6_netns_case.sh`. Test-only preload sets persistence on the
original fd after successful exclusive `TUNSETIFF` and records PID/name evidence.
Subsequent client starts use the unchanged binary without preload.

After real SIGKILL/wait, the harness verifies the original ifindex and kernel persist
flag, then starts a new managed client. Refusal must exit on its own with nonzero
status and the exact diagnostic; timeout is a FAIL. Link, addresses, both route tables
and journal are compared before/after. DNS scenarios additionally check the DNS marker,
servers and catch-all domain in real resolved, plus both filter tables. Identity/type
are rechecked before explicit operator removal; the existing matrix harness then
verifies ordinary restart, traffic and clean stop.

- **17/17 rows, 19 network scenarios, 506 main assertions PASS**.
- **17 persistent scenarios, 199 detailed checks PASS**. These sit inside 17 aggregate
  main assertions; their sum does not represent 705 independent tests.
- 12 outer IPv4/IPv6 × inner IPv4/IPv6 × TCP/UDP fake-TLS/UDP QUIC full scenarios,
  TAP, two DNS networks and two MTU/PMTU scenarios. Two split controls omit persistence.
- 15 route crash/restart scenarios also preserve an unrelated static route; two DNS
  crash/restart scenarios use real private resolved/D-Bus with the kill-switch enabled.
- Refusal took 0.016–0.017 s with exit 1; this is a lab observation, not an SLA.
- 8 matrix contract tests, shell syntax and shim compilation with
  `-Wall -Wextra -Werror` PASS.

Environment: Debian, Linux `6.12.105+deb13-amd64`, x86_64, GCC 14.2.0,
iptables/ip6tables 1.8.11 (nf_tables). Client and test server run in separate network
namespaces inside private mount/PID context; `/var/lib`, `/run`, `/var/log`, `/tmp`
and `/etc/qeli` are isolated. The running lab server was not replaced.

Runtime worker SHA256: `3f52a9d5c1b3484592d5df9214372eebb7f90e44b30265df20b5d714325de8c0`.
The previously frozen worker was reused: all 340 Rust/conformance files match its
verified snapshot; remote source was checked before and after the run. Rust was
unchanged and full Rust suites were not rerun. Preload affects only the test queue.
Harness archive SHA256: `f81d5203b39ce06117ad790ad3ac5f8e368ee7d346b8f4965e1e511bcd3beb50`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/persistent-tun-phase/`,
`persistent-tun-smoke-v1/`, `persistent-tun-matrix-v1/` and matching logs/rc/tar.
Commands, source/script/binary hashes, JSON snapshots and each refusal/restart are
retained. `persistent-tun-phase/matrix.sh` reproduces the run in isolated Linux context,
compiling the shim and enabling `QELI_PERSIST_TUN_SHIM`, `QELI_ROUTE_CRASH_CHECK=1`,
`QELI_DNS_CRASH_CHECK=1`, `QELI_DNS_KILL_SWITCH=1`.

## Limits

This confirms managed full-tunnel crash recovery with the old name and shared state
directory. Automatic adoption of foreign/persistent devices, renamed leftovers,
concurrent replacement by another root and manual repair of arbitrary hosts are not
certified. `dev_attach` with foreign sysfs remains D06; mixed nft/legacy/firewalld
remains D04/D10. These are not new benchmark or final native-build results.

Overall register: **3/15 DONE, 10 IN_PROGRESS, 2 TODO — 20% by closed groups**.
[Register](../../plans/AUDIT-DEBT.md) · [Operations](../../manuals/OPERATIONS.md).

Final D04 follow-up: [client mixed packet/recovery matrix and Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) completed; D04 is DONE in the current register. Historical IN_PROGRESS statements above refer to earlier snapshots. D10 (broader policies/topologies) and D13 (state growth) remain open.

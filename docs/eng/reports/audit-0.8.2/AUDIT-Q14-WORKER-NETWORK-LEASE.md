# Q14 — worker ownership within a network namespace

<!-- normative-sync: audit-q14-worker-network-lease-v1 -->

24 September 2026. Base `1bbd596c`. Partial D04/D06/D09 closure.

## Q14-F037, P1 — a different control socket bypassed worker exclusion

The control lease protected one filesystem path. Two workers with different
`QELI_CONTROL_SOCKET` and `STATE_DIRECTORY` paths, even in separate mount/PID
namespaces, could share one network. The second passed admission, loaded accounting
and called `nat::cleanup_all`: the startup sweep deleted the still-running first
worker's `qeli-nat:*` rules. Distinct profiles, TUNs and ports did not prevent this.

The isolated baseline started the second profile; the first worker's IPv4 rules
fell from **9 to 0**, including NAT, DNS INPUT and REDIRECT. Its process remained
alive. An ordinary second-instance startup could thus destroy active firewall state.

After config validation, before preflight, users/accounting, control listener, hooks
or network changes, the worker now binds the abstract AF_UNIX datagram name
`qeli.server.worker`. The kernel scopes it to the network namespace. The descriptor
remains alive through worker shutdown, including profiles/post_down and accounting.
Normal exit, startup errors and SIGKILL release the name by closing the fd. CLOEXEC
prevents commands and hooks from inheriting it. There is no file for this lease:
removing a control lock or changing directories cannot bypass namespace admission.

One namespace admits **one server worker with all its profiles**. Multiple workers
require separate network namespaces and separate config/state/control paths.
The normal supervisor + worker arrangement is unchanged; the supervisor does not
claim this name. Client lifetime reservations use different names.

## Validation

- **1491 host + 71 config, 9 feature/cross/lint checks PASS**.
- **2027 Linux + 34 privileged + 8 worker lifecycle PASS**.
- 4 new ordinary Linux regressions: repeated bind/drop, independent names, CLOEXEC
  and release after SIGKILL of a separate process. One new privileged test checks
  identical reservation names in different network namespaces.
- New `scripts/audit_worker_recovery.py`: **22 checks PASS**. Another worker with
  different control/state paths and separate mount/PID namespaces is refused before
  hooks, control binding or accounting; the first remains responsive with unchanged firewall.
- SIGKILL leaves NAT/DNS rules and the sysctl journal, removes the nonpersistent TUN,
  and releases admission. After deleting the old profile from config, the next worker
  removes its listable tagged rules while preserving foreign IPv4/IPv6 rules. Stop
  restores forwarding and retires the released sysctl journal.
- A further worker is refused during delayed `post_down`. An invalid users file after
  admission releases the lease; the subsequent valid startup and stop succeed.
- The same final runner on baseline gives the **expected FAIL** on second-worker
  admission and retains before/after evidence of all nine deleted rules. The initial
  fixture error (`dns.listen` not matching the TUN) remains separate and is not a pass.

327 source files verified before/after. Source archive:
`68528120cd890e9723eec8d2bd79b7259e9bd60ca2191048a8facbb103294453`.
Worker SHA256: `dfcbd8c654a57dd805aa15c3a7fc0feed1b372e66093a5cc251a7f91f9b5a72a`.
Baseline SHA256: `6b6f6eda9975cffe5dc52f451ee5b791e6a62a360999be02a0f10b3e2cfda018`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/worker-lease-phase/`,
`worker-lease-final.log`, `worker-admission-baseline-v4/`, `worker-admission-fixed-v2/`,
`lifecycle-worker-lease/`. Earlier runs remain under their own names.
Linux Rust 1.97, host 1.98; existing Clippy exception `chunks_exact_to_as_chunks`.
Live server `.10` was unchanged; `.11` was used with private namespaces.

## D04 boundaries

This is cooperative startup exclusion, **not a persistent exact-rule journal**.
Old binaries do not participate: stop the old worker before upgrading. An arbitrary
local process can bind the abstract name first and deny startup; this mechanism does
not protect availability against such a process. Qeli does not bypass an unknown
holder or automatically kill it.

Crash E2E covers the existing tagged sweep on listable iptables-nft chains. Mixed nft
where listing is unavailable, durable firewall/route specifications, crash DNS and
arbitrary external mutations remain open. D04 moves to IN_PROGRESS; the other debt
criteria remain in the register. No new INI key, ABI/wire change, release benchmark
or native certification. Windows VM/Mac/iOS/router runtime is skipped by user decision.

[Register](../../plans/AUDIT-DEBT.md) · [Operations](../../manuals/OPERATIONS.md)

Later follow-up: [Q14-F038](AUDIT-Q14-FIREWALL-JOURNAL.md) adds a persistent exact server firewall journal and verifies recovery with listing failures. Client crash recovery and the general mixed nft/firewalld matrix remain open.

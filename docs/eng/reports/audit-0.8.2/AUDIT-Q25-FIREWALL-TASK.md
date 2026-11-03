# Q25-F107/F108: asynchronous kill-switch operations and retained DROP after unhook failure

25 September 2026. Base `1d066863`. D05/D09, Linux.

## Q25-F107: blocking firewall operations and cancellation

Kill-switch setup and refresh already awaited DNS asynchronously, but then executed
all iptables/ip6tables commands on the async executor. `cleanup_routing_features`
also synchronously removed forwarding and firewall state. A delayed command stopped
neighboring tasks on a current-thread runtime. Simply moving work to a background task
would be insufficient: the old outer stop `select` could lose a running mutation and its error.

Preparation is separated from firewall mutation. `prepare_engage` and `prepare_refresh`
return owned work carrying namespace context, the original deadline, server addresses,
allowed resolvers and options. Read-only preparation can be cancelled immediately,
without changing firewall state. Admitted work runs on the shared joined worker,
inheriting NET/mount context. Its actual result is retained after stop: an error cannot
become successful cancellation. Successful setup/refresh after stop proceeds to ordinary
cleanup without a new connection. Existing operation and separate setup-rollback budgets remain.

All six terminal paths call asynchronous `cleanup_routing_features` and await the full
forwarding → kill-switch sequence before post_down and lease release. Earlier cleanup
failure still prevents kill-switch release. Thread creation/context/panic failures also
return errors; forced Drop synchronously joins the worker, leaving no unowned mutation.
Abandoning setup/refresh retains completed firewall rules for recovery: Drop does not
automatically remove protection.

No duplicate firewall algorithm was introduced. Existing test adapters invoke the same
prepared work on their own thread to preserve thread-local command models; the new
production thread boundary is checked separately. INI and public C ABI are unchanged.

## Q25-F108: never flush a chain whose hooks are not confirmed removed

`teardown_family` collected errors after failing to remove an OUTPUT/FORWARD jump,
but continued to `-F` and `-X`. Flushing removed DROP from a chain still receiving
traffic; failing to delete that chain did not restore protection.

An error or unknown unhook result now returns before `-F/-X`. The exact chain and
its DROP remain for recovery. This applies to ordinary release and setup rollback.
Successful cleanup of another family is not undone: failure of one IPv4/IPv6 operation
does not imply both families remain protected. The contract prevents flushing a
potentially referenced chain; it does not promise atomic two-family teardown or
protection against external root changes.

## Validation

- **8 new portable regressions PASS**: cancellation before/during read-only preparation,
  retained result and late error after stop, joined Drop, and no `-F/-X` with an OUTPUT/FORWARD
  jump still present or hook state unknown.
- Real-client current-thread runtime comparison: **8 baseline + 12 fixed scenarios**,
  TCP/UDP × setup/refresh/cleanup, normal stop and command faults. While held, baseline
  produced **0** heartbeat ticks, fixed produced **7–8** per approximately 800 ms interval,
  including after stop. All 20 competing starts failed with `cannot reserve TUN`:
  the original client retained its network lease.
- Before startup, 60 UDP probes received replies; while held, **60/60 were blocked**, with
  increasing DROP counters and zero delivery. After cleanup failure baseline passed
  **6/6**, fixed passed **0/6**. Fixed refresh failure blocked another **6/6**.
  Setup failure retained `failed`/exit 1 after complete rollback. Refresh/cleanup faults
  retained `failed`/exit 1 and recovery; **6/6 explicit subsequent starts** completed cleanup.
  Success requires exact route/rule restoration and absence of TUN and journal state.
- **38/38 hostname network cells**, 34 crash/recovery, **1220 main + 806 nested checks PASS**.
  Both IPv4/IPv6 nft/legacy arrangements with private firewalld: 1088 direct protected UDP
  attempts blocked; 656 allowed probes received replies.
- Full snapshot: **1564 host + 71 config; 2119 Linux + 46 privileged + 8 worker lifecycle PASS**.
  All 9 host/cross/feature/lint/format commands passed; the existing Clippy
  `chunks_exact_to_as_chunks` allowance remains. RU/EN documentation and `git diff --check` PASS.

## Evidence and limits

Lab: only `10.66.116.11`, Debian/Linux 6.12.105+deb13, Rust 1.97;
local Windows/Rust 1.98. Working server `10.66.116.10` was not used.
Private NET/mount/PID and `/run`, `/var/lib`, `/var/log`, `/etc/qeli`, `/tmp`.
Matrix: iptables 1.8.11 nft/legacy, nft 1.1.3, private firewalld 2.3.1.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`.
`firewall-task-phase/evidence.json` links results, archives and **349 source files**.
`checks.json`/logs retain commands. The **21-scenario-file** manifests retain raw/LF hashes;
the matrix used v1, new runtime used v2. Only `audit_firewall_task.py` changed between them:
an explicit server address replaced wildcard. Rust, driver and all other scenarios were
unchanged; matrix fixture hashes were checked against the original manifest.

Runs: `firewall-task-linux-v1`, `firewall-task-driver-v1`, `firewall-task-matrix-v1`,
`firewall-task-repro-v2`. Final harness exit 0; expected client exit within fault scenarios
is 1. Before/held/after/recovered snapshots, UDP counters/receiver logs, competing starts,
command wrappers, test-driver source and Cargo.lock are retained. Baseline is the frozen
F106 driver. Wrappers delay existing commands and inject faults before kernel mutation.

**Original `firewall-task-repro-v1` remains FAIL (19/20).** Fixed UDP refresh fault retained
protection, but its subsequent start received no ServerHello within 30 seconds. The server
listened on `0.0.0.0`, while the client used secondary IP `192.0.2.3`; server logs confirm
handshake receipt and replies. A separate native `firewall-task-wildcard-source` probe
confirmed wildcard UDP replies from `192.0.2.1`; explicit binding replies from `192.0.2.3`.
This explanation fits the observations, but Qeli packet capture has not yet been performed.
V2 binds the server to the intended address and all 20 scenarios pass. **Multiple-local-IP
wildcard UDP remains unfixed and is not PASS** — an open D06/D10 item.

Reproduce: `scripts/audit_firewall_task.py --qeli <worker> --driver <fixed-driver>
--baseline-driver <F106-driver> --artifacts <new-dir>`. Requires root and disposable Linux;
the driver is a test fixture, not a shipped client. DNS is disabled in the new runtime
scenarios; the matrix covers its own DNS combinations. Debug fixture timings are neither
a benchmark nor a whole-shutdown deadline guarantee.
| Artifact | SHA-256 |
|---|---|
| `qeli-firewall-task-v1-worker` | `584d73ff8048be5da5cb5391b462f6dfeea4447f89a0fe86317defc3c808651d` |
| `qeli-firewall-task-driver-v1` | `18f37b0b8b2972cf02a36cc1a8ec052d1bed01e7cca160b91f7a2f28a8ee6388` |
| `qeli-teardown-task-driver-v1 (baseline)` | `5ff88577bf07542d1b947a36800925d15eb2d74ccabc049377233ce5ded2e87f` |
| `linux-source-final.tar.gz` | `dad8570eb9d62a384296405341868e592461f86263c970c7d29cceb47cdb8495` |
| `firewall-task-matrix-v1.tar.gz` | `679a2e687ad292c71c509d7836a3c5be59daf739e01f04be2800e2c66b470a69` |
| `firewall-task-repro-v1.tar.gz` | `17e4440b35e9f94601400db15f8c8606248018333888ab345f2100df8db8c1ad` |
| `firewall-task-repro-v2.tar.gz` | `5ff4573e976259a1130e07184ef56446741e7062805da71d4174032f17e25ef1` |
| `firewall-task-scripts.tar.gz` | `e2cbadd3e2c44d03823a73689ecc02f4418f6152f536b3fd6ad46605727d6248` |
| `firewall-task-driver.tar.gz` | `ac32513cbaf04587a34631ebce51df2fff469829d426623a2baaab99edd87512` |
| `lifecycle-firewall-task-v1.tar.gz` | `bf960a5e4663a901c45d0395d6d53ff777030477104de22a2974f2012a0a7784` |
| `firewall-task-scripts-v2.tar.gz` | `920bbe0aea159f7cdc2555a91c14ab1676ea48a40ae24386df4aa5fce4a57f56` |


D05 remains **IN_PROGRESS**: startup route/DNS recovery, early error/Drop paths,
internal locks/I/O, diagnostic-file publication and whole NetworkPlan/shutdown deadlines
still need work. Forced cancellation can synchronously await a started syscall;
ordinary stop does not hard-interrupt a system operation.

D06/D10/D11/D12/D13 and the final benchmark remain open. No new full-audit sections
were opened. Windows VM, Mac/iOS and physical-router runtime remain **SKIPPED by user decision**;
no fresh Android package is tested here. Debt: **4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO**.
[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/OPERATIONS.md).

Follow-up: [Q15-F002](AUDIT-Q15-UDP-LOCAL-ADDRESS.md) confirmed Qeli reply sources by packet capture and fixed wildcard UDP. The original FAIL above is retained; overall D06/D10 remains open.

Reconciled after Q25-F109: startup route/DNS recovery now runs on a joined worker retaining its lease and late errors. This specific obligation is addressed; the other D05 limits above remain. [Result](AUDIT-Q25-STARTUP-RECOVERY-TASK.md).

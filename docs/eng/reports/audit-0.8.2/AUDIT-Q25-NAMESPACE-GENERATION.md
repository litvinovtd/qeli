# Q25 — network namespace generation in sysctl journal v4

<!-- normative-sync: audit-q25-namespace-generation-v1 -->

24 September 2026. Base: `ee2f5b002b6753db993078cdb31a05181a94bfbe`.
D02 closure in the [debt register](../../plans/AUDIT-DEBT.md).

## Q25-F090, P2 — namespace inode did not prove generation after a crash

Held namespace fds protected each transaction, but v3 stored only boot-id and dev/inode.
After the last owner dies, that inode can identify another namespace in the same boot.
The saved global original then lacks sufficient authority for replay into the new object.
Per-interface fd/witness safety was already addressed by v3.

V4 additionally stores `network_cookie`, read using `SO_NETNS_COOKIE` on a local UDP socket
without bind/connect/traffic. It is checked before owner pruning, sysctl reads/writes and
persistence. The context retains its namespace pins; OwnedFd closes the temporary socket.
Zero, wrong response size, inspection failure or cookie mismatch cannot authorize recovery.

The design follows Linux implementation: new network generations receive a cookie from
the common generator, and the socket option returns its socket network's cookie.
[Linux 6.12 generation](https://github.com/torvalds/linux/blob/v6.12/net/core/net_namespace.c),
[getsockopt](https://github.com/torvalds/linux/blob/v6.12/net/core/sock.c).
This is generation evidence within a boot-id, not cryptographic protection against root
editing the journal.

ENOPROTOOPT permits empty recovery but refuses new sysctl ownership before mutation with
`SO_NETNS_COOKIE is required`. Other socket errors remain errors. Nonempty same-boot v3
cannot be migrated by assigning the current cookie: that would invent evidence. Finish
verified ownership in the original network before upgrading, or use a planned reboot.
Valid previous-boot and empty legacy state upgrade without replay. Invalid v4 still fails
with a previous boot-id. Existing v1/v2 restrictions remain. Mixed versions are unsupported.

## Validation

Four new portable regressions cover reused inode/different cookie, missing/failed cookie,
nonempty legacy v3 and null/zero/string v4 cookies including previous-boot state.
Two older fixtures now provide the required cookie/current version. A new native test
verifies a stable cookie, a different one after unshare and the original after returning
through the pinned namespace fd.

**1479 host unit + 71 config**, all **9 feature/cross/lint commands PASS**.
**1995 ordinary Linux + 32 privileged + 8 worker lifecycle E2E PASS**.
An additional worker E2E uses SIGKILL, then rejects a different-cookie journal byte-for-byte
without global/per-interface sysctl changes or profile startup. Restoring the real cookie
allows global originals to recover; lost per-interface witness still fails while preserving
its original. Inode reuse is modeled by a portable test; forced kernel inode reuse is not
claimed.

Disabling the generation check reproduces the defect (exit 101). Byte-restored sources pass
36 namespace + 11 target + 1 native tests. The first local run exposed two old
fixture assumptions and Clippy needless_return; corrected runs pass and early logs remain.
Linux Rust 1.97, host Rust 1.98; existing Clippy `chunks_exact_to_as_chunks` allowance.
318 source hashes verified before/after runs. Worker SHA256: `96f96c31d42b501773bd0eeb223f923da966a3d5d6b5420862962c679d03183d`.
Archive SHA256: `0908e9bc9fd9aa140470a6cf1e7dfb0b08b58cdf4b3a69750263dac8ee634de4`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/namespace-cookie-phase/`,
`namespace-cookie-final.log`, `namespace-cookie-counterfactual/`, `sysctl-cookie-crash/`,
`lifecycle-namespace-cookie/`. Private lab `.11`; live `.10` unchanged.

## Closure limits

D02 is closed: lock/I/O/context, trusted state directory, namespace pins, original interface
objects and durable global network generation are verified. D04 remains open for persistent
exact firewall/DNS/routes recovery. Per-interface replay without a living witness
intentionally fails and preserves evidence for verified manual restoration. A cookie does
not identify an interface. Internal uninterruptible I/O and other subsystem operation
budgets remain D05. User configurations stay INI; `sysctls.state` is internal state.

[Manual](../../manuals/CONFIG.md) · [Troubleshooting](../../manuals/TROUBLESHOOTING.md)

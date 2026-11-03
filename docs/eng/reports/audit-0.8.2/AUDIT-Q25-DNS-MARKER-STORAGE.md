# Q25 — DNS markers: trusted storage and namespace generation

<!-- normative-sync: audit-q25-dns-marker-storage-v1 -->

24 September 2026. Base `668139dd`. Partial D04/D06/D09 closure.

## Q25-F096, P2 — DNS leases accepted untrusted state files

Lease creation followed an ordinary directory path; marker reads checked type, link
count and size but not owner, permissions or snapshot stability. Three regressions
on the original code reproduced acceptance of a directory symlink, a 0777 directory
and a 0666 marker. In the last case recovery probed the index and removed the untrusted
record. This proves an evidence-trust defect, not arbitrary DNS mutation: startup
already refused to revert live indices using a marker alone.

DNS now uses shared `state_storage`: component traversal without symlinks, owner/mode
checks and a held directory descriptor for the lease or recovery pass. Operations
address that descriptor; renaming the directory and replacing its old path cannot
redirect cleanup to another inode. Marker reads are bounded to 2048 bytes and validate
and read the same fd. Symlinks/FIFOs/hardlinks, foreign ownership and group/world write
are refused. Stable `.lock` files are checked before and after nonblocking flock;
creation preserves 0600 and the admitted service directory owner. Directory permissions
are rechecked before the resolver callback. Marker retirement fsyncs the directory;
a failure explicitly reports uncertain durability after an already completed unlink.

## Q25-F097, P2 — a namespace inode does not distinguish generations after a crash

V1 recorded boot ID and namespace device/inode but no kernel generation. Inode reuse
could let startup treat a foreign marker as local and delete it on an absent index.
V2 includes a nonzero `SO_NETNS_COOKIE` in the record and filename:
`dns-link-v2-<boot>-<netns-device>-<netns-inode>-<cookie>-<ifindex>.state`.
A scope mismatch skips both index probing and retirement; cleanup also compares the
cookie. Runtime recovery pins the namespace fd and checks it before and after the
index query. Managed DNS requires SO_NETNS_COOKIE, with no inode-only fallback.

Old `dns-link-v1-*` files remain with a warning and no automatic migration. A matching
old boot/device/inode/ifindex blocks a new lease pending administrator recovery.
Old `dns-resolvectl-*` evidence is likewise never adopted. Stop the old client cleanly
before upgrading; after a crash use TROUBLESHOOTING §6.50. A saved marker of any
generation alone never authorizes reverting DNS on a live interface.

## Validation

- **1506 host + 71 config; 9 feature/cross/lint checks PASS**.
- **2055 Linux + 37 privileged + 8 worker lifecycle PASS**.
- 5 new portable, 6 Linux and 2 privileged regressions cover cookies, v1, unsafe
  permissions/owners, directory replacement and uid/0600 inheritance. The last test
  checks inode ownership when root creates state in a service directory, not a client
  process running under another uid.
- Original code with three new file tests: **3 expected FAIL**, test exit 101;
  wrapper exit 0 verifies the expected reproduction. Original sources were restored.
- Packet matrix: **17/17 cases, 323 assertions PASS**. DNS4/DNS6 use real resolved/D-Bus; optional
  `QELI_DNS_CRASH_CHECK=1` covers SIGKILL, TUN/link-DNS disappearance, retained marker,
  restart, restored stub query and unchanged v1/foreign-cookie evidence. A valid fixture
  uses a different cookie with the same inode; actual nsfs inode reuse was not forced.
  These checks make no traffic-protection claim about the restart window.

Source snapshot: 334 files, archive SHA256 `f72ded338327d3c7edda62ee0c82bb8283b113e0d5919f60b6fb6b7f27eed74a`.
Worker SHA256: `88af383f121304b8e3b7d40b89e62ff22088aa624004ccfbc25b76f8ed8782b2`.
Baseline test binary SHA256: `956c5f39fbb8110b2be8db36d03edf8648f282ec1c9de26c8cac00d329b6d0b5`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/dns-marker-phase/`,
`dns-marker-baseline.log`, `dns-marker-final-v1.log`, `lifecycle-dns-marker/`,
`packet-matrix-dns-marker-v1/`.
Linux Rust 1.97; host Rust 1.98; existing Clippy allowance `chunks_exact_to_as_chunks`.

## Boundaries

Per-link DNS markers remain in `/var/lib/qeli`; `STATE_DIRECTORY` does not relocate
them. This is internal recovery state; user configuration remains INI. ABI/wire are
unchanged. Stable lock files deliberately remain: never unlink them while owners run.
Their accumulation belongs to D13. Legacy global `dns-backup.json` restoration and
holder files are not redesigned here; process-global DNS remains D06. Uninterruptible
filesystem I/O has no new hard deadline. A privileged external writer between a check
and its action remains a limitation. For an external persistent TUN with a live index,
startup retains evidence and requires administrator inspection.

D04 remains IN_PROGRESS: route/kill-switch recovery, the listed DNS boundaries and
the full mixed nft/firewalld matrix remain open. `.10` was unchanged; tests ran on `.11`.
Windows VM/Mac/iOS/router runtime remain SKIPPED by user decision.

[Debt register](../../plans/AUDIT-DEBT.md) · [DNS recovery](../../manuals/TROUBLESHOOTING.md)

Follow-up: [Q25-F101](AUDIT-Q25-LEGACY-DNS.md) closes legacy global DNS through refusal of automatic replay and manual migration. An old snapshot does not prove ownership of the current resolver; automatic restore/refcount and their test implementations were removed. Historical results above describe the earlier behavior.

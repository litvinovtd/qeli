# Q25-A125: WAN name reuse

Date: 25 September 2026. Base: `37104b1e`. Original D06 status: **IN_PROGRESS**.
Priority: P2 (egress through an unselected physical interface; the client address is NATed).

**Disposition on 3 October 2026:** the user cancelled production BPF integration.
Q25-A125 remains a known P2; D06 is dispositioned as **ACCEPTED_LIMITATION**,
not a fix. Earlier sections below are the investigation history.


Exit-node MARK, MASQUERADE, and FORWARD permits use `-o <wan>`. The remembered
WAN is a name, not a continuous network-device identity.
[Netfilter documentation](https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-7.html)
defines `-o` as an interface-name match. The
[nftables manual](https://netfilter.org/projects/nftables/manpage.html)
distinguishes `meta oif` (interface index) from `meta oifname` (name), explicitly
noting that a name rule matches a new interface created with the old name.

Three states were tested on isolated lab server .11 inside private network,
mount, and PID namespaces. The original `wan0` had ifindex 5 and emitted a
packet with NAT source `198.51.100.2`. After replacing the route with `wan1`
(ifindex 7), the guard dropped the packet: its counter reached 1 and the sink
saw no packet. The **new** interface, still ifindex 7, was then given the name
`wan0` and a default route, without a Qeli refresh. The old MARK/MASQUERADE
rules matched again, and the sink received `192.0.2.2 > 203.0.113.9`.
The client address `10.0.0.2` did not escape, but traffic used a different
physical device without WAN requalification. A separate live rename from
`wan0` to `wan-old` preserved both ifindex and the default route under the
new name; the old `-o wan0` selector no longer matched.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/wanrename3.log`
and `wanliverename.log`, with `wan-rename-reuse.sh` in the same directory.
Only private namespaces were changed; installed lab services were untouched.

**Contract until the backend is fixed:** do not rename, remove, or replace the
selected WAN while an exit-node profile is active. Stop the profile, verify
successful rule cleanup, change the interface, and then start the profile.
A route change to a distinct interface name is blocked until successful
refresh; reuse of the old name after its former device leaves is not a
protected scenario. The manual now says this explicitly; this audit step
makes no Rust changes.

A complete fix needs to bind egress admission to device identity on each
packet and account for identifier reuse after deletion. `nft meta oif` narrows
simple rename/name-reuse exposure, but an interface index can itself be
reused. Moving an isolated rule to nft without mixed iptables/nft/firewalld
and cleanup validation is not a complete fix. Design and packet/recovery
coverage remain in D06/D10.


## 2 October 2026 continuation: kernel guard selection

On baseline `5bbffe4b`, candidates were qualified; **Qeli was not fixed**:
[runner](../../../../scripts/audit_wan_identity_candidates.py) and
[evidence](../../../../release/certification/evidence/wan-identity-candidates-20261002.json).
Synthetic exit-shaped MARK/NAT/FORWARD rules use real IPv4/IPv6 UDP packets across
nft/nft, nft/legacy, legacy/nft and legacy/legacy. No worker or VPN runs in this
batch; existing working binaries are only SHA-checked. Rust and INI keys are unchanged.

There are **168 expected-outcome checks**, including reproduction of unsafe variants:
88 probes, 264 datagrams, 168 validated echo replies and 96 expected blocked sends.
In 32 negative checks the specific DROP counter increases by 3. This is not 168
proofs of a security fix.

| Candidate / state | Packet outcome on all four pairs |
|---|---|
| Old WAN name | A new device with the former name inherits MARK/NAT and forwards traffic |
| Preinstalled native nft `meta oif` | A forcibly created device reusing ifindex, name and MAC is also admitted; the native counter sees six packets per cell |
| `devgroup --dst-group` with a separate token | The original retains its token across rename; a new device starts with group 0 after deletion. Name/index/MAC reuse and an incorrect group are blocked |
| Root copies the token to the replacement | The new device is admitted again; the token is neither a secret nor protection against a privileged administrator |
| Foreign `--dst-group 0 -j DROP` rule | Assigning the token instead of group 0 stops this rule from applying to the WAN; restoring group 0 restores blocking |

The kernel `devgroup` matcher reads the outgoing device group:
[Linux source](https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/xt_devgroup.c).
That group belongs to host network policy. In addition to the demonstrated firewall
conflict, RPDB `suppress_ifgroup` uses it in
[IPv4](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/fib_rules.c) and
[IPv6](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv6/fib6_rules.c).
The RPDB effect is established from source, not a separate packet runtime in this
fixture. Automatic group mutation without an administrator ownership contract is
therefore rejected as a transparent fix. A current group of zero does not establish
that foreign rules, masks, sets/maps or route suppression do not use it.

The client monitor was reconciled: `ExitWanSnapshot` in
[gateway.rs](../../../../qeli/src/client/gateway.rs) stores only IPv4/IPv6 WAN names.
[spawn_exit_wan_monitor](../../../../qeli/src/client/mod.rs) compares snapshots every
five seconds and skips an equal snapshot after successful refresh. Name reuse alone
does not change it. Carrier path observation in
[roaming_linux.rs](../../../../qeli/src/client/roaming_linux.rs) can include an index,
but observes a different path and supplies no continuous egress guard. The existing
TCP/UDP [Q25-F127](AUDIT-Q25-EXIT-WAN-MONITOR.md) evidence still covers default WAN
changes to a different name; no fresh monitor E2E is claimed here. Adding an index
to the sampler would still leave the interval before observation and index reuse.

One coherent implementation batch remains: a kernel guard with an explicit ownership
contract for its per-device label, shared IPv4/IPv6 and profile/process leases,
namespace/device witnesses and a unique generation token, journal/rollback/cleanup/
crash recovery that cannot restore labels onto replacements. Then real client/server
packets, established conntrack/marks, mixed backends and recovery must be checked.
The group must not silently change foreign policy; restoration cannot trust only a
name, ifindex or MAC. These requirements have not been implemented.

The intermediate 164 outcomes from r2 are retained separately and not added to the
final 168: r3 installs the ifindex guard on the original WAN and verifies that the
rule stays unchanged across device deletion/recreation.

The first fixture failure is retained: down/up removed its manually assigned IPv6
address and the new default could not be installed. Private `keep_addr_on_down=1`
corrected the fixture; production code is unchanged. Every attempt restores the outer
host snapshot; the final comparison includes link groups, RPDB and no added/removed
kernel modules. Working services and `.10` are untouched. The passing matrix does
not cover a persistent group lease, SIGKILL/recovery or a real firewalld daemon.

**Q25-A125 / D06 remains an open P2.** D10 is closed for its previously supported
firewall composition; a future identity guard will need targeted rechecks of that
composition. The manual restriction on active WAN rename/delete/recreate remains.


## 3 October 2026 continuation: working DEVMAP prototype

A kernel guard was found without device-group mutation or TC redirection:
[low-level helper](../../../../scripts/audit_wan_devmap.py),
[packet runner](../../../../scripts/audit_wan_devmap_packets.py),
[evidence](../../../../release/certification/evidence/wan-devmap-20261003.json).
**This is a prototype, not an integrated Qeli production fix.** Working Rust,
client monitor, unit file and installed services are unchanged.

The original WAN is inserted into `BPF_MAP_TYPE_DEVMAP`, then `BPF_MAP_FREEZE`
rejects userspace updates. The kernel notifier removes the entry on
`NETDEV_UNREGISTER`; later numeric ifindex reuse cannot recreate it. This is
implemented in [Linux 6.12](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/bpf/devmap.c).
DEVMAP lookup is permitted by the
[verifier](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/bpf/verifier.c);
[xt_bpf](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/netfilter/xt_bpf.c)
executes the socket-filter program.

A 16-instruction program runs in `mangle/POSTROUTING` before NAT. It ignores
unrelated ingress and compares the selected TUN packet's **actual outgoing ifindex**
with the live map entry. An absent entry or different index causes DROP. The rule
is also scoped to the selected WAN name. Map presence alone is insufficient: the
original WAN may still live under another name while a different device claims
its former name. A separate negative scenario tests this case.

**4/4 pairs nft/nft, nft/legacy, legacy/nft, legacy/legacy** each execute 39 checks,
**156 total**; 72 packet probes / 216 UDP datagrams / 168 validated echo replies /
48 expected blocked sends. Every one of the 16 negative probes increments the new
mangle DROP by 3; direct queries prove receiver availability.

| State | Verified IPv4/IPv6 outcome |
|---|---|
| Original WAN | Consumer traffic retains the expected MASQUERADE source; local OUTPUT is unaffected |
| Owner FDs closed and pinned objects reopened | Live entry and normal NAT survive |
| Original renamed, another device claims its old name | Map remains live, but actual out index differs: DROP |
| Original deleted; replacement reuses name/index/MAC | Map stays empty across reopen; consumer DROP, local positive controls work |
| Attempt to update live or retired map | EPERM; old generation cannot reauthorize the replacement |
| Old guard rules removed; new generation created | The newly selected WAN is admitted with NAT |
| Cleanup | Original snapshot of both backends/native nft restored; rules removed before unpin/close/unmount |

**Two capability checks** also run as the actual `qeli` user (UID 103/GID 105)
through setpriv. With the unit's three stock capabilities, `CapEff=0x3400`, MAP_CREATE
fails with EPERM. Adding only `CAP_BPF` gives `CapEff=0x8000003400`: map/program
creation, freeze and pin succeed without process CAP_SYS_ADMIN. Privileged fixture
setup prepared bpffs and a writable directory beforehand. This is not systemd
startup/install verification; integration must test that. Working service privileges
have not changed.

A simpler TC workaround is rejected: mirred's device reference is visible in
[source](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/sched/act_mirred.c),
but redirect changes packet handling and a WAN-only filter cannot supply a firewall
deny on its replacement. **No TC packet scenario was executed**: source analysis
led to DEVMAP, which preserves the ordinary routing/NAT path.

Fixture failures are retained: ordinary verifier.log creation inside bpffs, DROP
counter lookup without `-t mangle`, then an unprimed empty native mangle POSTROUTING
hook in the baseline. The final fixture primes this hook before its snapshot; no
kernel/foreign objects are removed after verification to manufacture equality.
The intermediate 156 outcomes from r3 are not added to final r4; r4 removes the
unused old devgroup branch from the runner. AST, runtime fixture hashes and docs
are checked.

All outer firewall/routes/addresses/link groups/RPDB/listener/resolver snapshots
match before/after. One global effect is explicitly retained: the first xt_bpf use
autoloaded that kernel module, which is left loaded. Final r4 adds no modules. The
module set across all attempts is not described as unchanged. `.10` is untouched.
No full before/after global BPF-object inventory was taken.

D06 now needs **integration of the selected guard**, not another candidate search:
a shared Linux Rust helper with portable syscall ABI; trusted bpffs/bootstrap and
minimal service privileges; persistent owner/journal for server NAT44/NAT66 and
client exit; installation before admission and pins retained until exact rule
cleanup; a monitor that distinguishes lease loss and creates a new generation
without refilling the old map. Then real Qeli TUN, multiprofile, established
conntrack, policy/RFC1918/delegated paths, SIGKILL/recovery and missing-capability/
bpffs refusal must be tested on mixed backends. Unit/build/Clippy follow Rust edits.

The prototype helper is intentionally Linux x86_64 only. FD close/reopen is not
SIGKILL, and synthetic veth packets are not authenticated VPN E2E. Foreign TC/
mangle/firewalld policies and older kernels are not certified by this batch. The
current active WAN rename/delete/recreate restriction remains until integration.
**Q25-A125 / D06 IN_PROGRESS; D15 awaits the final production candidate.**

## 3 October 2026 disposition: production guard cancelled

The user declined BPF integration and expanded service capabilities. The unfinished
Rust draft was removed from the working tree and .11 build source; the running
binary and unit were unchanged. Previous prototype checks remain research evidence,
not proof of a production fix.

The known limitation remains: do not rename, delete or replace the selected WAN
while managed NAT44/NAT66 or client exit-node is active. Stop the profile and verify
cleanup first; then change the interface and restart the profile. Startup WAN
presence checks and the name monitor do not provide continuous device identity
or protection from name reuse.

[D06 user disposition](../../plans/AUDIT-DEBT.md) ·
[rollback record](../../../../release/certification/evidence/wan-identity-disposition-20261003.json).
The remainder is not represented as fixed. Next work is D15, then the full audit.

# Q25: owner evidence during setup and roaming

Date: 23 September 2026. Baseline: `0157dab6`.
Q25-F065–F066 are fixed within the limits below; sections 21/22/25 remain **IN_PROGRESS**.

## Findings

**Q25-F065, P2 — route installation did not recheck the original TUN before commands.**
After the initial bind, an external manager could rename/delete the device and reuse its
saved name. The initial installer checked route destinations/selectors, but not whether
the name still referred to the original fd. It could install a TUN route on a replacement
or continue physical bypass/blackhole setup for a lost tunnel. Managed MAC/address/up
had the same gap. The previous pass protected cleanup, not installation.

**Q25-F066, P2 — roaming commands and completion were not bound to a live original TUN.**
RouteOwner retained generation/namespace but gave a prepared path no access to its original
device. Prepare/add/replace/retire/FIB commands could continue after TUN loss; successful
physical rollback alone did not prove the generation was still usable. `refresh_platform`
also ran between admission and route mutation without a subsequent namespace check.
The ordinary gateway callback currently does not call setns; this namespace scenario
tests the internal callback contract, not an alleged normal reconnect namespace move.

## Fix

The original TunInterface is held in an Arc for the existing setup/TunGuard lifetime.
Bind records a Weak reference and device index in RouteOwner. Weak does not retain the fd,
extend device lifetime through prepared paths/orphan journals or create another TUN queue.
Loss of the original object cannot be replaced by looking up its saved name.

Every active setup/prepare/commit route command checks the held namespace, original fd,
name and index. This covers physical route lookup, initial pre/add/post queries, candidate
add/replace, retirement and FIB verification. route_local inventory checks admission too.
Direct managed MAC/address/up calls each check identity; a final check precedes publishing
successful managed setup. Diagnostic hook lookups and historical IPv4 fixtures remain
outside the mutating plan path.

Independent physical rollback/restore requires the original namespace but permits TUN
loss: proven owned physical records can still be removed/restored. Namespace loss refuses
those commands too. Existing selectors, ownership, borrowed routes, pending reservations
and postconditions remain intact; an uncertain installation never grants Qeli ownership.

Identity loss is sticky for the RouteOwner lifetime and closes admission. Restoring a
name/namespace does not resume setup in that generation. Cleanup can still retry permitted
actions and retire confirmed leftovers. Roaming returns `RouteCommitStateUnknown` on
identity loss, including admission failure and successful physical rollback. Checks run
before/after the platform callback and before successful commit completion. Losing evidence
during the final FIB query also triggers available rollback rather than acknowledging commit.

The unused route deletion wrapper without an explicit checked executor was removed.
User INI, C ABI, DNS API and server routing modes are unchanged. Gateway/firewall commands
inside the callback did not acquire per-command identity checks in this pass.

## Verification

**7 regressions: FAIL on original production logic → PASS after the fix.**
The baseline added explicit synthetic evidence fixtures only; old code did not read them.
Command models and the seven scenario bodies are retained. Six additional controls cover
namespace mismatch at admission, permanent generation refusal, restoring the previous
physical route after replace, TUN loss during the final FIB query, successful installation
in both families and preserving a borrowed carrier without claiming it.

**1401 host unit + 52 editor/policy + 7 examples + 12 server INI = 1472 Rust tests PASS.**
The 13 new host tests are included in that total. Existing command fixtures now explicitly
create synthetic owners; production `new` and native tests receive no such authorization.
The single ignored host fixture is the DNS-lock child explicitly run by its parent test.
All nine matrix commands and Linux no-default-features tests compilation pass; no new
warning headlines or Clippy exceptions. RU/EN documentation checks pass.

Four ignored native scenarios were added: refusing route add after rename; releasing TUN
while RouteOwner lives and refusing its replacement; rejecting setup for an unbound owner;
namespace change inside the roaming callback. With the previous three, the module has seven:

```bash
cargo test --manifest-path qeli/Cargo.toml --lib identity_linux_tests -- --ignored
```

Requires Linux, CAP_SYS_ADMIN/CAP_NET_ADMIN, `/dev/net/tun`, and `ip`. Tests first enter a
fresh namespace on a disposable thread. They were **compiled only**, as were the existing
seven TUN ioctl tests. No Windows host networking changes were performed.
Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/route-setup-identity-audit-20260923.

## Remaining limits and next pass

Fd checks and subsequent iproute2 commands are not atomic. Privileged external rename/delete/
move/reuse after the final observation remains possible. A numeric ifindex alone is not
kernel CAS. Physical uplinks still rely on their previous selectors.

Gateway/firewall/sysctl setup and rollback, refresh callback internals, kill-switch refresh
and external hooks need a separate ownership pass. An early route identity refusal does
not make an arbitrary callback safe. Attach and server setup did not receive these managed
MAC/address/up checks. Procfs/sysfs trust, parser/backend name consistency, resolver service/
bus namespace, overall deadlines and durable crash recovery remain open. Q14-F027 workers/FD,
Linux E2E, native certification and a new benchmark are not complete. Plan: 37 sections,
19 IN_PROGRESS, 18 TODO, no full PASS.

Follow-up: [Q25-F067–F068](AUDIT-Q25-GATEWAY-IDENTITY.md) adds gateway checks and cleanup before TUN release; sysctl journal internals remain a separate task.

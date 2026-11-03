# Q30: first-writer ownership of Keychain identity and trust

<!-- normative-sync: q30-ios-keychain-v1 -->

6 October 2026. Q30 IN_PROGRESS. Scoped storage/trust source fixes F292–F294;
this does not complete the engine/lifecycle/roaming/platform review.

## F292: device ID and TOFU pins could overwrite a concurrent first writer

`SecureIdentityStore` read a device ID or a host pin and then used Keychain
update/add. Two readers could both see an absent item, then the later write could
replace the first identity/pin. The device ID returned to one native generation
could differ from the persisted ID. Trust acceptance could approve a key while a
concurrent writer had pinned a different key. Existing master-key creation already
handled duplicate insertion; device identity and trust now share that contract.

`KeychainStore.insertIfAbsent` adds without updating. On duplicate it returns the
persisted winner, propagating read/access errors. Device ID creation validates and
returns that winner. An existing malformed/all-zero/non-16-byte ID fails explicitly;
it is no longer silently replaced. There is no automatic key/identity reset.

TOFU insertion returns the winning pin, and the engine compares it to the proven
peer key outside the persistence-error fallback. A different winner is always
`serverKeyMismatch`, including when `allow_unpinned_tofu` is enabled. That option
retains its existing handling of persistence failures only. Services, account names,
Keychain access groups and AfterFirstUnlockThisDeviceOnly remain unchanged.

The internal update/add `KeychainStore.write` method became unreferenced after both
runtime callers moved to insert-if-absent and was removed. Test fixture setup uses
unique test services/direct test-only deletion; no replacement update API was added.

## F293: invalid key sizes reached allocation/crypto or archive decode

Master-key creation now accepts only AES sizes 16/24/32, before allocation/RNG;
existing and concurrently inserted keys must match the requested size. Profile
archive reads require the 32-byte master key used by writes before AES decryption.
Invalid existing keys cause a clear error and are never overwritten or regenerated.

Seven added XCTest cases exercise real Keychain APIs in unique removable test
services: duplicate insertion/first winner, stable device ID, malformed ID without
rotation, conflicting TOFU proposals/separate endpoints, stable or malformed master
keys, invalid requested sizes (including zero/negative/Int.max), and archive reads
with a wrong-length master key. They are retained but NOT_RUN. These sequential
contract cases do not claim an observed cross-process race or engine handshake.

## F294: explicit profile requests could fall back to a different profile

The provider searched both the requested UUID and the persisted UUID and selected
the first available profile. Invalid explicit options became nil, and an explicit
UUID missing from the encrypted archive fell back to the configured profile. This
could launch a different profile instead of rejecting a stale app request.
A shared Foundation selector now chooses the requested value if present, validates
it without fallback, and only uses the persisted value for an absent request. The
provider looks up exactly one UUID; missing/malformed/stale selection fails before
engine construction. Four added selector XCTest cover explicit precedence, invalid
types, automatic launches and a removed profile. NOT_RUN; no real provider-launch
or managed delivery claim. Eleven new XCTest in this batch total.

## Verification and scope

Six Python IPA-verifier fixture regressions PASS. Ten current iOS plist/mobileconfig/
entitlement/privacy XML files parse and their template types remain unchanged.
Documentation (all nine checks), generated config bindings and diff checks PASS.
Swift compilation, eleven new XCTest, simulator/signed IPA, actual Keychain/shared
access group behavior and iOS VPN/TOFU races are NOT_RUN: Windows has no Swift/Xcode,
and Apple runtime was excluded by the user. No actual signed IPA qualification.

Reviewed storage source ownership: app alone publishes encrypted archives; provider
reads do not initialize missing stores; archive/config/profile count/name budgets,
read-only signing probes, existing master-key duplicate handling and shared settings
were reconciled with prior Q25 fixes. The remaining engine/provider stop/read/settings
callback lifetime review is open. In particular cancellation is not described as a
joined native-runner or packet-flow completion; no new shutdown PASS is claimed.

Unchanged Rust/native/Android/other-client Git input hashes retain prior verification
with original artifacts, dates and limits. No Linux/Android runtime matrix repeated.
Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-keychain-20261006.
Evidence: release/certification/evidence/q30-ios-keychain-20261006.json.
Overall28/37 DONE/PASS(75.7%),9 remain; Q29 SIGKILL FAIL/auto-null ENONET remain open.
Q30 IN_PROGRESS; D06 and user platform skips unchanged.

# Q30: provider messages and backup UI request state

<!-- normative-sync: q30-ios-messages-backup-v1 -->

Scoped source fixes F300–F302, 6 October 2026. Q30 IN_PROGRESS.

## F300: unbounded caller wait, obsolete replies and overlapping snapshot polls

The settings message used a bare continuation. A missing reply held its caller
indefinitely; cancellation had no completion path. A reply from an earlier tunnel
could still return success after reconnect. Snapshot polling also sent every second,
including while its previous callback was outstanding; multiple paths requested a
snapshot immediately after entering Connected.

ProviderMessageRequest uses the existing exactly-once completion helper, a cancellable
wait and a 20-second caller deadline (15s provider settings budget plus 5s IPC margin).
Synchronous reply/send error, cancellation before parking, timeout and duplicate/late
callbacks preserve one outcome. A reply or error is handled only while its connection
generation, session identity and status epoch remain current; obsolete timeout errors
are also suppressed as cancellation instead of raising an old settings alert.

Snapshot polling admits one outstanding request per status epoch. Reply (including
nil/invalid payload) and synchronous send failure release that specific poll. Duplicate
or old callbacks cannot release a newer epoch's poll. No reply stops further automatic
polling in that epoch; a status transition resets ownership to permit current polling.
This is not a global bound on OS callbacks across arbitrary status transitions.

Timeout/cancellation completes only the Swift wait. An already-issued OS message or
provider settings apply is not cancelled or rolled back; the provider-wide OS leases
from F297 remain callback-owned. Real IPC callback drainage remains OPEN qualification.

## F301: mutable passphrase state crossed backup suspension points

The export task read passphrase when it eventually started; its filename read the
live field again after encryption. Editing the field could label an encrypted file
as JSON or a plaintext file as encrypted. Restore reread passphrase after asynchronous
file reading, so a concurrent edit changed the password of an already-started import.

Export captures passphrase at the button event; BackupDocument derives the suggested
filename from the actual bytes using the existing envelope discriminator. Restore
captures passphrase before reading the selected file and holds one preparation slot
until decode finishes. Export/restore controls prevent concurrent preparation; pending
restore confirmation prevents a second restore from replacing its payload.

INI profile configs, Android-compatible JSON backup container and QELI-ENC-1 encryption
are unchanged. This does not reintroduce JSON profile configuration. SwiftUI presentation,
dismissal during detached work and actual FileDocument/FileImporter behavior are not
claimed as runtime-tested; detached crypto work is not claimed to be joined/cancelled.

## F302: unused Swift wire crypto still belonged to the production app

Production had already excluded Protocol but still compiled Crypto/PacketCipher and
Crypto/KeyDerivation, whose only callers belong to conformance tests. X25519KeyPair
had no source caller, including tests; KeyDerivation.handshakeTranscript,
serverAuthenticationProof and clientKeyProof likewise had no caller.

The app now excludes Crypto alongside Protocol; XCTest explicitly includes both.
The unused key-pair file and three unused auth helpers are removed. Classic/hybrid
HKDF and PacketCipher remain unchanged as conformance support in the test target.
Storage/BackupCrypto still uses CryptoKit directly. Production Rust crypto, ABI,
native libraries and encryption/backup formats are unchanged. No binary size or
actual Xcode compilation result is claimed from source membership alone.

## Checks and remaining work

Eleven new XCTest: seven production request-helper cases (sync/duplicate reply, send
error, nil, missing/late reply, zero budget, precancelled and cancelled issued request),
four snapshot ownership cases (one pending poll, old epoch, duplicate callback and
settings token epoch). Swift/XCTest NOT_RUN; current Windows PATH has no swift,
xcodebuild or xcrun. No toolchain installed. Apple runtime remains user-excluded.

Six IPA-verifier fixture regressions, ten XML structural reads, generated bindings,
all nine documentation checks and diff checks PASS. Fixtures do not qualify real
signed IPA, Swift syntax or Apple behavior. Unchanged implementation Git inputs retain
historical runtime statuses/artifacts/dates; no Linux/Android matrix rerun.

Whole-section memory/dead-code and source inventory reconciliation remain open; no
Q30 checklist item closed. Overall28/37(75.7%),9 remain. Q29 SIGKILL FAIL/auto-null
ENONET, D06 and platform exclusions unchanged.

Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-messages-backup-20261006.
Evidence: release/certification/evidence/q30-ios-messages-backup-20261006.json.

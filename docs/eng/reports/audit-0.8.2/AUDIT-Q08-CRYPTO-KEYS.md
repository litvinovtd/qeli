# Q08: cryptography, identity and keys

<!-- normative-sync: audit-q08-crypto-keys-v2 -->

Date: 3 October 2026. **Full Q08: DONE; both batches qualified.**
Configuration remains INI. The 32-byte key format, algorithms and wire protocol are unchanged.

## Findings

| ID | Problem | Fix |
| --- | --- | --- |
| Q08-F001, P2 | Three identity/panel/session-key loaders read unbounded files and could block on FIFOs; a dangling identity link was treated as missing and replaced with a new identity. | Shared crypto/key_file.rs validates the opened regular-file inode and size, reads at most 33 bytes, opens Unix FIFOs nonblocking, and refuses dangling links without generation. Temporary secret buffers use Zeroizing. |
| Q08-F002, P2 | Legacy panel-secret migration preceded the modern FileLock. Corrupt legacy material could silently cause generation of a key incompatible with existing password_enc. | Modern load, migration and generation share one lock and recheck; modern keys take precedence, corrupt/inaccessible legacy files never trigger replacement generation. |
| Q08-F003, P2 | Both client verifiers used unchecked X25519 DH for static identity; low-order keys allow computing proofs with an attacker-known zero shared secret. | Checked DH rejects those identities before proof acceptance and credential transmission in the shared transport core. No bypass of a valid nondegenerate pin was confirmed. |

Read/generation handling is shared across three loaders and their unbounded reads are removed. Publication retains the existing atomic-private writer. Operator links to existing regular files remain supported; reading preserves existing owner/mode, generated files are 0600. Damaged identities never rotate automatically. Session-key errors retain the existing per-process fallback and warning, so those cookies do not survive restart. CLI reversible password storage remains best-effort; Argon2 hashes are a separate authentication mechanism.

## Reproduction and validation

Previous exact release `ba7d93afc47c71592e2d1d20e18d2c7c6a6cb0eb4248b674cf713e756aa1c712`: **6 FAIL of 19** storage checks — identity FIFO, dangling link, unlocked migration, corrupt-legacy replacement, panel FIFO and session FIFO. Independent probes continued while the baseline failed overall. The corrected baseline fixture releases only its own FIFO and gracefully stops its supervisor; private network and external host/service snapshots are restored. The initial forced-supervisor-kill fixture is not accepted as the baseline because it failed orphan-worker cleanup.

First-batch release `0fdcb1a4ed45e850b9d7e6cd1b3bc3965f3775c6682ac59bcc0348a028e1a749`: **19 storage + 25 restore/state = 44 HTTP/system checks PASS** in verified private NET/mount/PID namespaces. Coverage includes eight identity readers, lengths 0/31/33/4 MiB, FIFO/dangling-link inode preservation, regular operator links, held modern FileLock and modern-key precedence, byte-identical 0600 migration, corrupt-legacy refusal, storage recovery and cookies across fresh supervisors. Q07 regression covers reissue, legacy migration, mixed users/groups and actual restored VPN clients with tunnel ping, including a new host without panel-secret.

The unit negative vector constructs computable proofs for public points 0 and 1 with DH=0; both verifiers now refuse them and subsequently accept a legitimate proof. Previous unchecked acceptance is established by source and proof construction; no live hostile-peer baseline or valid explicit-pin bypass is claimed. The shared verifier call was reviewed before credential construction/transmission in the transport core.

An independent Python HMAC-SHA256 implementation checks **5 HKDF wire vectors / 18 checks** across all four schemes, directions, IKM order and input changes. It never calls the Rust generator/helper. This is an independent consistency implementation, not an external crypto audit or independent primitive certification.

Linux: **2270 units PASS / 60 ignored**, full/minimal Clippy and rustfmt PASS. Fresh **18/327 matrix**, aggregate leak and **100 TCP + 100 QUIC / 33 soak checks PASS**. All four native cores pass independent A/B builds; ABI/canonical-client copies/provenance PASS. .11 snapshots/service/binary remain unchanged. The current .10 pair and fields are recorded; historical unattributed legacy IPv4 dump variability remains a limitation, with no general .10 host-preservation PASS. No working-service replacement, push or new performance benchmark. Physical advisory rows remain unchanged.

## Q08 completion

| ID | Problem | Fix |
| --- | --- | --- |
| Q08-F004, P2 | Optional ml-kem zeroize was disabled; retained decapsulation keys had no wiping Drop. | Enable ml-kem/module-lattice/hybrid-array zeroize; compile-time DecapKey: ZeroizeOnDrop regression. Helper SharedKey temporaries also use Zeroizing. |
| Q08-F005, P3 | Static session binding admitted unchecked DH with a low-order pin into the KDF. | Checked DH refuses before KDF. The later proof verifier already refused; no credential-send bypass is claimed here. |
| Q08-F006, P3 | Unused throwaway-PQ key-share helper and a counter_wraps test exercising only 100 ordinary packets. | Remove helper, exercise retained keypair, rename sequential test and test actual counter exhaustion. |
| Q08-F007, P2 | Documentation promised mandatory inner PQ for reality-tls despite its current classic private inner exchange. | Correct crypto comments and paired README, THREAT-MODEL, AUDIT, ROADMAP and COMPARISON: legacy camouflage requires inner hybrid; REALITY TLS PQ depends on outer negotiated group. |

Review covers seven areas: primitives/KDF/AEAD; static binding and proof-before-credentials; pin/TOFU; RNG/nonces; rotation/storage/trust; memory; dead code/security claims. Raw/fake-TLS TCP, UDP and JOIN/resume ordering was reviewed: verifier → trust admission → credentials/token. A real duplex raw-handshake test proves no credential bytes follow a forged proof or failed trust callback. Evidence contains the detailed review map.

Independent known answers: **60 NIST ML-KEM-768 cases** (25 keygen, 25 encapsulation, 10 decapsulation, five modified ciphertexts), pinned upstream commit/full-source SHA and tcId/tgId; retained subset checked byte-for-byte against originals. Invalid full-length ciphertext returns the expected implicit-rejection secret, wrong length returns None; canonical modulus/length refusals are checked. **RFC 7748 section6.1 X25519**, **RFC 8439 section2.8.2 ChaCha20-Poly1305**, independent Python cryptography empty-AAD oracle checks the actual allocating/detached wrappers. Each of 130 ciphertext/tag byte mutations fails; detached failure preserves ciphertext. Wrong nonce/AAD and short tags fail. **5 HKDF vectors / 18 Python HMAC checks PASS**. Existing RFC 8448 AES-128 record vector and AES-256 integration/roundtrip reviewed; full outer TLS remains Q11.

RNG review: OS/getrandom and rand0.10.2 ChaCha12 seeded/reseeded by SysRng, no weak fallback on entropy failure. Supervisor execs worker executable; current paths do not continue fork-copied ThreadRng state. REALITY fresh-ephemeral and reconnect fresh-session-key contracts, PRP bijection and raw/TLS exhaustion before wrap reviewed/tested; rejection preserves counters and clears stale output. This is source/invariant review, not statistical or side-channel certification.

Final exact release `670729a549217717f774408cf7839f72b09c26679e1acf03c72a65d339c2010e`: **31 keys/rotation + 25 restore/state = 56 HTTP/system checks PASS**. Actual pinned clients authenticate with the old identity before rotation and while the worker retains it, then with the new identity after explicit restart; wrong generations fail cryptographically. API/CLI rotation changes persisted bytes/public key with0600, API does not restart workers and list shows persisted generation. Restore preserves reissue and actual VPN traffic. **2279 Linux units PASS / 60 ignored**, pinned full/minimal Clippy/rustfmt PASS. Fresh **18/327 matrix**, aggregate leak and **100 TCP + 100 QUIC / 33 soak checks PASS**. Fresh four-core native A/B, ABI/copies/provenance PASS. .11 host/service/binary preserved; current .10 pair retained with its historical legacy-dump limitation.

## Assurance limits

X25519/ML-KEM key objects and specified loader/KDF/session buffers are wiped. Public Vec/array APIs transfer copies to callers; no total-erasure guarantee for temporary copies, FFI buffers, registers, swap or crash dumps. Previously accepted AES expanded-schedule limitation remains. Known answers do not replace an external cryptographic audit or security proof.

Operator regular links and existing read owner/mode remain supported; generated keys0600 and standard identity directory0700. Atomic writer/sidecar locks do not certify power loss, uncoordinated root writes or old binaries. Bounded bytes/FIFO refusal is not a hard regular-filesystem IO deadline. Session-key fallback, best-effort reversible CLI encryption and first-contact TOFU limits remain. Physical advisory exclusions unchanged; no working-service replacement, push, deploy or new performance benchmark.

**Q08 DONE:** all five checklist categories complete within these limits; current fixes have no pending mandatory checks. Next: Q09 handshake/pre-auth. [Final evidence](../../../../release/certification/evidence/q08-completion-20261003.json); [first batch/baseline](../../../../release/certification/evidence/q08-keys-20261003.json).

# Compact REALITY: INNER_PQ_V1

Status: implemented in development 0.8.4; not an independently audited protocol.
Discussion: [#69](https://github.com/litvinovtd/qeli/issues/69), thanks to
[@Singijeon](https://github.com/Singijeon).

## Activation and compatibility

`mode=reality-tls` with `reality_compact=true` keeps a small X25519-only **outer**
TLS ClientHello and requires the hybrid exchange below inside the established
TLS/H2 carrier. No GUI-specific crypto implementation is involved: primary AUTH,
secondary JOIN and roaming resume share the Rust key-exchange handler.

```ini
[qeli]
mode = reality-tls
reality_compact = true
reality_split = none
```

Keep the existing server address, pin, short ID, SNI and credentials. Update the
server first and then each client's native core. An unsupported server causes
an error before credentials; there is no automatic retry with classic exchange,
noncompact mode or a different algorithm/version. A smaller ClientHello does not
guarantee one TCP packet. No new key material is put in TLS random/session_id.

New servers still accept legacy raw exchange for old/noncompact peers. This is
compatibility, **not** evidence that an old compact client has PQ protection.
The new compact client itself cannot be downgraded through this legacy path.
Noncompact REALITY, plain, FakeTLS, obfs and UDP wire formats are unchanged.

## Fixed wire encoding

Only after TLS/H2 establishment:

| Flight | Layout | Total |
|---|---|---:|
| Client | sentinel(32 zero bytes), header(32), ephemeral X25519 public(32), ML-KEM-768 ek(1184) | 1280 bytes |
| Server | header(32), ephemeral X25519 public(32), ML-KEM-768 ciphertext(1088) | 1152 bytes |

The zero sentinel is not an admissible legacy X25519 key. A recognized PQ
request is either processed completely or rejected, never reparsed as legacy.
The server recognizes it only in the inner REALITY carrier, not plain mode.
The body is an INNER_PQ_V1 layout, not a TLS key_share extension: X25519 is first.

Header offsets (integers big-endian):

| Bytes | Value |
|---|---|
| 0..8 | client `QELIPQ\0C`, server `QELIPQ\0S` (eight bytes) |
| 8..10 | version `1` |
| 10..12 | group `0x11ec` (X25519MLKEM768) |
| 12..14 | policy `3`: PQ required and static binding required |
| 14..16 | body length: client `1216`, server `1120` |
| 16..32 | reserved, all zero |

Every header byte is checked, including roles/reserved bytes. Unknown versions,
groups, policies or lengths fail closed. Body buffers have fixed bounds; their
allocation never uses an attacker-provided length. Low-order X25519 keys and
invalid ML-KEM encapsulation keys are rejected. Full-length invalid ciphertexts
use ML-KEM implicit rejection; subsequent AEAD key confirmation rejects them.
Existing whole-handshake deadlines bound incomplete flights.

## Transcript and KDF

Primitives are the existing RustCrypto ML-KEM-768, X25519, HKDF-SHA256 and packet
AEAD. No new primitive, dependency or native ABI is introduced.

Let `C` and `S` be the complete client/server flights above and `P` the pinned
32-byte server static public key. Both peers compute:

```text
T    = SHA256("qeli-reality-inner-pq-v1 transcript\0" || C || S || P)
ee   = X25519(client_ephemeral, server_ephemeral)
es   = X25519(client_ephemeral, server_static)
ml   = ML-KEM-768 shared secret
PRK  = HKDF-Extract("qeli-reality-inner-pq-v1", ee || ml || es)
root = HKDF-Expand(PRK, "transcript-bound-session-root\0" || T, 32)
```

`root` is used directly as an HKDF-SHA256 PRK (no second Extract). The existing
32-byte Expand labels derive independent data, resume, CID and control keys:
`server-to-client-enc-key`, `client-to-server-enc-key`,
`qeli-resume-secret-v1`, `qeli-c2s-cid-secret-v1`,
`qeli-s2c-cid-secret-v1`, `qeli-control-secret-v1`.

This is a separate domain from every legacy KDF. Static identity binding is
mandatory in v1 even if legacy `bind_static=false` is present. ML-KEM shared-secret
buffers and intermediate root/IKM use zeroizing wrappers; session material and
primitive private keys retain their existing zeroize support. This is best-effort
memory hygiene, not a guarantee against compiler/register copies. Public flights
and transcript contain no shared secrets.

The transcript binds the **inner** exchange, not a TLS exporter. The inner
identity-authenticated hybrid session does not depend on outer confidentiality
remaining secure against future quantum computers. It may be relayed as opaque
ciphertext; no independent claim of TLS exporter/channel binding is made.

## Key confirmation, AUTH and resume

The server sends its existing identity proof inside a Raw PacketCodec record
encrypted under the new hybrid server-to-client key. That proof authenticates
the static identity, ephemeral DH and `T`. The client must decrypt it, verify
the pinned identity and pass its platform trust policy **before** sending AUTH,
JOIN tokens or resume proofs. Altering ek/ciphertext/policy/transcript breaks
the AEAD key confirmation or identity proof. A valid first client record confirms
the client-to-server key to the server before authorization.

All tunnel data uses the new directional keys. The primary session's resume
secret also comes from this PQ root, not a parallel classic KDF. Additional and
replacement compact carriers repeat INNER_PQ_V1; resume proofs bind the fresh
inner transcript while referring to the original session's resume secret.

## Scope and evidence

Goal: confidentiality against harvest-now/decrypt-later, provided ML-KEM remains
secure. Server identity authentication is still **classical X25519**, not a
post-quantum signature or a guarantee against an active quantum adversary.
There is no claim of absolute DPI invisibility; endpoints, lengths, timing and
traffic volume remain observable. Independent cryptographic review remains desirable.

Tests cover fixed headers/KDF vectors (`conformance/inner-pq-v1.json`, independent
Python stdlib HKDF oracle), arbitrary IO fragmentation, low-order keys, mutations
of version/group/policy/length/reserved bytes/ciphertext/proof/pin, trust rejection,
no AUTH/classic retry after rejection, and AUTH/data through real TLS/H2 with a
classic outer handshake. Existing compatibility and native config tests also run.
Primary implementation: `protocol/inner_pq.rs`, `crypto/derive.rs`,
`transport_core/session.rs`, `client/mod.rs`, `server/handler.rs`.
Primitive references: [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[HKDF RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

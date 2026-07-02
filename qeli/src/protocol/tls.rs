use crate::crypto::PublicKey;
use rand::Rng;

const TLS_HEADER_SIZE: usize = 5;
const MAX_HANDSHAKE_SIZE: usize = 16384;

/// Decoy SNI pool used when the caller passes a literal IP as server address.
/// Picking randomly per connection breaks the "all qeli flows use the same SNI"
/// fingerprint that a passive DPI box can otherwise build.
pub const DEFAULT_SNI_POOL: &[&str] = &[
    "www.cloudflare.com",
    "www.google.com",
    "www.microsoft.com",
    "www.apple.com",
    "www.amazon.com",
];

/// Pick a random SNI from the decoy pool. Falls back to "www.cloudflare.com"
/// in the (impossible) case of an empty pool.
pub fn pick_random_sni() -> &'static str {
    use rand::seq::SliceRandom;
    DEFAULT_SNI_POOL
        .choose(&mut rand::thread_rng())
        .copied()
        .unwrap_or("www.cloudflare.com")
}

pub struct FakeTlsHandshake;

fn put_u24(buf: &mut Vec<u8>, val: usize) {
    buf.push((val >> 16) as u8);
    buf.push((val >> 8) as u8);
    buf.push(val as u8);
}

/// A random GREASE value (RFC 8701): one of 0x0A0A, 0x1A1A, … 0xFAFA.
fn grease_value<R: rand::Rng>(rng: &mut R) -> u16 {
    let b: u8 = (rng.gen_range(0u8..16) << 4) | 0x0A;
    ((b as u16) << 8) | b as u16
}

impl FakeTlsHandshake {
    /// `pad_to_min` inflates the ClientHello record to at least this many bytes
    /// using a TLS padding extension (RFC 7685). For UDP this enforces an
    /// anti-amplification floor so the server's larger response cannot be used
    /// for reflection (a spoofed-source attacker must send ≥ the response size).
    /// Pass 0 for no padding (TCP).
    /// `reality_session_id`: when `Some`, the 32-byte legacy_session_id carries a
    /// REALITY authenticator (see `crypto::reality`) instead of random bytes, and
    /// an ALPN extension is added so the hello reads as a browser (the server then
    /// discriminates qeli clients by the crypto token, not by ALPN absence).
    ///
    /// Fingerprint-only variant: the X25519MLKEM768 share carries a throwaway ML-KEM
    /// key (the secret is discarded). For the real hybrid exchange use
    /// [`build_client_hello_pq`], which keeps the decapsulation key.
    pub fn build_client_hello(
        key_public: &PublicKey,
        server_name: &str,
        pad_to_min: usize,
        reality_session_id: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let (_dk, ek) = crate::crypto::mlkem::mlkem768_keypair();
        Self::build_client_hello_inner(key_public, server_name, pad_to_min, reality_session_id, &ek)
    }

    /// Like [`build_client_hello`] but RETAINS the ML-KEM-768 decapsulation key so
    /// the client can finish the hybrid key exchange: the server returns the ML-KEM
    /// ciphertext in its ServerHello key_share (see [`build_server_hello_pq`]), the
    /// client decapsulates with this key, and both fold the ML-KEM shared secret
    /// into the tunnel KDF ([`crate::crypto::derive_keys_hybrid`]).
    pub fn build_client_hello_pq(
        key_public: &PublicKey,
        server_name: &str,
        pad_to_min: usize,
        reality_session_id: Option<&[u8; 32]>,
    ) -> (Vec<u8>, crate::crypto::mlkem::DecapKey) {
        let (dk, ek) = crate::crypto::mlkem::mlkem768_keypair();
        let record = Self::build_client_hello_inner(
            key_public,
            server_name,
            pad_to_min,
            reality_session_id,
            &ek,
        );
        (record, dk)
    }

    /// Shared ClientHello builder; `ml_ek` is the X25519MLKEM768 encapsulation key
    /// placed in the key_share (the caller decides whether to keep the matching dk).
    fn build_client_hello_inner(
        key_public: &PublicKey,
        server_name: &str,
        pad_to_min: usize,
        reality_session_id: Option<&[u8; 32]>,
        ml_ek: &[u8],
    ) -> Vec<u8> {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let random: [u8; 32] = rng.gen();
        let session_id: [u8; 32] = reality_session_id.copied().unwrap_or_else(|| rng.gen());

        // GREASE values (RFC 8701): random reserved values of the form 0x?A?A.
        // Modern Chrome/Firefox always include them; their absence is itself a
        // fingerprint. We pick fresh ones per connection.
        let grease_first = grease_value(&mut rng);
        let grease_last = grease_value(&mut rng);
        let grease_cipher = grease_value(&mut rng);

        // Each non-GREASE extension is built into its own buffer so the order can
        // be shuffled per connection — this is what Chrome ≥110 does and it makes
        // the JA3 hash vary per connection, defeating static-JA3 blocklists. Our
        // server parses extensions by type, so order is irrelevant to us.
        let mut shuffleable: Vec<Vec<u8>> = Vec::new();
        let mut push_ext = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut e = Vec::new();
            f(&mut e);
            shuffleable.push(e);
        };
        push_ext(&|e| Self::build_sni_extension(e, server_name));
        push_ext(&|e| Self::build_empty_extension(e, 0x0017)); // extended_master_secret
        push_ext(&|e| Self::build_supported_groups_extension(e));
        push_ext(&|e| Self::build_key_share_extension(e, key_public, ml_ek));
        push_ext(&|e| Self::build_psk_key_exchange_modes(e));
        push_ext(&|e| Self::build_supported_versions_extension(e));
        push_ext(&|e| Self::build_signature_algorithms_extension(e));
        push_ext(&|e| Self::build_compress_certificate_extension(e));
        // Real browsers always send ALPN (h2/http1.1). Sending it unconditionally —
        // not only on the REALITY path — makes every hello browser-like, so a passive
        // DPI box can't key on ALPN absence. The server discriminates qeli clients by
        // the crypto token / key_share, never by ALPN, and skips this extension by TLV.
        push_ext(&|e| Self::build_alpn_extension(e));
        shuffleable.shuffle(&mut rng);

        // GREASE extension first and last (Chrome layout).
        let mut extensions = Vec::new();
        Self::build_grease_extension(&mut extensions, grease_first);
        for e in &shuffleable {
            extensions.extend_from_slice(e);
        }
        Self::build_grease_extension(&mut extensions, grease_last);

        // Anti-amplification / realism padding (RFC 7685). Non-extension record
        // bytes are a constant 90 (record+handshake headers, random, session id,
        // 4 cipher suites, compression, ext-length field), so the deficit is
        // filled with a padding extension to reach `pad_to_min`.
        const NON_EXT_BYTES: usize = 90;
        let projected = NON_EXT_BYTES + extensions.len();
        if pad_to_min > projected + 4 {
            let pad_data = pad_to_min - projected - 4; // 4 = padding ext header
            extensions.extend_from_slice(&[0x00, 0x15]); // padding extension type
            extensions.extend_from_slice(&(pad_data as u16).to_be_bytes());
            extensions.extend(std::iter::repeat_n(0u8, pad_data));
        }

        // Build handshake body
        let mut body = Vec::new();
        body.push(0x01); // ClientHello
        put_u24(&mut body, 0); // placeholder length

        body.extend_from_slice(&[0x03, 0x03]); // protocol version

        body.extend_from_slice(&random);

        body.push(0x20);
        body.extend_from_slice(&session_id);

        // Cipher suites — GREASE first, then the standard TLS 1.3 suites.
        body.extend_from_slice(&[0x00, 0x08]); // list length: 8 bytes (4 suites)
        body.extend_from_slice(&grease_cipher.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384
        body.extend_from_slice(&[0x13, 0x03]); // TLS_CHACHA20_POLY1305_SHA256

        body.push(0x01); // compression methods length
        body.push(0x00); // null compression

        let ext_len = extensions.len() as u16;
        body.extend_from_slice(&ext_len.to_be_bytes());
        body.extend_from_slice(&extensions);

        let body_len = body.len() - 4;
        body[1] = (body_len >> 16) as u8;
        body[2] = (body_len >> 8) as u8;
        body[3] = body_len as u8;

        Self::wrap_in_record(0x16, &body)
    }

    pub fn parse_client_hello(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < TLS_HEADER_SIZE + 38 {
            return None;
        }
        if data[0] != 0x16 {
            return None;
        }
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if record_len > MAX_HANDSHAKE_SIZE {
            return None;
        }
        if data.len() != TLS_HEADER_SIZE + record_len {
            return None;
        }
        let inner = &data[TLS_HEADER_SIZE..TLS_HEADER_SIZE + record_len];
        if inner.len() < 38 || inner[0] != 0x01 {
            return None;
        }

        let mut offset = 38;
        if offset + 1 > inner.len() {
            return None;
        }
        let sid_len = inner[offset] as usize;
        offset += 1 + sid_len;
        if offset + 2 > inner.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
        offset += 2 + cs_len;
        if offset + 1 > inner.len() {
            return None;
        }
        let comp_len = inner[offset] as usize;
        offset += 1 + comp_len;
        if offset + 2 > inner.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
        offset += 2;
        if offset + ext_len > inner.len() {
            return None;
        }

        Self::extract_key_share(&inner[offset..offset + ext_len])
    }

    /// Like [`parse_client_hello`] but also returns the 32-byte legacy_session_id
    /// (the REALITY token) and is tolerant of a truncated tail, so it works on a
    /// bounded server-side peek. Returns `(session_id, key_share)`.
    pub fn parse_client_hello_full(data: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
        if data.len() < TLS_HEADER_SIZE + 39 || data[0] != 0x16 {
            return None;
        }
        let inner = &data[TLS_HEADER_SIZE..];
        if inner.len() < 39 || inner[0] != 0x01 {
            return None;
        }
        let sid_len = inner[38] as usize;
        if sid_len != 32 || inner.len() < 39 + sid_len {
            return None;
        }
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&inner[39..39 + 32]);

        let mut offset = 39 + sid_len;
        if offset + 2 > inner.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
        offset += 2 + cs_len;
        if offset + 1 > inner.len() {
            return None;
        }
        let comp_len = inner[offset] as usize;
        offset += 1 + comp_len;
        if offset + 2 > inner.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
        offset += 2;
        let ext_end = (offset + ext_len).min(inner.len());
        let key_share = Self::extract_key_share(&inner[offset..ext_end])?;
        Some((session_id, key_share))
    }

    /// Legacy ServerHello selecting classic x25519 (0x001d) in the key_share. Used
    /// for the fingerprint-only path and tests; the real hybrid server uses
    /// [`build_server_hello_pq`].
    pub fn build_server_hello(key_public: &PublicKey) -> Vec<u8> {
        Self::build_server_hello_inner(key_public, None)
    }

    /// Hybrid ServerHello: selects the X25519MLKEM768 group and carries the ML-KEM
    /// ciphertext (`mlkem_ct`) followed by the server x25519 pub in the key_share, so
    /// the client decapsulates and folds the ML-KEM shared secret into the tunnel KDF
    /// ([`crate::crypto::derive_keys_hybrid`]). This is also more fingerprint-correct:
    /// a server answering a PQ-capable ClientHello selects the PQ group.
    pub fn build_server_hello_pq(key_public: &PublicKey, mlkem_ct: &[u8]) -> Vec<u8> {
        Self::build_server_hello_inner(key_public, Some(mlkem_ct))
    }

    fn build_server_hello_inner(key_public: &PublicKey, ml_ct: Option<&[u8]>) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let random: [u8; 32] = rng.gen();
        let session_id: [u8; 32] = rng.gen();

        let mut extensions = Vec::new();

        // Supported versions (0x002B) — TLS 1.3
        Self::build_server_supported_versions(&mut extensions);

        // Key share (0x0033)
        Self::build_server_key_share_extension(&mut extensions, key_public, ml_ct);

        let mut body = Vec::new();
        body.push(0x02); // ServerHello type
        put_u24(&mut body, 0);

        body.extend_from_slice(&[0x03, 0x03]); // version
        body.extend_from_slice(&random);
        body.push(0x20);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x00); // compression

        let ext_len = extensions.len() as u16;
        body.extend_from_slice(&ext_len.to_be_bytes());
        body.extend_from_slice(&extensions);

        let body_len = body.len() - 4;
        body[1] = (body_len >> 16) as u8;
        body[2] = (body_len >> 8) as u8;
        body[3] = body_len as u8;

        Self::wrap_in_record(0x16, &body)
    }

    pub fn parse_server_hello(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < TLS_HEADER_SIZE + 38 {
            return None;
        }
        if data[0] != 0x16 {
            return None;
        }
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if record_len > MAX_HANDSHAKE_SIZE {
            return None;
        }
        if data.len() != TLS_HEADER_SIZE + record_len {
            return None;
        }
        let inner = &data[TLS_HEADER_SIZE..TLS_HEADER_SIZE + record_len];
        if inner.len() < 38 || inner[0] != 0x02 {
            return None;
        }

        let mut offset = 38;
        if offset + 1 > inner.len() {
            return None;
        }
        let sid_len = inner[offset] as usize;
        offset += 1 + sid_len;
        offset += 3; // cipher suite (2) + compression (1)
        if offset + 2 > inner.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
        offset += 2;
        if offset + ext_len > inner.len() {
            return None;
        }

        Self::extract_key_share(&inner[offset..offset + ext_len])
    }

    /// Build a fake TLS Certificate message
    pub fn build_certificate() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        // Generate a certificate with somewhat realistic DER structure
        // Start with a minimal but valid-looking DER SEQUENCE header. Randomise the
        // length per connection (a fixed 512 is a passive size tell); the peer treats
        // the Certificate as an opaque blob and hashes it by its record length.
        let cert_inner_len = rng.gen_range(512..1800);
        let mut cert_data = Vec::with_capacity(cert_inner_len + 20);
        // DER SEQUENCE tag
        cert_data.push(0x30);
        // DER length (use long form for >127 bytes)
        let inner_len = cert_inner_len;
        if inner_len < 128 {
            cert_data.push(inner_len as u8);
        } else {
            cert_data.push(0x82);
            cert_data.push((inner_len >> 8) as u8);
            cert_data.push(inner_len as u8);
        }
        // Fill with structured-looking random data
        // PKCS#7 / X.509 style patterns
        cert_data.push(0x30); // SEQUENCE
        cert_data.push(0x82);
        let sub_len = inner_len - 4;
        cert_data.push((sub_len >> 8) as u8);
        cert_data.push(sub_len as u8);
        // TBSCertificate SEQUENCE
        cert_data.push(0x30);
        cert_data.push(0x82);
        let tbs_len = sub_len - 4;
        cert_data.push((tbs_len >> 8) as u8);
        cert_data.push(tbs_len as u8);
        // version [0] EXPLICIT
        cert_data.push(0xA0);
        cert_data.push(0x03);
        cert_data.push(0x02);
        cert_data.push(0x01);
        cert_data.push(0x02);
        // serial number
        cert_data.push(0x02);
        cert_data.push(0x01);
        cert_data.push(rng.gen::<u8>());
        // Fill remainder with random
        while cert_data.len() < cert_inner_len {
            cert_data.push(rng.gen::<u8>());
        }
        cert_data.truncate(cert_inner_len);

        let mut body = Vec::new();
        body.push(0x0B); // Certificate type
        put_u24(&mut body, 0);

        // Certificate list length
        let payload_len = cert_data.len() + 6;
        put_u24(&mut body, payload_len);
        // Certificate entry length
        put_u24(&mut body, cert_data.len());
        body.extend_from_slice(&cert_data);
        // Empty certificate list terminator (as per TLS 1.3)
        put_u24(&mut body, 0);

        let body_len = body.len() - 4;
        body[1] = (body_len >> 16) as u8;
        body[2] = (body_len >> 8) as u8;
        body[3] = body_len as u8;

        // Carry the Certificate as an application_data (0x17) record, not a cleartext
        // handshake (0x16) record. Real TLS 1.3 encrypts everything after ServerHello,
        // so a plaintext 0x16 Certificate immediately after ServerHello is a
        // state-machine DPI tell. The peer treats the flight as opaque length-delimited
        // records (it only recovers the qeli auth proof), so the content type is free to
        // match real TLS. NOTE: the fake-tls UDP client splits this flight by matching
        // the record type, so it must match 0x17 in lockstep (client/mod.rs UDP path).
        Self::wrap_in_record(0x17, &body)
    }

    /// Build a fake TLS Finished message (verify_data as random bytes)
    pub fn build_finished() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let verify_data: [u8; 32] = rng.gen();

        let mut body = Vec::new();
        body.push(0x14); // Finished type
        put_u24(&mut body, 0);

        body.extend_from_slice(&verify_data);

        let body_len = body.len() - 4;
        body[1] = (body_len >> 16) as u8;
        body[2] = (body_len >> 8) as u8;
        body[3] = body_len as u8;

        // application_data (0x17), not cleartext handshake (0x16): see build_certificate.
        Self::wrap_in_record(0x17, &body)
    }

    /// Build a ChangeCipherSpec message — required for TLS 1.3 middlebox compatibility
    pub fn build_change_cipher_spec() -> Vec<u8> {
        let mut record = Vec::with_capacity(6);
        record.push(0x14); // ChangeCipherSpec content type
        record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        record.extend_from_slice(&[0x00, 0x01]); // length: 1
        record.push(0x01); // the single byte payload
        record
    }

    /// Build a fake NewSessionTicket message — TLS 1.3 always sends these.
    /// Carried as application_data (0x17), not cleartext handshake (0x16): a real
    /// TLS 1.3 NewSessionTicket rides inside the encrypted application_data stream
    /// after ServerHello, so a plaintext 0x16 NST is a state-machine DPI tell (see
    /// build_certificate/build_finished). The whole post-ServerHello flight
    /// (Certificate, Finished, NewSessionTicket, auth-proof) is now uniformly 0x17,
    /// and peers consume it positionally by record length (they never key on the
    /// content type to tell NST from the auth-proof).
    pub fn build_new_session_ticket() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        // Randomise the ticket length per connection (a fixed 64 bytes is a passive
        // size tell). The peer never inspects the ticket, so any length is fine.
        let mut ticket = vec![0u8; rng.gen_range(32..=192)];
        rng.fill(&mut ticket[..]);

        let mut body = Vec::new();
        body.push(0x04); // NewSessionTicket type
        put_u24(&mut body, 0);

        // ticket_lifetime: 7200 seconds (2 hours)
        body.extend_from_slice(&7200u32.to_be_bytes());
        // ticket_age_add: random
        let age_add: [u8; 4] = rng.gen();
        body.extend_from_slice(&age_add);
        // ticket_nonce length + nonce
        body.push(0x04); // length 4
        body.extend_from_slice(&rng.gen::<[u8; 4]>());
        // ticket length + ticket
        body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        body.extend_from_slice(&ticket);
        // extensions length (0)
        body.extend_from_slice(&[0x00, 0x00]);

        let body_len = body.len() - 4;
        body[1] = (body_len >> 16) as u8;
        body[2] = (body_len >> 8) as u8;
        body[3] = body_len as u8;

        // application_data (0x17), not cleartext handshake (0x16): see build_certificate.
        Self::wrap_in_record(0x17, &body)
    }

    // ── Extension builders ──────────────────────────────────────────────────

    fn build_sni_extension(buf: &mut Vec<u8>, server_name: &str) {
        let name_bytes = server_name.as_bytes();
        buf.extend_from_slice(&[0x00, 0x00]); // SNI extension type

        // SNI extension data = server_name_list_length(2) + name_type(1) + name_length(2) + name
        let ext_data_total = 2 + 1 + 2 + name_bytes.len();

        buf.extend_from_slice(&(ext_data_total as u16).to_be_bytes()); // extension data length
        buf.extend_from_slice(&((ext_data_total - 2) as u16).to_be_bytes()); // server_name_list_length
        buf.push(0x00); // hostname type
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);
    }

    fn build_supported_groups_extension(buf: &mut Vec<u8>) {
        // Fresh GREASE group first (RFC 8701) — Chrome always leads the list with one,
        // so its absence is a fingerprint. The peer selects the key_share by group id
        // and never reads supported_groups, so an extra group is harmless.
        let grease = grease_value(&mut rand::thread_rng());
        buf.extend_from_slice(&[0x00, 0x0A]); // supported_groups
        buf.extend_from_slice(&[0x00, 0x0A]); // extension data length: 10
        buf.extend_from_slice(&[0x00, 0x08]); // list length: 8 (4 groups)
        buf.extend_from_slice(&grease.to_be_bytes()); // GREASE (0x?A?A)
        buf.extend_from_slice(&[0x11, 0xEC]); // X25519MLKEM768 (PQ, first like Chrome)
        buf.extend_from_slice(&[0x00, 0x1D]); // x25519
        buf.extend_from_slice(&[0x00, 0x17]); // secp256r1
    }

    fn build_key_share_extension(buf: &mut Vec<u8>, key_public: &PublicKey, ml_ek: &[u8]) {
        // Two shares, PQ first like current Chrome: X25519MLKEM768 (1216 B) then
        // classic x25519 (32 B). For the hybrid exchange the server now selects the
        // X25519MLKEM768 group and encapsulates against `ml_ek`; `extract_key_share`
        // still walks all entries and picks 0x001d for the classic half.
        let pq = crate::crypto::mlkem::x25519_mlkem768_share_from_ek(ml_ek, key_public.as_bytes());
        let pq_entry_len = 4 + pq.len(); // group(2) + key_length(2) + key
        let x25519_entry_len = 4 + 32;
        let shares_len = pq_entry_len + x25519_entry_len;
        let ext_data_len = shares_len + 2; // + client_shares_length field

        buf.extend_from_slice(&[0x00, 0x33]); // key_share
        buf.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        buf.extend_from_slice(&(shares_len as u16).to_be_bytes()); // client_shares_length
                                                                   // X25519MLKEM768 share
        buf.extend_from_slice(&[0x11, 0xEC]);
        buf.extend_from_slice(&(pq.len() as u16).to_be_bytes());
        buf.extend_from_slice(&pq);
        // x25519 share
        buf.extend_from_slice(&[0x00, 0x1D]);
        buf.extend_from_slice(&[0x00, 0x20]); // 32 bytes
        buf.extend_from_slice(key_public.as_bytes());
    }

    fn build_psk_key_exchange_modes(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[0x00, 0x2D]); // psk_key_exchange_modes
        buf.extend_from_slice(&[0x00, 0x02]); // extension data length: 2
        buf.push(0x01); // KE modes length: 1
        buf.push(0x01); // PSK with (EC)DHE
    }

    fn build_supported_versions_extension(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[0x00, 0x2B]); // supported_versions
        buf.extend_from_slice(&[0x00, 0x03]); // extension data length: 3
        buf.push(0x02); // versions list length: 2
        buf.extend_from_slice(&[0x03, 0x04]); // TLS 1.3 (0x0304)
    }

    fn build_signature_algorithms_extension(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[0x00, 0x0D]); // signature_algorithms
                                              // Extension data: length(2) + list_length(2) + algorithms
                                              // IANA SignatureScheme codepoints. No rsa_pkcs1_sha1 (0x0201): modern
                                              // browsers dropped SHA-1, so offering it is a fake-tls fingerprint tell.
        let algorithms: &[u8] = &[
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x06, 0x03, // ecdsa_secp521r1_sha512
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x01, // rsa_pkcs1_sha384
        ];
        let list_len = algorithms.len() as u16 + 2;
        buf.extend_from_slice(&list_len.to_be_bytes());
        buf.extend_from_slice(&(algorithms.len() as u16).to_be_bytes());
        buf.extend_from_slice(algorithms);
    }

    fn build_compress_certificate_extension(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[0x00, 0x1B]); // compress_certificate
        buf.extend_from_slice(&[0x00, 0x03]); // extension data length: 3
        buf.push(0x02); // algorithms list length: 2
        buf.extend_from_slice(&[0x00, 0x02]); // brotli
    }

    /// ALPN (RFC 7301): advertise `h2` + `http/1.1`, like a browser.
    fn build_alpn_extension(buf: &mut Vec<u8>) {
        let protos: &[&[u8]] = &[b"h2", b"http/1.1"];
        let mut list = Vec::new();
        for p in protos {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        buf.extend_from_slice(&[0x00, 0x10]); // ALPN extension type
        buf.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes()); // ext data len
        buf.extend_from_slice(&(list.len() as u16).to_be_bytes()); // ALPN list len
        buf.extend_from_slice(&list);
    }

    fn build_empty_extension(buf: &mut Vec<u8>, ext_type: u16) {
        buf.extend_from_slice(&ext_type.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // zero-length data
    }

    /// A GREASE extension: a reserved 0x?A?A type with empty data.
    fn build_grease_extension(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);
    }

    fn build_server_supported_versions(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[0x00, 0x2B]); // supported_versions
        buf.extend_from_slice(&[0x00, 0x02]); // extension data length: 2
        buf.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    }

    fn build_server_key_share_extension(
        buf: &mut Vec<u8>,
        key_public: &PublicKey,
        ml_ct: Option<&[u8]>,
    ) {
        buf.extend_from_slice(&[0x00, 0x33]); // key_share
        match ml_ct {
            None => {
                // Legacy: a single classic x25519 (0x001d) server share.
                let entry_len: u16 = 36; // group(2) + key_length(2) + key(32)
                buf.extend_from_slice(&(entry_len + 2).to_be_bytes()); // extension data length
                buf.extend_from_slice(&entry_len.to_be_bytes()); // server_share length (qeli format)
                buf.extend_from_slice(&[0x00, 0x1D]);
                buf.extend_from_slice(&[0x00, 0x20]);
                buf.extend_from_slice(key_public.as_bytes());
            }
            Some(ct) => {
                // Hybrid: X25519MLKEM768 (0x11ec), value = ML-KEM ciphertext ‖ x25519.
                let value_len = ct.len() + 32;
                let entry_len = 4 + value_len; // group(2) + key_length(2) + value
                let ext_data_len = entry_len + 2; // + server_share length field
                buf.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
                buf.extend_from_slice(&(entry_len as u16).to_be_bytes());
                buf.extend_from_slice(&[0x11, 0xEC]);
                buf.extend_from_slice(&(value_len as u16).to_be_bytes());
                buf.extend_from_slice(ct);
                buf.extend_from_slice(key_public.as_bytes());
            }
        }
    }

    /// Walk a key_share extension block and return the raw `key_exchange` bytes for
    /// `target_group`, or `None` if absent. Generalises [`extract_key_share`]; used by
    /// the hybrid parsers to pull the X25519MLKEM768 entry.
    fn extract_key_share_group(ext_data: &[u8], target_group: u16) -> Option<Vec<u8>> {
        let mut pos = 0;
        while pos + 4 <= ext_data.len() {
            let ext_type = u16::from_be_bytes([ext_data[pos], ext_data[pos + 1]]);
            let ext_len = u16::from_be_bytes([ext_data[pos + 2], ext_data[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > ext_data.len() {
                return None;
            }
            // key_share (0x0033): walk the share list (the 2-byte length prefix is
            // present on Chrome ClientHellos AND qeli's fake ServerHello) and return
            // the entry whose group matches.
            if ext_type == 0x0033 && ext_len >= 2 {
                let shares_len = u16::from_be_bytes([ext_data[pos], ext_data[pos + 1]]) as usize;
                let shares_end = (pos + 2 + shares_len).min(pos + ext_len);
                let mut q = pos + 2;
                while q + 4 <= shares_end {
                    let group = u16::from_be_bytes([ext_data[q], ext_data[q + 1]]);
                    let klen = u16::from_be_bytes([ext_data[q + 2], ext_data[q + 3]]) as usize;
                    q += 4;
                    if q + klen > shares_end {
                        break;
                    }
                    if group == target_group {
                        return Some(ext_data[q..q + klen].to_vec());
                    }
                    q += klen;
                }
            }
            pos += ext_len;
        }
        None
    }

    /// Classic x25519 (0x001d) key_share extractor — the 32-byte ephemeral public.
    fn extract_key_share(ext_data: &[u8]) -> Option<Vec<u8>> {
        let v = Self::extract_key_share_group(ext_data, 0x001d)?;
        if v.len() == 32 {
            Some(v)
        } else {
            None
        }
    }

    /// Server side: extract the client's X25519MLKEM768 encapsulation key (1184 B)
    /// from a (fake-TLS) ClientHello, so the server can encapsulate against it for the
    /// hybrid handshake. Mirrors [`parse_client_hello`]'s navigation exactly.
    pub fn extract_client_mlkem_ek(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < TLS_HEADER_SIZE + 38 || data[0] != 0x16 {
            return None;
        }
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if record_len > MAX_HANDSHAKE_SIZE || data.len() != TLS_HEADER_SIZE + record_len {
            return None;
        }
        let inner = &data[TLS_HEADER_SIZE..TLS_HEADER_SIZE + record_len];
        if inner.len() < 38 || inner[0] != 0x01 {
            return None;
        }
        let mut offset = 38;
        if offset + 1 > inner.len() {
            return None;
        }
        let sid_len = inner[offset] as usize;
        offset += 1 + sid_len;
        if offset + 2 > inner.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
        offset += 2 + cs_len;
        if offset + 1 > inner.len() {
            return None;
        }
        let comp_len = inner[offset] as usize;
        offset += 1 + comp_len;
        if offset + 2 > inner.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
        offset += 2;
        if offset + ext_len > inner.len() {
            return None;
        }
        let value = Self::extract_key_share_group(
            &inner[offset..offset + ext_len],
            crate::crypto::mlkem::X25519MLKEM768,
        )?;
        // value = ek(1184) ‖ x25519(32); return the ek half.
        if value.len() < crate::crypto::mlkem::MLKEM768_EK_LEN {
            return None;
        }
        Some(value[..crate::crypto::mlkem::MLKEM768_EK_LEN].to_vec())
    }

    /// Client side: parse a hybrid ServerHello, returning `(ml_kem_ciphertext (1088),
    /// server_x25519 (32))` from its X25519MLKEM768 key_share. Mirrors
    /// [`parse_server_hello`]'s navigation. `None` if the hybrid share is absent.
    pub fn parse_server_hello_pq(data: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
        if data.len() < TLS_HEADER_SIZE + 38 || data[0] != 0x16 {
            return None;
        }
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if record_len > MAX_HANDSHAKE_SIZE || data.len() != TLS_HEADER_SIZE + record_len {
            return None;
        }
        let inner = &data[TLS_HEADER_SIZE..TLS_HEADER_SIZE + record_len];
        if inner.len() < 38 || inner[0] != 0x02 {
            return None;
        }
        let mut offset = 38;
        if offset + 1 > inner.len() {
            return None;
        }
        let sid_len = inner[offset] as usize;
        offset += 1 + sid_len;
        offset += 3; // cipher suite (2) + compression (1)
        if offset + 2 > inner.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
        offset += 2;
        if offset + ext_len > inner.len() {
            return None;
        }
        let value = Self::extract_key_share_group(
            &inner[offset..offset + ext_len],
            crate::crypto::mlkem::X25519MLKEM768,
        )?;
        let ct_len = crate::crypto::mlkem::MLKEM768_CT_LEN; // 1088
        if value.len() != ct_len + 32 {
            return None;
        }
        let ct = value[..ct_len].to_vec();
        let mut x = [0u8; 32];
        x.copy_from_slice(&value[ct_len..ct_len + 32]);
        Some((ct, x))
    }

    fn wrap_in_record(content_type: u8, data: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(TLS_HEADER_SIZE + data.len());
        record.push(content_type);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(data.len() as u16).to_be_bytes());
        record.extend_from_slice(data);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_client_hello_roundtrip() {
        let kp = Keypair::generate();
        let hello = FakeTlsHandshake::build_client_hello(kp.public(), "example.com", 0, None);
        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16);

        let extracted = FakeTlsHandshake::parse_client_hello(&hello).unwrap();
        assert_eq!(extracted.len(), 32);
        assert_eq!(&extracted, kp.public().as_bytes());
    }

    #[test]
    fn client_hello_carries_pq_key_share() {
        let kp = Keypair::generate();
        let hello = FakeTlsHandshake::build_client_hello(kp.public(), "example.com", 0, None);
        // The server still recovers classic x25519 (it selects that group).
        assert_eq!(
            &FakeTlsHandshake::parse_client_hello(&hello).unwrap(),
            kp.public().as_bytes()
        );
        // X25519MLKEM768 share is present: group 0x11ec, key length 1216 (0x04c0).
        assert!(
            hello.windows(4).any(|w| w == [0x11, 0xEC, 0x04, 0xC0]),
            "ClientHello must carry the X25519MLKEM768 PQ key share"
        );
    }

    #[test]
    fn test_server_hello_roundtrip() {
        let kp = Keypair::generate();
        let hello = FakeTlsHandshake::build_server_hello(kp.public());
        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16);

        let extracted = FakeTlsHandshake::parse_server_hello(&hello).unwrap();
        assert_eq!(extracted.len(), 32);
        assert_eq!(&extracted, kp.public().as_bytes());
    }

    #[test]
    fn test_change_cipher_spec() {
        let ccs = FakeTlsHandshake::build_change_cipher_spec();
        assert_eq!(ccs.len(), 6);
        assert_eq!(ccs[0], 0x14);
        assert_eq!(ccs[5], 0x01);
    }

    #[test]
    fn test_new_session_ticket() {
        let ticket = FakeTlsHandshake::build_new_session_ticket();
        assert!(ticket.len() > 10);
        // NewSessionTicket now rides as application_data (0x17), like Certificate and
        // Finished, so the whole post-ServerHello flight is uniformly 0x17 and peers
        // parse it positionally by record length (F1).
        assert_eq!(ticket[0], 0x17);
    }

    #[test]
    fn cert_and_finished_are_application_data() {
        // Post-ServerHello messages must ride as 0x17 (application_data) records so the
        // server flight matches real TLS 1.3 (which encrypts everything after
        // ServerHello); a plaintext 0x16 Certificate/Finished is a DPI state tell.
        assert_eq!(FakeTlsHandshake::build_certificate()[0], 0x17);
        assert_eq!(FakeTlsHandshake::build_finished()[0], 0x17);
        // NewSessionTicket joined the all-0x17 flight (F1), so no post-ServerHello
        // record is a cleartext 0x16 handshake tell and the flight is consumed
        // positionally by length rather than by a 0x16-vs-0x17 NST/proof peek.
        assert_eq!(FakeTlsHandshake::build_new_session_ticket()[0], 0x17);
    }

    #[test]
    fn test_client_hello_has_supported_versions() {
        let kp = Keypair::generate();
        let hello = FakeTlsHandshake::build_client_hello(kp.public(), "test.com", 0, None);
        // The extensions should contain 0x002B (supported_versions)
        let has_sv = hello.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x2B);
        assert!(
            has_sv,
            "ClientHello must contain supported_versions extension"
        );
    }

    #[test]
    fn test_client_hello_has_psk_key_exchange() {
        let kp = Keypair::generate();
        let hello = FakeTlsHandshake::build_client_hello(kp.public(), "test.com", 0, None);
        let has_psk = hello.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x2D);
        assert!(
            has_psk,
            "ClientHello must contain psk_key_exchange_modes extension"
        );
    }

    #[test]
    fn test_client_hello_no_cca9() {
        let kp = Keypair::generate();
        let hello = FakeTlsHandshake::build_client_hello(kp.public(), "test.com", 0, None);
        // Scan ONLY the cipher_suites list, not the whole message: the 32-byte
        // client random / session_id and the random key_share would trip a
        // whole-message byte scan for 0xCCA9 ~0.1% of runs (a false flake).
        // Offset = record header (5) + handshake type(1) + len(3) + version(2)
        // + random(32) + session_id_len(1) + session_id(32) → cipher_suites length.
        let off = TLS_HEADER_SIZE + 1 + 3 + 2 + 32 + 1 + 32;
        let csl = u16::from_be_bytes([hello[off], hello[off + 1]]) as usize;
        let ciphers = &hello[off + 2..off + 2 + csl];
        let has_old_cipher = ciphers.chunks_exact(2).any(|c| c == [0xCC, 0xA9]);
        assert!(
            !has_old_cipher,
            "cipher_suites must not contain 0xCCA9 (ECDHE-ECDSA-CHACHA20-POLY1305)"
        );
    }

    #[test]
    fn test_sni_extension_format() {
        let kp = Keypair::generate();
        let hello = FakeTlsHandshake::build_client_hello(kp.public(), "www.example.com", 0, None);
        let extracted = FakeTlsHandshake::parse_client_hello(&hello).unwrap();
        assert_eq!(extracted.len(), 32);
    }

    #[test]
    fn test_padded_client_hello_meets_floor_and_parses() {
        let kp = Keypair::generate();
        let hello =
            FakeTlsHandshake::build_client_hello(kp.public(), "vpn.example.com", 1200, None);
        assert!(
            hello.len() >= 1200,
            "padded ClientHello must reach the anti-amplification floor"
        );
        // Padding lives in a real extension, so the key share still parses.
        let pub_key = FakeTlsHandshake::parse_client_hello(&hello).unwrap();
        assert_eq!(pub_key, kp.public().as_bytes());
    }

    #[test]
    fn test_client_hello_extension_order_varies() {
        // GREASE + shuffled extension order ⇒ the byte layout differs between
        // connections, so a static JA3 signature can't pin all qeli clients.
        let kp = Keypair::generate();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            let h = FakeTlsHandshake::build_client_hello(kp.public(), "x.com", 0, None);
            // key share must always be recoverable regardless of order
            assert_eq!(
                FakeTlsHandshake::parse_client_hello(&h).unwrap(),
                kp.public().as_bytes()
            );
            seen.insert(h);
        }
        assert!(
            seen.len() > 1,
            "ClientHello layout should vary across connections"
        );
    }

    #[test]
    fn test_full_handshake_roundtrip() {
        let client_kp = Keypair::generate();
        let server_kp = Keypair::generate();

        let client_hello =
            FakeTlsHandshake::build_client_hello(client_kp.public(), "vpn.example.com", 1200, None);
        let client_pub = FakeTlsHandshake::parse_client_hello(&client_hello).unwrap();
        assert_eq!(client_pub, client_kp.public().as_bytes());

        let server_hello = FakeTlsHandshake::build_server_hello(server_kp.public());
        let server_pub = FakeTlsHandshake::parse_server_hello(&server_hello).unwrap();
        assert_eq!(server_pub, server_kp.public().as_bytes());
    }

    /// Full hybrid X25519+ML-KEM handshake at the byte level (no sockets): the
    /// client keeps the ML-KEM dk, the server extracts the ek and encapsulates, the
    /// client decapsulates the ServerHello ct, and BOTH sides derive identical
    /// hybrid tunnel keys. This is the safety-net proving the PQ wire format +
    /// `derive_keys_hybrid` interoperate end-to-end.
    #[test]
    fn hybrid_handshake_roundtrip() {
        use crate::crypto::{derive_keys_hybrid, mlkem, PublicKey};

        // Client: ephemeral x25519 + a retained ML-KEM keypair (dk kept).
        let client_eph = Keypair::generate();
        let (client_hello, mlkem_dk) = FakeTlsHandshake::build_client_hello_pq(
            client_eph.public(),
            "www.microsoft.com",
            0,
            None,
        );

        // Server: recover the client x25519 AND the ML-KEM encapsulation key.
        let client_x = FakeTlsHandshake::parse_client_hello(&client_hello).unwrap();
        assert_eq!(client_x, client_eph.public().as_bytes());
        let client_ek = FakeTlsHandshake::extract_client_mlkem_ek(&client_hello).unwrap();
        assert_eq!(client_ek.len(), mlkem::MLKEM768_EK_LEN);

        // Server: encapsulate against the ek; build a hybrid ServerHello with the ct.
        let (ct, server_ml_ss) = mlkem::mlkem768_encapsulate(&client_ek).unwrap();
        let server_eph = Keypair::generate();
        let server_hello = FakeTlsHandshake::build_server_hello_pq(server_eph.public(), &ct);

        // Client: recover the server x25519 + ct, decapsulate to the ML-KEM secret.
        let (got_ct, server_x) = FakeTlsHandshake::parse_server_hello_pq(&server_hello).unwrap();
        assert_eq!(got_ct, ct, "client recovers the ML-KEM ciphertext");
        assert_eq!(
            server_x,
            *server_eph.public().as_bytes(),
            "client recovers the server x25519"
        );
        let client_ml_ss = mlkem::mlkem768_decapsulate(&mlkem_dk, &got_ct).unwrap();
        assert_eq!(client_ml_ss, server_ml_ss, "ML-KEM shared secret agrees");

        // Both sides compute the classic X25519 shared secret.
        let client_x25519 = client_eph.derive_shared(&PublicKey::from_bytes(&server_x));
        let server_x25519 = server_eph.derive_shared(&PublicKey::from_bytes(
            &<[u8; 32]>::try_from(client_x.as_slice()).unwrap(),
        ));
        assert_eq!(client_x25519.0, server_x25519.0, "X25519 agrees");

        // ...and derive identical hybrid tunnel keys.
        let ml_c: [u8; 32] = client_ml_ss.as_slice().try_into().unwrap();
        let ml_s: [u8; 32] = server_ml_ss.as_slice().try_into().unwrap();
        let client_keys = derive_keys_hybrid(&client_x25519.0, &ml_c);
        let server_keys = derive_keys_hybrid(&server_x25519.0, &ml_s);
        assert_eq!(
            client_keys, server_keys,
            "hybrid tunnel keys match end-to-end"
        );
    }
}

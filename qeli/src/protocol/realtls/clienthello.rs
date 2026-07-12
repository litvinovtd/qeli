//! M2.1 — byte-grade Chrome TLS 1.3 ClientHello + JA4 fingerprint.
//!
//! The cipher list and extension set replicate recent stable Chrome, so the
//! ClientHello's JA4 is `t13d1516h2_8daaf6152771_…` (JA4_b is the hash of
//! Chrome's exact cipher list — a version-stable byte-accuracy gate, asserted in
//! tests without needing a live capture). GREASE values and extension order vary
//! per connection (like Chrome ≥110's extension permutation); JA4 sorts, so the
//! fingerprint is stable regardless.
//!
//! The REALITY authenticator is embedded exactly as in M1: the 32-byte token
//! (`crypto::reality::seal_session_id`) is the `legacy_session_id`, and the
//! ephemeral X25519 public key is the x25519 `key_share`. The existing
//! [`crate::protocol::FakeTlsHandshake::parse_client_hello_full`] recovers both.

// M2.1 scaffolding: `build_client_hello`/`ja4` are consumed by the client
// handshake (M2.3) and the server REALITY-termination (M2.4). Until wired in,
// they're unreferenced in the non-test binary (tests exercise them fully), so
// permit dead_code at the module level; remove once `realtls::client` lands.
#![allow(dead_code)]

use crate::crypto::PublicKey;
use rand::prelude::*;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};

/// Chrome's TLS cipher suites (GREASE is prepended at build time, not listed
/// here). Order matches Chrome's ClientHello. The sorted form hashes to the
/// canonical Chrome JA4_b `8daaf6152771`.
const CHROME_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, // TLS 1.3 AES-128-GCM / AES-256-GCM / ChaCha20
    0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE AES-GCM (ECDSA/RSA)
    0xcca9, 0xcca8, // ECDHE ChaCha20 (ECDSA/RSA)
    0xc013, 0xc014, // ECDHE AES-CBC-SHA
    0x009c, 0x009d, // RSA AES-GCM
    0x002f, 0x0035, // RSA AES-CBC-SHA
];

/// A random GREASE value (RFC 8701): 0x0A0A, 0x1A1A, … 0xFAFA.
fn grease_value<R: Rng>(rng: &mut R) -> u16 {
    let b: u8 = (rng.random_range(0u8..16) << 4) | 0x0A;
    ((b as u16) << 8) | b as u16
}

fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = v as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

fn ext(buf: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    buf.extend_from_slice(&ext_type.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Build a Chrome-grade TLS 1.3 ClientHello carrying the REALITY token in
/// `legacy_session_id` and the client ephemeral in the x25519 `key_share`.
pub fn build_client_hello(
    key_public: &PublicKey,
    server_name: &str,
    session_id: &[u8; 32],
) -> (Vec<u8>, crate::crypto::mlkem::DecapKey) {
    let mut rng = rand::rng();
    // Real hybrid key exchange (L3.2): generate the ML-KEM-768 keypair and keep
    // the decapsulation key, so the client handshake can open the server's
    // ciphertext if it selects X25519MLKEM768.
    let (mlkem_dk, mlkem_ek) = crate::crypto::mlkem::mlkem768_keypair();
    let random: [u8; 32] = rng.random();
    let grease_first = grease_value(&mut rng);
    // The two GREASE *extension* values share the extension-type namespace, so
    // they must differ — otherwise the ClientHello has a duplicate extension type
    // and a strict server (rustls) rejects it. Chrome also uses distinct values.
    let grease_last = {
        let mut g = grease_value(&mut rng);
        while g == grease_first {
            g = grease_value(&mut rng);
        }
        g
    };
    let grease_cipher = grease_value(&mut rng);
    let grease_group = grease_value(&mut rng);
    let grease_version = grease_value(&mut rng);

    // ── Extensions (each a complete type|len|data record) ───────────────────
    // SNI (0x0000)
    let mut e_sni = Vec::new();
    {
        let name = server_name.as_bytes();
        let mut d = Vec::new();
        d.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // server_name_list len
        d.push(0x00); // host_name
        d.extend_from_slice(&(name.len() as u16).to_be_bytes());
        d.extend_from_slice(name);
        ext(&mut e_sni, 0x0000, &d);
    }
    // extended_master_secret (0x0017), empty
    let mut e_ems = Vec::new();
    ext(&mut e_ems, 0x0017, &[]);
    // renegotiation_info (0xff01): one length byte = 0
    let mut e_reneg = Vec::new();
    ext(&mut e_reneg, 0xff01, &[0x00]);
    // supported_groups (0x000a): GREASE, X25519MLKEM768, x25519, secp256r1, secp384r1
    let mut e_groups = Vec::new();
    {
        let mut list = Vec::new();
        list.extend_from_slice(&grease_group.to_be_bytes());
        list.extend_from_slice(&crate::crypto::mlkem::X25519MLKEM768.to_be_bytes());
        list.extend_from_slice(&0x001du16.to_be_bytes());
        list.extend_from_slice(&0x0017u16.to_be_bytes());
        list.extend_from_slice(&0x0018u16.to_be_bytes());
        let mut d = Vec::new();
        d.extend_from_slice(&(list.len() as u16).to_be_bytes());
        d.extend_from_slice(&list);
        ext(&mut e_groups, 0x000a, &d);
    }
    // ec_point_formats (0x000b): uncompressed
    let mut e_ecpf = Vec::new();
    ext(&mut e_ecpf, 0x000b, &[0x01, 0x00]);
    // session_ticket (0x0023), empty
    let mut e_ticket = Vec::new();
    ext(&mut e_ticket, 0x0023, &[]);
    // ALPN (0x0010): h2, http/1.1
    let mut e_alpn = Vec::new();
    {
        let mut list = Vec::new();
        for p in [b"h2".as_slice(), b"http/1.1".as_slice()] {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        let mut d = Vec::new();
        d.extend_from_slice(&(list.len() as u16).to_be_bytes());
        d.extend_from_slice(&list);
        ext(&mut e_alpn, 0x0010, &d);
    }
    // status_request (0x0005): OCSP, empty responder/extensions
    let mut e_status = Vec::new();
    ext(&mut e_status, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);
    // signature_algorithms (0x000d): Chrome list
    let mut e_sigalg = Vec::new();
    {
        let algs: &[u16] = &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut list = Vec::new();
        for a in algs {
            list.extend_from_slice(&a.to_be_bytes());
        }
        let mut d = Vec::new();
        d.extend_from_slice(&(list.len() as u16).to_be_bytes());
        d.extend_from_slice(&list);
        ext(&mut e_sigalg, 0x000d, &d);
    }
    // signed_certificate_timestamp (0x0012), empty
    let mut e_sct = Vec::new();
    ext(&mut e_sct, 0x0012, &[]);
    // key_share (0x0033): GREASE (1-byte), X25519MLKEM768 (1216-byte), x25519 (32-byte).
    // PQ share first like current Chrome; the server selects x25519 (no ML-KEM), so
    // the PQ key is decorative for fingerprint parity.
    let mut e_keyshare = Vec::new();
    {
        let mut pq = mlkem_ek; // ML-KEM-768 ek (1184 B)
        pq.extend_from_slice(key_public.as_bytes()); // ‖ x25519 (32 B) = 1216 B
        let mut shares = Vec::new();
        shares.extend_from_slice(&grease_group.to_be_bytes());
        shares.extend_from_slice(&0x0001u16.to_be_bytes());
        shares.push(0x00);
        shares.extend_from_slice(&crate::crypto::mlkem::X25519MLKEM768.to_be_bytes());
        shares.extend_from_slice(&(pq.len() as u16).to_be_bytes());
        shares.extend_from_slice(&pq);
        shares.extend_from_slice(&0x001du16.to_be_bytes());
        shares.extend_from_slice(&0x0020u16.to_be_bytes());
        shares.extend_from_slice(key_public.as_bytes());
        let mut d = Vec::new();
        d.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        d.extend_from_slice(&shares);
        ext(&mut e_keyshare, 0x0033, &d);
    }
    // psk_key_exchange_modes (0x002d): psk_dhe_ke
    let mut e_pskmodes = Vec::new();
    ext(&mut e_pskmodes, 0x002d, &[0x01, 0x01]);
    // supported_versions (0x002b): GREASE, TLS 1.3, TLS 1.2
    let mut e_versions = Vec::new();
    {
        let mut list = Vec::new();
        list.extend_from_slice(&grease_version.to_be_bytes());
        list.extend_from_slice(&0x0304u16.to_be_bytes());
        list.extend_from_slice(&0x0303u16.to_be_bytes());
        let mut d = Vec::new();
        d.push(list.len() as u8);
        d.extend_from_slice(&list);
        ext(&mut e_versions, 0x002b, &d);
    }
    // compress_certificate (0x001b): brotli
    let mut e_compress = Vec::new();
    ext(&mut e_compress, 0x001b, &[0x02, 0x00, 0x02]);
    // application_settings / ALPS (0x4469): h2
    let mut e_alps = Vec::new();
    {
        let mut list = Vec::new();
        list.push(2u8);
        list.extend_from_slice(b"h2");
        let mut d = Vec::new();
        d.extend_from_slice(&(list.len() as u16).to_be_bytes());
        d.extend_from_slice(&list);
        ext(&mut e_alps, 0x4469, &d);
    }

    // Chrome ≥110 permutes the middle extensions per connection. We shuffle the
    // non-boundary extensions; JA4 sorts, so the fingerprint stays stable.
    let mut middle: Vec<Vec<u8>> = vec![
        e_sni, e_ems, e_reneg, e_groups, e_ecpf, e_ticket, e_alpn, e_status, e_sigalg, e_sct,
        e_keyshare, e_pskmodes, e_versions, e_compress, e_alps,
    ];
    middle.shuffle(&mut rng);

    let mut extensions = Vec::new();
    // GREASE first (empty)
    extensions.extend_from_slice(&grease_first.to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x00]);
    for e in &middle {
        extensions.extend_from_slice(e);
    }
    // GREASE last (empty), then padding (0x0015) to a realistic size.
    extensions.extend_from_slice(&grease_last.to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x00]);
    pad_extensions(&mut extensions);

    // ── Handshake body ──────────────────────────────────────────────────────
    let mut body = Vec::new();
    body.push(0x01); // ClientHello
    body.extend_from_slice(&[0, 0, 0]); // length placeholder
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(&random);
    body.push(0x20); // session_id length 32
    body.extend_from_slice(session_id);

    // cipher_suites: GREASE + Chrome list
    let cs_bytes = 2 + CHROME_CIPHERS.len() * 2;
    body.extend_from_slice(&(cs_bytes as u16).to_be_bytes());
    body.extend_from_slice(&grease_cipher.to_be_bytes());
    for c in CHROME_CIPHERS {
        body.extend_from_slice(&c.to_be_bytes());
    }

    body.push(0x01); // compression methods length
    body.push(0x00); // null compression

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let body_len = body.len() - 4;
    body[1] = (body_len >> 16) as u8;
    body[2] = (body_len >> 8) as u8;
    body[3] = body_len as u8;

    // Wrap in a TLS record (handshake, 0x16).
    let mut record = Vec::with_capacity(5 + body.len());
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]); // record version TLS 1.0 (Chrome)
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    (record, mlkem_dk)
}

/// Pad the extensions block (RFC 7685) so the ClientHello falls in Chrome's
/// usual 512-byte handshake bucket — Chrome pads to avoid certain TLS bugs.
fn pad_extensions(extensions: &mut Vec<u8>) {
    // ClientHello fixed part before extensions: 4 (hs hdr) + 2 (ver) + 32 (rnd)
    // + 1 + 32 (sid) + 2 + 2 + CHROME_CIPHERS*2 (ciphers) + 2 (compression)
    // + 2 (ext-list len). The padding extension itself adds 4 + pad bytes.
    const FIXED: usize = 4 + 2 + 32 + 1 + 32 + 2 + 2 + 30 + 2 + 2;
    let projected = FIXED + extensions.len() + 4;
    let target: usize = 512;
    let pad = target.saturating_sub(projected);
    extensions.extend_from_slice(&[0x00, 0x15]); // padding extension
    extensions.extend_from_slice(&(pad as u16).to_be_bytes());
    extensions.extend(std::iter::repeat_n(0u8, pad));
}

// ── JA4 ─────────────────────────────────────────────────────────────────────

fn hex16(v: u16) -> String {
    format!("{:04x}", v)
}

fn sha12(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(12);
    for b in &digest[..6] {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

struct ParsedHello {
    sni: bool,
    ciphers: Vec<u16>,
    ext_types: Vec<u16>,
    alpn_first: Option<Vec<u8>>,
    sigalgs: Vec<u16>,
    max_version: u16,
}

fn parse(record: &[u8]) -> Option<ParsedHello> {
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }
    let inner = &record[5..];
    if inner.len() < 39 || inner[0] != 0x01 {
        return None;
    }
    let sid_len = inner[38] as usize;
    let mut o = 39 + sid_len;
    if o + 2 > inner.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([inner[o], inner[o + 1]]) as usize;
    o += 2;
    if o + cs_len > inner.len() {
        return None;
    }
    let mut ciphers = Vec::new();
    let mut i = 0;
    while i + 2 <= cs_len {
        ciphers.push(u16::from_be_bytes([inner[o + i], inner[o + i + 1]]));
        i += 2;
    }
    o += cs_len;
    if o + 1 > inner.len() {
        return None;
    }
    let comp_len = inner[o] as usize;
    o += 1 + comp_len;
    if o + 2 > inner.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([inner[o], inner[o + 1]]) as usize;
    o += 2;
    let ext_end = (o + ext_len).min(inner.len());

    let mut ext_types = Vec::new();
    let mut alpn_first = None;
    let mut sigalgs = Vec::new();
    let mut sni = false;
    let mut max_version = 0x0303u16;
    let mut p = o;
    while p + 4 <= ext_end {
        let et = u16::from_be_bytes([inner[p], inner[p + 1]]);
        let el = u16::from_be_bytes([inner[p + 2], inner[p + 3]]) as usize;
        p += 4;
        if p + el > ext_end {
            break;
        }
        let data = &inner[p..p + el];
        ext_types.push(et);
        match et {
            0x0000 => sni = true,
            0x0010 if data.len() >= 3 => {
                // ALPN list: list_len(2), then [len(1)+proto]...
                if data.len() >= 4 {
                    let plen = data[2] as usize;
                    if 3 + plen <= data.len() {
                        alpn_first = Some(data[3..3 + plen].to_vec());
                    }
                }
            }
            0x000d if data.len() >= 2 => {
                let ll = u16::from_be_bytes([data[0], data[1]]) as usize;
                let mut q = 2;
                while q + 2 <= 2 + ll && q + 2 <= data.len() {
                    sigalgs.push(u16::from_be_bytes([data[q], data[q + 1]]));
                    q += 2;
                }
            }
            0x002b if !data.is_empty() => {
                let ll = data[0] as usize;
                let mut q = 1;
                while q + 2 <= 1 + ll && q + 2 <= data.len() {
                    let v = u16::from_be_bytes([data[q], data[q + 1]]);
                    if !is_grease(v) && v > max_version {
                        max_version = v;
                    }
                    q += 2;
                }
            }
            _ => {}
        }
        p += el;
    }

    Some(ParsedHello {
        sni,
        ciphers,
        ext_types,
        alpn_first,
        sigalgs,
        max_version,
    })
}

/// Compute the JA4 TLS client fingerprint of a ClientHello record. Returns
/// `None` if the bytes are not a parseable ClientHello.
pub fn ja4(record: &[u8]) -> Option<String> {
    let h = parse(record)?;

    let ver = match h.max_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni = if h.sni { "d" } else { "i" };

    let ciphers_ng: Vec<u16> = h
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let exts_ng: Vec<u16> = h
        .ext_types
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();

    let alpn = match &h.alpn_first {
        Some(v) if !v.is_empty() => {
            let first = v[0] as char;
            let last = v[v.len() - 1] as char;
            format!("{}{}", first, last)
        }
        _ => "00".to_string(),
    };

    let ja4_a = format!(
        "t{}{}{:02}{:02}{}",
        ver,
        sni,
        ciphers_ng.len().min(99),
        exts_ng.len().min(99),
        alpn
    );

    // JA4_b: sorted cipher hex, comma-joined, sha256[:12].
    let mut cipher_hex: Vec<String> = ciphers_ng.iter().map(|c| hex16(*c)).collect();
    cipher_hex.sort();
    let ja4_b = sha12(&cipher_hex.join(","));

    // JA4_c: sorted extension hex (excluding SNI 0x0000 and ALPN 0x0010),
    // then "_", then signature algorithms in order. sha256[:12].
    let mut ext_hex: Vec<String> = exts_ng
        .iter()
        .filter(|e| **e != 0x0000 && **e != 0x0010)
        .map(|e| hex16(*e))
        .collect();
    ext_hex.sort();
    let sig_hex: Vec<String> = h.sigalgs.iter().map(|s| hex16(*s)).collect();
    let ja4_c = sha12(&format!("{}_{}", ext_hex.join(","), sig_hex.join(",")));

    Some(format!("{}_{}_{}", ja4_a, ja4_b, ja4_c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{reality, Keypair, StaticKeypair};
    use crate::protocol::FakeTlsHandshake;

    fn sample_hello() -> Vec<u8> {
        let reality_kp = StaticKeypair::generate();
        let eph = Keypair::generate();
        let sid = reality::seal_session_id(
            &reality_kp.public,
            &eph,
            &reality::short_id_from_hex("0123456789abcdef"),
        );
        build_client_hello(eph.public(), "www.microsoft.com", &sid).0
    }

    #[test]
    fn ja4_matches_chrome() {
        let hello = sample_hello();
        let ja4 = ja4(&hello).expect("parseable ClientHello");
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3, "JA4 has three parts: {}", ja4);
        // JA4_a: TLS 1.3, SNI=domain, 15 ciphers, 16 extensions, ALPN h2.
        assert_eq!(parts[0], "t13d1516h2", "JA4_a (full string: {})", ja4);
        // JA4_b is the hash of Chrome's exact cipher list — byte-accuracy gate.
        assert_eq!(
            parts[1], "8daaf6152771",
            "JA4_b cipher hash (full: {})",
            ja4
        );
        assert_eq!(parts[2].len(), 12, "JA4_c is 12 hex chars");
    }

    #[test]
    fn ja4_stable_across_connections() {
        // GREASE + extension permutation vary the bytes, but JA4 must be stable.
        let a = ja4(&sample_hello()).unwrap();
        let b = ja4(&sample_hello()).unwrap();
        assert_eq!(a, b, "JA4 must not vary with GREASE / extension order");
    }

    #[test]
    fn bytes_vary_across_connections() {
        // The wire bytes themselves must differ (GREASE + permutation).
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            seen.insert(sample_hello());
        }
        assert!(
            seen.len() > 1,
            "ClientHello bytes should vary per connection"
        );
    }

    #[test]
    fn reality_token_and_key_share_recoverable() {
        // The existing server-side parser must recover the embedded session_id
        // and x25519 key_share from the Chrome-grade hello.
        let reality_kp = StaticKeypair::generate();
        let eph = Keypair::generate();
        let id = reality::short_id_from_hex("0123456789abcdef");
        let sid = reality::seal_session_id(&reality_kp.public, &eph, &id);
        let hello = build_client_hello(eph.public(), "www.apple.com", &sid).0;

        let (got_sid, key_share) =
            FakeTlsHandshake::parse_client_hello_full(&hello).expect("server parses hello");
        assert_eq!(got_sid, sid, "session_id (REALITY token) recovered");
        assert_eq!(
            key_share,
            eph.public().as_bytes(),
            "x25519 key_share recovered"
        );

        // And the token opens with the matching reality key.
        let eph_pub = crate::crypto::PublicKey::from_bytes(
            &<[u8; 32]>::try_from(key_share.as_slice()).unwrap(),
        );
        assert_eq!(
            reality::open_session_id(&reality_kp, &eph_pub, &got_sid, 120).unwrap(),
            id
        );
    }

    #[test]
    fn pq_key_share_present() {
        // The Chrome-grade hello carries the X25519MLKEM768 share (group 0x11ec,
        // key length 1216 = 0x04c0), and the x25519 key_share is still recoverable.
        let hello = sample_hello();
        assert!(
            hello.windows(4).any(|w| w == [0x11, 0xEC, 0x04, 0xC0]),
            "hello must carry X25519MLKEM768 (0x11ec, 1216 B)"
        );
        let (_sid, ks) = FakeTlsHandshake::parse_client_hello_full(&hello).unwrap();
        assert_eq!(
            ks.len(),
            32,
            "x25519 key_share recovered despite the PQ entry"
        );
    }

    #[test]
    fn hello_is_well_formed_record() {
        let hello = sample_hello();
        assert_eq!(hello[0], 0x16, "TLS handshake record");
        let rec_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + rec_len, "record length matches");
        assert_eq!(hello[5], 0x01, "ClientHello handshake type");
    }
}

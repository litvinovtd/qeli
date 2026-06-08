//! Live realtls ServerHello probe (L3.5).
//!
//! Sends a genuine realtls ClientHello (Chrome-grade, REALITY token sealed into
//! the session_id, X25519 + X25519MLKEM768 key_shares) to a qeli server running
//! the hand-rolled REALITY terminator (`reality_proxy.handrolled = true`), reads
//! the ServerHello it sends back, and prints its JA3S inputs — TLS version,
//! cipher suite and the extension-type list — so they can be compared against the
//! borrowed target (e.g. `openssl s_client -trace www.microsoft.com:443`).
//!
//! Usage: realtls_probe <host:port> <reality_pub_hex> <short_id_hex> <sni>

use qeli::crypto::reality::{seal_session_id, short_id_from_hex};
use qeli::crypto::{Keypair, PublicKey};
use qeli::protocol::realtls::clienthello::build_client_hello;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn hex32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .filter_map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect();
    let mut out = [0u8; 32];
    assert!(bytes.len() >= 32, "reality_pub_hex must be 64 hex chars");
    out.copy_from_slice(&bytes[..32]);
    out
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 5 {
        eprintln!("usage: realtls_probe <host:port> <reality_pub_hex> <short_id_hex> <sni>");
        std::process::exit(2);
    }
    let (addr, pub_hex, short_hex, sni) = (&a[1], &a[2], &a[3], &a[4]);

    let reality_pub = PublicKey::from_bytes(&hex32(pub_hex));
    let eph = Keypair::generate();
    let sid = seal_session_id(&reality_pub, &eph, &short_id_from_hex(short_hex));
    let (ch, _dk) = build_client_hello(eph.public(), sni, &sid);
    println!("sent realtls ClientHello: {} bytes (sni={sni})", ch.len());

    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(&ch).expect("write ClientHello");
    s.flush().ok();

    // Read the first TLS record — the ServerHello.
    let mut hdr = [0u8; 5];
    if let Err(e) = s.read_exact(&mut hdr) {
        println!("no ServerHello (read error: {e}) — server rejected us?");
        return;
    }
    if hdr[0] != 0x16 {
        println!("first record is not handshake (type 0x{:02x})", hdr[0]);
        return;
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut m = vec![0u8; len];
    s.read_exact(&mut m).expect("read ServerHello body");
    print_serverhello_ja3s(&m);
}

/// Parse a ServerHello handshake message and print its JA3S inputs.
fn print_serverhello_ja3s(m: &[u8]) {
    if m.len() < 39 || m[0] != 0x02 {
        println!(
            "not a ServerHello (type 0x{:02x})",
            m.first().copied().unwrap_or(0)
        );
        return;
    }
    let version = u16::from_be_bytes([m[4], m[5]]); // legacy_version
    let sid_len = m[38] as usize;
    let mut o = 39 + sid_len;
    let cipher = u16::from_be_bytes([m[o], m[o + 1]]);
    o += 3; // cipher_suite(2) + legacy_compression(1)
    let ext_len = u16::from_be_bytes([m[o], m[o + 1]]) as usize;
    o += 2;
    let end = (o + ext_len).min(m.len());
    let mut exts = Vec::new();
    while o + 4 <= end {
        let et = u16::from_be_bytes([m[o], m[o + 1]]);
        let el = u16::from_be_bytes([m[o + 2], m[o + 3]]) as usize;
        exts.push(et);
        o += 4 + el;
    }
    let ext_dec: Vec<String> = exts.iter().map(|e| e.to_string()).collect();
    println!(
        "ServerHello: version=0x{version:04x} cipher=0x{cipher:04x} extensions={:?}",
        exts.iter()
            .map(|e| format!("0x{e:04x}"))
            .collect::<Vec<_>>()
    );
    // JA3S string = SSLVersion,Cipher,Extensions (all decimal; '-'-joined exts).
    println!("JA3S = {},{},{}", version, cipher, ext_dec.join("-"));
}

//! Live REALITY anti-replay probe (hardening step P1).
//!
//! Seals ONE valid qeli REALITY token into a browser-like ClientHello and sends
//! the *identical bytes* to a running server twice, on separate connections. With
//! the replay guard active the server must treat the first sighting as a qeli
//! client (terminate TLS) and the verbatim replay as a probe (bridge to the real
//! target). Watch the server log for, in order:
//!
//!   REALITY: Qeli client detected ...
//!   REALITY: replayed session_id ... bridging as probe
//!
//! Without the guard, both connections log "Qeli client detected" — that is the
//! exact leak this step closes.
//!
//! Usage: replay_probe <host:port> <reality_pub_hex> <short_id_hex> <sni>

use qeli::crypto::reality::{seal_session_id, short_id_from_hex};
use qeli::crypto::{Keypair, PublicKey};
use qeli::protocol::FakeTlsHandshake;
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
        eprintln!("usage: replay_probe <host:port> <reality_pub_hex> <short_id_hex> <sni>");
        std::process::exit(2);
    }
    let (addr, pub_hex, short_hex, sni) = (&a[1], &a[2], &a[3], &a[4]);

    // Build one valid sealed ClientHello, reused verbatim for both sends.
    let reality_pub = PublicKey::from_bytes(&hex32(pub_hex));
    let eph = Keypair::generate();
    let sid = seal_session_id(&reality_pub, &eph, &short_id_from_hex(short_hex));
    let ch = FakeTlsHandshake::build_client_hello(eph.public(), sni, 0, Some(&sid));
    println!(
        "built sealed ClientHello: {} bytes (short_id={}, sni={})",
        ch.len(),
        short_hex,
        sni
    );

    for label in [
        "FIRST  (expect server log: 'Qeli client detected')",
        "REPLAY (expect server log: 'replayed session_id ... bridging as probe')",
    ] {
        match TcpStream::connect(addr) {
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(4)));
                s.write_all(&ch).expect("write ClientHello");
                s.flush().ok();
                let mut buf = [0u8; 16];
                let n = s.read(&mut buf).unwrap_or(0);
                println!(
                    "[{}] sent {} bytes, server replied {} bytes (head={:02x?})",
                    label,
                    ch.len(),
                    n,
                    &buf[..n.min(8)]
                );
            }
            Err(e) => println!("[{}] connect failed: {}", label, e),
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    println!("done — inspect the server log for the two REALITY lines above");
}

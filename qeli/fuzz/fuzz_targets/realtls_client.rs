//! Complete and malformed ServerHello through the public sans-IO state machine.
#![no_main]
use libfuzzer_sys::fuzz_target;
use qeli_core::crypto::PublicKey;
use qeli_core::protocol::realtls::sansio::SansIoClient;

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0);
    let (mut client, hello) =
        SansIoClient::new(&PublicKey::from_bytes(&[9; 32]), &[0; 8], "example.com");
    let mut body = vec![3, 3];
    body.extend([7; 32]);
    body.push(32);
    body.extend(&hello[44..76]);
    body.extend([0x13, if selector & 1 == 0 { 1 } else { 2 }, 0]);
    let mut extensions = vec![0, 0x2b, 0, 2, 3, 4, 0, 0x33, 0, 36, 0, 0x1d, 0, 32];
    let mut key = [7; 32];
    for (to, from) in key.iter_mut().zip(data.get(1..).unwrap_or_default()) {
        *to = *from;
    }
    extensions.extend(key);
    match (selector >> 1) & 7 {
        1 => extensions.extend([0, 0x2b, 0, 2, 3, 4]),
        2 => extensions.push(0xff),
        3 => extensions.truncate(extensions.len().saturating_sub(1)),
        4 => body[37] ^= 1, // mismatched session ID echo
        5 => body[1] = 1,
        6 => body[69] = 1, // compression
        7 => {
            extensions = data
                .get(1..)
                .unwrap_or_default()
                .iter()
                .copied()
                .take(16300)
                .collect()
        }
        _ => {}
    }
    body.extend((extensions.len() as u16).to_be_bytes());
    body.extend(extensions);
    let n = body.len();
    let mut hs = vec![2, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    hs.extend(body);
    let mut record = vec![0x16, 3, 3];
    record.extend((hs.len() as u16).to_be_bytes());
    record.extend(hs);
    let chunk = 1 + usize::from(selector % 31);
    for fragment in record.chunks(chunk) {
        if client.recv(fragment).is_err() {
            assert!(!client.established());
            assert!(client.seal(b"x").is_err());
            break;
        }
    }
});

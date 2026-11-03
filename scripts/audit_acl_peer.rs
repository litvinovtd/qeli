//! Private session-lifecycle peer with valid PQ, pin proof and authenticated records.
//! The identity path must belong to the fresh fixture, never a running installation.
use anyhow::{ensure, Context, Result};
use qeli_core::crypto::{self, Keypair, PublicKey, StaticKeypair};
use qeli_core::protocol::{capabilities, udp_frag, FakeTlsHandshake, PacketCodec};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

enum Wire {
    Tcp(TcpStream),
    Udp(UdpSocket, bool, u32),
}
impl Wire {
    fn send(&mut self, data: &[u8], hello: bool) -> Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(data)?,
            Self::Udp(socket, quic, pn) => {
                let packets = if hello {
                    udp_frag::fragment(udp_frag::MSG_CLIENT_HELLO, data)
                        .map_err(anyhow::Error::msg)?
                } else {
                    vec![data.to_vec()]
                };
                for packet in packets {
                    let wire = if *quic {
                        let output = if hello {
                            qeli_core::protocol::wrap_quic_long(&packet, &[3; 4], *pn)
                        } else {
                            qeli_core::protocol::wrap_quic_short(&packet, &[3; 4], *pn)
                        };
                        *pn += 1;
                        output
                    } else {
                        packet
                    };
                    ensure!(socket.send(&wire)? == wire.len(), "short datagram");
                }
            }
        }
        Ok(())
    }
    fn receive(&mut self) -> Result<Vec<u8>> {
        match self {
            Self::Tcp(stream) => {
                let mut header = [0; 5];
                stream.read_exact(&mut header)?;
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                ensure!(
                    length <= qeli_core::protocol::packet::MAX_RECORD_SIZE,
                    "oversized peer record"
                );
                let mut bytes = header.to_vec();
                bytes.resize(5 + length, 0);
                stream.read_exact(&mut bytes[5..])?;
                Ok(bytes)
            }
            Self::Udp(socket, quic, _) => {
                let mut fragments = udp_frag::Reassembler::new();
                let mut buffer = [0; 65535];
                loop {
                    let length = socket.recv(&mut buffer)?;
                    let bytes = if *quic {
                        qeli_core::protocol::unwrap_quic(&buffer[..length])
                            .map_err(|_| anyhow::anyhow!("invalid QUIC envelope"))?
                            .payload
                    } else {
                        buffer[..length].to_vec()
                    };
                    if udp_frag::is_fragment(&bytes) {
                        if let Some(complete) =
                            fragments.push(&bytes).map_err(anyhow::Error::msg)?
                        {
                            return Ok(complete);
                        }
                    } else {
                        return Ok(bytes);
                    }
                }
            }
        }
    }
}
fn records(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 5, "short record header");
        let length = 5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        ensure!(length <= bytes.len(), "short record body");
        result.push(bytes[..length].to_vec());
        bytes = &bytes[length..];
    }
    Ok(result)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 7,
        "usage: peer tcp|udp|quic endpoint fixture-identity-key user device command"
    );
    ensure!(args[6] == "command", "peer mode");
    let timeout = Some(Duration::from_secs(2));
    let mut wire = if args[1] == "tcp" {
        let stream = TcpStream::connect(&args[2])?;
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        Wire::Tcp(stream)
    } else {
        ensure!(args[1] == "udp" || args[1] == "quic", "transport");
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(&args[2])?;
        socket.set_read_timeout(timeout)?;
        socket.set_write_timeout(timeout)?;
        Wire::Udp(socket, args[1] == "quic", 0)
    };
    let key: [u8; 32] = std::fs::read(&args[3])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid fixture identity"))?;
    let pin = StaticKeypair::from_private_bytes(key)
        .public
        .as_bytes()
        .to_owned();
    let client = Keypair::generate();
    let (hello, dk) =
        FakeTlsHandshake::build_client_hello_pq(client.public(), "example.com", 0, None);
    wire.send(&hello, true)?;
    let flight = if matches!(wire, Wire::Tcp(_)) {
        let mut flight = Vec::new();
        for _ in 0..6 {
            flight.push(wire.receive()?)
        }
        flight
    } else {
        records(&wire.receive()?)?
    };
    ensure!(flight.len() == 6, "complete server flight");
    let (ct, ephemeral) =
        FakeTlsHandshake::parse_server_hello_pq(&flight[0]).context("PQ server hello")?;
    let shared = client
        .derive_shared_checked(&PublicKey::from_bytes(&ephemeral))
        .context("low-order server key")?;
    let pq = crypto::mlkem::mlkem768_decapsulate(&dk, &ct).context("decapsulation")?;
    let pq: [u8; 32] = pq.as_slice().try_into()?;
    let (down, up) = crypto::derive_keys_hybrid(&shared.0, &pq);
    let mut rx = PacketCodec::new(down);
    let mut tx = PacketCodec::new(up);
    let transcript =
        crypto::handshake_transcript_hash(&[&hello, &flight[0], &flight[2], &flight[3]]);
    let static_shared = client
        .derive_shared_checked(&PublicKey::from_bytes(&pin))
        .context("fixture pin")?;
    let proof = rx.decrypt_packet(&flight[5])?;
    let (prefix, advertised) = capabilities::split_server_capabilities(&proof)?;
    ensure!(
        prefix.len() == 32
            && crypto::auth::ct_eq(
                prefix,
                &crypto::compute_auth_proof(&static_shared.0, &shared.0, &transcript)
            ),
        "server proof invalid"
    );
    ensure!(
        advertised.is_some_and(|caps| caps.contains(capabilities::server_capability::AUTH_EXT_V1)),
        "extension not advertised"
    );
    let mut auth =
        crypto::compute_client_key_proof(&static_shared.0, &shared.0, &transcript).to_vec();
    auth.push(0);
    auth.extend_from_slice(&[args[5].parse::<u8>()?; 16]);
    capabilities::append_client_capabilities(
        &mut auth,
        capabilities::ClientCapabilities {
            core_bits: capabilities::client_capability::INNER_IPV6
                | capabilities::client_capability::NETWORK_PLAN_V2
                | capabilities::client_capability::UDP_DATA_FRAG_V1,
            platform_bits: qeli_core::transport_core::platform_capability::IPV6_TUN
                | qeli_core::transport_core::platform_capability::IPV6_ROUTES
                | qeli_core::transport_core::platform_capability::IPV6_DNS,
            ..capabilities::ClientCapabilities::default()
        },
    );
    auth.extend_from_slice(format!("{}:fixture-password", args[4]).as_bytes());
    wire.send(&tx.encrypt_packet(&auth, &[])?, false)?;
    let response = match wire.receive() {
        Ok(bytes) => Some(String::from_utf8(rx.decrypt_packet(&bytes)?)?),
        Err(error)
            if error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                )
            }) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let info: serde_json::Value = response.as_ref().filter(|t|t.starts_with("OK:")).map(|t|serde_json::from_str(&t[3..])).transpose()?.unwrap_or(serde_json::Value::Null);
    println!("{}", serde_json::json!({"accepted":!info.is_null(),"server_proof_verified":true,"addresses":info["addresses"],"routes":info["routes"]}));
    std::io::stdout().flush()?;
    if info.is_null() { return Ok(()); }
    match &wire { Wire::Tcp(s)=>s.set_read_timeout(Some(Duration::from_millis(300)))?,Wire::Udp(s,_,_)=>s.set_read_timeout(Some(Duration::from_millis(300)))? };
    use std::io::BufRead;
    for line in std::io::stdin().lock().lines() {
        let line=line?;
        if let Some(hex)=line.strip_prefix("SEND ") {
            ensure!(hex.len()%2==0,"hex length");
            let packet:Vec<u8>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16)).collect::<std::result::Result<_,_>>()?;
            wire.send(&tx.encrypt_packet(&packet,&[])?,false)?;
            println!("{}",serde_json::json!({"sent":packet.len()}));
        } else if line=="RECV" {
            let until=std::time::Instant::now()+Duration::from_millis(1200);
            let mut found=None;
            while std::time::Instant::now()<until {
                match wire.receive() {
                    Ok(bytes)=>{let packet=rx.decrypt_packet(&bytes)?;if packet.ends_with(b"Q16UP!") && ((packet.first().is_some_and(|b|b>>4==4) && packet.get(9)==Some(&17)) || (packet.first().is_some_and(|b|b>>4==6) && packet.get(6)==Some(&17))) {found=Some(packet.iter().map(|b|format!("{b:02x}")).collect::<String>());break;}},
                    Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|x|matches!(x.kind(),std::io::ErrorKind::TimedOut|std::io::ErrorKind::WouldBlock))=>{},
                    Err(e)=>return Err(e),
                }
            }
            println!("{}",serde_json::json!({"packet":found}));
        } else {ensure!(line=="STOP","command");break;}
        std::io::stdout().flush()?;
    }
    Ok(())
}

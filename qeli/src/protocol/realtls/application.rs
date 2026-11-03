//! Shared established TLS record policy for async and sans-IO transports.
use std::io;

/// A bounded handshake accumulator. Tickets are ignored, but their framing may
/// span records. KeyUpdate is unsupported and must terminate this key epoch.
#[derive(Default)]
pub(crate) struct ApplicationRecords {
    handshake: Vec<u8>,
    pub(crate) peer_closed: bool,
    failure: Option<(io::ErrorKind, String)>,
}

const MAX_POST_HANDSHAKE_BODY: usize = 128 * 1024;

impl ApplicationRecords {
    pub(crate) fn error(&self) -> Option<io::Error> {
        self.failure
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }

    pub(crate) fn fail(&mut self, error: io::Error) {
        if self.failure.is_none() {
            self.failure = Some((error.kind(), error.to_string()));
        }
        self.handshake.clear();
    }

    pub(crate) fn accept(&mut self, kind: u8, plaintext: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        if kind != 0x16 && !self.handshake.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "interleaved incomplete TLS handshake message",
            ));
        }
        match kind {
            0x17 => Ok(Some(plaintext)),
            0x16 => {
                // A record carries at most 16 KiB, and the length is checked as
                // soon as its four-byte header is available, before buffering a body.
                self.handshake.extend_from_slice(&plaintext);
                let mut consumed = 0;
                while self.handshake.len() - consumed >= 4 {
                    let msg = &self.handshake[consumed..];
                    match msg[0] {
                        4 => {}, // NewSessionTicket; session resumption is not implemented.
                        0x18 => return Err(io::Error::new(io::ErrorKind::Unsupported,
                            "TLS KeyUpdate is not supported; reconnecting before record keys diverge")),
                        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected TLS post-handshake message")),
                    }
                    let len = (usize::from(msg[1]) << 16)
                        | (usize::from(msg[2]) << 8)
                        | usize::from(msg[3]);
                    if len > MAX_POST_HANDSHAKE_BODY {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TLS post-handshake message exceeds buffer cap",
                        ));
                    }
                    if msg.len() < 4 + len {
                        break;
                    }
                    consumed += 4 + len;
                }
                self.handshake.drain(..consumed);
                Ok(None)
            }
            0x15 if plaintext.len() == 2 && plaintext[1] == 0 => {
                self.peer_closed = true;
                Ok(None)
            }
            0x15 => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!(
                    "TLS peer sent alert {}",
                    plaintext.get(1).copied().unwrap_or(0xff)
                ),
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected TLS inner content type",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q11_post_handshake_bounds_and_interleaving() {
        let mut state = ApplicationRecords::default();
        assert!(state.accept(0x16, vec![4, 0, 0]).is_ok());
        assert!(state.accept(0x17, b"interleaved".to_vec()).is_err());
        let mut state = ApplicationRecords::default();
        assert!(state.accept(0x16, vec![4, 0xff, 0xff, 0xff]).is_err());
        assert_eq!(
            state.handshake.len(),
            4,
            "oversized body must not be accumulated"
        );
        let mut state = ApplicationRecords::default();
        for fragment in [vec![4], vec![0, 0], vec![0, 4, 0, 0, 0]] {
            state.accept(0x16, fragment).unwrap();
        }
        assert!(
            state.handshake.is_empty(),
            "multiple fragmented messages drained"
        );
    }
}

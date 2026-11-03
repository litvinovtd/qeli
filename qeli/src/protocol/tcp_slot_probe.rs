//! Bounded TCP downlink probe, carried only inside an authenticated resume.
use crate::protocol::control_v2;
#[cfg(all(feature = "server", target_os = "linux"))]
use crate::protocol::control_v2::Frame;
use crate::protocol::stream_io::WriteAllFlush;
use crate::protocol::{read_record, Framing, PacketCodec};
use tokio::io::{AsyncRead, AsyncWrite};

const REQUEST_TYPE: u8 = 0x28;
const PROBE: &[u8] = b"QELI-TCP-SLOT-PROBE";
pub(crate) const CHUNK: usize = 1024;
pub(crate) const CHUNKS: usize = 256;
pub(crate) const BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) slot: u32,
    pub(crate) nonce: u64,
}

impl Request {
    #[cfg(all(feature = "server", target_os = "linux"))]
    pub(crate) fn encode(self) -> anyhow::Result<Vec<u8>> {
        let mut payload = [0; 12];
        payload[..4].copy_from_slice(&self.slot.to_be_bytes());
        payload[4..].copy_from_slice(&self.nonce.to_be_bytes());
        Ok(Frame {
            message_type: REQUEST_TYPE,
            flags: 0,
            message_id: 0,
            part_index: 0,
            part_count: 1,
            payload: &payload,
        }
        .encode()?)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let frame = control_v2::decode(bytes).ok()?;
        if frame.message_type != REQUEST_TYPE || frame.part_count != 1 || frame.flags != 0 {
            return None;
        }
        let payload: &[u8; 12] = frame.payload.try_into().ok()?;
        Some(Self {
            slot: u32::from_be_bytes(payload[..4].try_into().ok()?),
            nonce: u64::from_be_bytes(payload[4..].try_into().ok()?),
        })
    }

    pub(crate) fn probe_message(self) -> Vec<u8> {
        let mut result = PROBE.to_vec();
        result.extend_from_slice(&self.nonce.to_be_bytes());
        result
    }
}

#[cfg(all(feature = "server", target_os = "linux"))]
pub(crate) fn probe_nonce(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(
        bytes.strip_prefix(PROBE)?.try_into().ok()?,
    ))
}

pub(crate) async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    framing: Framing,
    tx: &mut PacketCodec,
    rx: &mut PacketCodec,
    request: Request,
) -> anyhow::Result<()> {
    stream
        .write_all_flush(&tx.encrypt_packet(&request.probe_message(), &[])?)
        .await?;
    let mut receipt = Vec::new();
    for _ in 0..CHUNKS {
        let bytes = rx.decrypt_packet(&read_record(stream, framing).await?)?;
        if bytes.len() != CHUNK {
            anyhow::bail!("invalid TCP slot probe record size");
        }
        receipt = bytes;
    }
    stream
        .write_all_flush(&tx.encrypt_packet(&receipt[..16], &[])?)
        .await?;
    Ok(())
}

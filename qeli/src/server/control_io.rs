//! Bounded single-line control protocol. JSON here is an API envelope, not a config format.
use std::io;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

pub(crate) const MAX_REQUEST: usize = 64 * 1024;
pub(crate) const MAX_RESPONSE: usize = 8 * 1024 * 1024;
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) async fn read_line<R: AsyncRead + Unpin>(
    reader: R,
    limit: usize,
    deadline: Duration,
) -> io::Result<Option<String>> {
    // Two bytes of lookahead distinguish an exact-size payload + CRLF from
    // overflow. Take(limit) alone manufactures EOF and can accept a valid prefix.
    let mut reader = BufReader::new(reader.take(limit.saturating_add(2) as u64));
    let mut bytes = Vec::new();
    let n = tokio::time::timeout(deadline, reader.read_until(b'\n', &mut bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control read timed out"))??;
    if n == 0 {
        return Ok(None);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame exceeds size limit",
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(crate) async fn write_line<W: AsyncWrite + Unpin>(
    mut writer: W,
    line: &str,
    limit: usize,
    deadline: Duration,
) -> io::Result<()> {
    if line.len() > limit || line.contains(['\n', '\r']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid control frame size or newline",
        ));
    }
    tokio::time::timeout(deadline, async {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control write timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_valid_json_prefix_followed_by_oversized_input() {
        let prefix = br#"{"cmd":"kick","username":"alice"}"#;
        let mut input = prefix.to_vec();
        input.extend_from_slice(b"not part of that command\n");
        let error = read_line(input.as_slice(), prefix.len(), IO_TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn exact_limit_lf_crlf_and_eof_roundtrip() {
        for suffix in ["\n", "\r\n", ""] {
            let input = format!("abcd{suffix}");
            assert_eq!(
                read_line(input.as_bytes(), 4, IO_TIMEOUT).await.unwrap(),
                Some("abcd".into())
            );
        }
        assert_eq!(read_line(&b""[..], 4, IO_TIMEOUT).await.unwrap(), None);
        assert_eq!(
            read_line(&b"\n"[..], 4, IO_TIMEOUT).await.unwrap(),
            Some(String::new())
        );
    }

    #[tokio::test]
    async fn rejects_overflow_and_invalid_utf8() {
        for input in [
            &b"abcde\n"[..],
            &b"abcde"[..],
            &b"abcd\r"[..],
            &b"\xff\n"[..],
        ] {
            assert_eq!(
                read_line(input, 4, IO_TIMEOUT).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn reads_complete_response_without_waiting_for_eof() {
        let (mut peer, stream) = tokio::io::duplex(128);
        peer.write_all(b"{\"ok\":true}\n").await.unwrap();
        assert_eq!(
            read_line(stream, MAX_RESPONSE, RESPONSE_TIMEOUT)
                .await
                .unwrap()
                .unwrap(),
            "{\"ok\":true}"
        );
    }

    #[tokio::test]
    async fn silent_peer_has_read_deadline() {
        let (_peer, stream) = tokio::io::duplex(1);
        assert_eq!(
            read_line(stream, MAX_REQUEST, Duration::from_millis(20))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn stalled_reader_has_write_deadline() {
        let (_peer, stream) = tokio::io::duplex(1);
        assert_eq!(
            write_line(stream, "abcd", MAX_REQUEST, Duration::from_millis(20))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn outbound_size_and_framing_are_checked_before_write() {
        for line in ["abcde", "a\nb", "a\rb"] {
            assert_eq!(
                write_line(tokio::io::sink(), line, 4, IO_TIMEOUT)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let mut output = Vec::new();
        write_line(&mut output, "abcd", 4, IO_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(output, b"abcd\n");
    }
}

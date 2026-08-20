use rand::prelude::*;

pub struct Obfuscator {
    rng: rand::rngs::ThreadRng,
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl Obfuscator {
    pub fn new() -> Self {
        Obfuscator { rng: rand::rng() }
    }

    /// Random padding bytes, `min..=max` of them.
    ///
    /// `randomize` in `generate_padding_opts` selects the *length* policy — the CONTENT
    /// is always random. Both fixed-length paths used to return `vec![0u8; n]`, and the
    /// equal-bounds call `generate_padding(n, n)` is what most callers actually use
    /// (cover traffic in `handler.rs`/`udp_handler.rs`, size normalisation in
    /// `client/mod.rs`), so in practice nearly all padding this project emitted was a run
    /// of zero bytes. That is invisible today because padding travels inside the AEAD
    /// record — but the name and the doc promise otherwise, and any future caller that
    /// emits padding outside the AEAD would inherit a perfect distinguisher.
    /// (Audit 2026-07-27, E8.)
    pub fn generate_padding(&mut self, min: u16, max: u16) -> Vec<u8> {
        let mut out = Vec::new();
        self.generate_padding_into(min, max, &mut out);
        out
    }

    /// Caller-owned variant of [`Self::generate_padding`].
    pub fn generate_padding_into(&mut self, min: u16, max: u16, out: &mut Vec<u8>) {
        let len = if max <= min {
            min
        } else {
            self.rng.random_range(min..=max)
        };
        out.clear();
        out.resize(len as usize, 0);
        self.rng.fill_bytes(out);
    }

    /// Padding that honours the full PaddingConfig contract:
    ///   * `enabled == false`            → no padding;
    ///   * `probability < 1.0`           → padded only with that probability;
    ///   * `randomize == false`          → fixed `min` bytes;
    ///   * otherwise                     → random length in `[min, max]`.
    ///
    /// (Previously `probability`, `randomize` and `enabled` were silently
    /// ignored and every packet was padded.) `max` is the caller's effective
    /// cap — callers clamp it to fit under the UDP path MTU.
    pub fn generate_padding_opts(
        &mut self,
        enabled: bool,
        min: u16,
        max: u16,
        randomize: bool,
        probability: f64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        self.generate_padding_opts_into(enabled, min, max, randomize, probability, &mut out);
        out
    }

    /// Caller-owned variant of [`Self::generate_padding_opts`]. Disabled/probability-miss
    /// branches clear stale output while retaining its allocation.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_padding_opts_into(
        &mut self,
        enabled: bool,
        min: u16,
        max: u16,
        randomize: bool,
        probability: f64,
        out: &mut Vec<u8>,
    ) {
        out.clear();
        if !enabled || max == 0 {
            return;
        }
        if probability < 1.0 && self.rng.random::<f64>() > probability {
            return;
        }
        let min = min.min(max);
        if randomize {
            self.generate_padding_into(min, max, out);
        } else {
            // Fixed LENGTH, still random content — see generate_padding's note.
            self.generate_padding_into(min, min, out);
        }
    }

    /// Split `data` into randomly-sized chunks, at most `max_fragments` of them,
    /// each `min_chunk..=max_chunk` bytes (the last one absorbs any remainder).
    ///
    /// Fragmenting is NOT decided here — the caller gates it on
    /// `obf.fragmentation.enabled`. It used to roll a 30% die internally, which
    /// meant an operator who explicitly turned fragmentation on got it seven
    /// times out of ten anyway; for the handshake record that is the difference
    /// between breaking a DPI signature and mostly not.
    pub fn fragment_packet(
        &mut self,
        data: &[u8],
        min_chunk: u16,
        max_chunk: u16,
        max_fragments: u16,
    ) -> Vec<Vec<u8>> {
        let max_frags = max_fragments as usize;
        if max_frags == 0 {
            return vec![data.to_vec()];
        }

        let min_chunk_size = min_chunk as usize;
        let max_chunk_size = max_chunk as usize;

        if data.len() <= min_chunk_size {
            return vec![data.to_vec()];
        }

        let optimal_chunk = data.len().div_ceil(max_frags);
        let chunk_size = optimal_chunk.max(min_chunk_size).min(max_chunk_size);

        let mut fragments = Vec::new();
        let mut offset = 0;

        while offset < data.len() && fragments.len() < max_frags {
            let remaining = data.len() - offset;
            let current_chunk = if fragments.len() == max_frags - 1 {
                remaining
            } else {
                let upper = chunk_size.min(remaining);
                let size = if min_chunk_size >= upper {
                    // Empty/inverted range — gen_range(a..=b) panics when a > b.
                    // Fall back to the lower bound (clamped to what remains).
                    min_chunk_size
                } else {
                    self.rng.random_range(min_chunk_size..=upper)
                };
                size.min(remaining)
            };

            fragments.push(data[offset..offset + current_chunk].to_vec());
            offset += current_chunk;
        }

        if offset < data.len() {
            if let Some(last) = fragments.last_mut() {
                last.extend_from_slice(&data[offset..]);
            }
        }

        fragments
    }

    /// Number of AEAD padding bytes needed to round a payload up to the next configured
    /// size, never past `max_len`.
    ///
    /// Normalization MUST NOT append bytes to an already formed IP datagram: doing so makes
    /// the IPv4 total-length / IPv6 payload-length field disagree with the record returned by
    /// decryption. The bytes therefore travel in PacketCodec's authenticated padding region
    /// and are stripped before the inner packet reaches TUN or any packet parser.
    pub fn normalization_padding_len(
        data_len: usize,
        round_sizes: &[u16],
        max_len: usize,
    ) -> usize {
        for &size in round_sizes {
            let size = size as usize;
            if size > max_len {
                continue;
            }
            if data_len <= size {
                return size - data_len;
            }
        }
        0
    }

    /// Append random normalization bytes to an existing AEAD padding buffer.
    pub fn append_normalization_padding_into(
        &mut self,
        data_len: usize,
        round_sizes: &[u16],
        max_len: usize,
        out: &mut Vec<u8>,
    ) {
        let count = Self::normalization_padding_len(data_len, round_sizes, max_len);
        if count != 0 {
            let start = out.len();
            out.resize(start + count, 0);
            self.rng.fill_bytes(&mut out[start..]);
        }
    }

    // NOTE: a `generate_heartbeat` helper used to live here, emitting a TLS record with
    // content type 0x18 (Heartbeat, RFC 6520) full of random cleartext. It had no callers
    // — and it must not acquire any. TLS 1.3 does not use heartbeats, and qeli's
    // ClientHello never negotiates the heartbeat extension, so an unsolicited 0x18 record
    // after the ServerHello would identify the flow immediately: the exact opposite of
    // what this module exists for. Dead code shaped like a feature invites someone to
    // "finally wire it up", so it is gone. The tunnel's real heartbeat is an EMPTY AEAD
    // record scheduled by `Shaper`. (Audit 2026-07-27, X2.)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_respects_bounds() {
        let mut obf = Obfuscator::new();
        for _ in 0..100 {
            let padding = obf.generate_padding(10, 50);
            assert!(padding.len() >= 10);
            assert!(padding.len() <= 50);
        }
    }

    #[test]
    fn test_padding_exact_when_min_equals_max() {
        let mut obf = Obfuscator::new();
        for _ in 0..20 {
            let padding = obf.generate_padding(64, 64);
            assert_eq!(padding.len(), 64);
        }
    }

    #[test]
    fn test_padding_empty_when_zero() {
        let mut obf = Obfuscator::new();
        let padding = obf.generate_padding(0, 0);
        assert!(padding.is_empty());
    }

    /// Fixed-LENGTH padding must still carry random CONTENT. The equal-bounds call is
    /// the one nearly every caller uses (cover traffic, size normalisation), and it used
    /// to return a run of zero bytes. (Audit 2026-07-27, E8.)
    #[test]
    fn test_fixed_length_padding_is_not_all_zero() {
        let mut obf = Obfuscator::new();
        // 64 bytes of CSPRNG output being all-zero has probability 2^-512.
        let padding = obf.generate_padding(64, 64);
        assert_eq!(padding.len(), 64);
        assert!(
            padding.iter().any(|&b| b != 0),
            "fixed-length padding must be random, not a zero run"
        );

        // Same for the randomize=false branch of the opts API.
        let fixed = obf.generate_padding_opts(true, 64, 64, false, 1.0);
        assert_eq!(fixed.len(), 64);
        assert!(
            fixed.iter().any(|&b| b != 0),
            "randomize=false selects a fixed length, not zero content"
        );

        // Two draws of the same length must differ.
        let a = obf.generate_padding(32, 32);
        let b = obf.generate_padding(32, 32);
        assert_ne!(a, b, "padding must not be deterministic");
    }

    #[test]
    fn caller_owned_padding_reuses_and_clears_storage() {
        let mut obf = Obfuscator::new();
        let mut padding = Vec::with_capacity(256);
        let allocation = padding.as_ptr();

        obf.generate_padding_into(64, 64, &mut padding);
        assert_eq!(padding.len(), 64);
        assert_eq!(padding.as_ptr(), allocation);
        assert!(padding.iter().any(|&byte| byte != 0));

        obf.generate_padding_opts_into(false, 64, 128, true, 1.0, &mut padding);
        assert!(padding.is_empty());
        assert_eq!(padding.as_ptr(), allocation);

        obf.generate_padding_opts_into(true, 32, 128, false, 1.0, &mut padding);
        assert_eq!(padding.len(), 32);
        assert_eq!(padding.as_ptr(), allocation);
    }

    #[test]
    fn test_fragment_packet_splits_correctly() {
        let mut obf = Obfuscator::new();
        let data = vec![0xABu8; 1000];

        // Whatever the random chunk sizes come out to, the fragments must always
        // reassemble to exactly the original bytes.
        for _ in 0..50 {
            let fragments = obf.fragment_packet(&data, 100, 500, 10);
            let mut reconstructed = Vec::new();
            for frag in &fragments {
                reconstructed.extend_from_slice(frag);
            }
            assert_eq!(
                reconstructed, data,
                "reassembled data does not match original"
            );
        }
    }

    #[test]
    fn test_fragment_packet_respects_max_fragments() {
        let mut obf = Obfuscator::new();
        let data = vec![0xABu8; 10000];
        let max_frags = 5;
        let fragments = obf.fragment_packet(&data, 1, 100, max_frags);
        assert!(fragments.len() <= max_frags as usize);

        let mut reconstructed = Vec::new();
        for frag in &fragments {
            reconstructed.extend_from_slice(frag);
        }
        assert_eq!(reconstructed.len(), data.len());
    }

    #[test]
    fn test_normalize_packet_length_rounds_up() {
        let sizes = vec![64u16, 128, 256, 512, 1024];
        assert_eq!(
            Obfuscator::normalization_padding_len(50, &sizes, usize::MAX),
            14
        );
        assert_eq!(
            Obfuscator::normalization_padding_len(70, &sizes, usize::MAX),
            58
        );
    }

    #[test]
    fn test_normalize_packet_length_no_round_needed() {
        let sizes = vec![64u16, 128, 256];
        assert_eq!(
            Obfuscator::normalization_padding_len(256, &sizes, usize::MAX),
            0
        );
    }

    /// Normalization must never round a packet past what the tunnel can carry. The pad cap
    /// downstream only trims PADDING, so an over-MTU normalized packet went out as-is and —
    /// with DF armed after a successful path-MTU probe — was dropped with EMSGSIZE.
    #[test]
    fn normalize_never_exceeds_the_tunnel_mtu() {
        let sizes = [1500u16];
        assert_eq!(Obfuscator::normalization_padding_len(1200, &sizes, 1280), 0);
        assert_eq!(
            Obfuscator::normalization_padding_len(1200, &sizes, 1500),
            300
        );
        let mixed = [1500u16, 1280];
        assert_eq!(
            Obfuscator::normalization_padding_len(1200, &mixed, 1280),
            80
        );
    }

    #[test]
    fn test_normalize_packet_length_larger_than_max() {
        let sizes = vec![64u16, 128];
        assert_eq!(
            Obfuscator::normalization_padding_len(200, &sizes, usize::MAX),
            0
        );
    }

    #[test]
    fn normalization_is_stripped_as_aead_padding_and_never_mutates_ip_data() {
        let mut obf = Obfuscator::new();
        let sizes = [64u16, 128, 256];
        let data = vec![0xAB; 70];
        let mut padding = vec![1, 2, 3];
        obf.append_normalization_padding_into(data.len(), &sizes, usize::MAX, &mut padding);
        assert_eq!(data.len() + padding.len(), 131);

        let key = [7u8; 32];
        let mut tx = crate::protocol::packet::PacketCodec::new_raw(key);
        let mut rx = crate::protocol::packet::PacketCodec::new_raw(key);
        let encrypted = tx.encrypt_packet(&data, &padding).unwrap();
        assert_eq!(rx.decrypt_packet(&encrypted).unwrap(), data);
    }
}

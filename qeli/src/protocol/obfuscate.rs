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

    pub fn generate_padding(&mut self, min: u16, max: u16) -> Vec<u8> {
        if max <= min {
            return vec![0u8; min as usize];
        }
        let len = self.rng.random_range(min..=max);
        (0..len).map(|_| self.rng.random()).collect()
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
        if !enabled || max == 0 {
            return Vec::new();
        }
        if probability < 1.0 && self.rng.random::<f64>() > probability {
            return Vec::new();
        }
        let min = min.min(max);
        if randomize {
            self.generate_padding(min, max)
        } else {
            vec![0u8; min as usize]
        }
    }

    // fragment_packet / should_fragment / generate_heartbeat are covered by the
    // obfuscate test-suite but not wired into the live data path (the codec does
    // padding + normalization inline). Kept as tested building blocks.
    #[allow(dead_code)]
    pub fn fragment_packet(
        &mut self,
        data: &[u8],
        min_chunk: u16,
        max_chunk: u16,
        max_fragments: u16,
    ) -> Vec<Vec<u8>> {
        if !self.should_fragment() {
            return vec![data.to_vec()];
        }

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

    #[allow(dead_code)]
    fn should_fragment(&mut self) -> bool {
        self.rng.random_bool(0.3)
    }

    pub fn normalize_packet_length(&mut self, data: &[u8], round_sizes: &[u16]) -> Vec<u8> {
        let current_len = data.len();
        for &size in round_sizes {
            let size = size as usize;
            if current_len <= size {
                let pad_len = size - current_len;
                let mut padded = data.to_vec();
                padded.extend((0..pad_len).map(|_| self.rng.random::<u8>()));
                return padded;
            }
        }
        data.to_vec()
    }

    #[allow(dead_code)]
    pub fn generate_heartbeat(&mut self, data_size: u16) -> Vec<u8> {
        let size = std::cmp::max(data_size as usize, 4);
        let mut heartbeat = Vec::with_capacity(size + 5);
        heartbeat.push(0x18); // TLS Heartbeat
        heartbeat.extend_from_slice(&[0x03, 0x03]);
        heartbeat.extend_from_slice(&(size as u16).to_be_bytes());
        heartbeat.extend((0..size).map(|_| self.rng.random::<u8>()));
        heartbeat
    }
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

    #[test]
    fn test_fragment_packet_splits_correctly() {
        let mut obf = Obfuscator::new();
        let data = vec![0xABu8; 1000];

        // should_fragment returns true only 30% of the time,
        // but with large chunks, even single fragments should
        // reconstruct to the original data
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
        let mut obf = Obfuscator::new();
        let sizes = vec![64u16, 128, 256, 512, 1024];

        let data = vec![0xAAu8; 50];
        let padded = obf.normalize_packet_length(&data, &sizes);
        assert_eq!(padded.len(), 64);

        let data = vec![0xAAu8; 70];
        let padded = obf.normalize_packet_length(&data, &sizes);
        assert_eq!(padded.len(), 128);
    }

    #[test]
    fn test_normalize_packet_length_no_round_needed() {
        let mut obf = Obfuscator::new();
        let sizes = vec![64u16, 128, 256];

        let data = vec![0xABu8; 256];
        let padded = obf.normalize_packet_length(&data, &sizes);
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn test_normalize_packet_length_larger_than_max() {
        let mut obf = Obfuscator::new();
        let sizes = vec![64u16, 128];

        let data = vec![0xABu8; 200];
        let padded = obf.normalize_packet_length(&data, &sizes);
        // If larger than all round sizes, return as-is
        assert_eq!(padded.len(), 200);
    }

    #[test]
    fn test_generate_heartbeat_min_size() {
        let mut obf = Obfuscator::new();
        let hb = obf.generate_heartbeat(0);
        assert_eq!(hb[0], 0x18); // heartbeat content type
        assert_eq!(hb[1..3], [0x03, 0x03]); // TLS version
        assert!(hb.len() >= 9); // header + min 4 bytes payload
    }

    #[test]
    fn test_generate_heartbeat_custom_size() {
        let mut obf = Obfuscator::new();
        let hb = obf.generate_heartbeat(100);
        assert_eq!(hb[0], 0x18);
        // size field at offset 3-4
        let size = u16::from_be_bytes([hb[3], hb[4]]) as usize;
        assert_eq!(size, 100);
        assert_eq!(hb.len(), 5 + 100);
    }
}

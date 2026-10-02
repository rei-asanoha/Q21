//! SipHash-2-4.
//!
//! A short, fast and above all **keyed** hash function. That last property is
//! what matters here: the short ids of compact block relay are six bytes long,
//! so collisions are possible. If the function were not keyed, an attacker
//! could craft in advance transactions whose short id collides with those of
//! an upcoming block, and prevent its reconstruction.
//!
//! The key derives from the block header, hence from the nonce, hence from a
//! value nobody knows before the block is mined. Collisions become random
//! again, and randomness we can absorb: a collision costs one extra round
//! trip, not a vulnerability.
//!
//! Published by Aumasson and Bernstein in 2012. Implemented here rather than
//! imported, for the same reason as SHA-256: consensus must depend only on
//! what can be audited and frozen.

/// SipHash-2-4 state.
pub struct SipHasher {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buffer: [u8; 8],
    buffered: usize,
    total: usize,
}

#[inline(always)]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

impl SipHasher {
    pub fn new(k0: u64, k1: u64) -> SipHasher {
        SipHasher {
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
            buffer: [0u8; 8],
            buffered: 0,
            total: 0,
        }
    }

    #[inline]
    fn absorb(&mut self, m: u64) {
        self.v3 ^= m;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= m;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len();

        if self.buffered > 0 {
            let need = 8 - self.buffered;
            let take = need.min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 8 {
                let m = u64::from_le_bytes(self.buffer);
                self.absorb(m);
                self.buffered = 0;
            }
        }

        while data.len() >= 8 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&data[..8]);
            self.absorb(u64::from_le_bytes(w));
            data = &data[8..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    pub fn finalize(mut self) -> u64 {
        // Last word: the remaining bytes, then the total length modulo 256 in
        // the most significant byte.
        let mut last = [0u8; 8];
        last[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
        last[7] = (self.total % 256) as u8;
        self.absorb(u64::from_le_bytes(last));

        self.v2 ^= 0xff;
        for _ in 0..4 {
            sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// Shortcut: SipHash-2-4 of a complete message.
pub fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut h = SipHasher::new(k0, k1);
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vectors from the Aumasson and Bernstein paper.
    ///
    /// Key `00 01 02 ... 0f`, message `00 01 02 ... (len-1)`.
    #[test]
    fn reference_vectors() {
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);

        let expected: [u64; 8] = [
            0x726f_db47_dd0e_0e31,
            0x74f8_39c5_93dc_67fd,
            0x0d6c_8009_d9a9_4f5a,
            0x8567_6696_d7fb_7e2d,
            0xcf27_94e0_2771_87b7,
            0x1876_5564_cd99_a68d,
            0xcbc9_466e_58fe_e3ce,
            0xab02_00f5_8b01_d137,
        ];

        for (len, expected_hash) in expected.iter().enumerate() {
            let msg: Vec<u8> = (0..len as u8).collect();
            assert_eq!(
                siphash24(k0, k1, &msg),
                *expected_hash,
                "wrong vector for length {len}"
            );
        }
    }

    #[test]
    fn splitting_does_not_change_result() {
        let msg: Vec<u8> = (0u8..=255).cycle().take(500).collect();
        let direct = siphash24(1, 2, &msg);
        for size in [1usize, 3, 7, 8, 9, 64, 127] {
            let mut h = SipHasher::new(1, 2);
            for piece in msg.chunks(size) {
                h.update(piece);
            }
            assert_eq!(h.finalize(), direct, "failure with pieces of {size}");
        }
    }

    #[test]
    fn two_keys_give_two_results() {
        let msg = b"the same transaction";
        assert_ne!(siphash24(1, 2, msg), siphash24(3, 4, msg));
    }

    #[test]
    fn one_message_bit_changes_everything() {
        let a = siphash24(9, 9, b"transaction A");
        let b = siphash24(9, 9, b"transaction B");
        assert_ne!(a, b);
        // Avalanche effect roughly checked: at least a third of the bits.
        assert!((a ^ b).count_ones() > 20, "avalanche too weak");
    }

    #[test]
    fn empty_message_is_handled() {
        assert_eq!(siphash24(0, 0, b""), siphash24(0, 0, &[]));
    }
}

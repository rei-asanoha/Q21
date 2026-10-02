//! BLAKE2b, as described by RFC 7693.
//!
//! # Why a second hash function
//!
//! All of consensus rests on SHA-256, and nothing here changes that. BLAKE2b
//! is used in only one place: the key derivation of the wallet file, where
//! Argon2 ([`crate::argon2`]) requires it — the algorithm is defined on top
//! of BLAKE2b, and replacing it with SHA-256 would give something other than
//! Argon2, without its test vectors or its cryptanalysis.
//!
//! # What is implemented, and what is not
//!
//! The complete function, for any output length from 1 to 64 bytes, with or
//! without a key. Neither tree mode, nor salt, nor personalization: Argon2
//! does not need them, and each missing option is an option that cannot be
//! misused.
//!
//! The implementation is checked against the vectors of RFC 7693 appendix A
//! and against the official keyed vector of the BLAKE2 suite.

/// Initialization vector: the same constants as SHA-512.
const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Message permutations, one per round (rounds 10 and 11 reuse the first
/// two).
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Size of a block, in bytes.
pub const BLOCK_BYTES: usize = 128;

/// Incremental state.
pub struct Blake2b {
    h: [u64; 8],
    /// Counter of absorbed bytes, on 128 bits.
    t: [u64; 2],
    buffer: [u8; BLOCK_BYTES],
    filled: usize,
    output_len: usize,
}

impl Blake2b {
    /// New state for an output of `output_len` bytes (1 to 64), without a
    /// key.
    pub fn new(output_len: usize) -> Blake2b {
        Self::with_key(output_len, &[])
    }

    /// New state with a key (0 to 64 bytes). The key, if there is one, is
    /// absorbed as the first block, padded with zeros: this is the native
    /// keyed mode of BLAKE2, which does not need HMAC.
    pub fn with_key(output_len: usize, key: &[u8]) -> Blake2b {
        assert!((1..=64).contains(&output_len), "output of 1 to 64 bytes");
        assert!(key.len() <= 64, "key of 64 bytes at most");
        let mut h = IV;
        // Parameter block: output length, key length, fanout 1, depth 1. The
        // rest at zero.
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ output_len as u64;
        let mut s = Blake2b {
            h,
            t: [0, 0],
            buffer: [0u8; BLOCK_BYTES],
            filled: 0,
            output_len,
        };
        if !key.is_empty() {
            s.buffer[..key.len()].copy_from_slice(key);
            s.filled = BLOCK_BYTES;
        }
        s
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // A full block is compressed only once we know it is not the last
            // one: the last one carries the final flag.
            if self.filled == BLOCK_BYTES {
                self.increment(BLOCK_BYTES as u64);
                let block = self.buffer;
                self.compress(&block, false);
                self.filled = 0;
            }
            let n = (BLOCK_BYTES - self.filled).min(data.len());
            self.buffer[self.filled..self.filled + n].copy_from_slice(&data[..n]);
            self.filled += n;
            data = &data[n..];
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.increment(self.filled as u64);
        for o in &mut self.buffer[self.filled..] {
            *o = 0;
        }
        let block = self.buffer;
        self.compress(&block, true);
        let mut out = Vec::with_capacity(64);
        for word in self.h {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(self.output_len);
        out
    }

    fn increment(&mut self, n: u64) {
        let (low, carry) = self.t[0].overflowing_add(n);
        self.t[0] = low;
        if carry {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn compress(&mut self, block: &[u8; BLOCK_BYTES], last: bool) {
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(b);
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        if last {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// The G mixing function of RFC 7693.
#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// BLAKE2b in one call, for an output of `len` bytes.
pub fn blake2b(len: usize, data: &[u8]) -> Vec<u8> {
    let mut h = Blake2b::new(len);
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 7693, appendix A: BLAKE2b-512("abc").
    #[test]
    fn rfc_7693_vector() {
        assert_eq!(
            hex(&blake2b(64, b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    /// The empty string, a classic vector of the BLAKE2 suite.
    #[test]
    fn the_empty_string() {
        assert_eq!(
            hex(&blake2b(64, b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    /// Splitting into blocks changes nothing: a message longer than one
    /// block, absorbed all at once or byte by byte, gives the same hash. And
    /// the message of exactly 128 bytes — a full block, which must still be
    /// the last one — is handled correctly.
    #[test]
    fn incremental_absorption_is_the_same() {
        for n in [1usize, 127, 128, 129, 255, 256, 1000] {
            let m: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
            let all_at_once = blake2b(64, &m);
            let mut h = Blake2b::new(64);
            for o in &m {
                h.update(std::slice::from_ref(o));
            }
            assert_eq!(h.finish(), all_at_once, "length {n}");
        }
    }

    /// Official keyed vector of the BLAKE2 suite (`blake2b-kat.txt`): empty
    /// message, key = 00 01 02 ... 3f.
    #[test]
    fn keyed_vector() {
        let key: Vec<u8> = (0u8..64).collect();
        let mut h = Blake2b::with_key(64, &key);
        h.update(b"");
        assert_eq!(
            hex(&h.finish()),
            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786\
             b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"
        );
    }

    /// A truncated output is not a prefix of the long output: the length
    /// goes into the parameter block.
    #[test]
    fn output_length_is_mixed_in() {
        let short = blake2b(32, b"abc");
        let long = blake2b(64, b"abc");
        assert_eq!(short.len(), 32);
        assert_ne!(&short[..], &long[..32]);
    }
}

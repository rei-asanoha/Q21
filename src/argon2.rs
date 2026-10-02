//! Argon2, as described by RFC 9106.
//!
//! # Why
//!
//! The wallet file is encrypted with a key derived from the passphrase. With
//! PBKDF2, deriving that key costs a sequence of hashes — an operation that a
//! dedicated circuit runs thousands of times faster than a processor. An
//! attacker who steals `wallet.dat` then tests passphrases at a speed the
//! user cannot imagine, and the only remaining defense was the length of the
//! passphrase.
//!
//! Argon2 makes each attempt **memory-expensive**: deriving a key requires
//! filling and rereading tens of mebibytes, in an order that depends on the
//! data. A dedicated circuit must carry as much memory per attempt as a
//! processor, and gains almost nothing from it. It is the winner of the
//! Password Hashing Competition (2015), and the choice recommended by RFC
//! 9106 as well as by OWASP.
//!
//! # Why write it here
//!
//! This project refuses to invent primitives; it does not refuse to
//! implement them from their standard when the standard provides what is
//! needed to check them. SHA-256 is written here and checked against FIPS
//! 180-4; BLAKE2b against RFC 7693; Argon2 against the three vectors of RFC
//! 9106 (Argon2d, Argon2i, Argon2id), which exercise the lanes, the passes
//! and both addressing modes. An implementation that reproduces these three
//! vectors to the byte is the RFC's.
//!
//! # What is implemented
//!
//! The three variants, version 0x13, any number of lanes (processed one
//! after the other: the result is the same as in parallel), any output
//! length, optional secret and associated data. The wallet uses only
//! Argon2id.

use crate::blake2b::{blake2b, Blake2b};

/// Algorithm version.
const VERSION: u32 = 0x13;

/// Size of a memory block, in bytes.
const BLOCK_SIZE: usize = 1024;

/// 64-bit words per block.
const WORDS: usize = BLOCK_SIZE / 8;

/// Number of slices per pass (the RFC fixes it at four).
const SLICES: usize = 4;

/// The three variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Data-dependent addressing: the most resistant to time-memory
    /// trade-offs, vulnerable to side channels.
    D = 0,
    /// Data-independent addressing: no side channel, less resistant to the
    /// trade-off.
    I = 1,
    /// Hybrid: independent on the first half of the first pass, dependent
    /// afterwards. The recommended choice.
    Id = 2,
}

/// Cost parameters.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub variant: Variant,
    /// Memory, in kibibytes. At least `8 * lanes`.
    pub memory_kib: u32,
    /// Passes over the memory. At least 1.
    pub passes: u32,
    /// Lanes. At least 1.
    pub lanes: u32,
}

/// A block of 1,024 bytes, seen as 128 words.
#[derive(Clone, Copy)]
struct Block([u64; WORDS]);

impl Block {
    const ZERO: Block = Block([0u64; WORDS]);

    fn from_bytes(o: &[u8]) -> Block {
        let mut b = Block::ZERO;
        for (i, word) in b.0.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&o[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(w);
        }
        b
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(BLOCK_SIZE);
        for word in self.0 {
            v.extend_from_slice(&word.to_le_bytes());
        }
        v
    }

    fn xor(&self, other: &Block) -> Block {
        let mut r = *self;
        for (a, b) in r.0.iter_mut().zip(other.0.iter()) {
            *a ^= *b;
        }
        r
    }
}

/// The variable-length hash function H' of the RFC (section 3.3).
fn h_prime(len: usize, input: &[u8]) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(4 + input.len());
    prefixed.extend_from_slice(&(len as u32).to_le_bytes());
    prefixed.extend_from_slice(input);
    if len <= 64 {
        return blake2b(len, &prefixed);
    }
    let r = len.div_ceil(32) - 2;
    let mut out = Vec::with_capacity(len);
    let mut v = blake2b(64, &prefixed);
    out.extend_from_slice(&v[..32]);
    for _ in 1..r {
        v = blake2b(64, &v);
        out.extend_from_slice(&v[..32]);
    }
    let rest = len - 32 * r;
    out.extend_from_slice(&blake2b(rest, &v));
    out
}

/// The GB function of the permutation P: the G of BLAKE2b, where the
/// addition is enriched with the product of the low halves (BlaMka), so that
/// the computation depends on multiplications that silicon does not
/// parallelize for free.
#[inline(always)]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    #[inline(always)]
    fn mix(x: u64, y: u64) -> u64 {
        let xl = x as u32 as u64;
        let yl = y as u32 as u64;
        x.wrapping_add(y)
            .wrapping_add(2u64.wrapping_mul(xl).wrapping_mul(yl))
    }
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The permutation P on sixteen words (eight registers of sixteen bytes).
fn p(v: &mut [u64; 16]) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// The compression function G(X, Y) of the RFC (section 3.5).
fn compress(x: &Block, y: &Block) -> Block {
    let r = x.xor(y);
    let mut q = r;
    // P on each of the eight rows of 128 bytes.
    for row in 0..8 {
        let mut v = [0u64; 16];
        v.copy_from_slice(&q.0[row * 16..row * 16 + 16]);
        p(&mut v);
        q.0[row * 16..row * 16 + 16].copy_from_slice(&v);
    }
    // P on each of the eight columns: column `c` is made of words 2c, 2c+1
    // of each row.
    for column in 0..8 {
        let mut v = [0u64; 16];
        for row in 0..8 {
            v[2 * row] = q.0[row * 16 + 2 * column];
            v[2 * row + 1] = q.0[row * 16 + 2 * column + 1];
        }
        p(&mut v);
        for row in 0..8 {
            q.0[row * 16 + 2 * column] = v[2 * row];
            q.0[row * 16 + 2 * column + 1] = v[2 * row + 1];
        }
    }
    q.xor(&r)
}

/// Derives `len` bytes from `password` and `salt`.
///
/// `secret` and `associated_data` are the optional inputs K and X of the
/// RFC; empty in practice here, present to reproduce the vectors.
pub fn derive_key(
    params: Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    len: usize,
) -> Vec<u8> {
    let lanes = params.lanes.max(1) as usize;
    let passes = params.passes.max(1);
    assert!(len >= 4, "output of 4 bytes at least");
    // m' = 4 * p * floor(m / 4p): memory is rounded down to a multiple of the
    // number of segments.
    let memory = (params.memory_kib as usize).max(8 * lanes);
    let m_prime = 4 * lanes * (memory / (4 * lanes));
    let q = m_prime / lanes;
    let segment = q / SLICES;

    // H0 = H^64(p, T, m, t, v, y, |P|, P, |S|, S, |K|, K, |X|, X).
    let mut h = Blake2b::new(64);
    for v in [
        lanes as u32,
        len as u32,
        params.memory_kib,
        passes,
        VERSION,
        params.variant as u32,
    ] {
        h.update(&v.to_le_bytes());
    }
    for part in [password, salt, secret, associated_data] {
        h.update(&(part.len() as u32).to_le_bytes());
        h.update(part);
    }
    let h0 = h.finish();

    // The first two blocks of each lane.
    let mut blocks = vec![Block::ZERO; m_prime];
    for lane in 0..lanes {
        for j in 0..2u32 {
            let mut e = Vec::with_capacity(72);
            e.extend_from_slice(&h0);
            e.extend_from_slice(&j.to_le_bytes());
            e.extend_from_slice(&(lane as u32).to_le_bytes());
            blocks[lane * q + j as usize] = Block::from_bytes(&h_prime(BLOCK_SIZE, &e));
        }
    }

    for pass in 0..passes {
        for slice in 0..SLICES {
            for lane in 0..lanes {
                fill_segment(
                    &mut blocks,
                    params.variant,
                    pass,
                    passes,
                    slice,
                    lane,
                    lanes,
                    q,
                    segment,
                    m_prime,
                );
            }
        }
    }

    // C = XOR of the last blocks of each lane; output = H'^T(C).
    let mut c = blocks[q - 1];
    for lane in 1..lanes {
        c = c.xor(&blocks[lane * q + q - 1]);
    }
    let out = h_prime(len, &c.encode());
    // The working memory held derivatives of the password: wipe it.
    for b in blocks.iter_mut() {
        crate::kdf::wipe(words_as_bytes(&mut b.0));
    }
    out
}

/// Byte view of an array of words, for wiping.
fn words_as_bytes(words: &mut [u64; WORDS]) -> &mut [u8] {
    // Safe: `u64` has no invalid value, byte alignment is trivial, and the
    // length is exactly that of the array.
    unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr() as *mut u8, WORDS * 8) }
}

/// Fills one segment (one lane, one slice) of a pass.
#[allow(clippy::too_many_arguments)]
fn fill_segment(
    memory: &mut [Block],
    variant: Variant,
    pass: u32,
    passes: u32,
    slice: usize,
    lane: usize,
    lanes: usize,
    q: usize,
    segment: usize,
    m_prime: usize,
) {
    // Data-independent addressing: Argon2i everywhere, Argon2id on the first
    // half of the first pass.
    let independent = match variant {
        Variant::I => true,
        Variant::Id => pass == 0 && slice < SLICES / 2,
        Variant::D => false,
    };

    // The address generator of independent addressing: G(0, G(0, Z)), where
    // Z describes the position, with a counter incremented for each block of
    // 128 addresses.
    let mut addresses = Block::ZERO;
    let mut input = Block::ZERO;
    if independent {
        input.0[0] = pass as u64;
        input.0[1] = lane as u64;
        input.0[2] = slice as u64;
        input.0[3] = m_prime as u64;
        input.0[4] = passes as u64;
        input.0[5] = variant as u64;
    }
    let next_addresses = |input: &mut Block| -> Block {
        input.0[6] = input.0[6].wrapping_add(1);
        compress(&Block::ZERO, &compress(&Block::ZERO, input))
    };

    // In the first slice of the first pass, the first two blocks already
    // exist.
    let start = if pass == 0 && slice == 0 { 2 } else { 0 };

    for i in start..segment {
        let current = lane * q + slice * segment + i;
        let prev = if slice * segment + i == 0 {
            lane * q + q - 1
        } else {
            current - 1
        };

        let (j1, j2) = if independent {
            if i % WORDS == 0 || (i == start && start == 2) {
                addresses = next_addresses(&mut input);
            }
            let word = addresses.0[i % WORDS];
            (word as u32 as u64, word >> 32)
        } else {
            let word = memory[prev].0[0];
            (word as u32 as u64, word >> 32)
        };

        // The reference lane: our own in the very first slice.
        let ref_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            (j2 % lanes as u64) as usize
        };

        // The size of the reference area, per the RFC (section 3.4.1.3).
        let same_lane = ref_lane == lane;
        let area = if pass == 0 {
            if slice == 0 {
                i - 1
            } else if same_lane {
                slice * segment + i - 1
            } else {
                slice * segment - if i == 0 { 1 } else { 0 }
            }
        } else if same_lane {
            q - segment + i - 1
        } else {
            q - segment - if i == 0 { 1 } else { 0 }
        };

        // Position in the area, biased toward recent blocks.
        let x = (j1 * j1) >> 32;
        let y = ((area as u64) * x) >> 32;
        let zz = (area as u64) - 1 - y;
        let area_start = if pass == 0 || slice == SLICES - 1 {
            0
        } else {
            (slice + 1) * segment
        };
        let ref_index = (area_start + zz as usize) % q;
        let reference = ref_lane * q + ref_index;

        let new_block = compress(&memory[prev], &memory[reference]);
        memory[current] = if pass == 0 {
            new_block
        } else {
            new_block.xor(&memory[current])
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The inputs shared by the three vectors of RFC 9106 (section 5):
    /// password 32 x 0x01, salt 16 x 0x02, secret 8 x 0x03, associated data
    /// 12 x 0x04, t = 3, m = 32 KiB, p = 4, 32-byte output.
    fn vector(variant: Variant) -> String {
        let p = Params {
            variant,
            memory_kib: 32,
            passes: 3,
            lanes: 4,
        };
        hex(&derive_key(
            p, &[1u8; 32], &[2u8; 16], &[3u8; 8], &[4u8; 12], 32,
        ))
    }

    #[test]
    fn rfc_9106_argon2d_vector() {
        assert_eq!(
            vector(Variant::D),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        );
    }

    #[test]
    fn rfc_9106_argon2i_vector() {
        assert_eq!(
            vector(Variant::I),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        );
    }

    #[test]
    fn rfc_9106_argon2id_vector() {
        assert_eq!(
            vector(Variant::Id),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// A single lane, several passes, long output: the path the wallet
    /// actually uses must be deterministic and sensitive to each input.
    #[test]
    fn one_lane_is_deterministic_and_sensitive() {
        let p = Params {
            variant: Variant::Id,
            memory_kib: 256,
            passes: 2,
            lanes: 1,
        };
        let a = derive_key(p, b"passphrase", b"salt-16-bytes-ok", &[], &[], 64);
        let b = derive_key(p, b"passphrase", b"salt-16-bytes-ok", &[], &[], 64);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert_ne!(
            a,
            derive_key(p, b"passphrasE", b"salt-16-bytes-ok", &[], &[], 64)
        );
        assert_ne!(
            a,
            derive_key(p, b"passphrase", b"salt-16-bytes-oK", &[], &[], 64)
        );
        let more = Params { passes: 3, ..p };
        assert_ne!(
            a,
            derive_key(more, b"passphrase", b"salt-16-bytes-ok", &[], &[], 64)
        );
    }
}

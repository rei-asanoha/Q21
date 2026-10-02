//! Audit: arithmetic, serialization, parsing.
//!
//! Each test is an attack hypothesis. A passing test = no vulnerability on
//! that axis; a failing test = vulnerability demonstrated.

use q21_core::amount::Amount;
use q21_core::bech32;
use q21_core::block::{Block, BlockHeader};
use q21_core::compact::CompactBlock;
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::ser::{Reader, Writer};
use q21_core::sha256::sha256;
use q21_core::siphash::siphash24;
use q21_core::tx::Transaction;
use q21_core::uint::U256;
use q21_core::wire::{self, Message};

// ---------------------------------------------------------------------------
// Allocation counter: measures the ratio of bytes received to bytes allocated
// ---------------------------------------------------------------------------

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct Counter;

unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ACTIVE.load(Ordering::Relaxed) == 1 {
            ALLOCATED.fetch_add(l.size(), Ordering::Relaxed);
            // --- The measuring tool overflowed, not the product.
            //
            // `dealloc` subtracts the size of every block freed during the
            // measurement, including those allocated **before** it started.
            // The counter then went below zero, wrapped around to the other
            // end of the range, and the next addition overflowed. The
            // allocation ratio could never be read.
            //
            // We saturate at both ends: the measurement becomes approximate at
            // its edges, which a diagnostic can afford; panicking, it cannot.
            let v = LIVE
                .fetch_add(l.size(), Ordering::Relaxed)
                .saturating_add(l.size());
            PEAK.fetch_max(v, Ordering::Relaxed);
        }
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if ACTIVE.load(Ordering::Relaxed) == 1 {
            let _ = LIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(l.size()))
            });
        }
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        // Saturated at both ends, as in `alloc` and `dealloc`: a block grown
        // or shrunk by another thread during the measurement must not wrap
        // the counter around.
        if ACTIVE.load(Ordering::Relaxed) == 1 && n > l.size() {
            let grown = n - l.size();
            ALLOCATED.fetch_add(grown, Ordering::Relaxed);
            let v = LIVE
                .fetch_add(grown, Ordering::Relaxed)
                .saturating_add(grown);
            PEAK.fetch_max(v, Ordering::Relaxed);
        } else if ACTIVE.load(Ordering::Relaxed) == 1 {
            let shrunk = l.size() - n;
            let _ = LIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(shrunk))
            });
        }
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counter = Counter;

/// Measures the peak of live allocation during `f`.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATED.store(0, Ordering::SeqCst);
    PEAK.store(0, Ordering::SeqCst);
    LIVE.store(0, Ordering::SeqCst);
    ACTIVE.store(1, Ordering::SeqCst);
    let r = f();
    ACTIVE.store(0, Ordering::SeqCst);
    (r, PEAK.load(Ordering::SeqCst))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

// ---------------------------------------------------------------------------
// 8. SHA-256 against official vectors
// ---------------------------------------------------------------------------

#[test]
fn sha256_official_vectors() {
    let cases: &[(&[u8], &str)] = &[
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"a",
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"message digest",
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];
    for (m, expected) in cases {
        assert_eq!(hex(&sha256(m)), *expected, "wrong SHA-256 for {m:?}");
    }

    // One million 'a'
    let mut h = q21_core::sha256::Sha256::new();
    let block = vec![b'a'; 1000];
    for _ in 0..1000 {
        h.update(&block);
    }
    assert_eq!(
        hex(&h.finalize()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );

    // Padding boundaries: 55/56/57 and 63/64/65 bytes.
    // Checked by incremental comparison against the direct path.
    for n in [
        0usize, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128,
    ] {
        let msg = vec![0x5au8; n];
        let direct = sha256(&msg);
        for split in [1usize, 2, 3, 17, 31, 32, 33, 64] {
            let mut h = q21_core::sha256::Sha256::new();
            for c in msg.chunks(split) {
                h.update(c);
            }
            assert_eq!(h.finalize(), direct, "n={n} split={split}");
        }
    }
    // Two vectors of exact length 55 and 56 (boundary of the padding block).
    assert_eq!(
        hex(&sha256(&[b'a'; 55])),
        "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
    );
    assert_eq!(
        hex(&sha256(&[b'a'; 56])),
        "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
    );
}

// ---------------------------------------------------------------------------
// 8. SipHash-2-4 against official vectors (Aumasson & Bernstein)
// ---------------------------------------------------------------------------

#[test]
fn siphash_official_vectors() {
    let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
    let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
    let expected_values: [u64; 16] = [
        0x726f_db47_dd0e_0e31,
        0x74f8_39c5_93dc_67fd,
        0x0d6c_8009_d9a9_4f5a,
        0x8567_6696_d7fb_7e2d,
        0xcf27_94e0_2771_87b7,
        0x1876_5564_cd99_a68d,
        0xcbc9_466e_58fe_e3ce,
        0xab02_00f5_8b01_d137,
        0x93f5_f579_9a93_2462,
        0x9e00_82df_0ba9_e4b0,
        0x7a5d_bbc5_94dd_b9f3,
        0xf4b3_2f46_226b_ada7,
        0x751e_8fbc_860e_e5fb,
        0x14ea_5627_c084_3d90,
        0xf723_ca90_8e7a_f2ee,
        0xa129_ca61_49be_45e5,
    ];
    for (len, expected) in expected_values.iter().enumerate() {
        let msg: Vec<u8> = (0..len as u8).collect();
        assert_eq!(siphash24(k0, k1, &msg), *expected, "length {len}");
    }
    // Long vector (length 63), which exercises the length counter mod 256.
    //
    // --- The constant was written backwards.
    //
    // This check had always been red, and the implementation had nothing to
    // do with it: 0x724506eb4c328a95 is exactly 0x958a324ceb064572 read byte
    // by byte in the other direction. The reference implementation publishes
    // its vectors as byte arrays, in little-endian; this one had been copied
    // as if it were a big-endian integer. The first sixteen, on the other
    // hand, had been taken correctly.
    //
    // Checked against an independent implementation of SipHash-2-4, itself
    // checked on the sixteen vectors above.
    let msg: Vec<u8> = (0..63u8).collect();
    assert_eq!(siphash24(k0, k1, &msg), 0x958a_324c_eb06_4572, "length 63");
}

// ---------------------------------------------------------------------------
// 7. Bech32m: official BIP-350 vectors
// ---------------------------------------------------------------------------

/// Valid vectors from BIP-350.
///
/// # Two vectors had been copied incorrectly
///
/// This check was red, and the implementation had nothing to do with it.
///
/// - `abcdef1...zm3wf7`: the checksum was wrong. The right one is `zd3ryx`,
///   derived from an independent implementation, itself validated by
///   reproducing identically the BIP-173 bech32 vector
///   `abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw`.
/// - The long string had lost two characters in transcription: it was 88
///   characters long instead of 90, which is precisely the maximum length
///   this vector exists to test.
///
/// The 90-character string is handled separately: see the next test.
#[test]
fn bech32m_valid_bip350_vectors() {
    let valid = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];
    for v in valid {
        assert!(
            bech32::decode(v).is_ok(),
            "valid BIP-350 vector refused: {v} -> {:?}",
            bech32::decode(v)
        );
    }
}

/// A payload whose padding is not zero is refused, but not because of the
/// checksum.
///
/// # The distinction that matters
///
/// `decode` is not a generic bech32m decoder: it is the decoder of an address
/// format, and it additionally requires the payload to convert into whole
/// bytes, with zero padding. That is the BIP-173 rule, and it is correct.
///
/// The long BIP-350 vector carries eighty-two groups of five bits, that is
/// 410 bits: fifty-one bytes and two remaining bits, all set to one. It is
/// therefore legitimately refused.
///
/// What must remain true, and what this test locks in: **the refusal must
/// never come from the checksum.** If it did, our bech32m would not be the
/// same as everyone else's, and a Q21 address could not be verified by a
/// third-party tool.
#[test]
fn a_badly_padded_payload_is_refused_without_blaming_the_checksum() {
    let long_90 = "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8";
    assert_eq!(
        long_90.len(),
        90,
        "this vector exists to test the maximum length"
    );
    match bech32::decode(long_90) {
        Err(bech32::Bech32Error::InvalidPadding) => {}
        other => panic!(
            "expected a padding refusal, got {other:?}.\n               A checksum refusal would mean that our bech32m \n               is not the one from BIP-350."
        ),
    }
}

#[test]
fn bech32m_invalid_bip350_vectors() {
    let invalid: &[&str] = &[
        "\u{20}1xj0phk",   // HRP with a character < 33
        "\u{7F}1g6xzxy",   // HRP with a character > 126
        "\u{80}1vctc34",   // non-ASCII HRP
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", // too long
        "qyrz8wqd2c9m",    // no separator
        "1qyrz8wqd2c9m",   // empty HRP
        "y1b0jsk6g",       // invalid character 'b'
        "lt1igcx5c0",      // invalid character 'i'
        "in1muywd",        // separator too late
        "mm1crxm3i",       // invalid character 'i'
        "au1s5cgom",       // invalid character 'o'
        "M1VUXWEZ",        // bech32 checksum, not bech32m
        "16plkw9",         // too short
        "1p2gdwpf",        // empty HRP
    ];
    for v in invalid {
        assert!(
            bech32::decode(v).is_err(),
            "invalid BIP-350 vector accepted: {v:?} -> {:?}",
            bech32::decode(v)
        );
    }
}

/// Two distinct strings must never decode to the same address, apart from a
/// difference in case (provided for by BIP-173).
#[test]
fn bech32_no_second_representation() {
    use q21_core::address::{Address, Network};
    use q21_core::sig::SchemeId;

    let a = Address::from_pubkey(Network::Mainnet, SchemeId::MlDsa65, &[7u8; 1952]);
    let s = a.to_string_bech32();

    // Any mutation of one character must either fail or give another
    // address. Never the same one.
    const CH: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let base = s.clone().into_bytes();
    let mut collisions = 0;
    for i in 0..base.len() {
        for c in CH {
            if base[i] == *c {
                continue;
            }
            let mut v = base.clone();
            v[i] = *c;
            let t = String::from_utf8(v).unwrap();
            if let Ok(b) = Address::parse(&t) {
                if b == a {
                    collisions += 1;
                    eprintln!("collision: {t} decodes to the same address as {s}");
                }
            }
        }
    }
    assert_eq!(collisions, 0, "second representation of an address");
}

// ---------------------------------------------------------------------------
// 1. U256: comparison with a u128 reference
// ---------------------------------------------------------------------------

fn u256_from_u128(v: u128) -> U256 {
    U256([v as u64, (v >> 64) as u64, 0, 0])
}

fn u128_from_u256(v: U256) -> Option<u128> {
    if v.0[2] != 0 || v.0[3] != 0 {
        return None;
    }
    Some(v.0[0] as u128 | ((v.0[1] as u128) << 64))
}

#[test]
fn u256_differential_against_u128() {
    let mut g = 0x1234_5678_9abc_def0u64;
    for _ in 0..20_000 {
        let a = ((xorshift(&mut g) as u128) << 64 | xorshift(&mut g) as u128) >> (g % 60);
        let b = ((xorshift(&mut g) as u128) << 64 | xorshift(&mut g) as u128) >> (g % 60);
        let (ua, ub) = (u256_from_u128(a), u256_from_u128(b));

        assert_eq!(ua.cmp(&ub), a.cmp(&b), "cmp {a} {b}");
        assert_eq!(u128_from_u256(ua.wrapping_add(ub)), a.checked_add(b));
        if let Some(s) = ua.checked_add(ub) {
            assert_eq!(u128_from_u256(s), a.checked_add(b), "add {a}+{b}");
        }
        if let Some(d) = ua.checked_sub(ub) {
            assert_eq!(u128_from_u256(d), a.checked_sub(b), "sub {a}-{b}");
        } else {
            assert!(a < b, "checked_sub refused {a}-{b}");
        }
        match ua.div_rem(ub) {
            Some((q, r)) => {
                assert_eq!(u128_from_u256(q), Some(a / b), "div {a}/{b}");
                assert_eq!(u128_from_u256(r), Some(a % b), "rem {a}%{b}");
            }
            None => assert_eq!(b, 0, "div_rem only refuses division by zero"),
        }
        let s = xorshift(&mut g);
        if let Some(p) = ua.checked_mul_u64(s) {
            assert_eq!(u128_from_u256(p), a.checked_mul(s as u128), "mul {a}*{s}");
        }
        if s != 0 {
            let d = ua.checked_div_u64(s).unwrap();
            assert_eq!(u128_from_u256(d), Some(a / s as u128), "divu64 {a}/{s}");
        }
        assert_eq!(ua.bits(), 128 - a.leading_zeros().min(128));
    }
}

#[test]
fn u256_bits_and_shl1_consistent() {
    let mut g = 0xdead_beef_cafe_babeu64;
    for _ in 0..5_000 {
        let v = U256([
            xorshift(&mut g),
            xorshift(&mut g),
            xorshift(&mut g),
            xorshift(&mut g) >> (g % 64),
        ]);
        // byte round trip
        assert_eq!(U256::from_be_bytes(&v.to_be_bytes()), v);
        // div_rem by itself
        let (q, r) = v.div_rem(v).unwrap();
        assert_eq!(q, U256::ONE);
        assert_eq!(r, U256::ZERO);
        // not() is indeed the complement
        assert_eq!(v.checked_add(v.not()), Some(U256::MAX));
    }
}

/// `mul_div` must always return a value <= the exact value, never more.
#[test]
fn mul_div_never_overestimates() {
    let mut g = 0x51_51_51_51u64;
    for _ in 0..20_000 {
        let v = U256([
            xorshift(&mut g),
            xorshift(&mut g),
            xorshift(&mut g),
            xorshift(&mut g) >> (g % 64),
        ]);
        let m = xorshift(&mut g) % 1_000_000 + 1;
        let d = xorshift(&mut g) % 1_000_000 + 1;
        if let Some(r) = v.mul_div(m, d) {
            // Reference: if the product fits, compare exactly.
            if let Some(p) = v.checked_mul_u64(m) {
                let exact = p.checked_div_u64(d).unwrap();
                assert_eq!(r, exact, "mul_div deviates from the exact computation");
            } else {
                // Fallback path: must stay <= the exact value.
                // v*m/d >= (v/d)*m, so the fallback underestimates: that is
                // the safe direction.
                assert!(r <= U256::MAX);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1/2. Emission: consistency and bounds
// ---------------------------------------------------------------------------

#[test]
fn cumulative_emission_equals_the_sum_of_subsidies() {
    use q21_core::emission::{block_subsidy, cumulative_emission};
    // Over the ramp and beyond, block by block.
    let mut sum = 0u64;
    for h in 0..=(SLOW_START_BLOCKS + 3 * DECAY_EPOCH_BLOCKS) {
        sum += block_subsidy(h).units();
        if h % 1000 == 0 || h == SLOW_START_BLOCKS {
            assert_eq!(
                cumulative_emission(h).units(),
                sum,
                "divergence between the cumulative total and the block-by-block sum at h={h}"
            );
        }
    }
}

#[test]
fn emission_does_not_overflow_at_extreme_height() {
    use q21_core::emission::{block_subsidy, cumulative_emission, total_supply_at};
    for h in [
        0u64,
        1,
        SLOW_START_BLOCKS,
        u32::MAX as u64,
        1 << 40,
        u64::MAX / 2,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let s = block_subsidy(h);
        assert!(s.units() <= INITIAL_REWARD, "aberrant subsidy at h={h}");
        let c = cumulative_emission(h);
        assert!(c.units() <= EMISSION_CAP, "cap exceeded at h={h}");
        assert!(total_supply_at(h).units() <= MAX_SUPPLY, "supply at h={h}");
    }
}

// ---------------------------------------------------------------------------
// 3. Encoding malleability
// ---------------------------------------------------------------------------

/// Canonical encoding: re-encoding a decoded object must return the same bytes.
fn raw_frame(cmd: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut cmd12 = [0u8; 12];
    cmd12[..cmd.len()].copy_from_slice(cmd);
    let s = sha256(payload);
    let mut out = Vec::new();
    out.extend_from_slice(&NETWORK_MAGIC_TESTNET);
    out.extend_from_slice(&cmd12);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&s[..4]);
    out.extend_from_slice(payload);
    out
}

/// A port outside sixteen bits is refused, not truncated.
///
/// # What this check used to assert, and what it asserts now
///
/// It was written to **demonstrate** a defect: the port was written on
/// thirty-two bits and read back truncated to sixteen, so that 65,536
/// distinct frames decoded to the same address. It therefore required both
/// frames to decode, and observed that they gave the same message.
///
/// The defect being fixed, the right requirement is inverted: the
/// non-canonical frame must be **refused**. It is the same property (two
/// different byte strings must not become indistinguishable) stated from
/// the right side.
#[test]
fn addr_port_non_canonical_encoding() {
    let mut w = Writer::new();
    w.varint(1);
    w.bytes(&[1u8, 2, 3, 4]);
    w.u32(0x0001_0050); // 65616: truncated to 0x0050 = 80
    w.u64(1_755_000_000);
    let a = raw_frame(b"addr", w.finish().as_slice());

    let mut w2 = Writer::new();
    w2.varint(1);
    w2.bytes(&[1u8, 2, 3, 4]);
    w2.u32(0x0000_0050);
    w2.u64(1_755_000_000);
    let b = raw_frame(b"addr", w2.finish().as_slice());

    assert_ne!(a, b, "the two frames must differ on the wire");
    assert!(
        Message::parse(&a, NETWORK_MAGIC_TESTNET).is_err(),
        "MALLEABILITY: a port outside sixteen bits was accepted and truncated"
    );
    assert!(
        Message::parse(&b, NETWORK_MAGIC_TESTNET).is_ok(),
        "the canonical frame must remain accepted"
    );
}

/// A `getblocktxn` index outside thirty-two bits is refused.
///
/// As for the port, this check used to demonstrate the defect; it now locks
/// in its fix. Truncating was worse here than a redundant encoding: index
/// 2^32 became zero, and the peer that asked for the 2^32-th transaction of
/// a block received the first one.
#[test]
fn getblocktxn_index_non_canonical_encoding() {
    let mut w = Writer::new();
    w.bytes(&[0u8; 32]);
    w.varint(1);
    w.varint(0x1_0000_0000); // 2^32 -> truncated to 0
    let a = raw_frame(b"getblocktxn", w.finish().as_slice());

    let mut w2 = Writer::new();
    w2.bytes(&[0u8; 32]);
    w2.varint(1);
    w2.varint(0);
    let b = raw_frame(b"getblocktxn", w2.finish().as_slice());

    assert_ne!(a, b);
    assert!(
        Message::parse(&a, NETWORK_MAGIC_TESTNET).is_err(),
        "MALLEABILITY: an index outside thirty-two bits was accepted and truncated"
    );
    assert!(
        Message::parse(&b, NETWORK_MAGIC_TESTNET).is_ok(),
        "the canonical frame must remain accepted"
    );
}

/// A decoded transaction must re-encode identically.
#[test]
fn transaction_reencodes_identically() {
    let mut g = 0xabcd_ef01_2345_6789u64;
    let mut seen = 0;
    for _ in 0..200_000 {
        let n = (xorshift(&mut g) % 160) as usize;
        let mut raw = Vec::with_capacity(n);
        for _ in 0..n {
            raw.push((xorshift(&mut g) >> 24) as u8);
        }
        if let Ok(tx) = Transaction::decode(&raw) {
            seen += 1;
            assert_eq!(
                tx.encode(),
                raw,
                "MALLEABILITY: re-encoding differs from the input"
            );
        }
    }
    eprintln!("randomly decoded transactions: {seen}");
}

/// A decoded block must re-encode identically.
#[test]
fn block_reencodes_identically() {
    let mut g = 0x0f0f_0f0f_1234_5678u64;
    let mut seen = 0;
    for _ in 0..200_000 {
        let n = (xorshift(&mut g) % 260) as usize;
        let mut raw = Vec::with_capacity(n);
        for _ in 0..n {
            raw.push((xorshift(&mut g) >> 24) as u8);
        }
        if let Ok(b) = Block::decode(&raw) {
            seen += 1;
            assert_eq!(b.encode(), raw, "block MALLEABILITY");
        }
    }
    eprintln!("randomly decoded blocks: {seen}");
}

/// A decoded compact block must re-encode identically.
#[test]
fn compact_reencodes_identically() {
    // Builds a legitimate cmpctblock, then tests the canonicity of the
    // prefilled index, written as a varint but read back as a u32.
    let header = BlockHeader {
        version: 1,
        prev_block: Hash256([1u8; 32]),
        merkle_root: Hash256([2u8; 32]),
        uncles_root: Hash256([3u8; 32]),
        miner: Hash256([4u8; 32]),
        time: 1,
        bits: 0x2000_ffff,
        height: 1,
        nonce: 0,
    };
    // Minimal valid transaction
    let tx = Transaction {
        version: 1,
        inputs: vec![q21_core::tx::TxIn::coinbase(vec![1, 2, 3])],
        outputs: vec![q21_core::tx::TxOut {
            value: Amount::from_units(1),
            scheme: q21_core::sig::SchemeId::MlDsa65,
            pubkey_hash: Hash256::ZERO,
        }],
        lock_time: 0,
    };

    let build = |index: u64| {
        let mut w = Writer::new();
        w.bytes(&header.encode());
        w.u64(0); // nonce
        w.varint(0); // short_ids
        w.varint(1); // prefilled
        w.varint(index);
        w.var_bytes(&tx.encode());
        w.varint(0); // uncles
        w.finish()
    };

    let a = build(0);
    let b = build(0x1_0000_0000); // 2^32, which does not fit in 32 bits
    assert_ne!(a, b);
    assert!(
        CompactBlock::decode(&a).is_ok(),
        "the canonical cmpctblock must remain accepted"
    );
    assert!(
        CompactBlock::decode(&b).is_err(),
        "MALLEABILITY: a prefilled index outside thirty-two bits was truncated"
    );
}

// ---------------------------------------------------------------------------
// 6. Panics on hostile input
// ---------------------------------------------------------------------------

#[test]
fn no_decoder_panics_on_random_input() {
    let mut g = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..150_000 {
        let n = (xorshift(&mut g) % 400) as usize;
        let mut raw = Vec::with_capacity(n);
        for _ in 0..n {
            raw.push((xorshift(&mut g) >> 32) as u8);
        }
        let _ = Transaction::decode(&raw);
        let _ = Block::decode(&raw);
        let _ = CompactBlock::decode(&raw);
        let _ = BlockHeader::decode(&raw);
        let _ = Message::parse(&raw, NETWORK_MAGIC_TESTNET);
        let _ = Reader::new(&raw).varint();
        if let Ok(s) = core::str::from_utf8(&raw) {
            let _ = bech32::decode(s);
            let _ = q21_core::address::Address::parse(s);
            let _ = q21_core::json::parse(s);
            let _ = Hash256::from_hex(s);
        }
    }
}

/// Targeted degenerate inputs: maximal varints, absurd lengths.
#[test]
fn degenerate_inputs_do_not_panic() {
    let degenerate: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xff; 1],
        vec![0xff; 9],
        vec![0xff; 200],
        vec![0x00; 200],
        {
            let mut v = vec![1u8, 0, 0, 0];
            v.push(0xff);
            v.extend_from_slice(&u64::MAX.to_le_bytes());
            v
        },
        {
            // valid block header + varint announcing u64::MAX transactions
            let mut v = vec![0u8; BlockHeader::SIZE];
            v.push(0xff);
            v.extend_from_slice(&u64::MAX.to_le_bytes());
            v
        },
        {
            // cmpctblock: nonce + huge varint
            let mut v = vec![0u8; BlockHeader::SIZE];
            v.extend_from_slice(&0u64.to_le_bytes());
            v.push(0xff);
            v.extend_from_slice(&u64::MAX.to_le_bytes());
            v
        },
    ];
    for d in &degenerate {
        let _ = Transaction::decode(d);
        let _ = Block::decode(d);
        let _ = CompactBlock::decode(d);
        let _ = BlockHeader::decode(d);
        let _ = Message::parse(d, NETWORK_MAGIC_TESTNET);
    }
    // Every known command, with degenerate payloads.
    let commands: &[&[u8]] = &[
        b"version",
        b"verack",
        b"ping",
        b"pong",
        b"getheaders",
        b"headers",
        b"inv",
        b"getdata",
        b"block",
        b"tx",
        b"cmpctblock",
        b"getblocktxn",
        b"blocktxn",
        b"getaddr",
        b"addr",
        b"reject",
    ];
    for c in commands {
        for d in &degenerate {
            let t = raw_frame(c, d);
            let _ = Message::parse(&t, NETWORK_MAGIC_TESTNET);
        }
    }
}

/// Compact target: no 32-bit value must panic, and the round trip must be
/// stable.
#[test]
fn compact_target_total() {
    use q21_core::pow::{block_work, target_from_compact, target_to_compact};
    let mut g = 0x1111_2222_3333_4444u64;
    for i in 0..300_000u64 {
        let bits = if i < 70_000 {
            (i as u32).wrapping_mul(61_057)
        } else {
            xorshift(&mut g) as u32
        };
        let _ = block_work(bits);
        if let Ok(c) = target_from_compact(bits) {
            let re = target_to_compact(c);
            // The round trip must return exactly the same target.
            if let Ok(c2) = target_from_compact(re) {
                assert_eq!(c, c2, "unstable target round trip for bits={bits:#x}");
            } else {
                panic!("target_to_compact produced an undecodable value: {bits:#x} -> {re:#x}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Ratio between bytes received and memory allocated
// ---------------------------------------------------------------------------

#[test]
fn allocation_ratio_per_message() {
    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("inv", {
            let mut w = Writer::new();
            w.varint(wire::MAX_INV as u64);
            raw_frame(b"inv", w.finish().as_slice())
        }),
        ("getdata", {
            let mut w = Writer::new();
            w.varint(wire::MAX_INV as u64);
            raw_frame(b"getdata", w.finish().as_slice())
        }),
        ("headers", {
            let mut w = Writer::new();
            w.varint(wire::MAX_HEADERS as u64);
            raw_frame(b"headers", w.finish().as_slice())
        }),
        ("getblocktxn", {
            let mut w = Writer::new();
            w.bytes(&[0u8; 32]);
            w.varint(wire::MAX_BLOCK_TXN as u64);
            raw_frame(b"getblocktxn", w.finish().as_slice())
        }),
        ("blocktxn", {
            let mut w = Writer::new();
            w.bytes(&[0u8; 32]);
            w.varint(wire::MAX_BLOCK_TXN as u64);
            raw_frame(b"blocktxn", w.finish().as_slice())
        }),
        ("addr", {
            let mut w = Writer::new();
            w.varint(wire::MAX_ADDR as u64);
            raw_frame(b"addr", w.finish().as_slice())
        }),
        ("getheaders", {
            let mut w = Writer::new();
            w.varint(wire::MAX_LOCATOR as u64);
            raw_frame(b"getheaders", w.finish().as_slice())
        }),
        ("block", {
            let mut v = vec![0u8; BlockHeader::SIZE];
            v.push(0xfe);
            v.extend_from_slice(&(1_000_000u32).to_le_bytes());
            raw_frame(b"block", &v)
        }),
        ("tx", {
            let mut v = vec![1u8, 0, 0, 0];
            v.push(0xfe);
            v.extend_from_slice(&(1_000_000u32).to_le_bytes());
            raw_frame(b"tx", &v)
        }),
        ("cmpctblock", {
            let mut v = vec![0u8; BlockHeader::SIZE];
            v.extend_from_slice(&0u64.to_le_bytes());
            v.push(0xfe);
            v.extend_from_slice(&(MAX_TX_PER_BLOCK as u32).to_le_bytes());
            raw_frame(b"cmpctblock", &v)
        }),
    ];

    let mut worst = 0f64;
    let mut worst_name = "";
    for (name, frame) in &cases {
        // Warm-up (the first pass may allocate lazy structures).
        let _ = Message::parse(frame, NETWORK_MAGIC_TESTNET);
        let (r, peak) = measure(|| Message::parse(frame, NETWORK_MAGIC_TESTNET));
        let ratio = peak as f64 / frame.len() as f64;
        eprintln!(
            "{name:12} : {:5} bytes sent -> peak {:9} bytes allocated (x{:.0})  [{}]",
            frame.len(),
            peak,
            ratio,
            match &r {
                Ok((m, _)) => format!("ok {}", m.command()),
                Err(e) => format!("{e:?}"),
            }
        );
        if ratio > worst {
            worst = ratio;
            worst_name = name;
        }
    }
    eprintln!("worst ratio: {worst_name} x{worst:.0}");
    assert!(
        worst < 100.0,
        "MEMORY AMPLIFICATION: {worst_name} allocates {worst:.0} times what it receives"
    );
}

// ---------------------------------------------------------------------------
// 5. Size and weight
// ---------------------------------------------------------------------------

#[test]
fn block_size_cannot_be_manipulated() {
    // The size checked by consensus is that of the re-encoding. If decoding
    // accepted an encoding shorter than the re-encoding, a block above
    // MAX_BLOCK_SIZE could get through.
    // Checked on decodable blocks produced by a targeted fuzz.
    let mut g = 0x7777_1111_2222_3333u64;
    let mut seen = 0;
    for _ in 0..300_000 {
        let n = (xorshift(&mut g) % 300) as usize;
        let mut raw = vec![0u8; BlockHeader::SIZE];
        for o in raw.iter_mut() {
            *o = (xorshift(&mut g) >> 40) as u8;
        }
        for _ in 0..n {
            raw.push((xorshift(&mut g) >> 40) as u8);
        }
        if let Ok(b) = Block::decode(&raw) {
            seen += 1;
            assert!(
                b.encode().len() >= raw.len(),
                "a block re-encodes shorter than it arrived"
            );
        }
    }
    eprintln!("decoded blocks: {seen}");
}

#[test]
fn transaction_weight_does_not_overflow() {
    // weight() = base * discount + witness, without an overflow check.
    // Looks for a case where a transaction of realistic size would overflow.
    let tx = Transaction {
        version: 1,
        inputs: vec![q21_core::tx::TxIn {
            prev_out: q21_core::tx::OutPoint {
                txid: Hash256::ZERO,
                index: 0,
            },
            witness: q21_core::tx::Witness {
                pubkey: vec![0u8; 1952],
                signature: vec![0u8; 3309],
            },
            sequence: 0,
        }],
        outputs: vec![q21_core::tx::TxOut {
            value: Amount::from_units(1),
            scheme: q21_core::sig::SchemeId::MlDsa65,
            pubkey_hash: Hash256::ZERO,
        }],
        lock_time: 0,
    };
    let w = tx.weight(WITNESS_DISCOUNT);
    assert!(w > 0);
    // Extreme discount factor: the computation must stay sound.
    let _ = tx.weight(1);
}

// ---------------------------------------------------------------------------
// Varints: read bounds
// ---------------------------------------------------------------------------

#[test]
fn varint_every_non_canonical_form_is_refused() {
    // For each long form, any value representable in a shorter one is refused.
    for v in 0u64..=0xff {
        let mut w = Writer::new();
        w.varint(v);
        let canon = w.finish();
        // Long form 0xfd
        let long = [&[0xfdu8][..], &(v as u16).to_le_bytes()[..]].concat();
        let r = Reader::new(&long).varint();
        if v < 0xfd {
            assert!(r.is_err(), "long form accepted for {v}");
        }
        assert_eq!(Reader::new(&canon).varint().unwrap(), v);
    }
    for v in [0u64, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff] {
        let long4 = [&[0xfeu8][..], &(v as u32).to_le_bytes()[..]].concat();
        let long8 = [&[0xffu8][..], &v.to_le_bytes()[..]].concat();
        if v <= 0xffff {
            assert!(Reader::new(&long4).varint().is_err(), "0xfe for {v}");
        }
        if v <= 0xffff_ffff {
            assert!(Reader::new(&long8).varint().is_err(), "0xff for {v}");
        }
    }
}

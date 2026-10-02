//! Audit of the ML-DSA dependency: crate `ml-dsa` 0.1.1, vendored.
//!
//! A signature is a consensus rule. Any difference in acceptance with FIPS
//! 204 — between two implementations or two versions — splits the chain; any
//! malleability affects the identifier of the witnesses. These tests
//! therefore go through the node's entry point, `q21_core::sig::verify`, and
//! cross-check with the crate itself when useful.
//!
//! What is established here:
//! - exact key and signature lengths, all others refused before the crate;
//! - "pure" ML-DSA, empty context, M' = 0 || 0 || M, identical on the wallet
//!   side and on the node side;
//! - HintBitUnpack (FIPS 204, alg. 21): non-increasing indices, duplicates,
//!   non-zero padding, counters > omega or decreasing refused at decoding;
//! - bound ||z|| < gamma1 - beta, including with a consistent c~;
//! - no byte modifiable without rejection, canonical encoding (decoding then
//!   re-encoding gives the same bytes);
//! - UseHint / Decompose edge vectors built with a key t1 = 0;
//! - no panic and a bounded time under fuzzing.
//!
//! Vectors: `tests/vectors/mldsa/t1_zero_edges.txt`, built locally
//! (construction described at the top of the file), 40 vectors, 507,282
//! bytes, SHA-256 cdb661c56a699ff12d3ac670ce5e9359b2295a5c5ef25562dfcc7706d079a737.
//! The C2SP/Wycheproof vectors (`testvectors_v1/mldsa_65_verify_test.json`,
//! `mldsa_87_verify_test.json`) and the NIST ACVP vectors were not available
//! offline when this test was written.

#![cfg(feature = "mldsa")]

use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::signature::Keypair;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, MlDsa87, MlDsaParams, Signature, SigningKey, B32};
use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::hash::{tagged_hash, tagged_hash_parts, tags, Hash256};
use q21_core::sha256::sha256;
use q21_core::sig::{self, SchemeId, VerifyError};
use q21_core::wallet::Wallet;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Parameters and tools
// ---------------------------------------------------------------------------

const GAMMA1: i64 = 1 << 19;

/// What describes the encoding of a signature for a parameter set.
#[derive(Clone, Copy)]
struct ParamSet {
    scheme: SchemeId,
    /// Length of c~ in bytes (lambda / 4).
    lambda: usize,
    k: usize,
    l: usize,
    omega: usize,
    beta: i64,
}

impl ParamSet {
    /// Start of z in the signature.
    fn z(&self) -> usize {
        self.lambda
    }
    /// Start of the hint encoding.
    fn h(&self) -> usize {
        self.lambda + self.l * 640
    }
}

const SET65: ParamSet = ParamSet {
    scheme: SchemeId::MlDsa65,
    lambda: 48,
    k: 6,
    l: 5,
    omega: 55,
    beta: 196,
};
const SET87: ParamSet = ParamSet {
    scheme: SchemeId::MlDsa87,
    lambda: 64,
    k: 8,
    l: 7,
    omega: 75,
    beta: 120,
};
const SETS: [ParamSet; 2] = [SET65, SET87];

/// Seed of the example key pair published by RustCrypto (bytes 0x00 to 0x1f).
const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Reproducible pseudo-random test generator.
struct Xs(u64);

impl Xs {
    fn n(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.n() as u8).collect()
    }
    fn below(&mut self, n: usize) -> usize {
        (self.n() % n as u64) as usize
    }
}

/// Reproducible signing randomness, presented under the trait expected by
/// `sign_randomized` (the wallet plugs `rng.rs` into it).
struct TestRng(Xs);

impl TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.n() as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.n())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.copy_from_slice(&self.0.bytes(dst.len()));
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

fn hex(o: &[u8]) -> String {
    o.iter().map(|b| format!("{b:02x}")).collect()
}

fn dehex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hexadecimal"))
        .collect()
}

/// Genuine (public key, signature) pair. `rnd` is the FIPS 204 randomness;
/// the signed message is M' = 0 || 0 || M, exactly what
/// `sign_randomized(M, b"", ..)` does in the wallet.
fn key_and_sig_p<P: MlDsaParams>(seed: [u8; 32], msg: &[u8], rnd: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::<P>::from_seed(&B32::from(seed));
    let pk = sk.verifying_key().encode()[..].to_vec();
    let sig = sk
        .expanded_key()
        .sign_internal(&[&[0u8, 0u8], msg], &B32::from(rnd))
        .encode()[..]
        .to_vec();
    (pk, sig)
}

fn key_and_sig(j: &ParamSet, seed: [u8; 32], msg: &[u8], rnd: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    match j.scheme {
        SchemeId::MlDsa65 => key_and_sig_p::<MlDsa65>(seed, msg, rnd),
        _ => key_and_sig_p::<MlDsa87>(seed, msg, rnd),
    }
}

/// Decoding only (sigDecode + norm check), by the crate.
fn decode_p<P: MlDsaParams>(sig: &[u8]) -> Option<Vec<u8>> {
    Signature::<P>::try_from(sig)
        .ok()
        .map(|s| s.encode()[..].to_vec())
}

/// Returns the re-encoding if the crate agrees to decode.
fn decode(j: &ParamSet, sig: &[u8]) -> Option<Vec<u8>> {
    match j.scheme {
        SchemeId::MlDsa65 => decode_p::<MlDsa65>(sig),
        _ => decode_p::<MlDsa87>(sig),
    }
}

/// Verification by the crate, without going through Q21.
fn crate_verify_p<P: MlDsaParams>(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(enc) = EncodedVerifyingKey::<P>::try_from(pk) else {
        return false;
    };
    let vk = ml_dsa::VerifyingKey::<P>::decode(&enc);
    Signature::<P>::try_from(sig)
        .map(|s| vk.verify_with_context(msg, &[], &s))
        .unwrap_or(false)
}

fn crate_verify(j: &ParamSet, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match j.scheme {
        SchemeId::MlDsa65 => crate_verify_p::<MlDsa65>(pk, msg, sig),
        _ => crate_verify_p::<MlDsa87>(pk, msg, sig),
    }
}

/// Verification through the node's entry point.
fn q21(j: &ParamSet, pk: &[u8], msg: &Hash256, sig: &[u8]) -> Result<(), VerifyError> {
    sig::verify(j.scheme, pk, msg, sig)
}

/// Hint indices of h, polynomial by polynomial (HintBitUnpack without
/// checks).
fn read_hints(j: &ParamSet, sig: &[u8]) -> Vec<Vec<u8>> {
    let h = &sig[j.h()..];
    let mut start = 0;
    (0..j.k)
        .map(|i| {
            let end = h[j.omega + i] as usize;
            let v = h[start..end].to_vec();
            start = end;
            v
        })
        .collect()
}

/// HintBitPack: writes indices and counters, zero padding.
fn write_hints(j: &ParamSet, sig: &mut [u8], polys: &[Vec<u8>]) {
    let h = &mut sig[j.h()..];
    h.iter_mut().for_each(|o| *o = 0);
    let mut n = 0;
    for (i, p) in polys.iter().enumerate() {
        for &x in p {
            h[n] = x;
            n += 1;
        }
        h[j.omega + i] = n as u8;
    }
    assert!(n <= j.omega);
}

/// Writes coefficient `c` of polynomial `p` of z, encodes gamma1 - z on 20
/// bits, little-endian bit by bit (BitPack, FIPS 204 alg. 17).
fn write_z(j: &ParamSet, sig: &mut [u8], p: usize, c: usize, z: i64) {
    let e = (GAMMA1 - z) as u32;
    assert!(e < 1 << 20);
    let base = (j.z() + p * 640) * 8 + c * 20;
    for b in 0..20 {
        let pos = base + b;
        let mask = 1u8 << (pos % 8);
        if (e >> b) & 1 == 1 {
            sig[pos / 8] |= mask;
        } else {
            sig[pos / 8] &= !mask;
        }
    }
}

/// A genuine signature whose hints lend themselves to every mutation: a
/// polynomial with at least two indices, free padding, a non-empty
/// polynomial followed by another.
fn suitable_signature(j: &ParamSet, msg: &Hash256) -> (Vec<u8>, Vec<u8>) {
    for counter in 0u64..1000 {
        let mut rnd = [0u8; 32];
        rnd[..8].copy_from_slice(&counter.to_le_bytes());
        let (pk, sig) = key_and_sig(j, SEED, msg.as_bytes(), rnd);
        let hints = read_hints(j, &sig);
        let total: usize = hints.iter().map(Vec::len).sum();
        let two = hints.iter().any(|p| p.len() >= 2);
        if two && total + 2 <= j.omega && total >= 3 {
            return (pk, sig);
        }
    }
    panic!("no suitable signature found");
}

// ---------------------------------------------------------------------------
// 1. Lengths
// ---------------------------------------------------------------------------

/// Q21's lengths are those of FIPS 204, and c~ does take lambda / 4 bytes
/// there: 48 for ML-DSA-65, 64 for ML-DSA-87.
#[test]
fn lengths_follow_from_the_parameters() {
    for j in SETS {
        assert_eq!(j.scheme.sig_len(), j.lambda + j.l * 640 + j.omega + j.k);
        assert_eq!(j.scheme.pubkey_len(), 32 + j.k * 320);
        let (pk, sig) = key_and_sig(&j, SEED, &[0u8; 32], [0u8; 32]);
        assert_eq!(pk.len(), j.scheme.pubkey_len());
        assert_eq!(sig.len(), j.scheme.sig_len());
    }
}

/// Any length other than the exact one is refused by Q21 before the crate,
/// and the crate refuses it on its side too.
#[test]
fn any_wrong_length_is_refused() {
    let m = Hash256([7u8; 32]);
    for j in SETS {
        let (pk, sig) = key_and_sig(&j, SEED, m.as_bytes(), [1u8; 32]);
        assert_eq!(q21(&j, &pk, &m, &sig), Ok(()));
        let (lp, ls) = (pk.len(), sig.len());

        for n in (0..=lp + 64).chain([2 * lp, 4 * lp]) {
            if n == lp {
                continue;
            }
            let mut p = pk.clone();
            p.resize(n, 0x5a);
            assert_eq!(
                q21(&j, &p, &m, &sig),
                Err(VerifyError::InvalidKeyLength {
                    expected: lp,
                    received: n
                })
            );
        }
        for n in (0..=ls + 64).chain([2 * ls, 4 * ls]) {
            if n == ls {
                continue;
            }
            let mut s = sig.clone();
            s.resize(n, 0x00);
            assert_eq!(
                q21(&j, &pk, &m, &s),
                Err(VerifyError::InvalidSignatureLength {
                    expected: ls,
                    received: n
                })
            );
            assert!(decode(&j, &s).is_none(), "the crate decodes {n} bytes");
        }
        // One byte truncated, one extra zero byte: the two common cases.
        assert!(q21(&j, &pk, &m, &sig[..ls - 1]).is_err());
        let mut longer = sig.clone();
        longer.push(0);
        assert!(q21(&j, &pk, &m, &longer).is_err());
    }
}

// ---------------------------------------------------------------------------
// 2. Message and context
// ---------------------------------------------------------------------------

/// Pure ML-DSA, empty context, on both sides.
///
/// - `sign_internal(0 || 0 || M)` with zero rnd gives, byte for byte, the
///   deterministic signature `sign_deterministic(M, "")`: M' is well formed;
/// - the wallet's path (`sign_randomized(M, b"", rng)`) verifies;
/// - a non-empty context, the internal variant without prefix, and the
///   pre-hash prefix (0x01) are refused by the node.
#[test]
fn pure_ml_dsa_empty_context_on_both_sides() {
    let m = tagged_hash("Q21/audit", b"context");
    fn case<P: MlDsaParams>(j: &ParamSet, m: &Hash256) {
        let sk = SigningKey::<P>::from_seed(&B32::from(SEED));
        let pk = sk.verifying_key().encode()[..].to_vec();
        let esk = sk.expanded_key();
        let rnd0 = B32::from([0u8; 32]);

        let det = esk
            .sign_deterministic(m.as_bytes(), b"")
            .expect("short ctx");
        let internal = esk.sign_internal(&[&[0u8, 0u8], m.as_bytes()], &rnd0);
        assert_eq!(det.encode(), internal.encode(), "M' = 0 || 0 || M");
        assert_eq!(sig::verify(j.scheme, &pk, m, &det.encode()), Ok(()));

        // Wallet path: hedged variant, empty context.
        let mut rng = TestRng(Xs(0xa1ea));
        let s = esk
            .sign_randomized(m.as_bytes(), b"", &mut rng)
            .expect("randomness");
        assert_ne!(
            s.encode(),
            det.encode(),
            "hedged differs from deterministic"
        );
        assert_eq!(sig::verify(j.scheme, &pk, m, &s.encode()), Ok(()));

        let refused = Err(VerifyError::InvalidSignature);
        let ctx = esk.sign_deterministic(m.as_bytes(), b"Q21").expect("ctx");
        assert_eq!(sig::verify(j.scheme, &pk, m, &ctx.encode()), refused);
        let ctx255 = esk
            .sign_deterministic(m.as_bytes(), &[0u8; 255])
            .expect("ctx");
        assert_eq!(sig::verify(j.scheme, &pk, m, &ctx255.encode()), refused);
        let raw = esk.sign_internal(&[m.as_bytes()], &rnd0);
        assert_eq!(sig::verify(j.scheme, &pk, m, &raw.encode()), refused);
        let pre = esk.sign_internal(&[&[1u8, 0u8], m.as_bytes()], &rnd0);
        assert_eq!(sig::verify(j.scheme, &pk, m, &pre.encode()), refused);
        // Context longer than 255 bytes: the crate refuses to sign.
        assert!(esk.sign_deterministic(m.as_bytes(), &[0u8; 256]).is_err());
    }
    case::<MlDsa65>(&SET65, &m);
    case::<MlDsa87>(&SET87, &m);
}

/// End to end on ML-DSA-87, the default scheme: the wallet signs, consensus
/// verifies the same hash. Then what malleability implies: the key holder can
/// produce another valid signature (hedged variant), which changes the
/// `wtxid` but never the `txid`; a third party cannot touch a single bit.
#[test]
fn wallet_and_node_sign_and_verify_the_same_message() {
    let network = Network::Regtest;
    let seed = [0x21u8; 32];
    let mut w = Wallet::from_seed_scheme(seed, network, SchemeId::MlDsa87).expect("ML-DSA-87");
    let _ = w.new_address();
    let mut c = Chain::new(network, genesis_block(network));
    for i in 0..(COINBASE_MATURITY + 2) {
        let a = w.new_address();
        assert_eq!(a.scheme, SchemeId::MlDsa87);
        let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(a.hash, SchemeId::MlDsa87, &[], t, 20_000_000)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }
    let mut dest = Wallet::from_seed_scheme([0x22; 32], network, SchemeId::MlDsa87).expect("87");
    let a = dest.new_address();
    let tx = w
        .create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(50_000),
            Amount::from_units(1_000),
        )
        .expect("build");
    let check = |tx: &q21_core::tx::Transaction| {
        let mut seen = std::collections::HashSet::new();
        q21_core::validate::check_transaction(tx, &c.utxo, network, c.height() + 1, &mut seen)
    };
    assert_eq!(check(&tx), Ok(Amount::from_units(1_000)));

    // The revealed key is bound to the lock by pubkey_hash(scheme, key).
    let spent = c.utxo.get(&tx.inputs[0].prev_out).expect("utxo").output;
    let witness = &tx.inputs[0].witness;
    assert_eq!(
        sig::pubkey_hash(SchemeId::MlDsa87, &witness.pubkey),
        spent.pubkey_hash
    );
    assert_ne!(
        sig::pubkey_hash(SchemeId::MlDsa65, &witness.pubkey),
        spent.pubkey_hash
    );

    // Recovers the seed derived for the index, as the wallet's private
    // `derived_seed` does.
    let derived = (0u32..400)
        .map(|i| {
            tagged_hash_parts(
                tags::WALLET_SEED,
                &[&seed, &i.to_le_bytes(), &[SchemeId::MlDsa87.as_u8()]],
            )
            .0
        })
        .find(|g| {
            SigningKey::<MlDsa87>::from_seed(&B32::from(*g))
                .verifying_key()
                .encode()[..]
                == witness.pubkey[..]
        })
        .expect("index found");
    let sk = SigningKey::<MlDsa87>::from_seed(&B32::from(derived));
    let message = tx.sighash(0, network, &spent);

    // The wallet signed exactly `sighash` in pure ML-DSA, empty context.
    assert_eq!(
        sig::verify(
            SchemeId::MlDsa87,
            &witness.pubkey,
            &message,
            &witness.signature
        ),
        Ok(())
    );

    // Second signature by the holder: valid, same txid, different wtxid.
    let mut rng = TestRng(Xs(0x5ec0));
    let other = sk
        .expanded_key()
        .sign_randomized(message.as_bytes(), b"", &mut rng)
        .expect("randomness")
        .encode()[..]
        .to_vec();
    assert_ne!(other, witness.signature);
    let mut tx2 = tx.clone();
    tx2.inputs[0].witness.signature = other;
    assert_eq!(check(&tx2), Ok(Amount::from_units(1_000)));
    assert_eq!(tx2.txid(), tx.txid(), "the txid ignores the witness");
    assert_ne!(tx2.wtxid(), tx.wtxid(), "the wtxid commits to the witness");
    assert_ne!(tx2.merkle_leaf(), tx.merkle_leaf(), "so does the leaf");

    // A third party: one bit flipped in each area, refused by consensus.
    for pos in [0, SET87.z() + 7, SET87.h() + 1, SET87.h() + SET87.omega] {
        let mut tx3 = tx.clone();
        tx3.inputs[0].witness.signature[pos] ^= 0x01;
        assert!(check(&tx3).is_err(), "byte {pos}");
    }
}

// ---------------------------------------------------------------------------
// 3. Malleability: hints (HintBitUnpack, FIPS 204 alg. 21)
// ---------------------------------------------------------------------------

/// Any malformed shape of the hints is refused *at decoding*, not only
/// because c~ no longer matches. GHSA-5x2r-hc65-25f9 (duplicates accepted,
/// ml-dsa <= 0.1.0-rc.3) does not apply to 0.1.1: the duplicate is refused
/// here.
#[test]
fn malformed_hints_refused_at_decoding() {
    let m = tagged_hash("Q21/audit", b"hints");
    for j in SETS {
        let (pk, sig) = suitable_signature(&j, &m);
        let hints = read_hints(&j, &sig);
        let total: usize = hints.iter().map(Vec::len).sum();
        let p = hints.iter().position(|v| v.len() >= 2).expect("suitable");
        let start: usize = hints[..p].iter().map(Vec::len).sum();
        let h = j.h();

        let mut mutants: Vec<(&str, Vec<u8>)> = Vec::new();
        // Two neighboring indices swapped: not increasing.
        let mut s = sig.clone();
        s.swap(h + start, h + start + 1);
        mutants.push(("swap", s));
        // Duplicated index: equality, refused (strictly increasing).
        let mut s = sig.clone();
        s[h + start + 1] = s[h + start];
        mutants.push(("duplicate", s));
        // Non-zero padding right after the last index, then at the end.
        let mut s = sig.clone();
        s[h + total] = 1;
        mutants.push(("padding 1", s));
        let mut s = sig.clone();
        s[h + j.omega - 1] = 0xff;
        mutants.push(("padding at the end", s));
        // Last counter beyond omega.
        for v in [j.omega + 1, 0xff] {
            let mut s = sig.clone();
            s[h + j.omega + j.k - 1] = v as u8;
            mutants.push(("counter > omega", s));
        }
        // Decreasing counters.
        let mut s = sig.clone();
        s[h + j.omega] = s[h + j.omega + 1].wrapping_add(1);
        mutants.push(("decreasing counters", s));

        for (name, s) in &mutants {
            assert!(
                decode(&j, s).is_none(),
                "{}: {name} decodes",
                j.scheme.name()
            );
            assert_eq!(
                q21(&j, &pk, &m, s),
                Err(VerifyError::InvalidSignature),
                "{}: {name}",
                j.scheme.name()
            );
        }
    }
}

/// Well-formed but different hints: decoding passes (and re-encodes
/// identically), verification fails. Adding, removing, moving an index from
/// one polynomial to the next.
#[test]
fn well_formed_but_modified_hints_refused() {
    let m = tagged_hash("Q21/audit", b"well-formed hints");
    for j in SETS {
        let (pk, sig) = suitable_signature(&j, &m);
        let hints = read_hints(&j, &sig);
        let mut variants: Vec<(&str, Vec<Vec<u8>>)> = Vec::new();

        // Removal of the last index of a non-empty polynomial.
        let p = hints.iter().position(|v| !v.is_empty()).expect("non-empty");
        let mut v = hints.clone();
        v[p].pop();
        variants.push(("removal", v));
        // Addition of a free index in each polynomial where possible.
        for (i, poly) in hints.iter().enumerate() {
            if let Some(free) = (0..=255u8).find(|x| !poly.contains(x)) {
                let mut v = hints.clone();
                v[i].push(free);
                v[i].sort_unstable();
                variants.push(("addition", v));
            }
        }
        // Moving the last index of a polynomial to the next one, when the
        // strict order is still respected.
        for i in 0..j.k - 1 {
            if let Some(&x) = hints[i].last() {
                if hints[i + 1].first().map_or(true, |&y| x < y) {
                    let mut v = hints.clone();
                    v[i].pop();
                    v[i + 1].insert(0, x);
                    variants.push(("move", v));
                }
            }
        }
        assert!(variants.len() >= 3);
        for (name, v) in &variants {
            let mut s = sig.clone();
            write_hints(&j, &mut s, v);
            assert_ne!(s, sig);
            assert_eq!(decode(&j, &s).as_deref(), Some(&s[..]), "{name} canonical");
            assert_eq!(
                q21(&j, &pk, &m, &s),
                Err(VerifyError::InvalidSignature),
                "{}: {name}",
                j.scheme.name()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Malleability: z, c~, any byte
// ---------------------------------------------------------------------------

/// Bound of z at decoding: |z| = gamma1 - beta - 1 passes, gamma1 - beta is
/// refused (FIPS 204 alg. 8, line 13), likewise for the encodable extremes.
/// The encoding of z is a bijection on 20 bits: there is no other encoding of
/// the same z (checked by identical re-encoding).
#[test]
fn bound_of_z_at_decoding() {
    let m = tagged_hash("Q21/audit", b"z");
    for j in SETS {
        let (pk, sig) = key_and_sig(&j, SEED, m.as_bytes(), [3u8; 32]);
        let lim = GAMMA1 - j.beta;
        for (z, allowed) in [
            (lim - 1, true),
            (-(lim - 1), true),
            (lim, false),
            (-lim, false),
            (GAMMA1, false),
            (-GAMMA1 + 1, false),
            (0, true),
        ] {
            for (p, c) in [(0, 0), (j.l - 1, 255), (j.l / 2, 101)] {
                let mut s = sig.clone();
                write_z(&j, &mut s, p, c, z);
                let d = decode(&j, &s);
                assert_eq!(d.is_some(), allowed, "{} z={z}", j.scheme.name());
                if let Some(re) = d {
                    assert_eq!(re, s, "identical re-encoding");
                }
                if s != sig {
                    assert_eq!(q21(&j, &pk, &m, &s), Err(VerifyError::InvalidSignature));
                }
            }
        }
    }
}

/// Every byte of the signature, flipped one bit at a time: none leaves the
/// signature valid. Covers c~ up to its last byte, z and h.
#[test]
fn no_byte_can_be_modified() {
    let m = tagged_hash("Q21/audit", b"every byte");
    for j in SETS {
        let (pk, sig) = key_and_sig(&j, SEED, m.as_bytes(), [9u8; 32]);
        assert_eq!(q21(&j, &pk, &m, &sig), Ok(()));
        for pos in 0..sig.len() {
            let mut s = sig.clone();
            s[pos] ^= 1 << (pos % 8);
            assert_eq!(
                q21(&j, &pk, &m, &s),
                Err(VerifyError::InvalidSignature),
                "{} byte {pos}",
                j.scheme.name()
            );
        }
        // Last byte of c~ alone: c~ is compared over its whole length.
        let mut s = sig.clone();
        s[j.lambda - 1] ^= 0x80;
        assert!(q21(&j, &pk, &m, &s).is_err());
        // Public key: one bit of rho, one bit of t1.
        for pos in [0, 31, 32, pk.len() - 1] {
            let mut p = pk.clone();
            p[pos] ^= 0x01;
            assert!(q21(&j, &p, &m, &sig).is_err(), "key byte {pos}");
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Vectors
// ---------------------------------------------------------------------------

struct Vector {
    id: u32,
    set: ParamSet,
    case: String,
    valid: bool,
    pk: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

fn read_vectors() -> Vec<Vector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/mldsa/t1_zero_edges.txt"
    );
    let text = std::fs::read_to_string(path).expect("vector file");
    assert_eq!(
        hex(&sha256(text.as_bytes())),
        "cdb661c56a699ff12d3ac670ce5e9359b2295a5c5ef25562dfcc7706d079a737",
        "the vector file has changed"
    );
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let field = |key: &str| {
            block
                .lines()
                .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(": ")))
                .map(str::to_owned)
        };
        let Some(id) = field("id") else { continue };
        out.push(Vector {
            id: id.parse().expect("id"),
            set: if field("set").as_deref() == Some("1") {
                SET65
            } else {
                SET87
            },
            case: field("case").expect("case"),
            valid: field("expected").as_deref() == Some("valid"),
            pk: dehex(&field("pk").expect("pk")),
            msg: dehex(&field("msg").expect("msg")),
            sig: dehex(&field("sig").expect("sig")),
        });
    }
    out
}

/// Edge vectors built with a key t1 = 0: UseHint with r0 = 0
/// (GHSA-h37v-hp6w-2pp8, fixed in 0.1.0-rc.5), r = 0, r = q - 1, edge cases
/// of Decompose, r0 = gamma2 and -gamma2 + 1, bound of z with a consistent
/// c~, exactly omega hints. Each invalid vector differs from a valid one by a
/// single faulty choice; Q21 and the crate must return the expected verdict,
/// without exception.
#[test]
fn fips_204_edge_vectors() {
    let v = read_vectors();
    assert_eq!(v.len(), 40);
    let mut tally = [[0u32; 2]; 2];
    for t in &v {
        let msg = Hash256(t.msg.as_slice().try_into().expect("32 bytes"));
        let r = q21(&t.set, &t.pk, &msg, &t.sig);
        let expected = if t.valid {
            Ok(())
        } else {
            Err(VerifyError::InvalidSignature)
        };
        assert_eq!(r, expected, "vector {} ({})", t.id, t.case);
        assert_eq!(
            crate_verify(&t.set, &t.pk, &t.msg, &t.sig),
            t.valid,
            "crate, vector {}",
            t.id
        );
        // Valid vectors have a canonical encoding.
        if t.valid {
            assert_eq!(decode(&t.set, &t.sig).as_deref(), Some(&t.sig[..]));
        }
        let i = usize::from(t.set.scheme == SchemeId::MlDsa87);
        tally[i][usize::from(t.valid)] += 1;
    }
    println!(
        "ML-DSA-65: {} valid, {} invalid; ML-DSA-87: {} valid, {} invalid",
        tally[0][1], tally[0][0], tally[1][1], tally[1][0]
    );
    assert_eq!(tally, [[8, 12], [8, 12]]);
}

/// Non-regression pins: deterministic signature (zero rnd) for RustCrypto's
/// example seed. A crate update that changed the encoding or the signing
/// algorithm shows up here. The derived key is already compared with the
/// published PKCS#8 files (`sig::mldsa_tests`).
#[test]
fn deterministic_signature_pins() {
    let m = [0x51u8; 32];
    let expected_hashes = [
        (
            SET65,
            "16e4cdf6251ef0feab38b6ed19da925557bda6c2f5de3d7500cfe9a953d74527",
        ),
        (
            SET87,
            "da2d2303bfce8731007fa1a8c37ed420e9d6dbd6640768eeb37b77b9d411b3f2",
        ),
    ];
    for (j, expected) in expected_hashes {
        let (pk, sig) = key_and_sig(&j, SEED, &m, [0u8; 32]);
        let h = hex(&sha256(&sig));
        println!("{}: {h}", j.scheme.name());
        assert_eq!(h, expected, "{}", j.scheme.name());
        assert_eq!(q21(&j, &pk, &Hash256(m), &sig), Ok(()));
    }
}

// ---------------------------------------------------------------------------
// 6. Binding of the scheme
// ---------------------------------------------------------------------------

/// The scheme comes from the spent output, not from the witness; it goes into
/// the hash of the key and into the signed hash. A reserved scheme without a
/// verifier is never accepted.
#[test]
fn the_scheme_is_bound_to_the_key_and_the_address() {
    let m = Hash256([1u8; 32]);
    let (pk87, sig87) = key_and_sig(&SET87, SEED, m.as_bytes(), [0u8; 32]);
    let (pk65, sig65) = key_and_sig(&SET65, SEED, m.as_bytes(), [0u8; 32]);
    assert!(matches!(
        sig::verify(SchemeId::MlDsa65, &pk87, &m, &sig87),
        Err(VerifyError::InvalidKeyLength { .. })
    ));
    assert!(matches!(
        sig::verify(SchemeId::MlDsa87, &pk65, &m, &sig65),
        Err(VerifyError::InvalidKeyLength { .. })
    ));
    assert_ne!(
        sig::pubkey_hash(SchemeId::MlDsa65, &pk87),
        sig::pubkey_hash(SchemeId::MlDsa87, &pk87)
    );
    // SPHINCS+: exact sizes, never accepted, forbidden everywhere.
    let s = SchemeId::SphincsPlus;
    assert_eq!(
        sig::verify(s, &vec![0; s.pubkey_len()], &m, &vec![0; s.sig_len()]),
        Err(VerifyError::SchemeUnavailable(s))
    );
    for r in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        assert!(!s.allowed_on(r));
    }
}

// ---------------------------------------------------------------------------
// 7. Robustness
// ---------------------------------------------------------------------------

/// Tally of a campaign: number of attempts, acceptances, maximum time.
#[derive(Default)]
struct Tally {
    attempts: u64,
    accepted: u64,
    decoded: u64,
    max: Duration,
    total: Duration,
}

impl Tally {
    fn measure(&mut self, f: impl FnOnce() -> Result<(), VerifyError>) -> bool {
        let t = Instant::now();
        let r = f();
        let d = t.elapsed();
        self.attempts += 1;
        self.total += d;
        self.max = self.max.max(d);
        let ok = r.is_ok();
        self.accepted += u64::from(ok);
        ok
    }
}

/// Fuzzing campaign on the node's entry point. A panic would kill the node
/// (`panic = "abort"`, `overflow-checks = true`): here it would make the
/// test fail.
fn campaign(n: u64, seed: u64) {
    let mut r = Xs(seed);
    let m = tagged_hash("Q21/audit", b"fuzz");
    for j in SETS {
        let (pk, sig) = key_and_sig(&j, SEED, m.as_bytes(), [5u8; 32]);
        let (lp, ls) = (pk.len(), sig.len());
        let mut random = Tally::default();
        let mut mutated = Tally::default();
        let mut lengths = Tally::default();

        for _ in 0..n {
            // Fully random key and signature, exact lengths.
            let p = r.bytes(lp);
            let s = r.bytes(ls);
            assert!(!random.measure(|| q21(&j, &p, &m, &s)));

            // Genuine signature mutated: bits, bytes, hint area, coefficients
            // of z at the bounds; sometimes the key too.
            let mut s = sig.clone();
            let mut p = pk.clone();
            for _ in 0..1 + r.below(4) {
                match r.below(6) {
                    0 => {
                        let i = r.below(ls);
                        s[i] ^= 1 << r.below(8);
                    }
                    1 => {
                        let i = r.below(ls);
                        s[i] = r.n() as u8;
                    }
                    2 => {
                        let i = j.h() + r.below(j.omega + j.k);
                        s[i] = r.n() as u8;
                    }
                    3 => {
                        let i = j.h() + j.omega + r.below(j.k);
                        s[i] = [0, j.omega as u8, j.omega as u8 + 1, 0xff][r.below(4)];
                    }
                    4 => {
                        let lim = GAMMA1 - j.beta;
                        let z = [lim - 1, lim, -lim, GAMMA1, 1 - GAMMA1][r.below(5)];
                        write_z(&j, &mut s, r.below(j.l), r.below(256), z);
                    }
                    _ => {
                        let i = r.below(lp);
                        p[i] ^= 1 << r.below(8);
                    }
                }
            }
            if let Some(re) = decode(&j, &s) {
                mutated.decoded += 1;
                assert_eq!(re, s, "canonical encoding");
            }
            let accepted = mutated.measure(|| q21(&j, &p, &m, &s));
            assert_eq!(accepted, s == sig && p == pk, "mutation accepted");

            // Any length, any content.
            let lpx = r.below(lp * 2);
            let lsx = r.below(ls * 2);
            let p = r.bytes(lpx);
            let s = r.bytes(lsx);
            let ok = lengths.measure(|| q21(&j, &p, &m, &s));
            assert!(!ok);
        }
        for (name, b) in [
            ("random", &random),
            ("mutated", &mutated),
            ("lengths", &lengths),
        ] {
            println!(
                "{} {name:<10}: {} attempts, {} accepted, {} decoded, mean {:?}, max {:?}",
                j.scheme.name(),
                b.attempts,
                b.accepted,
                b.decoded,
                b.total / b.attempts.max(1) as u32,
                b.max
            );
            // Wide bound: a verification costs less than a millisecond; a
            // decoder that loops would show up here.
            assert!(b.max < Duration::from_millis(250), "{name}: {:?}", b.max);
        }
    }
}

#[test]
fn fuzz_verification_without_panic_or_time_drift() {
    campaign(1_500, 0x51_2026);
}

/// Long campaign, outside ordinary runs:
/// `cargo test --release --features audit --test audit_mldsa -- --ignored --nocapture`
#[test]
#[ignore = "long campaign"]
fn fuzz_verification_long() {
    campaign(50_000, 0x0dd_ba11);
}

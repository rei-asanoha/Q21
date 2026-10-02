//! Signature schemes and algorithmic agility.
//!
//! This is where the lesson of section 4 of the white paper plays out. Bitcoin
//! is a prisoner of ECDSA because its original address format never
//! considered that another scheme could exist. Q21 encodes the scheme
//! identifier in the address itself: adding a scheme becomes a compatible
//! evolution, never a chain split.
//!
//! # Why ML-DSA is not implemented in this file
//!
//! Writing a lattice-based signature scheme yourself is professional
//! malpractice. Side channels, rejection sampling and constant-time modular
//! arithmetic are exactly the ground where a home-made implementation looks
//! correct, passes every functional test, and leaks the private key.
//!
//! A useful reminder: in February 2022, Rainbow — a NIST competition
//! finalist — fell in a weekend on a laptop. A few months later, SIKE fell in
//! an hour on a single core. These schemes had survived five years of public
//! review by professional cryptographers. Our home-made code would not have
//! survived five minutes.
//!
//! So this module defines the interface. The implementation is wired in
//! through the `mldsa` feature, backed by RustCrypto's `ml-dsa` crate.

use crate::hash::{tagged_hash, tags, Hash256};

/// Scheme identifier, as it appears in the address and in the witness.
///
/// The numeric value is part of consensus: it must never change once the
/// genesis block has been produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum SchemeId {
    /// NIST security level 3, roughly AES-192.
    ///
    /// Kept for uses where throughput matters more than margin: a
    /// transaction weighs 5,403 bytes there instead of 7,361, that is 370
    /// transactions per block instead of 271.
    MlDsa65 = 1,
    /// **Q21 default.** NIST security level 5, roughly AES-256.
    ///
    /// # Why the maximum level, and not the usual level
    ///
    /// The choice comes down to what it costs, and measurement settled it. On
    /// an ordinary machine:
    ///
    /// | | ML-DSA-65 | ML-DSA-87 |
    /// |---|---|---|
    /// | verifications per second | 3,944 | 2,494 |
    /// | **full block verified in** | **94 ms** | **109 ms** |
    ///
    /// The block target is one hundred twenty seconds. The maximum level of
    /// the standard therefore costs **fifteen milliseconds per block**:
    /// nothing anyone will ever notice.
    ///
    /// What is really paid is throughput — 271 transactions per block instead
    /// of 370, for the same size. That is the only real trade-off, and it
    /// leans toward margin: a chain is launched once, and the addresses it
    /// issues live for decades.
    ///
    /// # What would have served no purpose
    ///
    /// Lengthening the **seed** to 512 bits. FIPS 204 fixes it at thirty-two
    /// bytes for all three levels, and the quantum resistance of ML-DSA does
    /// not come from its length but from the lattice problem. A 256-bit seed
    /// against Grover is worth 2^128: a wall nothing will reach. Lengthening
    /// it would have required rewriting ML-DSA by hand — the one thing this
    /// project forbids itself.
    MlDsa87 = 2,
    /// The parachute. Security based only on hash functions, hence on
    /// assumptions independent of lattices.
    SphincsPlus = 3,
    /// Lamport, one-time use. **Test networks only.**
    ///
    /// Present so that the chain is usable — mine, sign, transfer — before
    /// ML-DSA was wired in. Reusing a key reveals the private key;
    /// [`SchemeId::allowed_on`] therefore forbids it on mainnet, and this ban
    /// is a consensus rule, not a recommendation.
    LamportOts = 4,
}

impl SchemeId {
    pub fn from_u8(v: u8) -> Option<SchemeId> {
        match v {
            1 => Some(SchemeId::MlDsa65),
            2 => Some(SchemeId::MlDsa87),
            3 => Some(SchemeId::SphincsPlus),
            4 => Some(SchemeId::LamportOts),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            SchemeId::MlDsa65 => "ML-DSA-65",
            SchemeId::MlDsa87 => "ML-DSA-87",
            SchemeId::SphincsPlus => "SPHINCS+-SHA2-192s",
            SchemeId::LamportOts => "Lamport-OTS (test only)",
        }
    }

    /// Expected size of a public key, in bytes.
    pub const fn pubkey_len(self) -> usize {
        match self {
            SchemeId::MlDsa65 => 1952,
            SchemeId::MlDsa87 => 2592,
            SchemeId::SphincsPlus => 48,
            SchemeId::LamportOts => crate::lamport::PUBKEY_LEN,
        }
    }

    /// Expected size of a signature, in bytes.
    ///
    /// Compare with the 71 bytes of ECDSA. This is the line that drives block
    /// sizing.
    pub const fn sig_len(self) -> usize {
        match self {
            SchemeId::MlDsa65 => 3309,
            SchemeId::MlDsa87 => 4627,
            SchemeId::SphincsPlus => 16224,
            SchemeId::LamportOts => crate::lamport::SIG_LEN,
        }
    }

    /// All the schemes recognized by the protocol.
    pub const ALL: [SchemeId; 4] = [
        SchemeId::MlDsa65,
        SchemeId::MlDsa87,
        SchemeId::SphincsPlus,
        SchemeId::LamportOts,
    ];

    /// Consensus rule: which schemes are accepted on which network.
    ///
    /// Lamport is one-time. A reused key reveals the private key, and nothing
    /// lets a validator detect the reuse before it is too late. Mainnet
    /// therefore refuses it outright.
    ///
    /// This rule lives in consensus and not in the documentation, because a
    /// documented rule is a rule that gets forgotten.
    pub const fn allowed_on(self, network: crate::address::Network) -> bool {
        match self {
            SchemeId::LamportOts => !matches!(network, crate::address::Network::Mainnet),
            SchemeId::MlDsa65 | SchemeId::MlDsa87 => true,
            // SPHINCS+ is reserved in the enumeration but has no verification
            // implementation ([`Self::is_available`] is false everywhere,
            // without even depending on a build option). As long as it is not
            // implemented, the protocol allows it nowhere: allowing an output
            // to be locked to it let funds burn that NOBODY could ever spend
            // — verification would always return `SchemeUnavailable`. Silent
            // burn found by the phase 8b red team. The day a backend exists,
            // this arm opens — not before.
            SchemeId::SphincsPlus => false,
        }
    }

    /// A key of this scheme can be used only once.
    ///
    /// True for Lamport, and for it alone. It is a property of the scheme,
    /// not a precaution: signing twice with the same Lamport key reveals the
    /// private key. ML-DSA does not have this constraint — the wallet still
    /// changes address every time, but for privacy.
    pub const fn is_one_time(self) -> bool {
        matches!(self, SchemeId::LamportOts)
    }

    /// Can this binary verify this scheme?
    ///
    /// Distinct from [`Self::allowed_on`]: the protocol may allow a scheme
    /// that this build cannot handle. A node that meets this case must refuse
    /// the transaction, never accept it without verifying it.
    pub const fn is_available(self) -> bool {
        match self {
            SchemeId::LamportOts => true,
            SchemeId::MlDsa65 | SchemeId::MlDsa87 => cfg!(feature = "mldsa"),
            SchemeId::SphincsPlus => false,
        }
    }
}

/// Hash of a public key, as it appears in an address.
///
/// The full key is revealed only when spending: an ML-DSA-65 address would
/// otherwise carry 1952 bytes, which would make it unusable.
pub fn pubkey_hash(scheme: SchemeId, pubkey: &[u8]) -> Hash256 {
    let mut buf = Vec::with_capacity(1 + pubkey.len());
    buf.push(scheme.as_u8());
    buf.extend_from_slice(pubkey);
    tagged_hash(tags::ADDRESS, &buf)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VerifyError {
    /// The scheme is not yet compiled into this binary.
    SchemeUnavailable(SchemeId),
    /// Wrong public key length for this scheme.
    InvalidKeyLength { expected: usize, received: usize },
    /// Wrong signature length for this scheme.
    InvalidSignatureLength { expected: usize, received: usize },
    /// The signature does not verify.
    InvalidSignature,
}

/// Checks that the announced sizes match the scheme.
///
/// This check is useful even without a cryptographic implementation wired
/// in: it rejects a malformed transaction before any expensive computation,
/// and is therefore part of the defense against denial of service.
pub fn check_sizes(scheme: SchemeId, pubkey: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    if pubkey.len() != scheme.pubkey_len() {
        return Err(VerifyError::InvalidKeyLength {
            expected: scheme.pubkey_len(),
            received: pubkey.len(),
        });
    }
    if sig.len() != scheme.sig_len() {
        return Err(VerifyError::InvalidSignatureLength {
            expected: scheme.sig_len(),
            received: sig.len(),
        });
    }
    Ok(())
}

/// Verifies a signature.
///
/// Without the `mldsa` feature, the format checks apply but cryptographic
/// verification returns `SchemeUnavailable`. This behavior is deliberately
/// loud: a node must never accept a signature it has not verified.
pub fn verify(
    scheme: SchemeId,
    pubkey: &[u8],
    message: &Hash256,
    sig: &[u8],
) -> Result<(), VerifyError> {
    check_sizes(scheme, pubkey, sig)?;

    // Lamport depends on no external crate: always available.
    if scheme == SchemeId::LamportOts {
        return if crate::lamport::verify(pubkey, message, sig) {
            Ok(())
        } else {
            Err(VerifyError::InvalidSignature)
        };
    }

    #[cfg(feature = "mldsa")]
    {
        if let Some(r) = mldsa_backend::verify(scheme, pubkey, message.as_bytes(), sig) {
            return if r {
                Ok(())
            } else {
                Err(VerifyError::InvalidSignature)
            };
        }
    }

    let _ = message;
    Err(VerifyError::SchemeUnavailable(scheme))
}

/// Adapter to RustCrypto's `ml-dsa` crate.
///
/// Compiled only with `--features mldsa`. Splitting it into a module fully
/// isolates the rest of the core from the crate's API: if that API evolves,
/// only this file moves.
/// # Design choices checked against the `ml-dsa` 0.1.1 sources
///
/// **`VerifyingKey::decode` is infallible.** It returns `Self`, not
/// `Option<Self>`: any sequence of 1952 bytes decodes into *a* key. A public
/// key is therefore never "invalid" — it is only well or badly formed in
/// length, which `check_sizes` has already decided. Q21 must above all not
/// invent an extra rejection here: it would be a consensus rule that other
/// implementations would not have.
///
/// **`Signature::decode` is fallible**, on the other hand. In particular it
/// rejects signatures whose infinity norm of `z` exceeds `GAMMA1 - BETA`. A
/// malformed signature is therefore invalid, not unavailable: we return
/// `Some(false)` and not `None`.
///
/// **The context is empty.** `Verifier::verify` calls FIPS 204
/// `ML-DSA.Verify` with `ctx = []`. This is "pure" ML-DSA. Q21 already binds
/// the transaction to its scheme through the tagged hash of `pubkey_hash`,
/// and a non-empty context would be a divergence from the standard.
#[cfg(feature = "mldsa")]
mod mldsa_backend {
    use super::SchemeId;
    use ml_dsa::{
        signature::Verifier, EncodedVerifyingKey, MlDsa65, MlDsa87, MlDsaParams, Signature,
        VerifyingKey,
    };

    /// Verification generic over the parameter set.
    ///
    /// `None` means "I do not know how to verify", `Some(false)` means "I
    /// verified and it is false". Confusing the two would accept by default
    /// what could not be read.
    fn verify_params<P: MlDsaParams>(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
        // Key length: already guaranteed by check_sizes, but the safety of a
        // decoding is not made to rest on a caller.
        let enc = EncodedVerifyingKey::<P>::try_from(pubkey).ok()?;
        let vk = VerifyingKey::<P>::decode(&enc);

        // Malformed signature => invalid, not unavailable.
        let Ok(s) = Signature::<P>::try_from(sig) else {
            return Some(false);
        };

        Some(vk.verify(msg, &s).is_ok())
    }

    pub fn verify(scheme: SchemeId, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
        match scheme {
            SchemeId::MlDsa65 => verify_params::<MlDsa65>(pubkey, msg, sig),
            SchemeId::MlDsa87 => verify_params::<MlDsa87>(pubkey, msg, sig),
            // SPHINCS+ is still to be wired in: see the roadmap.
            SchemeId::SphincsPlus => None,
            SchemeId::LamportOts => None,
        }
    }
}

/// Tests of the real ML-DSA implementation.
///
/// These tests only run with `--features mldsa`. They do not check "the code
/// compiles": they check that Q21 accepts a genuine ML-DSA signature, refuses
/// a forged one, and that the sizes written in [`SchemeId`] are indeed those
/// of FIPS 204.
#[cfg(all(test, feature = "mldsa"))]
mod mldsa_tests {
    use super::*;
    use crate::sha256::sha256;
    use ml_dsa::{signature::Keypair, MlDsaParams, Signer, SigningKey, B32};

    /// Seed of the example key pair published by RustCrypto
    /// (`tests/examples/ML-DSA-*-seed.priv`): the bytes 0x00 to 0x1f.
    const SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    /// SHA-256 of the expected public key, extracted from RustCrypto's PKCS#8
    /// file `ML-DSA-65.pub` (the last 1952 bytes of the DER).
    const SHA_PK_65: &str = "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9";
    /// Same for `ML-DSA-87.pub` (the last 2592 bytes of the DER).
    const SHA_PK_87: &str = "91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd";

    fn hex(o: &[u8; 32]) -> String {
        o.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Builds a genuine (public key, signature) pair.
    fn key_and_sig<P: MlDsaParams>(msg: &Hash256) -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::<P>::from_seed(&B32::from(SEED));
        let vk = sk.verifying_key().encode();
        let sig = sk.sign(msg.as_bytes()).encode();
        (vk[..].to_vec(), sig[..].to_vec())
    }

    /// The external vector: the key derived from the seed must be, byte for
    /// byte, the one in the published PKCS#8 file. If this test fails, Q21's
    /// key encoding has diverged from the standard and no other
    /// implementation will be able to read our addresses.
    #[test]
    fn derived_key_matches_the_external_vector() {
        let sk65 = SigningKey::<ml_dsa::MlDsa65>::from_seed(&B32::from(SEED));
        assert_eq!(hex(&sha256(&sk65.verifying_key().encode()[..])), SHA_PK_65);

        let sk87 = SigningKey::<ml_dsa::MlDsa87>::from_seed(&B32::from(SEED));
        assert_eq!(hex(&sha256(&sk87.verifying_key().encode()[..])), SHA_PK_87);
    }

    /// The sizes in [`SchemeId`] were announced without ever having been
    /// measured. They are measured here, on real objects.
    #[test]
    fn real_sizes_confirm_the_constants() {
        let m = Hash256::ZERO;
        let (pk, sig) = key_and_sig::<ml_dsa::MlDsa65>(&m);
        assert_eq!(pk.len(), SchemeId::MlDsa65.pubkey_len());
        assert_eq!(sig.len(), SchemeId::MlDsa65.sig_len());

        let (pk, sig) = key_and_sig::<ml_dsa::MlDsa87>(&m);
        assert_eq!(pk.len(), SchemeId::MlDsa87.pubkey_len());
        assert_eq!(sig.len(), SchemeId::MlDsa87.sig_len());
    }

    #[test]
    fn a_genuine_signature_is_accepted() {
        let m = tagged_hash("Q21/test", b"payment");
        for (scheme, (pk, sig)) in [
            (SchemeId::MlDsa65, key_and_sig::<ml_dsa::MlDsa65>(&m)),
            (SchemeId::MlDsa87, key_and_sig::<ml_dsa::MlDsa87>(&m)),
        ] {
            assert_eq!(verify(scheme, &pk, &m, &sig), Ok(()), "{}", scheme.name());
        }
    }

    /// One bit changed anywhere in the signature must make it invalid — and
    /// invalid, not "unavailable".
    #[test]
    fn a_single_flipped_bit_invalidates_the_signature() {
        let m = tagged_hash("Q21/test", b"payment");
        let (pk, sig) = key_and_sig::<ml_dsa::MlDsa65>(&m);

        // Start, middle, end: the three areas of the format (c_tilde, z, h).
        for pos in [0usize, sig.len() / 2, sig.len() - 1] {
            let mut forged = sig.clone();
            forged[pos] ^= 0x01;
            assert_eq!(
                verify(SchemeId::MlDsa65, &pk, &m, &forged),
                Err(VerifyError::InvalidSignature),
                "byte {pos}"
            );
        }
    }

    #[test]
    fn the_signature_only_holds_for_its_message() {
        let m = tagged_hash("Q21/test", b"payment");
        let other = tagged_hash("Q21/test", b"payment.");
        let (pk, sig) = key_and_sig::<ml_dsa::MlDsa65>(&m);

        assert_eq!(verify(SchemeId::MlDsa65, &pk, &m, &sig), Ok(()));
        assert_eq!(
            verify(SchemeId::MlDsa65, &pk, &other, &sig),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn the_signature_only_holds_for_its_key() {
        let m = tagged_hash("Q21/test", b"payment");
        let (pk, sig) = key_and_sig::<ml_dsa::MlDsa65>(&m);

        let mut seed = SEED;
        seed[0] ^= 0xff;
        let other_pk = SigningKey::<ml_dsa::MlDsa65>::from_seed(&B32::from(seed))
            .verifying_key()
            .encode()[..]
            .to_vec();
        assert_ne!(pk, other_pk);

        assert_eq!(
            verify(SchemeId::MlDsa65, &other_pk, &m, &sig),
            Err(VerifyError::InvalidSignature)
        );
    }

    /// Security levels are not interchangeable: an ML-DSA-87 signature
    /// presented as ML-DSA-65 is rejected on length, before any computation.
    #[test]
    fn levels_are_not_interchangeable() {
        let m = Hash256::ZERO;
        let (pk87, sig87) = key_and_sig::<ml_dsa::MlDsa87>(&m);
        assert!(matches!(
            verify(SchemeId::MlDsa65, &pk87, &m, &sig87),
            Err(VerifyError::InvalidKeyLength { .. })
        ));
    }

    /// Measurement benchmark, excluded from ordinary runs.
    ///
    /// `cargo test --release --features mldsa -- --ignored --nocapture bench`
    ///
    /// The figure that matters for block sizing: how many signatures can a
    /// node verify per second? A 2 MiB block in ML-DSA-65 holds at most ~380
    /// witnesses; if verification costs more than the propagation time, the
    /// network starts orphaning blocks.
    #[test]
    #[ignore = "measurement benchmark, not an assertion"]
    fn verification_bench() {
        let m = tagged_hash("Q21/test", b"bench");
        for (name, (pk, sig)) in [
            ("ML-DSA-65", key_and_sig::<ml_dsa::MlDsa65>(&m)),
            ("ML-DSA-87", key_and_sig::<ml_dsa::MlDsa87>(&m)),
        ] {
            let scheme = if name == "ML-DSA-65" {
                SchemeId::MlDsa65
            } else {
                SchemeId::MlDsa87
            };
            const N: u32 = 2_000;
            let t0 = std::time::Instant::now();
            for _ in 0..N {
                assert_eq!(verify(scheme, &pk, &m, &sig), Ok(()));
            }
            let d = t0.elapsed();
            let per_sec = f64::from(N) / d.as_secs_f64();
            println!(
                "{name}: {per_sec:.0} verifications/s  ({:.1} us per signature)",
                d.as_secs_f64() * 1e6 / f64::from(N)
            );
        }
    }

    /// Any public key always decodes (that is the standard), but then no
    /// signature can verify. The node must neither panic nor accept.
    #[test]
    fn an_arbitrary_key_verifies_nothing() {
        let m = Hash256::ZERO;
        let pk = vec![0xabu8; SchemeId::MlDsa65.pubkey_len()];
        let sig = vec![0xcdu8; SchemeId::MlDsa65.sig_len()];
        assert_eq!(
            verify(SchemeId::MlDsa65, &pk, &m, &sig),
            Err(VerifyError::InvalidSignature)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_identifiers_are_stable() {
        // These values are part of consensus. Changing them invalidates every
        // existing address.
        assert_eq!(SchemeId::MlDsa65.as_u8(), 1);
        assert_eq!(SchemeId::MlDsa87.as_u8(), 2);
        assert_eq!(SchemeId::SphincsPlus.as_u8(), 3);
        assert_eq!(SchemeId::LamportOts.as_u8(), 4);
    }

    #[test]
    fn identifier_round_trip() {
        for s in SchemeId::ALL {
            assert_eq!(SchemeId::from_u8(s.as_u8()), Some(s));
        }
        assert_eq!(SchemeId::from_u8(0), None);
        assert_eq!(SchemeId::from_u8(5), None);
        assert_eq!(SchemeId::from_u8(255), None);
    }

    /// Q21's default scheme is the maximum level of the standard.
    ///
    /// This is not a convenience detail: it is the security level carried by
    /// every address issued by the binary, and it goes into the identifier of
    /// the genesis block. Letting it slip without noticing would change the
    /// chain.
    #[test]
    fn the_default_is_the_maximum_level_of_the_standard() {
        use crate::address::Network;
        // Regtest, not Mainnet: the genesis scheme does not depend on the
        // network, whereas building the mainnet genesis requires the two-GiB
        // proof-of-work table. A test must never pay that price to check a
        // constant.
        assert_eq!(
            crate::chain::genesis_block(Network::Regtest).transactions[0].outputs[0].scheme,
            SchemeId::MlDsa87,
            "the genesis must carry ML-DSA-87"
        );
        // And the maximum level is indeed that one: no higher-rank
        // lattice-based scheme exists in the standard.
        assert!(SchemeId::MlDsa87 > SchemeId::MlDsa65);
        assert!(SchemeId::MlDsa87.allowed_on(Network::Mainnet));
    }

    /// The numeric values of the schemes are part of consensus.
    ///
    /// They appear in every address and in every witness. Swapping them —
    /// even through an innocent reordering of the enumeration — would make
    /// existing addresses read as designating another scheme.
    #[test]
    fn scheme_identifiers_do_not_move() {
        assert_eq!(SchemeId::MlDsa65 as u8, 1);
        assert_eq!(SchemeId::MlDsa87 as u8, 2);
        assert_eq!(SchemeId::SphincsPlus as u8, 3);
        assert_eq!(SchemeId::LamportOts as u8, 4);
    }

    #[test]
    fn sizes_match_fips_204() {
        assert_eq!(SchemeId::MlDsa65.pubkey_len(), 1952);
        assert_eq!(SchemeId::MlDsa65.sig_len(), 3309);
        assert_eq!(SchemeId::MlDsa87.pubkey_len(), 2592);
        assert_eq!(SchemeId::MlDsa87.sig_len(), 4627);
    }

    #[test]
    fn overhead_versus_ecdsa_is_as_announced() {
        // The white paper announces a factor of 47. If this test fails, the
        // block sizing of section 7 must be redone.
        const ECDSA_SIG: usize = 71;
        let factor = SchemeId::MlDsa65.sig_len() / ECDSA_SIG;
        assert_eq!(factor, 46, "actual factor: {factor}");
    }

    #[test]
    fn wrong_sizes_are_rejected() {
        let s = SchemeId::MlDsa65;
        let good_key = vec![0u8; s.pubkey_len()];
        let good_sig = vec![0u8; s.sig_len()];

        assert!(check_sizes(s, &good_key, &good_sig).is_ok());
        assert!(matches!(
            check_sizes(s, &[0u8; 10], &good_sig),
            Err(VerifyError::InvalidKeyLength { .. })
        ));
        assert!(matches!(
            check_sizes(s, &good_key, &[0u8; 10]),
            Err(VerifyError::InvalidSignatureLength { .. })
        ));
    }

    #[test]
    fn without_backend_verification_fails_loudly() {
        let s = SchemeId::MlDsa65;
        let r = verify(
            s,
            &vec![0u8; s.pubkey_len()],
            &Hash256::ZERO,
            &vec![0u8; s.sig_len()],
        );
        // Never Ok(()): a node does not validate what it has not verified.
        assert!(r.is_err());
    }

    #[test]
    fn two_schemes_give_two_different_hashes() {
        let key = vec![7u8; 100];
        assert_ne!(
            pubkey_hash(SchemeId::MlDsa65, &key),
            pubkey_hash(SchemeId::MlDsa87, &key),
            "the hash must bind the key to its scheme"
        );
    }
}

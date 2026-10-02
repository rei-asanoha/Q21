//! Lamport signatures, one-time use.
//!
//! Published by Leslie Lamport in 1979, these signatures rest only on the
//! preimage resistance of a hash function. No algebraic structure, hence
//! nothing for Shor's algorithm to grab onto. These are the ones BitcoinTalk
//! threads were digging up as early as 2010 when Nakamoto was asked the
//! quantum question, and they are the direct ancestor of SPHINCS+.
//!
//! # Why they are here, and why they will not go to production
//!
//! This module exists for a practical reason: to make it possible to sign,
//! and therefore to transfer, before ML-DSA was wired in. It is infinitely
//! better than a stub that would accept anything.
//!
//! But Lamport is **strictly one-time**. Signing two different messages with
//! the same key reveals, for every bit where the two messages differ, *both*
//! preimages of the pair — and lets anyone forge a signature on a third
//! message. There is no possible recovery.
//!
//! This is exactly the trap that section 4 of the white paper holds against
//! XMSS and the QRL scheme: state to manage on the wallet side, where
//! forgetting it is fatal. The restriction is therefore written into
//! consensus, not into the documentation: [`crate::sig::SchemeId::allowed_on`]
//! refuses Lamport on mainnet.
//!
//! # Dimensions
//!
//! | | Size |
//! |---|---|
//! | Private key | derived from a 32-byte seed |
//! | Public key | 16,384 bytes (512 hashes) |
//! | Signature | 8,192 bytes (256 revealed preimages) |
//!
//! Heavier than ML-DSA-65 and its 3,309 bytes. On a test network, of no
//! importance.

use crate::hash::{tagged_hash_parts, Hash256};

pub const N_BITS: usize = 256;
pub const PUBKEY_LEN: usize = N_BITS * 2 * 32;
pub const SIG_LEN: usize = N_BITS * 32;

const TAG_DERIVE: &str = "Q21/lamport/derive";
const TAG_COMMIT: &str = "Q21/lamport/commit";

/// Private key, represented by the seed it is derived from.
///
/// The 16 KB of preimages are never stored: they are recomputed on demand.
/// The wallet backup thus comes down to 32 bytes plus a counter.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    seed: [u8; 32],
    /// Index of the key in the wallet. Two indices give two independent keys
    /// from the same master seed.
    index: u32,
}

/// The derived seed is wiped when the key is dropped; see
/// [`crate::kdf::wipe`].
impl Drop for SecretKey {
    fn drop(&mut self) {
        crate::kdf::wipe(&mut self.seed);
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never display the seed, even when debugging.
        write!(f, "SecretKey {{ index: {}, seed: <hidden> }}", self.index)
    }
}

impl SecretKey {
    pub fn from_seed(seed: [u8; 32], index: u32) -> SecretKey {
        SecretKey { seed, index }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Preimage of bit `bit`, value `value` (0 or 1).
    fn preimage(&self, bit: usize, value: u8) -> [u8; 32] {
        tagged_hash_parts(
            TAG_DERIVE,
            &[
                &self.seed,
                &self.index.to_le_bytes(),
                &(bit as u16).to_le_bytes(),
                &[value],
            ],
        )
        .0
    }

    /// Public key: the hash of each preimage, in order.
    pub fn public_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBKEY_LEN);
        for bit in 0..N_BITS {
            for value in 0..2u8 {
                let p = self.preimage(bit, value);
                out.extend_from_slice(&tagged_hash_parts(TAG_COMMIT, &[&p]).0);
            }
        }
        out
    }

    /// Signs a 256-bit hash.
    ///
    /// Reminder: call only once per key. The wallet is responsible for never
    /// reusing an index.
    pub fn sign(&self, message: &Hash256) -> Vec<u8> {
        let m = message.as_bytes();
        let mut out = Vec::with_capacity(SIG_LEN);
        for bit in 0..N_BITS {
            let b = (m[bit / 8] >> (7 - (bit % 8))) & 1;
            out.extend_from_slice(&self.preimage(bit, b));
        }
        out
    }
}

/// Verifies a Lamport signature.
///
/// Cannot know whether the key has already been used: that is a property of
/// the scheme, not an oversight. The wallet must guarantee uniqueness.
pub fn verify(pubkey: &[u8], message: &Hash256, sig: &[u8]) -> bool {
    if pubkey.len() != PUBKEY_LEN || sig.len() != SIG_LEN {
        return false;
    }
    let m = message.as_bytes();
    for bit in 0..N_BITS {
        let b = ((m[bit / 8] >> (7 - (bit % 8))) & 1) as usize;
        let revealed = &sig[bit * 32..bit * 32 + 32];
        let expected = &pubkey[(bit * 2 + b) * 32..(bit * 2 + b) * 32 + 32];
        if tagged_hash_parts(TAG_COMMIT, &[revealed]).0 != expected {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: u32) -> SecretKey {
        SecretKey::from_seed([0x42; 32], index)
    }

    #[test]
    fn sizes_are_as_announced() {
        let sk = key(0);
        assert_eq!(sk.public_key().len(), PUBKEY_LEN);
        assert_eq!(sk.sign(&Hash256::ZERO).len(), SIG_LEN);
        assert_eq!(PUBKEY_LEN, 16_384);
        assert_eq!(SIG_LEN, 8_192);
    }

    #[test]
    fn a_valid_signature_is_accepted() {
        let sk = key(0);
        let pk = sk.public_key();
        let msg = crate::hash::tagged_hash("test", b"pay alice");
        assert!(verify(&pk, &msg, &sk.sign(&msg)));
    }

    #[test]
    fn a_signature_only_holds_for_its_message() {
        let sk = key(0);
        let pk = sk.public_key();
        let a = crate::hash::tagged_hash("test", b"pay alice 10");
        let b = crate::hash::tagged_hash("test", b"pay alice 1000");
        assert!(!verify(&pk, &b, &sk.sign(&a)), "replayable signature");
    }

    #[test]
    fn another_key_does_not_verify() {
        let msg = crate::hash::tagged_hash("test", b"m");
        let sig = key(0).sign(&msg);
        assert!(!verify(&key(1).public_key(), &msg, &sig));
    }

    #[test]
    fn two_indices_give_two_independent_keys() {
        assert_ne!(key(0).public_key(), key(1).public_key());
    }

    #[test]
    fn two_seeds_give_two_keys() {
        let a = SecretKey::from_seed([1u8; 32], 0);
        let b = SecretKey::from_seed([2u8; 32], 0);
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn derivation_is_deterministic() {
        // The wallet backup comes down to the seed: so the same seed must
        // reproduce exactly the same keys.
        assert_eq!(key(7).public_key(), key(7).public_key());
        let m = Hash256([3u8; 32]);
        assert_eq!(key(7).sign(&m), key(7).sign(&m));
    }

    #[test]
    fn a_truncated_or_extended_signature_is_refused() {
        let sk = key(0);
        let pk = sk.public_key();
        let msg = Hash256([9u8; 32]);
        let sig = sk.sign(&msg);

        assert!(!verify(&pk, &msg, &sig[..SIG_LEN - 1]));
        let mut too_long = sig.clone();
        too_long.push(0);
        assert!(!verify(&pk, &msg, &too_long));
        assert!(!verify(&pk[..PUBKEY_LEN - 1], &msg, &sig));
    }

    #[test]
    fn a_modified_byte_invalidates_the_signature() {
        let sk = key(0);
        let pk = sk.public_key();
        let msg = Hash256([5u8; 32]);
        let mut sig = sk.sign(&msg);
        sig[100] ^= 0x01;
        assert!(!verify(&pk, &msg, &sig));
    }

    #[test]
    fn cannot_forge_with_a_single_signature() {
        // An attacker sees one signature. For each bit they know only one of
        // the two preimages. Any message differing by at least one bit
        // requires a preimage they do not have.
        let sk = key(0);
        let pk = sk.public_key();
        let seen = Hash256([0x00; 32]);
        let seen_sig = sk.sign(&seen);

        let target = Hash256([0xff; 32]); // every bit different
        assert!(!verify(&pk, &target, &seen_sig));
    }

    /// Documents the weakness of the scheme rather than keeping quiet about it.
    #[test]
    fn two_signatures_reveal_both_preimages() {
        let sk = key(0);
        let a = Hash256([0x00; 32]);
        let b = Hash256([0xff; 32]);
        let sig_a = sk.sign(&a);
        let sig_b = sk.sign(&b);

        // For each bit, the two signatures reveal opposite preimages. An
        // attacker who has both can sign any message: that is why consensus
        // forbids Lamport on mainnet.
        assert_ne!(&sig_a[..32], &sig_b[..32]);
    }
}

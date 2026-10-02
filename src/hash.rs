//! Digests and tagged hashing.
//!
//! Q21 uses **tagged hashes** everywhere, following the BIP-340 model:
//!
//! ```text
//! tagged_hash(tag, m) = SHA256( SHA256(tag) || SHA256(tag) || m )
//! ```
//!
//! Two properties follow, and both fix real defects of Bitcoin.
//!
//! 1. **Domain separation.** A digest computed for a transaction id can never
//!    be confused with an internal Merkle tree node or a block header. Bitcoin
//!    had to resort to patches (`CVE-2012-2459`) for not having separated its
//!    domains from the start.
//!
//! 2. **Immunity to length extension.** The 64-byte prefix makes the attack
//!    ineffective, which Bitcoin's double SHA-256 achieved by a more costly
//!    means.

use crate::sha256::{sha256, Sha256};
use core::fmt;

/// 256-bit digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Hash256 = Hash256([0u8; 32]);

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Option<Hash256> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Hash256(out))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

/// Domain tags. Each use of hashing in the protocol has its own.
pub mod tags {
    pub const TX: &str = "Q21/tx";
    pub const BLOCK_HEADER: &str = "Q21/header";
    pub const MERKLE_LEAF: &str = "Q21/merkle/leaf";
    pub const MERKLE_BRANCH: &str = "Q21/merkle/branch";
    pub const ADDRESS: &str = "Q21/address";
    pub const SIGHASH: &str = "Q21/sighash/2";
    /// Wallet key derivation. Purely local: no consensus rule depends on it,
    /// but changing this tag changes every address derived from an existing
    /// seed.
    pub const WALLET_SEED: &str = "Q21/wallet/seed";
}

/// Tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || message)`.
pub fn tagged_hash(tag: &str, message: &[u8]) -> Hash256 {
    let tag_hash = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(&tag_hash);
    h.update(&tag_hash);
    h.update(message);
    Hash256(h.finalize())
}

/// Multi-part variant, to avoid concatenating in memory.
pub fn tagged_hash_parts(tag: &str, parts: &[&[u8]]) -> Hash256 {
    let tag_hash = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(&tag_hash);
    h.update(&tag_hash);
    for p in parts {
        h.update(p);
    }
    Hash256(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_separated() {
        let m = b"exactly the same message";
        let a = tagged_hash(tags::MERKLE_LEAF, m);
        let b = tagged_hash(tags::MERKLE_BRANCH, m);
        let c = tagged_hash(tags::TX, m);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn tag_differs_from_bare_hash() {
        let m = b"message";
        assert_ne!(tagged_hash(tags::TX, m).0, crate::sha256::sha256(m));
    }

    #[test]
    fn splitting_does_not_change_result() {
        let whole = tagged_hash(tags::TX, b"abcdef");
        let pieces = tagged_hash_parts(tags::TX, &[b"abc", b"def"]);
        assert_eq!(whole, pieces);
    }

    #[test]
    fn hex_round_trip() {
        let h = tagged_hash(tags::TX, b"whatever");
        assert_eq!(Hash256::from_hex(&h.to_hex()), Some(h));
        assert_eq!(Hash256::from_hex("too short"), None);
        assert_eq!(Hash256::from_hex(&"z".repeat(64)), None);
    }

    #[test]
    fn hashing_is_deterministic() {
        assert_eq!(tagged_hash(tags::TX, b"x"), tagged_hash(tags::TX, b"x"));
    }
}

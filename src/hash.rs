//! Condensats et hachage taggé.
//!
//! Q21 utilise des **hachages taggés** partout, sur le modele de BIP-340 :
//!
//! ```text
//! tagged_hash(tag, m) = SHA256( SHA256(tag) || SHA256(tag) || m )
//! ```
//!
//! Deux proprietes en decoulent, et les deux corrigent des defauts reels de
//! Bitcoin.
//!
//! 1. **Separation de domaine.** Un condensat calcule pour un identifiant de
//!    transaction ne peut jamais etre confondu avec un noeud interne d'arbre de
//!    Merkle ou un en-tete de bloc. Bitcoin a du recourir a des rustines
//!    (`CVE-2012-2459`) faute d'avoir separe ses domaines des le depart.
//!
//! 2. **Immunite a l'extension de longueur.** Le prefixe de 64 octets rend
//!    l'attaque inoperante, ce que le double-SHA256 de Bitcoin obtenait par un
//!    moyen plus couteux.

use crate::sha256::{sha256, Sha256};
use core::fmt;

/// Condensat de 256 bits.
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
        for (i, octet) in out.iter_mut().enumerate() {
            *octet = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
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

/// Etiquettes de domaine. Chaque usage de hachage du protocole a la sienne.
pub mod tags {
    pub const TX: &str = "Q21/tx";
    pub const BLOCK_HEADER: &str = "Q21/header";
    pub const MERKLE_LEAF: &str = "Q21/merkle/leaf";
    pub const MERKLE_BRANCH: &str = "Q21/merkle/branch";
    pub const ADDRESS: &str = "Q21/address";
    pub const SIGHASH: &str = "Q21/sighash/2";
    /// Derivation des clefs de portefeuille. Purement local : aucune regle de
    /// consensus n'en depend, mais changer ce tag change toutes les adresses
    /// derivees d'une graine existante.
    pub const WALLET_SEED: &str = "Q21/wallet/seed";
}

/// Hachage taggé : `SHA256(SHA256(tag) || SHA256(tag) || message)`.
pub fn tagged_hash(tag: &str, message: &[u8]) -> Hash256 {
    let tag_hash = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(&tag_hash);
    h.update(&tag_hash);
    h.update(message);
    Hash256(h.finalize())
}

/// Variante a plusieurs morceaux, pour eviter de concatener en memoire.
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
    fn les_domaines_sont_bien_separes() {
        let m = b"le meme message exactement";
        let a = tagged_hash(tags::MERKLE_LEAF, m);
        let b = tagged_hash(tags::MERKLE_BRANCH, m);
        let c = tagged_hash(tags::TX, m);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn un_tag_differe_d_un_hachage_nu() {
        let m = b"message";
        assert_ne!(tagged_hash(tags::TX, m).0, crate::sha256::sha256(m));
    }

    #[test]
    fn le_decoupage_ne_change_pas_le_resultat() {
        let entier = tagged_hash(tags::TX, b"abcdef");
        let morceaux = tagged_hash_parts(tags::TX, &[b"abc", b"def"]);
        assert_eq!(entier, morceaux);
    }

    #[test]
    fn conversion_hexadecimale_aller_retour() {
        let h = tagged_hash(tags::TX, b"peu importe");
        assert_eq!(Hash256::from_hex(&h.to_hex()), Some(h));
        assert_eq!(Hash256::from_hex("trop court"), None);
        assert_eq!(Hash256::from_hex(&"z".repeat(64)), None);
    }

    #[test]
    fn le_hachage_est_deterministe() {
        assert_eq!(tagged_hash(tags::TX, b"x"), tagged_hash(tags::TX, b"x"));
    }
}

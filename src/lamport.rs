//! Signatures de Lamport, a usage unique.
//!
//! Publiees par Leslie Lamport en 1979, ces signatures ne reposent que sur la
//! resistance a la preimage d'une fonction de hachage. Aucune structure
//! algebrique, donc aucune prise pour l'algorithme de Shor. Ce sont elles que
//! les fils de BitcoinTalk exhumaient des 2010 quand on posait a Nakamoto la
//! question quantique, et elles sont l'ancetre direct de SPHINCS+.
//!
//! # Pourquoi elles sont ici, et pourquoi elles n'iront pas en production
//!
//! Ce module existe pour une raison pratique : permettre de signer, donc de
//! transferer, avant que ML-DSA soit branche. Il vaut infiniment mieux qu'un
//! stub qui accepterait n'importe quoi.
//!
//! Mais Lamport est **a usage strictement unique**. Signer deux messages
//! differents avec la meme clef revele, pour chaque bit ou les deux messages
//! different, les *deux* preimages de la paire — et permet a quiconque de forger
//! une signature sur un troisieme message. Il n'y a pas de rattrapage possible.
//!
//! C'est exactement le piege que la section 4 du livre blanc reproche a XMSS et
//! au schema de QRL : un etat a gerer cote portefeuille, dont l'oubli est fatal.
//! La restriction est donc inscrite dans le consensus, pas dans la
//! documentation : [`crate::sig::SchemeId::allowed_on`] refuse Lamport sur le
//! reseau principal.
//!
//! # Dimensions
//!
//! | | Taille |
//! |---|---|
//! | Clef privee | derivee d'une graine de 32 octets |
//! | Clef publique | 16 384 octets (512 condensats) |
//! | Signature | 8 192 octets (256 preimages revelees) |
//!
//! Plus lourd que ML-DSA-65 et ses 3 309 octets. Sur un reseau de test, sans
//! importance.

use crate::hash::{tagged_hash_parts, Hash256};

pub const N_BITS: usize = 256;
pub const PUBKEY_LEN: usize = N_BITS * 2 * 32;
pub const SIG_LEN: usize = N_BITS * 32;

const TAG_DERIVE: &str = "Q21/lamport/derive";
const TAG_COMMIT: &str = "Q21/lamport/commit";

/// Clef privee, representee par la graine dont elle se derive.
///
/// On ne stocke jamais les 16 Ko de preimages : ils se recalculent a la demande.
/// La sauvegarde du portefeuille se reduit ainsi a 32 octets plus un compteur.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretKey {
    seed: [u8; 32],
    /// Indice de la clef dans le portefeuille. Deux indices donnent deux clefs
    /// independantes issues de la meme graine maitre.
    index: u32,
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ne jamais afficher la graine, meme en deboguage.
        write!(f, "SecretKey {{ index: {}, seed: <masquee> }}", self.index)
    }
}

impl SecretKey {
    pub fn from_seed(seed: [u8; 32], index: u32) -> SecretKey {
        SecretKey { seed, index }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Preimage du bit `bit`, valeur `valeur` (0 ou 1).
    fn preimage(&self, bit: usize, valeur: u8) -> [u8; 32] {
        tagged_hash_parts(
            TAG_DERIVE,
            &[
                &self.seed,
                &self.index.to_le_bytes(),
                &(bit as u16).to_le_bytes(),
                &[valeur],
            ],
        )
        .0
    }

    /// Clef publique : le condensat de chaque preimage, dans l'ordre.
    pub fn public_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBKEY_LEN);
        for bit in 0..N_BITS {
            for valeur in 0..2u8 {
                let p = self.preimage(bit, valeur);
                out.extend_from_slice(&tagged_hash_parts(TAG_COMMIT, &[&p]).0);
            }
        }
        out
    }

    /// Signe un condensat de 256 bits.
    ///
    /// Rappel : n'appeler qu'une seule fois par clef. Le portefeuille est
    /// responsable de ne jamais reutiliser un indice.
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

/// Verifie une signature de Lamport.
///
/// Ne peut pas savoir si la clef a deja servi : c'est une propriete du schema,
/// pas un oubli. Le portefeuille doit garantir l'unicite.
pub fn verify(pubkey: &[u8], message: &Hash256, sig: &[u8]) -> bool {
    if pubkey.len() != PUBKEY_LEN || sig.len() != SIG_LEN {
        return false;
    }
    let m = message.as_bytes();
    for bit in 0..N_BITS {
        let b = ((m[bit / 8] >> (7 - (bit % 8))) & 1) as usize;
        let revele = &sig[bit * 32..bit * 32 + 32];
        let attendu = &pubkey[(bit * 2 + b) * 32..(bit * 2 + b) * 32 + 32];
        if tagged_hash_parts(TAG_COMMIT, &[revele]).0 != attendu {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clef(index: u32) -> SecretKey {
        SecretKey::from_seed([0x42; 32], index)
    }

    #[test]
    fn les_tailles_sont_celles_annoncees() {
        let sk = clef(0);
        assert_eq!(sk.public_key().len(), PUBKEY_LEN);
        assert_eq!(sk.sign(&Hash256::ZERO).len(), SIG_LEN);
        assert_eq!(PUBKEY_LEN, 16_384);
        assert_eq!(SIG_LEN, 8_192);
    }

    #[test]
    fn une_signature_valide_est_acceptee() {
        let sk = clef(0);
        let pk = sk.public_key();
        let msg = crate::hash::tagged_hash("test", b"payer alice");
        assert!(verify(&pk, &msg, &sk.sign(&msg)));
    }

    #[test]
    fn une_signature_ne_vaut_que_pour_son_message() {
        let sk = clef(0);
        let pk = sk.public_key();
        let a = crate::hash::tagged_hash("test", b"payer alice 10");
        let b = crate::hash::tagged_hash("test", b"payer alice 1000");
        assert!(!verify(&pk, &b, &sk.sign(&a)), "signature rejouable");
    }

    #[test]
    fn une_autre_clef_ne_valide_pas() {
        let msg = crate::hash::tagged_hash("test", b"m");
        let sig = clef(0).sign(&msg);
        assert!(!verify(&clef(1).public_key(), &msg, &sig));
    }

    #[test]
    fn deux_indices_donnent_deux_clefs_independantes() {
        assert_ne!(clef(0).public_key(), clef(1).public_key());
    }

    #[test]
    fn deux_graines_donnent_deux_clefs() {
        let a = SecretKey::from_seed([1u8; 32], 0);
        let b = SecretKey::from_seed([2u8; 32], 0);
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn la_derivation_est_deterministe() {
        // La sauvegarde du portefeuille se reduit a la graine : il faut donc
        // que la meme graine reproduise exactement les memes clefs.
        assert_eq!(clef(7).public_key(), clef(7).public_key());
        let m = Hash256([3u8; 32]);
        assert_eq!(clef(7).sign(&m), clef(7).sign(&m));
    }

    #[test]
    fn une_signature_tronquee_ou_rallongee_est_refusee() {
        let sk = clef(0);
        let pk = sk.public_key();
        let msg = Hash256([9u8; 32]);
        let sig = sk.sign(&msg);

        assert!(!verify(&pk, &msg, &sig[..SIG_LEN - 1]));
        let mut trop_long = sig.clone();
        trop_long.push(0);
        assert!(!verify(&pk, &msg, &trop_long));
        assert!(!verify(&pk[..PUBKEY_LEN - 1], &msg, &sig));
    }

    #[test]
    fn un_octet_modifie_invalide_la_signature() {
        let sk = clef(0);
        let pk = sk.public_key();
        let msg = Hash256([5u8; 32]);
        let mut sig = sk.sign(&msg);
        sig[100] ^= 0x01;
        assert!(!verify(&pk, &msg, &sig));
    }

    #[test]
    fn on_ne_peut_pas_forger_avec_une_seule_signature() {
        // Un attaquant voit une signature. Pour chaque bit il connait une seule
        // des deux preimages. Tout message differant d'au moins un bit exige une
        // preimage qu'il n'a pas.
        let sk = clef(0);
        let pk = sk.public_key();
        let vu = Hash256([0x00; 32]);
        let sig_vue = sk.sign(&vu);

        let cible = Hash256([0xff; 32]); // tous les bits differents
        assert!(!verify(&pk, &cible, &sig_vue));
    }

    /// Documente la faiblesse du schema plutot que de la taire.
    #[test]
    fn deux_signatures_revelent_les_deux_preimages() {
        let sk = clef(0);
        let a = Hash256([0x00; 32]);
        let b = Hash256([0xff; 32]);
        let sig_a = sk.sign(&a);
        let sig_b = sk.sign(&b);

        // Pour chaque bit, les deux signatures revelent des preimages opposees.
        // Un attaquant qui dispose des deux peut signer n'importe quel message :
        // c'est pourquoi le consensus interdit Lamport sur le reseau principal.
        assert_ne!(&sig_a[..32], &sig_b[..32]);
    }
}

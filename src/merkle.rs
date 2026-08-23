//! Arbre de Merkle.
//!
//! Deux differences avec Bitcoin, toutes deux volontaires.
//!
//! **On ne duplique pas le noeud impair.** Bitcoin duplique le dernier condensat
//! quand un niveau compte un nombre impair d'elements. Cette astuce a produit
//! `CVE-2012-2459` : deux listes de transactions differentes pouvaient donner la
//! meme racine, ce qui permettait de fabriquer un bloc invalide que les noeuds
//! marquaient definitivement comme rejete, bloquant le bloc valide correspondant.
//! Q21 promeut le noeud impair inchange au niveau superieur.
//!
//! **Les feuilles et les branches ont des etiquettes distinctes.** Sans cette
//! separation, un attaquant peut presenter un noeud interne comme une feuille et
//! construire une seconde preimage. Le probleme est connu depuis longtemps ; on
//! le regle a la conception plutot qu'en aval.

use crate::hash::{tagged_hash, tagged_hash_parts, tags, Hash256};

/// Condensat d'une feuille.
pub fn leaf_hash(data: &[u8]) -> Hash256 {
    tagged_hash(tags::MERKLE_LEAF, data)
}

/// Condensat d'un noeud interne, a partir de ses deux enfants.
pub fn branch_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    tagged_hash_parts(tags::MERKLE_BRANCH, &[left.as_bytes(), right.as_bytes()])
}

/// Racine de Merkle d'une liste de condensats de feuilles.
///
/// Un arbre vide rend `Hash256::ZERO`. Un arbre a une feuille rend cette feuille.
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return Hash256::ZERO;
    }
    let mut niveau: Vec<Hash256> = leaves.to_vec();
    while niveau.len() > 1 {
        let mut suivant = Vec::with_capacity(niveau.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < niveau.len() {
            suivant.push(branch_hash(&niveau[i], &niveau[i + 1]));
            i += 2;
        }
        if i < niveau.len() {
            // Nombre impair : on promeut, on ne duplique pas.
            suivant.push(niveau[i]);
        }
        niveau = suivant;
    }
    niveau[0]
}

/// Element d'une preuve d'inclusion : un condensat frere et son cote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: Hash256,
    /// Vrai si le frere se trouve a droite du noeud courant.
    pub sibling_on_right: bool,
}

/// Construit la preuve d'inclusion de la feuille d'indice `index`.
pub fn merkle_proof(leaves: &[Hash256], index: usize) -> Option<Vec<ProofStep>> {
    if index >= leaves.len() {
        return None;
    }
    let mut preuve = Vec::new();
    let mut niveau: Vec<Hash256> = leaves.to_vec();
    let mut pos = index;

    while niveau.len() > 1 {
        let mut suivant = Vec::with_capacity(niveau.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < niveau.len() {
            if i == pos || i + 1 == pos {
                let frere_a_droite = pos == i;
                preuve.push(ProofStep {
                    sibling: if frere_a_droite {
                        niveau[i + 1]
                    } else {
                        niveau[i]
                    },
                    sibling_on_right: frere_a_droite,
                });
                pos = suivant.len();
            }
            suivant.push(branch_hash(&niveau[i], &niveau[i + 1]));
            i += 2;
        }
        if i < niveau.len() {
            if i == pos {
                // Noeud promu : il monte seul, sans etape de preuve.
                pos = suivant.len();
            }
            suivant.push(niveau[i]);
        }
        niveau = suivant;
    }
    Some(preuve)
}

/// Verifie qu'une feuille appartient bien a l'arbre de racine `root`.
pub fn verify_proof(leaf: &Hash256, proof: &[ProofStep], root: &Hash256) -> bool {
    let mut courant = *leaf;
    for etape in proof {
        courant = if etape.sibling_on_right {
            branch_hash(&courant, &etape.sibling)
        } else {
            branch_hash(&etape.sibling, &courant)
        };
    }
    courant == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feuilles(n: usize) -> Vec<Hash256> {
        (0..n)
            .map(|i| leaf_hash(format!("transaction {i}").as_bytes()))
            .collect()
    }

    #[test]
    fn arbre_vide_et_arbre_unitaire() {
        assert_eq!(merkle_root(&[]), Hash256::ZERO);
        let une = feuilles(1);
        assert_eq!(merkle_root(&une), une[0]);
    }

    #[test]
    fn la_racine_change_si_une_feuille_change() {
        let a = feuilles(7);
        let mut b = a.clone();
        b[3] = leaf_hash(b"autre chose");
        assert_ne!(merkle_root(&a), merkle_root(&b));
    }

    #[test]
    fn l_ordre_des_feuilles_compte() {
        let a = feuilles(4);
        let mut b = a.clone();
        b.swap(0, 1);
        assert_ne!(merkle_root(&a), merkle_root(&b));
    }

    /// Le test qui traduit `CVE-2012-2459`.
    ///
    /// Avec la duplication de Bitcoin, un arbre a 3 feuilles [A,B,C] et un arbre
    /// a 4 feuilles [A,B,C,C] donnent la meme racine. Ici, non.
    #[test]
    fn la_duplication_du_noeud_impair_ne_collisionne_pas() {
        let trois = feuilles(3);
        let mut quatre = trois.clone();
        quatre.push(trois[2]);
        assert_ne!(
            merkle_root(&trois),
            merkle_root(&quatre),
            "collision de type CVE-2012-2459"
        );
    }

    #[test]
    fn une_feuille_ne_peut_pas_se_faire_passer_pour_une_branche() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let branche = branch_hash(&a, &b);
        let mut concat = Vec::new();
        concat.extend_from_slice(a.as_bytes());
        concat.extend_from_slice(b.as_bytes());
        assert_ne!(branche, leaf_hash(&concat));
    }

    #[test]
    fn les_preuves_sont_valides_pour_toutes_les_tailles() {
        for n in 1..=33usize {
            let f = feuilles(n);
            let racine = merkle_root(&f);
            for i in 0..n {
                let p = merkle_proof(&f, i).expect("preuve manquante");
                assert!(
                    verify_proof(&f[i], &p, &racine),
                    "preuve invalide : n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn une_preuve_falsifiee_est_rejetee() {
        let f = feuilles(8);
        let racine = merkle_root(&f);
        let p = merkle_proof(&f, 3).unwrap();
        assert!(!verify_proof(&leaf_hash(b"feuille inventee"), &p, &racine));
    }

    #[test]
    fn index_hors_bornes() {
        assert_eq!(merkle_proof(&feuilles(4), 4), None);
    }
}

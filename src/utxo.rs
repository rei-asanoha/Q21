//! Jeu d'UTXO : l'ensemble des sorties non depensees.
//!
//! C'est l'etat de la monnaie. Le reste — blocs, transactions, preuve de
//! travail — n'est qu'un mecanisme pour se mettre d'accord sur le contenu de
//! cet ensemble.
//!
//! Chaque entree retient sa hauteur d'origine et son caractere de coinbase, pour
//! deux raisons distinctes : la maturite des coinbases, et la possibilite de
//! defaire proprement un bloc lors d'une reorganisation.

use crate::amount::Amount;
use crate::tx::{OutPoint, Transaction, TxOut};
use std::collections::{HashMap, HashSet};

/// Vue en lecture sur un ensemble de sorties non depensees.
///
/// Introduit pour que la validation ne depende plus d'un jeu concret. Un
/// mempool acceptant des chaines de transactions non confirmees doit valider
/// contre « les sorties confirmees **plus** celles que le mempool va creer » —
/// sans cloner le jeu confirme a chaque transaction, ce qui serait lineaire en
/// la taille de la chaine pour chaque acceptation.
pub trait UtxoView {
    fn lookup(&self, o: &OutPoint) -> Option<UtxoEntry>;
}

impl UtxoView for UtxoSet {
    fn lookup(&self, o: &OutPoint) -> Option<UtxoEntry> {
        self.get(o).copied()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UtxoEntry {
    pub output: TxOut,
    pub height: u64,
    pub is_coinbase: bool,
}

#[derive(Clone, Default, Debug)]
pub struct UtxoSet {
    map: HashMap<OutPoint, UtxoEntry>,
    /// Index derive : empreinte de clef publique -> sorties correspondantes.
    ///
    /// # Pourquoi il existe
    ///
    /// `spendable_for` parcourait tout le jeu d'UTXO pour **chaque** adresse
    /// interrogee. Un portefeuille de soixante mille adresses sur un jeu de
    /// soixante mille sorties demandait donc plusieurs milliards de
    /// comparaisons : vingt secondes pour afficher un solde. Le cout etait
    /// quadratique et invisible tant que les chaines de test restaient courtes.
    ///
    /// Cet index est entierement derive de `map` et n'entre pas dans l'egalite
    /// de deux jeux d'UTXO : deux ensembles identiques restent identiques quel
    /// que soit l'ordre dans lequel ils ont ete construits.
    par_empreinte: HashMap<crate::hash::Hash256, HashSet<OutPoint>>,
}

/// L'index derive ne participe pas a l'egalite : seul l'ensemble des sorties
/// definit l'etat de la monnaie.
impl PartialEq for UtxoSet {
    fn eq(&self, autre: &Self) -> bool {
        self.map == autre.map
    }
}

impl Eq for UtxoSet {}

/// Trace de ce qu'un bloc a modifie, pour pouvoir le defaire.
///
/// Sans cela, annuler un bloc exigerait de rejouer la chaine depuis la genese —
/// ce qui rend toute reorganisation prohibitive.
#[derive(Clone, Debug, Default)]
pub struct UndoRecord {
    consommees: Vec<(OutPoint, UtxoEntry)>,
    creees: Vec<OutPoint>,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, o: &OutPoint) -> Option<&UtxoEntry> {
        self.map.get(o)
    }

    pub fn contains(&self, o: &OutPoint) -> bool {
        self.map.contains_key(o)
    }

    pub fn insert(&mut self, o: OutPoint, e: UtxoEntry) {
        let empreinte = e.output.pubkey_hash;
        if let Some(ancien) = self.map.insert(o, e) {
            // Remplacement : l'ancienne empreinte ne designe plus cette sortie.
            if ancien.output.pubkey_hash != empreinte {
                self.desindexer(&ancien.output.pubkey_hash, &o);
            }
        }
        self.par_empreinte.entry(empreinte).or_default().insert(o);
    }

    fn desindexer(&mut self, empreinte: &crate::hash::Hash256, o: &OutPoint) {
        if let Some(s) = self.par_empreinte.get_mut(empreinte) {
            s.remove(o);
            if s.is_empty() {
                self.par_empreinte.remove(empreinte);
            }
        }
    }

    pub fn remove(&mut self, o: &OutPoint) -> Option<UtxoEntry> {
        let e = self.map.remove(o);
        if let Some(v) = &e {
            let empreinte = v.output.pubkey_hash;
            self.desindexer(&empreinte, o);
        }
        e
    }

    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &UtxoEntry)> {
        self.map.iter()
    }

    /// Somme de toutes les sorties non depensees.
    ///
    /// C'est la masse monetaire reellement en circulation. Le test qui la compare
    /// a l'emission theorique est le garde-fou anti-inflation du projet.
    pub fn total_value(&self) -> Amount {
        Amount::checked_sum(self.map.values().map(|e| e.output.value))
            .expect("la masse monetaire ne peut pas deborder sous le plafond")
    }

    /// Applique une transaction : consomme ses entrees, cree ses sorties.
    ///
    /// Ne valide rien. La validation a lieu dans [`crate::validate`], avant.
    pub fn apply_transaction(&mut self, tx: &Transaction, height: u64, undo: &mut UndoRecord) {
        let coinbase = tx.is_coinbase();
        if !coinbase {
            for entree in &tx.inputs {
                if let Some(e) = self.remove(&entree.prev_out) {
                    undo.consommees.push((entree.prev_out, e));
                }
            }
        }
        let txid = tx.txid();
        for (i, sortie) in tx.outputs.iter().enumerate() {
            let o = OutPoint {
                txid,
                index: i as u32,
            };
            // Toujours par `insert` et `remove`, jamais directement sur `map` :
            // l'index par empreinte doit suivre chaque mouvement, sinon un solde
            // devient faux sans qu'aucun test de consensus ne s'en apercoive.
            self.insert(
                o,
                UtxoEntry {
                    output: *sortie,
                    height,
                    is_coinbase: coinbase,
                },
            );
            undo.creees.push(o);
        }
    }

    /// Defait un bloc : supprime ce qu'il a cree, restaure ce qu'il a consomme.
    pub fn undo(&mut self, record: &UndoRecord) {
        for o in &record.creees {
            self.remove(o);
        }
        for (o, e) in &record.consommees {
            self.insert(*o, *e);
        }
    }

    /// Sorties depensables par le detenteur d'une empreinte de clef donnee.
    ///
    /// Filtre la maturite des coinbases : une recompense de bloc fraiche n'est
    /// pas depensable.
    pub fn spendable_for(
        &self,
        pubkey_hash: &crate::hash::Hash256,
        hauteur_courante: u64,
        maturite: u64,
    ) -> Vec<(OutPoint, UtxoEntry)> {
        let Some(points) = self.par_empreinte.get(pubkey_hash) else {
            return Vec::new();
        };
        let mut v: Vec<(OutPoint, UtxoEntry)> = points
            .iter()
            .filter_map(|o| self.map.get(o).map(|e| (*o, *e)))
            .filter(|(_, e)| !e.is_coinbase || hauteur_courante >= e.height + maturite)
            .collect();
        // Ordre deterministe : sans cela, deux executions construiraient des
        // transactions differentes a partir du meme portefeuille.
        v.sort_by_key(|(o, _)| *o);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash256;
    use crate::sig::SchemeId;
    use crate::tx::{TxIn, Witness};

    fn sortie(v: u64, h: u8) -> TxOut {
        TxOut {
            value: Amount::from_units(v),
            scheme: SchemeId::LamportOts,
            pubkey_hash: Hash256([h; 32]),
        }
    }

    fn coinbase(v: u64, h: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(vec![1, 2, 3])],
            outputs: vec![sortie(v, h)],
            lock_time: 0,
        }
    }

    #[test]
    fn appliquer_une_coinbase_cree_une_sortie() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        let cb = coinbase(5_000, 1);
        u.apply_transaction(&cb, 1, &mut undo);

        assert_eq!(u.len(), 1);
        assert_eq!(u.total_value(), Amount::from_units(5_000));
        let e = u
            .get(&OutPoint {
                txid: cb.txid(),
                index: 0,
            })
            .unwrap();
        assert!(e.is_coinbase);
        assert_eq!(e.height, 1);
    }

    #[test]
    fn depenser_consomme_et_cree() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        let cb = coinbase(10_000, 1);
        u.apply_transaction(&cb, 1, &mut undo);

        let depense = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: cb.txid(),
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![sortie(6_000, 2), sortie(3_000, 1)],
            lock_time: 0,
        };
        let mut undo2 = UndoRecord::default();
        u.apply_transaction(&depense, 2, &mut undo2);

        assert_eq!(u.len(), 2);
        // 1 000 unites manquent : ce sont les frais, captes par la coinbase.
        assert_eq!(u.total_value(), Amount::from_units(9_000));
        assert!(!u.contains(&OutPoint {
            txid: cb.txid(),
            index: 0
        }));
    }

    #[test]
    fn defaire_restaure_l_etat_exactement() {
        let mut u = UtxoSet::new();
        let mut undo1 = UndoRecord::default();
        let cb = coinbase(10_000, 1);
        u.apply_transaction(&cb, 1, &mut undo1);
        let avant = u.total_value();
        let taille_avant = u.len();

        let depense = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: cb.txid(),
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![sortie(9_000, 2)],
            lock_time: 0,
        };
        let mut undo2 = UndoRecord::default();
        u.apply_transaction(&depense, 2, &mut undo2);
        assert_ne!(u.total_value(), avant);

        u.undo(&undo2);
        assert_eq!(
            u.total_value(),
            avant,
            "l'annulation n'a pas restaure l'etat"
        );
        assert_eq!(u.len(), taille_avant);
        assert!(u.contains(&OutPoint {
            txid: cb.txid(),
            index: 0
        }));
    }

    #[test]
    fn une_coinbase_immature_n_est_pas_depensable() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        u.apply_transaction(&coinbase(10_000, 7), 10, &mut undo);
        let h = Hash256([7u8; 32]);

        assert!(u.spendable_for(&h, 50, 200).is_empty(), "trop tot");
        assert_eq!(u.spendable_for(&h, 210, 200).len(), 1, "devrait etre mure");
    }

    #[test]
    fn le_filtrage_par_clef_fonctionne() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        u.apply_transaction(&coinbase(1_000, 1), 0, &mut undo);
        u.apply_transaction(&coinbase(2_000, 2), 0, &mut undo);

        assert_eq!(u.spendable_for(&Hash256([1u8; 32]), 1000, 0).len(), 1);
        assert_eq!(u.spendable_for(&Hash256([9u8; 32]), 1000, 0).len(), 0);
    }

    #[test]
    fn l_ordre_des_utxo_est_deterministe() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        for i in 0..20u8 {
            let mut cb = coinbase(1_000, 1);
            cb.inputs[0].witness.signature = vec![i];
            u.apply_transaction(&cb, 0, &mut undo);
        }
        let h = Hash256([1u8; 32]);
        let a: Vec<_> = u
            .spendable_for(&h, 1000, 0)
            .iter()
            .map(|(o, _)| *o)
            .collect();
        let b: Vec<_> = u
            .spendable_for(&h, 1000, 0)
            .iter()
            .map(|(o, _)| *o)
            .collect();
        assert_eq!(a, b, "l'ordre doit etre stable entre deux appels");
    }
}

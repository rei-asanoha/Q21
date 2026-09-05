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
    /// Empreinte MuHash tenue **au fil de l'eau**.
    ///
    /// # Pourquoi elle est ici
    ///
    /// `commitment()` reconstruisait l'empreinte depuis zero — une
    /// multiplication modulaire de 3 072 bits **par sortie** — a chaque appel.
    /// Or elle est appelee par l'explorateur public a chaque affichage de sa
    /// page, et par l'instantane toutes les cinq minutes, sous le verrou de la
    /// chaine. A un million de sorties, chaque visite figeait le noeud
    /// plusieurs secondes : un rafraichissement en boucle suffisait a le
    /// mettre hors service.
    ///
    /// MuHash est fait pour l'incrementiel : inserer multiplie le numerateur,
    /// retirer multiplie le denominateur, et l'empreinte finale ne coute qu'une
    /// division. Chaque `insert` et chaque `remove` la tiennent a jour ; c'est
    /// le meme choix que Bitcoin Core. Comme l'index par empreinte, elle est
    /// entierement derivee de `map` et n'entre pas dans l'egalite.
    empreinte: crate::muhash::MuHash,
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
            // Remplacement : l'ancienne piece sort de l'empreinte, et
            // l'ancienne clef ne designe plus cette sortie.
            self.empreinte.remove(&piece_serialisee(&o, &ancien));
            if ancien.output.pubkey_hash != empreinte {
                self.desindexer(&ancien.output.pubkey_hash, &o);
            }
        }
        self.empreinte.insert(&piece_serialisee(&o, &e));
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
            self.empreinte.remove(&piece_serialisee(o, v));
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

    /// Empreinte de l'ensemble : le condensat MuHash de toutes les sorties non
    /// depensees.
    ///
    /// # Ce qu'elle vaut
    ///
    /// C'est l'engagement sur l'etat de la monnaie. Deux noeuds qui detiennent le
    /// meme jeu d'UTXO en tirent la meme empreinte, quel que soit l'ordre dans
    /// lequel ils ont recu les blocs — la multiplication du MuHash est
    /// commutative, et c'est pourquoi ce parcours n'a pas besoin de trier. Une
    /// falsification qui *deplace* la propriete d'une sortie sans rien creer —
    /// celle que le controle d'emission de `state.rs` ne pouvait pas attraper —
    /// change l'empreinte : la piece serialisee inclut l'empreinte de clef.
    ///
    /// # Le format de la piece
    ///
    /// Chaque sortie est serialisee dans l'ordre exact de l'instantane
    /// ([`crate::state`]) : point de sortie, valeur, schema, empreinte de clef,
    /// hauteur, caractere de coinbase. Ce format est fige : le changer changerait
    /// toutes les empreintes.
    ///
    /// # Ce qu'elle coute
    ///
    /// Une division modulaire, quelle que soit la taille de l'ensemble :
    /// l'accumulateur est tenu a jour par `insert` et `remove`. La version qui
    /// reparcourt tout est [`Self::commitment_recalculee`] ; elle ne sert qu'a
    /// prouver que les deux coincident.
    pub fn commitment(&self) -> crate::hash::Hash256 {
        self.empreinte.digest()
    }

    /// L'empreinte recalculee depuis zero, sortie par sortie.
    ///
    /// C'est la definition ; [`Self::commitment`] en est la tenue incrementale.
    /// Lineaire en la taille de l'ensemble : reservee aux epreuves et aux
    /// verifications explicites, jamais au chemin chaud.
    pub fn commitment_recalculee(&self) -> crate::hash::Hash256 {
        let mut mu = crate::muhash::MuHash::new();
        for (o, e) in self.map.iter() {
            mu.insert(&piece_serialisee(o, e));
        }
        mu.digest()
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
    /// Cet ensemble contient-il au moins une sortie payant cette empreinte ?
    ///
    /// Sert a la decouverte d'adresses lors d'une restauration : on ne veut ni
    /// les montants, ni la maturite, ni meme le nombre — seulement savoir si
    /// l'indice essaye a deja recu quelque chose. La question se resout par une
    /// seule consultation de l'index, sans construire de vecteur.
    pub fn connait(&self, pubkey_hash: &crate::hash::Hash256) -> bool {
        self.par_empreinte
            .get(pubkey_hash)
            .is_some_and(|s| !s.is_empty())
    }

    /// Solde et nombre de sorties non depensees d'une empreinte.
    ///
    /// # Le defaut que cette methode ferme
    ///
    /// L'explorateur calculait ce solde en parcourant **tout** le jeu d'UTXO, et
    /// il le faisait en tenant le verrou global — celui-la meme qui sert a
    /// valider les blocs et a servir le reservoir. Sur une chaine mure, chaque
    /// consultation d'adresse — publique, non authentifiee, et l'usage principal
    /// d'un explorateur — immobilisait donc le consensus le temps d'un balayage
    /// complet. Quelques requetes par seconde suffisaient a ralentir
    /// l'acceptation des blocs, sans qu'aucune n'ait l'air malveillante.
    ///
    /// L'index par empreinte existait deja pour `spendable_for`, ou il avait
    /// resolu exactement le meme cout quadratique. Il ne restait qu'a s'en
    /// servir ici : le prix passe de la taille du jeu entier au nombre de
    /// sorties de la seule adresse demandee.
    ///
    /// La valeur rendue est identique a celle du balayage, saturation comprise :
    /// c'est le meme calcul, sur les memes sorties, dans un ordre different.
    pub fn solde_de(&self, pubkey_hash: &crate::hash::Hash256) -> (u64, u64) {
        let Some(points) = self.par_empreinte.get(pubkey_hash) else {
            return (0, 0);
        };
        let mut somme = 0u64;
        let mut nombre = 0u64;
        for o in points {
            if let Some(e) = self.map.get(o) {
                somme = somme.saturating_add(e.output.value.units());
                nombre += 1;
            }
        }
        (somme, nombre)
    }

    /// Toutes les sorties non depensees d'une empreinte, **maturite comprise**.
    ///
    /// [`UtxoSet::spendable_for`] ecarte les coinbases trop jeunes ; il faut
    /// parfois justement celles-la — pour dire a un mineur quand sa recompense
    /// se liberera. Passer par l'index evite de parcourir tout le jeu pour
    /// retrouver les quelques sorties d'une seule adresse.
    pub fn sorties_de(&self, pubkey_hash: &crate::hash::Hash256) -> Vec<(OutPoint, UtxoEntry)> {
        let Some(points) = self.par_empreinte.get(pubkey_hash) else {
            return Vec::new();
        };
        let mut v: Vec<(OutPoint, UtxoEntry)> = points
            .iter()
            .filter_map(|o| self.map.get(o).map(|e| (*o, *e)))
            .collect();
        // Ordre deterministe : deux executions doivent rendre la meme reponse.
        v.sort_by_key(|(o, _)| *o);
        v
    }

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

/// Serialise une sortie non depensee dans le format canonique de la piece.
///
/// 86 octets, dans l'ordre de l'instantane : txid (32), index (4), valeur (8),
/// schema (1), empreinte de clef (32), hauteur (8), coinbase (1). C'est cette
/// suite d'octets qui entre dans le MuHash ; son ordre est du consensus local et
/// ne doit jamais changer.
fn piece_serialisee(o: &OutPoint, e: &UtxoEntry) -> Vec<u8> {
    let mut w = crate::ser::Writer::with_capacity(86);
    w.bytes(o.txid.as_bytes());
    w.u32(o.index);
    w.u64(e.output.value.units());
    w.u8(e.output.scheme.as_u8());
    w.bytes(e.output.pubkey_hash.as_bytes());
    w.u64(e.height);
    w.u8(u8::from(e.is_coinbase));
    w.finish()
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

    /// Le solde rendu par l'index doit coincider avec un balayage complet, en
    /// toute circonstance — y compris apres une annulation, qui remet en
    /// circulation des sorties depensees et retire des sorties creees. C'est
    /// precisement la qu'un index derive peut s'ecarter de la verite, et le
    /// solde d'un explorateur ne vaut que s'il ne s'en ecarte jamais.
    #[test]
    fn le_solde_par_empreinte_coincide_toujours_avec_le_balayage() {
        fn balayage(u: &UtxoSet, cle: &Hash256) -> (u64, u64) {
            let mut somme = 0u64;
            let mut n = 0u64;
            for (_, e) in u.iter() {
                if e.output.pubkey_hash == *cle {
                    somme = somme.saturating_add(e.output.value.units());
                    n += 1;
                }
            }
            (somme, n)
        }
        fn verifier(u: &UtxoSet, etape: &str) {
            for h in 0..5u8 {
                let cle = Hash256([h; 32]);
                assert_eq!(
                    u.solde_de(&cle),
                    balayage(u, &cle),
                    "{etape} : l'index diverge du balayage sur l'empreinte {h}"
                );
            }
        }

        let mut u = UtxoSet::new();

        // Deux sorties sur une meme empreinte, une troisieme ailleurs.
        let a1 = coinbase(5_000, 1);
        let a2 = coinbase(3_000, 1);
        let b1 = coinbase(7_000, 2);
        let mut undo1 = UndoRecord::default();
        u.apply_transaction(&a1, 1, &mut undo1);
        u.apply_transaction(&a2, 1, &mut undo1);
        u.apply_transaction(&b1, 1, &mut undo1);
        verifier(&u, "apres creation");
        assert_eq!(u.solde_de(&Hash256([1; 32])), (8_000, 2));

        // Une depense : l'empreinte 1 perd une sortie, l'empreinte 3 en gagne.
        let depense = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: a1.txid(),
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![sortie(4_000, 3)],
            lock_time: 0,
        };
        let mut undo2 = UndoRecord::default();
        u.apply_transaction(&depense, 2, &mut undo2);
        verifier(&u, "apres depense");
        assert_eq!(u.solde_de(&Hash256([1; 32])), (3_000, 1));
        assert_eq!(u.solde_de(&Hash256([3; 32])), (4_000, 1));

        // Annulation : l'index doit revenir exactement a l'etat precedent.
        u.undo(&undo2);
        verifier(&u, "apres annulation");
        assert_eq!(u.solde_de(&Hash256([1; 32])), (8_000, 2));
        assert_eq!(
            u.solde_de(&Hash256([3; 32])),
            (0, 0),
            "une sortie annulee ne doit plus compter"
        );

        // Une empreinte inconnue n'a ni solde ni sortie.
        assert_eq!(u.solde_de(&Hash256([42; 32])), (0, 0));
    }

    /// L'empreinte tenue au fil de l'eau coincide avec l'empreinte recalculee,
    /// en toute circonstance : creations, depenses, annulations, remplacement
    /// d'une sortie sous le meme point, et retrait d'une sortie inconnue.
    ///
    /// C'est le contrat qui autorise `commitment()` a ne plus parcourir
    /// l'ensemble. La moindre derive entre les deux chemins ferait refuser un
    /// instantane valide — ou accepter un instantane faux — par tout le reseau.
    #[test]
    fn l_empreinte_incrementale_coincide_toujours_avec_le_recalcul() {
        fn verifier(u: &UtxoSet, etape: &str) {
            assert_eq!(
                u.commitment(),
                u.commitment_recalculee(),
                "{etape} : l'empreinte incrementale diverge du recalcul"
            );
        }

        let mut u = UtxoSet::new();
        verifier(&u, "vide");
        let vide = u.commitment();

        let a1 = coinbase(5_000, 1);
        let a2 = coinbase(3_000, 1);
        let b1 = coinbase(7_000, 2);
        let mut undo1 = UndoRecord::default();
        u.apply_transaction(&a1, 1, &mut undo1);
        verifier(&u, "une creation");
        u.apply_transaction(&a2, 1, &mut undo1);
        u.apply_transaction(&b1, 1, &mut undo1);
        verifier(&u, "trois creations");
        let trois = u.commitment();
        assert_ne!(trois, vide);

        let depense = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: a1.txid(),
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![sortie(4_000, 3), sortie(900, 4)],
            lock_time: 0,
        };
        let mut undo2 = UndoRecord::default();
        u.apply_transaction(&depense, 2, &mut undo2);
        verifier(&u, "apres depense");

        // L'annulation ramene exactement a l'empreinte d'avant : ce n'est pas
        // seulement « coherent avec le recalcul », c'est la meme valeur.
        u.undo(&undo2);
        verifier(&u, "apres annulation");
        assert_eq!(u.commitment(), trois);

        // Remplacement sous le meme point de sortie : l'ancienne piece doit
        // sortir de l'empreinte avant que la nouvelle y entre.
        let point = OutPoint {
            txid: b1.txid(),
            index: 0,
        };
        u.insert(
            point,
            UtxoEntry {
                output: sortie(7_000, 9),
                height: 1,
                is_coinbase: true,
            },
        );
        verifier(&u, "apres remplacement");
        assert_ne!(u.commitment(), trois);

        // Retirer une sortie inconnue ne touche a rien.
        let avant = u.commitment();
        assert!(u
            .remove(&OutPoint {
                txid: Hash256([0xEE; 32]),
                index: 7,
            })
            .is_none());
        assert_eq!(u.commitment(), avant);
        verifier(&u, "apres retrait inconnu");

        // Tout annuler ramene a l'ensemble vide, et a son empreinte.
        u.undo(&undo1);
        u.remove(&point);
        assert!(u.is_empty());
        verifier(&u, "vide a nouveau");
        assert_eq!(u.commitment(), vide);
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

    #[test]
    fn l_empreinte_est_independante_de_l_ordre_d_insertion() {
        // Deux jeux identiques, remplis dans deux ordres opposes, ont la meme
        // empreinte : c'est toute la promesse du MuHash.
        let mut a = UtxoSet::new();
        let mut b = UtxoSet::new();
        let mut entrees = Vec::new();
        for i in 0..25u8 {
            let o = OutPoint {
                txid: Hash256([i; 32]),
                index: u32::from(i),
            };
            let e = UtxoEntry {
                output: sortie(1_000 + u64::from(i), i),
                height: u64::from(i),
                is_coinbase: i % 4 == 0,
            };
            entrees.push((o, e));
        }
        for (o, e) in &entrees {
            a.insert(*o, *e);
        }
        for (o, e) in entrees.iter().rev() {
            b.insert(*o, *e);
        }
        assert_eq!(a.commitment(), b.commitment());
    }

    #[test]
    fn l_empreinte_du_jeu_vide_est_stable() {
        assert_eq!(UtxoSet::new().commitment(), UtxoSet::new().commitment());
    }

    #[test]
    fn depenser_change_l_empreinte_et_defaire_la_restaure() {
        let mut u = UtxoSet::new();
        let mut undo0 = UndoRecord::default();
        u.apply_transaction(&coinbase(10_000, 1), 1, &mut undo0);
        let avant = u.commitment();

        let cb_txid = coinbase(10_000, 1).txid();
        let depense = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: cb_txid,
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![sortie(9_000, 2)],
            lock_time: 0,
        };
        let mut undo = UndoRecord::default();
        u.apply_transaction(&depense, 2, &mut undo);
        assert_ne!(u.commitment(), avant, "depenser doit changer l'empreinte");

        u.undo(&undo);
        assert_eq!(u.commitment(), avant, "defaire doit restaurer l'empreinte");
    }

    #[test]
    fn deplacer_la_propriete_change_l_empreinte() {
        // La falsification que le controle d'emission ne voit pas : meme montant,
        // meme hauteur, autre beneficiaire. L'empreinte, elle, la voit.
        let o = OutPoint {
            txid: Hash256([9; 32]),
            index: 0,
        };
        let mut honnete = UtxoSet::new();
        honnete.insert(
            o,
            UtxoEntry {
                output: sortie(5_000, 1),
                height: 3,
                is_coinbase: false,
            },
        );
        let mut falsifie = UtxoSet::new();
        falsifie.insert(
            o,
            UtxoEntry {
                output: sortie(5_000, 2), // meme montant, autre empreinte de clef
                height: 3,
                is_coinbase: false,
            },
        );
        assert_ne!(honnete.commitment(), falsifie.commitment());
    }
}

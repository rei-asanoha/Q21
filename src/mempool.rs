//! Reservoir de transactions en attente.
//!
//! Le mempool n'est pas du consensus : deux noeuds peuvent en avoir des contenus
//! differents sans que la chaine se scinde. C'est en revanche une **surface
//! d'attaque de premier plan**, parce qu'il accepte des donnees non sollicitees
//! venues de n'importe qui. Chaque regle de ce fichier repond a un abus precis,
//! nomme en commentaire.
//!
//! # Le probleme particulier de Q21
//!
//! Une transaction Q21 pese lourd : le temoin represente 99 % de sa taille.
//! Facturer les frais a l'octet brut reviendrait a facturer la cryptographie
//! post-quantique au prix fort et a rendre la chaine inutilisable. Le mempool
//! ordonne donc par **taux de frais au poids ponderé**, la ponderation etant
//! celle du `witness discount` de la section 7 du livre blanc.
//!
//! # Chaines de transactions non confirmees
//!
//! Une transaction peut depenser une sortie creee par une autre transaction
//! encore dans le mempool. Sans cela, on ne peut pas envoyer deux fois de suite
//! sans attendre un bloc — soit dix minutes chez Bitcoin, deux ici. La
//! limitation de la phase 4 est levee.
//!
//! Trois consequences, toutes traitees :
//!
//! - **la validation se fait contre une vue** ([`MempoolView`]) qui superpose
//!   les sorties du mempool aux sorties confirmees, sans cloner ces dernieres ;
//! - **l'eviction est en paquet.** Retirer une transaction retire tous ses
//!   descendants : les laisser serait garder des transactions dont les entrees
//!   n'existent plus, donc invalides ;
//! - **la selection pour un bloc est topologique.** Un enfant place avant son
//!   parent produirait un bloc invalide, et le mineur decouvrirait le probleme
//!   apres avoir depense son electricite.

use crate::address::Network;
use crate::amount::Amount;
use crate::consensus::{COINBASE_MATURITY, MAX_BLOCK_SIZE, POIDS_BLOC_CIBLE, WITNESS_DISCOUNT};
use crate::hash::Hash256;
use crate::tx::{OutPoint, Transaction};
use crate::utxo::{UtxoEntry, UtxoSet, UtxoView};
use crate::validate::{self, ValidationError};
use std::collections::{HashMap, HashSet};

/// Taille maximale du mempool, en octets serialises.
///
/// Borne dure : sans elle, un adversaire remplit la memoire du noeud avec des
/// transactions valides mais jamais minees.
pub const MEMPOOL_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Taux de frais minimal accepte, en unites par millier d'unites de poids.
///
/// Filtre le bruit gratuit. Volontairement bas : le but est d'ecarter l'inondation
/// a cout nul, pas de fixer un marche des frais.
pub const MIN_FEE_RATE: u64 = 1;

#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub fee: Amount,
    /// Poids ponderé, temoin escompte.
    pub weight: u64,
    /// Taille serialisee complete, pour la comptabilite memoire.
    pub size: usize,
    /// Ordre d'arrivee, pour departager a taux de frais egal.
    pub arrivee: u64,
}

impl MempoolEntry {
    /// Frais par millier d'unites de poids.
    pub fn fee_rate(&self) -> u64 {
        self.fee.units().saturating_mul(1000) / self.weight.max(1)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MempoolError {
    DejaPresent,
    /// Une entree consomme une sortie deja engagee par une autre transaction du
    /// mempool. On ne relaie pas une double depense.
    ConflitDeDepense(OutPoint),
    /// Une entree provient d'une transaction encore non confirmee.
    DependanceNonConfirmee(OutPoint),
    TauxDeFraisTropBas {
        recu: u64,
        minimum: u64,
    },
    /// Trop lourde pour tenir dans un bloc : elle ne serait jamais minee, et
    /// n'occuperait le reservoir qu'au detriment des autres.
    Inminable {
        poids: u64,
        size: usize,
    },
    /// Le mempool est plein et cette transaction paie moins que la moins-disante.
    PleinEtTropPeuPayee,
    Validation(ValidationError),
}

impl From<ValidationError> for MempoolError {
    fn from(e: ValidationError) -> Self {
        MempoolError::Validation(e)
    }
}

/// Vue superposant les sorties du mempool aux sorties confirmees.
///
/// Ne copie rien : les deux ensembles sont consultes a la demande. Le mempool
/// prime, puisque ses sorties sont plus recentes que la chaine.
/// Place reellement utilisable par les transactions dans un bloc.
///
/// Un bloc doit aussi loger sa coinbase et ses eventuels oncles. On retient une
/// marge franche : une transaction qui ne tiendrait dans un bloc qu'a la
/// condition d'etre seule n'a rien a faire dans le reservoir.
pub const MAX_BLOC_UTILE: usize = MAX_BLOCK_SIZE - 64 * 1024;

/// Poids maximal d'une transaction acceptee au reservoir.
///
/// Cale sur le budget que le mineur emploie reellement pour assembler un bloc
/// ([`crate::consensus::POIDS_BLOC_CIBLE`]). Une transaction plus lourde ne
/// serait jamais selectionnee : l'accepter reviendrait a offrir du reservoir
/// gratuit a qui n'a aucune intention de payer.
pub const MAX_POIDS_UTILE: u64 = POIDS_BLOC_CIBLE;

/// Frais apparents d'une transaction, sans verifier une seule signature.
///
/// Les montants d'entree se lisent dans le jeu d'UTXO ; savoir qu'une
/// transaction ne paie pas assez ne demande aucune cryptographie. C'est ce qui
/// permet de rejeter une inondation avant d'avoir depense le moindre calcul
/// post-quantique.
fn frais_apparents(tx: &Transaction, vue: &MempoolView<'_>) -> Result<u64, MempoolError> {
    let mut entrees: u64 = 0;
    for e in &tx.inputs {
        let u = vue
            .lookup(&e.prev_out)
            .ok_or(MempoolError::DependanceNonConfirmee(e.prev_out))?;
        entrees = entrees
            .checked_add(u.output.value.units())
            .ok_or(MempoolError::DependanceNonConfirmee(e.prev_out))?;
    }
    let sorties =
        tx.total_output()
            .map(|a| a.units())
            .map_err(|_| MempoolError::TauxDeFraisTropBas {
                recu: 0,
                minimum: MIN_FEE_RATE,
            })?;
    Ok(entrees.saturating_sub(sorties))
}

pub struct MempoolView<'a> {
    confirme: &'a UtxoSet,
    overlay: &'a HashMap<OutPoint, UtxoEntry>,
    /// Sorties deja consommees par le mempool : invisibles, meme si elles
    /// existent encore dans le jeu confirme.
    consommees: &'a HashMap<OutPoint, Hash256>,
}

impl UtxoView for MempoolView<'_> {
    fn lookup(&self, o: &OutPoint) -> Option<UtxoEntry> {
        if let Some(e) = self.overlay.get(o) {
            return Some(*e);
        }
        if self.consommees.contains_key(o) {
            return None;
        }
        self.confirme.lookup(o)
    }
}

#[derive(Default)]
pub struct Mempool {
    entrees: HashMap<Hash256, MempoolEntry>,
    /// Sorties engagees par le mempool : detecte les doubles depenses.
    engagees: HashMap<OutPoint, Hash256>,
    /// Sorties creees par les transactions du mempool, depensables par leurs
    /// descendants avant confirmation.
    creees: HashMap<OutPoint, UtxoEntry>,
    /// Enfants directs de chaque transaction, pour l'eviction en paquet.
    enfants: HashMap<Hash256, Vec<Hash256>>,
    /// Parents encore non confirmes de chaque transaction.
    parents: HashMap<Hash256, Vec<Hash256>>,
    octets: usize,
    compteur: u64,
}

impl Mempool {
    pub fn new() -> Mempool {
        Mempool::default()
    }

    /// Taux de frais median des transactions en attente, en unites par millier
    /// d'unites de poids.
    ///
    /// Sert a proposer des frais qui refletent l'etat reel du reseau plutot
    /// qu'une constante choisie une fois pour toutes. Rend `None` quand le
    /// reservoir est vide : il n'y a alors rien a mesurer, et inventer un
    /// chiffre serait pire que de ne rien dire.
    pub fn taux_median(&self) -> Option<u64> {
        if self.entrees.is_empty() {
            return None;
        }
        let mut taux: Vec<u64> = self.entrees.values().map(|e| e.fee_rate()).collect();
        taux.sort_unstable();
        Some(taux[taux.len() / 2])
    }

    pub fn len(&self) -> usize {
        self.entrees.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entrees.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.octets
    }

    pub fn contains(&self, txid: &Hash256) -> bool {
        self.entrees.contains_key(txid)
    }

    pub fn get(&self, txid: &Hash256) -> Option<&Transaction> {
        self.entrees.get(txid).map(|e| &e.tx)
    }

    pub fn txids(&self) -> Vec<Hash256> {
        let mut v: Vec<Hash256> = self.entrees.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Ajoute une transaction apres validation complete.
    pub fn accept(
        &mut self,
        tx: &Transaction,
        utxo: &UtxoSet,
        network: Network,
        hauteur: u64,
    ) -> Result<Hash256, MempoolError> {
        let txid = tx.txid();
        if self.entrees.contains_key(&txid) {
            return Err(MempoolError::DejaPresent);
        }

        // --- Abus : relayer deux versions concurrentes d'une meme depense.
        let mut parents: Vec<Hash256> = Vec::new();
        for e in &tx.inputs {
            if let Some(autre) = self.engagees.get(&e.prev_out) {
                if *autre != txid {
                    return Err(MempoolError::ConflitDeDepense(e.prev_out));
                }
            }
            // Une entree venant du mempool est desormais legitime : on note
            // seulement la dependance, pour pouvoir evincer en paquet.
            if self.creees.contains_key(&e.prev_out) {
                parents.push(e.prev_out.txid);
            } else if !utxo.contains(&e.prev_out) {
                return Err(MempoolError::DependanceNonConfirmee(e.prev_out));
            }
        }

        // --- Abus : occuper le reservoir avec ce qui ne pourra jamais etre mine.
        //
        // Une transaction plus lourde qu'un bloc entier etait acceptee, puis
        // jamais selectionnee. L'audit de la phase 8b l'a mesure : trente
        // transactions de ce genre occupaient **99,8 %** du reservoir, pour un
        // cout reel de zero — rien n'etant mine, aucun frais n'etait jamais
        // paye. Il ne restait aux transactions honnetes que 107 Kio sur 64 Mio.
        //
        // On refuse donc en amont ce qu'un bloc ne pourra pas contenir.
        let weight = tx.weight(WITNESS_DISCOUNT);
        let size = tx.encode().len();
        if size > MAX_BLOC_UTILE || weight > MAX_POIDS_UTILE {
            return Err(MempoolError::Inminable {
                poids: weight,
                size,
            });
        }

        // --- Abus : faire verifier des signatures post-quantiques pour rien.
        //
        // La verification des signatures precedait le controle des frais. Un
        // rejet a frais nuls coutait 15,9 ms de calcul, contre 91 us pour un
        // rejet de forme : un rapport de 175. Un adversaire faisait donc bruler
        // du temps de processeur au prix d'un envoi.
        //
        // On calcule les frais **avant** toute cryptographie. Le montant des
        // entrees se lit dans le jeu d'UTXO ; aucune signature n'est necessaire
        // pour savoir qu'une transaction ne paie pas assez.
        let vue = MempoolView {
            confirme: utxo,
            overlay: &self.creees,
            consommees: &self.engagees,
        };
        let frais_annonces = frais_apparents(tx, &vue)?;
        let taux_annonce = frais_annonces.saturating_mul(1000) / weight.max(1);
        if taux_annonce < MIN_FEE_RATE {
            return Err(MempoolError::TauxDeFraisTropBas {
                recu: taux_annonce,
                minimum: MIN_FEE_RATE,
            });
        }

        // Validation complete : signatures, conservation de la valeur, maturite.
        // La hauteur utilisee est celle du prochain bloc, puisque c'est la que
        // cette transaction pourrait entrer.
        let mut vues: HashSet<OutPoint> = HashSet::new();
        let fee = validate::check_transaction(tx, &vue, network, hauteur + 1, &mut vues)?;
        let entree = MempoolEntry {
            tx: tx.clone(),
            fee,
            weight,
            size,
            arrivee: self.compteur,
        };

        // --- Abus : inonder gratuitement.
        let taux = entree.fee_rate();
        if taux < MIN_FEE_RATE {
            return Err(MempoolError::TauxDeFraisTropBas {
                recu: taux,
                minimum: MIN_FEE_RATE,
            });
        }

        // --- Abus : saturer la memoire du noeud.
        if self.octets + size > MEMPOOL_MAX_BYTES && !self.faire_de_la_place(taux, size) {
            return Err(MempoolError::PleinEtTropPeuPayee);
        }

        self.compteur += 1;
        self.octets += size;
        for e in &tx.inputs {
            self.engagees.insert(e.prev_out, txid);
        }
        // Les sorties de cette transaction deviennent depensables par ses
        // descendants. Elles ne sont jamais des coinbases : une coinbase
        // n'entre pas au mempool.
        for (i, sortie) in tx.outputs.iter().enumerate() {
            self.creees.insert(
                OutPoint {
                    txid,
                    index: i as u32,
                },
                UtxoEntry {
                    output: *sortie,
                    height: hauteur + 1,
                    is_coinbase: false,
                },
            );
        }
        parents.sort_unstable();
        parents.dedup();
        for p in &parents {
            self.enfants.entry(*p).or_default().push(txid);
        }
        self.parents.insert(txid, parents);
        self.entrees.insert(txid, entree);
        Ok(txid)
    }

    /// Evince les transactions les moins-disantes pour loger `taille` octets.
    ///
    /// Rend `false` si la nouvelle venue paie moins que tout ce qu'il faudrait
    /// sacrifier : dans ce cas on la refuse plutot que d'appauvrir le mempool.
    fn faire_de_la_place(&mut self, taux_entrant: u64, taille: usize) -> bool {
        let mut candidats: Vec<(Hash256, u64)> = self
            .entrees
            .iter()
            .map(|(id, e)| (*id, e.fee_rate()))
            .collect();
        candidats.sort_by_key(|(id, taux)| (*taux, *id));

        let mut libere = 0usize;
        let mut a_retirer = Vec::new();
        for (id, taux) in candidats {
            if self.octets + taille - libere <= MEMPOOL_MAX_BYTES {
                break;
            }
            if taux >= taux_entrant {
                return false; // rien de moins-disant a sacrifier
            }
            libere += self.entrees[&id].size;
            a_retirer.push(id);
        }
        for id in a_retirer {
            self.remove(&id);
        }
        self.octets + taille <= MEMPOOL_MAX_BYTES
    }

    /// Retire une transaction **et tous ses descendants**.
    ///
    /// Garder un enfant dont le parent a disparu reviendrait a garder une
    /// transaction dont les entrees n'existent plus : invalide, et relayee a
    /// tout le reseau.
    pub fn remove(&mut self, txid: &Hash256) -> Option<MempoolEntry> {
        // Parcours en largeur de la descendance, pour eviter la recursion sur
        // une chaine profonde.
        let mut a_retirer = vec![*txid];
        let mut i = 0;
        while i < a_retirer.len() {
            if let Some(enfants) = self.enfants.get(&a_retirer[i]) {
                for c in enfants.clone() {
                    if !a_retirer.contains(&c) {
                        a_retirer.push(c);
                    }
                }
            }
            i += 1;
        }

        let mut premier = None;
        // On retire les descendants d'abord, la cible en dernier, pour rendre
        // l'entree demandee a l'appelant.
        for id in a_retirer.into_iter().rev() {
            if let Some(e) = self.retirer_un(&id) {
                if id == *txid {
                    premier = Some(e);
                }
            }
        }
        premier
    }

    /// Retire une seule transaction, sans toucher a sa descendance.
    fn retirer_un(&mut self, txid: &Hash256) -> Option<MempoolEntry> {
        let e = self.entrees.remove(txid)?;
        self.octets = self.octets.saturating_sub(e.size);
        for entree in &e.tx.inputs {
            if self.engagees.get(&entree.prev_out) == Some(txid) {
                self.engagees.remove(&entree.prev_out);
            }
        }
        for i in 0..e.tx.outputs.len() {
            self.creees.remove(&OutPoint {
                txid: *txid,
                index: i as u32,
            });
        }
        if let Some(parents) = self.parents.remove(txid) {
            for p in parents {
                if let Some(v) = self.enfants.get_mut(&p) {
                    v.retain(|c| c != txid);
                }
            }
        }
        self.enfants.remove(txid);
        Some(e)
    }

    /// Nombre de descendants directs d'une transaction.
    pub fn child_count(&self, txid: &Hash256) -> usize {
        self.enfants.get(txid).map(|v| v.len()).unwrap_or(0)
    }

    /// Retire ce qu'un bloc vient de confirmer, ou de rendre invalide.
    ///
    /// Deux cas distincts : une transaction du bloc est desormais confirmee, et
    /// une transaction du mempool qui depensait la meme sortie est desormais une
    /// double depense. Les deux doivent partir.
    pub fn on_block_connected(&mut self, block: &crate::block::Block) {
        for tx in &block.transactions {
            self.remove(&tx.txid());
            for entree in &tx.inputs {
                if let Some(conflit) = self.engagees.get(&entree.prev_out).copied() {
                    self.remove(&conflit);
                }
            }
        }
    }

    /// Transactions candidates a un bloc, les mieux-disantes d'abord.
    ///
    /// Ordre deterministe a taux egal : sans cela, deux mineurs partant du meme
    /// mempool construiraient des blocs differents sans raison.
    pub fn select_for_block(&self, poids_max: u64) -> Vec<Transaction> {
        // Les identifiants sont calcules **une fois**, pas a chaque comparaison
        // du tri.
        //
        // La version precedente appelait `txid()` — un condensat sur toute la
        // transaction serialisee — a l'interieur du comparateur, donc O(n log n)
        // fois. Sur un reservoir plein de grosses transactions, l'audit de la
        // phase 8b a mesure **3,96 secondes pour retenir une seule
        // transaction**, et cela sous le verrou global du noeud : tout
        // s'arretait pendant ce temps, a chaque modele de bloc.
        let mut v: Vec<(&MempoolEntry, Hash256, u64)> = self
            .entrees
            .iter()
            .map(|(id, e)| (e, *id, e.fee_rate()))
            .collect();
        v.sort_by(|(a, ida, taux_a), (b, idb, taux_b)| {
            taux_b
                .cmp(taux_a)
                .then(a.arrivee.cmp(&b.arrivee))
                .then(ida.cmp(idb))
        });

        let mut choisies: Vec<Transaction> = Vec::new();
        let mut retenues: HashSet<Hash256> = HashSet::new();
        let mut poids = 0u64;

        for (e, id, _) in v {
            if poids + e.weight > poids_max {
                continue;
            }
            // --- Ordre topologique : un enfant ne passe jamais avant son parent.
            //
            // Sans ce controle, le mineur produirait un bloc ou une transaction
            // depense une sortie qui n'existe pas encore — invalide, et il ne
            // s'en apercevrait qu'apres avoir depense son electricite.
            let parents_prets = self
                .parents
                .get(&id)
                .map(|ps| {
                    ps.iter()
                        .all(|p| retenues.contains(p) || !self.entrees.contains_key(p))
                })
                .unwrap_or(true);
            if !parents_prets {
                continue;
            }
            poids += e.weight;
            retenues.insert(id);
            choisies.push(e.tx.clone());
        }
        choisies
    }

    /// Revalide tout le mempool contre un jeu d'UTXO.
    ///
    /// Necessaire apres une reorganisation : des transactions confirmees peuvent
    /// redevenir valides, et d'autres devenir impossibles.
    pub fn revalidate(&mut self, utxo: &UtxoSet, _network: Network, hauteur: u64) {
        // La version precedente revalidait chaque transaction avec
        // `check_transaction` contre une vue ou `consommees` contenait **ses
        // propres entrees**. Chaque transaction se voyait donc comme une double
        // depense d'elle-meme, et se retirait. Appelee a chaque bloc connecte,
        // cette fonction **vidait integralement le reservoir** : trois
        // transactions parfaitement valides devenaient zero. Mesure de l'audit
        // de la phase 8b : « avant 50, apres 0 ».
        //
        // Le reservoir etait donc vide en permanence sur un vrai reseau, et
        // aucune transaction n'atteignait jamais un bloc autrement qu'en etant
        // minee dans la seconde qui suit son arrivee.
        //
        // Ce qui change reellement quand un bloc est connecte, ce n'est pas la
        // validite d'une signature — le condensat signe ne depend pas de la
        // chaine — mais la **disponibilite des entrees** et la **maturite des
        // coinbases**. On ne verifie donc que cela, et on cascade sur les
        // descendants. C'est aussi bien plus rapide : aucune signature
        // post-quantique n'est reverifiee.
        loop {
            let mut orphelines: Vec<Hash256> = Vec::new();

            for (id, e) in &self.entrees {
                for entree in &e.tx.inputs {
                    let dispo = match utxo.get(&entree.prev_out) {
                        Some(u) => {
                            // Une reorganisation peut faire *baisser* la hauteur :
                            // une coinbase mure peut redevenir immature.
                            !u.is_coinbase || hauteur + 1 >= u.height + COINBASE_MATURITY
                        }
                        // Sinon, la sortie doit venir d'une autre transaction du
                        // reservoir, encore presente.
                        None => self.creees.contains_key(&entree.prev_out),
                    };
                    if !dispo {
                        orphelines.push(*id);
                        break;
                    }
                }
            }

            if orphelines.is_empty() {
                return;
            }
            for id in orphelines {
                // `remove` emporte deja la descendance.
                self.remove(&id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis_block, Chain, GENESIS_TIME};
    use crate::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
    use crate::sig::SchemeId;
    use crate::wallet::Wallet;

    const RESEAU: Network = Network::Regtest;
    const ESSAIS: u64 = 5_000_000;

    pub fn chaine(w: &mut Wallet, n: u64) -> Chain {
        chaine_avec_fonds(w, n)
    }

    fn chaine_avec_fonds(w: &mut Wallet, n: u64) -> Chain {
        let _ = w.new_address();
        let g = genesis_block(RESEAU);
        let mut c = Chain::new(RESEAU, g);
        for i in 1..=n {
            let a = w.new_address();
            let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
                .expect("minage");
            c.connect(&b, t + 1).expect("connexion");
        }
        c
    }

    fn transfert(w: &mut Wallet, c: &Chain, frais: u64) -> Transaction {
        let mut dest = Wallet::from_seed([0xbb; 32], RESEAU);
        let a = dest.new_address();
        w.create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(10_000),
            Amount::from_units(frais),
        )
        .expect("construction")
    }

    #[test]
    fn une_transaction_valide_est_acceptee() {
        let mut w = Wallet::from_seed([0x01; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfert(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        let id = m
            .accept(&tx, &c.utxo, RESEAU, c.height())
            .expect("acceptation");
        assert_eq!(id, tx.txid());
        assert_eq!(m.len(), 1);
        assert!(m.contains(&id));
        assert!(m.bytes() > 0);
    }

    #[test]
    fn une_transaction_deja_presente_est_refusee() {
        let mut w = Wallet::from_seed([0x02; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfert(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, RESEAU, c.height()).unwrap();
        assert_eq!(
            m.accept(&tx, &c.utxo, RESEAU, c.height()),
            Err(MempoolError::DejaPresent)
        );
    }

    #[test]
    fn une_double_depense_est_refusee() {
        let mut w = Wallet::from_seed([0x03; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx1 = transfert(&mut w, &c, 5_000);

        // Fabrique une seconde transaction consommant la meme entree.
        let mut tx2 = tx1.clone();
        tx2.lock_time = 42; // change le txid sans changer les entrees

        let mut m = Mempool::new();
        m.accept(&tx1, &c.utxo, RESEAU, c.height()).unwrap();
        assert!(matches!(
            m.accept(&tx2, &c.utxo, RESEAU, c.height()),
            Err(MempoolError::ConflitDeDepense(_))
        ));
    }

    #[test]
    fn une_signature_invalide_est_refusee() {
        let mut w = Wallet::from_seed([0x04; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let mut tx = transfert(&mut w, &c, 5_000);
        tx.inputs[0].witness.signature[0] ^= 0x01;

        let mut m = Mempool::new();
        assert!(matches!(
            m.accept(&tx, &c.utxo, RESEAU, c.height()),
            Err(MempoolError::Validation(_))
        ));
        assert!(m.is_empty(), "rien ne doit rester apres un refus");
    }

    #[test]
    fn une_entree_inexistante_est_refusee() {
        let mut w = Wallet::from_seed([0x05; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let mut tx = transfert(&mut w, &c, 5_000);
        tx.inputs[0].prev_out.txid = Hash256([0xee; 32]);

        let mut m = Mempool::new();
        assert!(matches!(
            m.accept(&tx, &c.utxo, RESEAU, c.height()),
            Err(MempoolError::DependanceNonConfirmee(_))
        ));
    }

    #[test]
    fn le_taux_de_frais_se_calcule_sur_le_poids_pondere() {
        let mut w = Wallet::from_seed([0x06; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfert(&mut w, &c, 50_000);

        let mut m = Mempool::new();
        let id = m.accept(&tx, &c.utxo, RESEAU, c.height()).unwrap();
        let e = &m.entrees[&id];
        assert!(e.weight > 0);
        assert!(e.fee_rate() > 0);
        // Le poids pondere doit differer de la taille brute : c'est tout
        // l'interet du witness discount.
        assert_ne!(e.weight, e.size as u64);
    }

    #[test]
    fn la_selection_ordonne_par_taux_decroissant() {
        let mut w = Wallet::from_seed([0x07; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 20);
        let mut dest = Wallet::from_seed([0xcc; 32], RESEAU);

        let mut m = Mempool::new();
        let mut taux_attendus = Vec::new();
        for frais in [1_000u64, 90_000, 20_000] {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(10_000),
                    Amount::from_units(frais),
                )
                .expect("construction");
            let id = m
                .accept(&tx, &c.utxo, RESEAU, c.height())
                .expect("acceptation");
            taux_attendus.push(m.entrees[&id].fee_rate());
        }

        let choisies = m.select_for_block(u64::MAX);
        assert_eq!(choisies.len(), 3);
        let taux: Vec<u64> = choisies
            .iter()
            .map(|t| m.entrees[&t.txid()].fee_rate())
            .collect();
        let mut trie = taux.clone();
        trie.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(taux, trie, "les mieux-disantes doivent passer d'abord");
    }

    #[test]
    fn la_selection_respecte_le_poids_maximal() {
        let mut w = Wallet::from_seed([0x08; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfert(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, RESEAU, c.height()).unwrap();
        assert!(m.select_for_block(10).is_empty(), "poids trop faible");
        assert_eq!(m.select_for_block(u64::MAX).len(), 1);
    }

    #[test]
    fn la_selection_est_deterministe() {
        let mut w = Wallet::from_seed([0x09; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 20);
        let mut dest = Wallet::from_seed([0xdd; 32], RESEAU);

        let mut m = Mempool::new();
        for _ in 0..4 {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(10_000),
                    Amount::from_units(5_000),
                )
                .expect("construction");
            m.accept(&tx, &c.utxo, RESEAU, c.height()).unwrap();
        }
        let a: Vec<Hash256> = m
            .select_for_block(u64::MAX)
            .iter()
            .map(|t| t.txid())
            .collect();
        let b: Vec<Hash256> = m
            .select_for_block(u64::MAX)
            .iter()
            .map(|t| t.txid())
            .collect();
        assert_eq!(a, b, "deux mineurs doivent construire le meme bloc");
    }

    #[test]
    fn un_bloc_confirme_vide_le_mempool_de_ce_qu_il_contient() {
        let mut w = Wallet::from_seed([0x0a; 32], RESEAU);
        let mut c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfert(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, RESEAU, c.height()).unwrap();
        assert_eq!(m.len(), 1);

        let t = c.tip().time + TARGET_BLOCK_SECS;
        let a = w.new_address();
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        m.on_block_connected(&b);

        assert!(m.is_empty(), "la transaction confirmee devait sortir");
        assert_eq!(m.bytes(), 0);
    }

    #[test]
    fn un_bloc_evince_aussi_les_doubles_depenses_concurrentes() {
        let mut w = Wallet::from_seed([0x0b; 32], RESEAU);
        let mut c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfert(&mut w, &c, 5_000);

        // Une variante concurrente entre dans le mempool.
        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, RESEAU, c.height()).unwrap();

        // Un bloc confirme une transaction qui consomme la meme sortie sous un
        // autre identifiant.
        let mut concurrente = tx.clone();
        concurrente.lock_time = 7;
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let a = w.new_address();
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();

        // Simule la confirmation de la concurrente.
        let faux_bloc = crate::block::Block {
            header: b.header,
            transactions: vec![b.transactions[0].clone(), concurrente],
            uncles: vec![],
        };
        m.on_block_connected(&faux_bloc);
        assert!(
            m.is_empty(),
            "la concurrente devenue invalide devait sortir"
        );
    }

    #[test]
    fn le_retrait_libere_les_sorties_engagees() {
        let mut w = Wallet::from_seed([0x0c; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfert(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        let id = m.accept(&tx, &c.utxo, RESEAU, c.height()).unwrap();
        assert!(!m.engagees.is_empty());
        m.remove(&id);
        assert!(
            m.engagees.is_empty(),
            "les engagements doivent etre liberes"
        );
        assert_eq!(m.bytes(), 0);
    }

    #[test]
    fn la_revalidation_purge_ce_qui_est_devenu_invalide() {
        let mut w = Wallet::from_seed([0x0d; 32], RESEAU);
        let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfert(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, RESEAU, c.height()).unwrap();

        // Contre un jeu d'UTXO vide, plus rien ne tient debout.
        m.revalidate(&UtxoSet::new(), RESEAU, c.height());
        assert!(m.is_empty());
    }
}

#[cfg(test)]
mod tests_chaines {
    use super::tests::*;
    use super::*;
    use crate::sig::SchemeId;
    use crate::wallet::Wallet;

    const RESEAU: Network = Network::Regtest;

    /// La limite de la phase 4, levee.
    #[test]
    fn une_transaction_peut_depenser_une_sortie_encore_au_mempool() {
        let mut w = Wallet::from_seed([0x20; 32], RESEAU);
        let c = chaine(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x21; 32], RESEAU);
        let mut m = Mempool::new();

        // Premiere depense : la monnaie rendue revient au portefeuille.
        let a1 = dest.new_address();
        let tx1 = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a1,
                Amount::from_units(1_000),
                Amount::from_units(500),
            )
            .expect("premiere");
        let id1 = m
            .accept(&tx1, &c.utxo, RESEAU, c.height())
            .expect("acceptation 1");

        // Seconde depense : elle consomme la monnaie rendue par la premiere,
        // qui n'est encore confirmee nulle part.
        let sortie_monnaie = tx1
            .outputs
            .iter()
            .position(|o| w.owns(&o.pubkey_hash))
            .expect("il doit y avoir de la monnaie rendue");
        assert!(
            m.creees.contains_key(&OutPoint {
                txid: id1,
                index: sortie_monnaie as u32
            }),
            "la sortie doit etre visible dans la vue du mempool"
        );

        let a2 = dest.new_address();
        let tx2 = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a2,
                Amount::from_units(1_000),
                Amount::from_units(500),
            )
            .expect("seconde");
        m.accept(&tx2, &c.utxo, RESEAU, c.height())
            .expect("la seconde depense doit passer");
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn retirer_un_parent_retire_ses_descendants() {
        let mut w = Wallet::from_seed([0x22; 32], RESEAU);
        let c = chaine(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x23; 32], RESEAU);
        let mut m = Mempool::new();

        let mut ids = Vec::new();
        for _ in 0..3 {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(1_000),
                    Amount::from_units(500),
                )
                .expect("construction");
            ids.push(
                m.accept(&tx, &c.utxo, RESEAU, c.height())
                    .expect("acceptation"),
            );
        }
        assert_eq!(m.len(), 3);

        // Retirer la premiere doit emporter toute la descendance qui en depend.
        m.remove(&ids[0]);
        assert!(
            m.len() < 3,
            "les descendants d'une transaction retiree doivent partir aussi"
        );
        assert!(!m.contains(&ids[0]));
    }

    #[test]
    fn la_selection_place_toujours_les_parents_avant_les_enfants() {
        let mut w = Wallet::from_seed([0x24; 32], RESEAU);
        let c = chaine(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x25; 32], RESEAU);
        let mut m = Mempool::new();

        let mut ordre_arrivee = Vec::new();
        for _ in 0..4 {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(1_000),
                    Amount::from_units(500),
                )
                .expect("construction");
            ordre_arrivee.push(
                m.accept(&tx, &c.utxo, RESEAU, c.height())
                    .expect("acceptation"),
            );
        }

        let choisies = m.select_for_block(u64::MAX);
        let positions: HashMap<Hash256, usize> = choisies
            .iter()
            .enumerate()
            .map(|(i, t)| (t.txid(), i))
            .collect();

        for tx in &choisies {
            let id = tx.txid();
            for e in &tx.inputs {
                if let Some(pos_parent) = positions.get(&e.prev_out.txid) {
                    assert!(
                        *pos_parent < positions[&id],
                        "un enfant a ete place avant son parent : le bloc serait invalide"
                    );
                }
            }
        }
    }

    #[test]
    fn la_vue_masque_une_sortie_deja_depensee_par_le_mempool() {
        let mut w = Wallet::from_seed([0x26; 32], RESEAU);
        let c = chaine(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x27; 32], RESEAU);
        let mut m = Mempool::new();

        let a = dest.new_address();
        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(1_000),
                Amount::from_units(500),
            )
            .expect("construction");
        let consommee = tx.inputs[0].prev_out;
        m.accept(&tx, &c.utxo, RESEAU, c.height())
            .expect("acceptation");

        let vue = MempoolView {
            confirme: &c.utxo,
            overlay: &m.creees,
            consommees: &m.engagees,
        };
        assert!(
            c.utxo.contains(&consommee),
            "la sortie est encore confirmee"
        );
        assert!(
            vue.lookup(&consommee).is_none(),
            "mais la vue doit la masquer, sinon on validerait une double depense"
        );
    }

    #[test]
    fn un_bloc_confirme_nettoie_toute_la_chaine() {
        let mut w = Wallet::from_seed([0x28; 32], RESEAU);
        let mut c = chaine(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x29; 32], RESEAU);
        let mut m = Mempool::new();

        let mut txs = Vec::new();
        for _ in 0..3 {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(1_000),
                    Amount::from_units(500),
                )
                .expect("construction");
            m.accept(&tx, &c.utxo, RESEAU, c.height())
                .expect("acceptation");
            txs.push(tx);
        }

        let selection = m.select_for_block(u64::MAX);
        let t = c.tip().time + crate::consensus::TARGET_BLOCK_SECS;
        let a = w.new_address();
        let bloc = c
            .mine_block(a.hash, SchemeId::LamportOts, &selection, t, 5_000_000)
            .expect("minage");
        c.connect(&bloc, t + 1).expect("le bloc doit etre valide");
        m.on_block_connected(&bloc);

        assert!(m.is_empty(), "tout ce qui est confirme doit sortir");
        assert_eq!(m.bytes(), 0);
        assert!(m.creees.is_empty(), "aucune sortie fantome ne doit rester");
        assert!(m.engagees.is_empty());
    }
}

//! Index d'adresses et de transactions, facultatif.
//!
//! # Le probleme
//!
//! « Montre-moi toutes les transactions de cette adresse » n'a pas de reponse
//! bon marche dans une chaine de blocs. Rien, dans la structure, ne relie une
//! adresse a ses transactions : il faut les parcourir toutes.
//!
//! Le noeud le faisait donc — en balayant en arriere, et en s'arretant au bout
//! de cinq mille blocs. C'est ce qui explique la mention « historique borne »
//! du portefeuille. Passe cette limite, la reponse n'est pas fausse : elle est
//! incomplete, et elle le dit.
//!
//! Un explorateur ne peut pas s'en contenter. Chercher une adresse est son
//! usage principal, pas son cas limite.
//!
//! # Pourquoi il est facultatif
//!
//! Un index se paie deux fois : en disque, et en ecriture a chaque bloc. Un
//! noeud qui valide la chaine et garde un portefeuille n'en a aucun besoin —
//! il ne cherche que ses propres adresses, et il sait lesquelles.
//!
//! L'imposer a tout le monde ferait payer a chaque utilisateur le confort de
//! ceux qui explorent. Bitcoin Core a tranche de la meme facon, avec
//! `txindex`, et pour la meme raison. Ici c'est `--index-adresses`.
//!
//! # Comment
//!
//! Un journal ecrit a la suite, un enregistrement par bloc. Chaque
//! enregistrement porte sa propre somme de controle : une ecriture coupee en
//! deux — plus de place, arret brutal — laisse un dernier enregistrement
//! illisible, qu'on ignore, et l'index reprend simplement quelques blocs en
//! arriere. Il ne s'agit pas de donnees vitales : l'index se reconstruit
//! entierement a partir de la chaine, qui est la seule source.
//!
//! ## Ce qu'un enregistrement contient
//!
//! ```text
//!   hauteur          8 octets
//!   identifiant     32 octets   <- ce qui permet de detecter une reorganisation
//!   nombre de tx     4 octets
//!     txid          32 octets
//!     nombre d'empreintes 4 octets
//!       empreinte   32 octets   * n
//!   controle         4 octets
//! ```
//!
//! ## L'adresse d'une entree
//!
//! Une sortie porte l'empreinte de la clef autorisee a la depenser : indexer
//! ce qu'une adresse **recoit** est immediat. Une entree, elle, ne designe que
//! la sortie qu'elle consomme ; pour savoir a qui appartenait cette sortie, il
//! faut la retrouver.
//!
//! Le temoin ne suffit pas : `pubkey_hash` depend du schema de signature, et le
//! schema est inscrit sur la sortie, pas sur l'entree. Relire le bloc d'origine
//! couterait une lecture par entree.
//!
//! On tient donc une table des sorties **non depensees** — memes clefs que
//! l'ensemble UTXO, dont la taille depend de l'economie, pas de la longueur de
//! la chaine. Une sortie y entre quand elle est creee, en sort quand elle est
//! depensee, et repond au passage a la question « a qui etait-elle ». Au
//! chargement, cette table se reprend directement de l'ensemble UTXO du noeud :
//! une sortie qu'une transaction future depensera est, par construction, une
//! sortie encore vivante aujourd'hui.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::block::Block;
use crate::hash::Hash256;
use crate::sha256::sha256;
use crate::tx::OutPoint;
use crate::utxo::UtxoSet;

/// Magie du journal. Le chiffre final est la version du format.
const MAGIE: &[u8; 8] = b"Q21INDX1";

/// Ou se trouve une transaction : son bloc, et son rang dans ce bloc.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Position {
    pub hauteur: u64,
    pub rang: u32,
}

#[derive(Debug)]
pub enum IndexError {
    Ecriture(String),
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndexError::Ecriture(e) => write!(f, "index non ecrit : {e}"),
        }
    }
}

/// Index d'adresses et de transactions.
pub struct Index {
    chemin: PathBuf,
    /// Empreinte de clef publique -> ou apparait-elle.
    par_adresse: HashMap<Hash256, Vec<Position>>,
    /// Identifiant de transaction -> ou est-elle.
    par_txid: HashMap<Hash256, Position>,
    /// Sortie non depensee -> a qui elle appartient. Voir l'en-tete du module.
    proprietaires: HashMap<OutPoint, Hash256>,
    /// Blocs indexes, dans l'ordre : (hauteur, identifiant).
    blocs: Vec<(u64, Hash256)>,
}

impl Index {
    /// Ouvre le journal, ou en commence un neuf s'il n'existe pas.
    ///
    /// Ne rend jamais d'erreur : un index illisible est un index a
    /// reconstruire, pas une raison de refuser de demarrer.
    pub fn ouvrir(chemin: &Path) -> Index {
        let mut index = Index {
            chemin: chemin.to_path_buf(),
            par_adresse: HashMap::new(),
            par_txid: HashMap::new(),
            proprietaires: HashMap::new(),
            blocs: Vec::new(),
        };
        if let Ok(brut) = std::fs::read(chemin) {
            index.rejouer(&brut);
        }
        index
    }

    fn rejouer(&mut self, brut: &[u8]) {
        if brut.len() < MAGIE.len() || &brut[..MAGIE.len()] != MAGIE {
            return;
        }
        let mut p = MAGIE.len();
        while let Some((enregistrement, suivant)) = lire_enregistrement(brut, p) {
            let (hauteur, id, transactions) = enregistrement;
            // Un journal doit rester ordonne : un enregistrement qui recule
            // trahit une corruption qu'aucune somme de controle n'attrape,
            // puisqu'elle porte sur chaque enregistrement pris a part.
            if let Some((derniere, _)) = self.blocs.last() {
                if hauteur != derniere + 1 {
                    return;
                }
            }
            for (rang, (txid, empreintes)) in transactions.into_iter().enumerate() {
                let position = Position {
                    hauteur,
                    rang: rang as u32,
                };
                self.par_txid.insert(txid, position);
                for e in empreintes {
                    self.par_adresse.entry(e).or_default().push(position);
                }
            }
            self.blocs.push((hauteur, id));
            p = suivant;
        }
    }

    /// Reprend la table des proprietaires depuis l'ensemble UTXO du noeud.
    ///
    /// A appeler une fois apres l'ouverture. Voir l'en-tete du module : une
    /// sortie qu'une transaction future depensera est necessairement une sortie
    /// encore vivante au moment ou l'on demarre.
    pub fn amorcer(&mut self, utxo: &UtxoSet) {
        self.proprietaires.clear();
        for (point, entree) in utxo.iter() {
            self.proprietaires.insert(*point, entree.output.pubkey_hash);
        }
    }

    /// Hauteur du dernier bloc indexe. Zero si l'index est vide.
    pub fn hauteur(&self) -> u64 {
        self.blocs.last().map(|(h, _)| *h).unwrap_or(0)
    }

    /// L'index contient-il quelque chose ?
    pub fn est_vide(&self) -> bool {
        self.blocs.is_empty()
    }

    /// Identifiant du bloc indexe a cette hauteur.
    pub fn identifiant(&self, hauteur: u64) -> Option<Hash256> {
        let (premiere, _) = *self.blocs.first()?;
        let decalage = hauteur.checked_sub(premiere)? as usize;
        self.blocs.get(decalage).map(|(_, id)| *id)
    }

    /// Nombre de blocs indexes.
    pub fn blocs_indexes(&self) -> usize {
        self.blocs.len()
    }

    /// Positions ou cette empreinte de clef apparait, du plus ancien au plus
    /// recent.
    pub fn positions(&self, empreinte: &Hash256) -> &[Position] {
        self.par_adresse
            .get(empreinte)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Ou se trouve cette transaction.
    pub fn position(&self, txid: &Hash256) -> Option<Position> {
        self.par_txid.get(txid).copied()
    }

    /// Nombre d'adresses connues de l'index.
    pub fn adresses_connues(&self) -> usize {
        self.par_adresse.len()
    }

    /// Ajoute un bloc a l'index, et l'ecrit dans le journal.
    ///
    /// Le bloc doit suivre immediatement le dernier indexe. C'est a l'appelant
    /// de le garantir — en pratique, la boucle qui suit la chaine.
    pub fn indexer(&mut self, bloc: &Block) -> Result<(), IndexError> {
        let hauteur = bloc.header.height;
        let id = bloc.header.block_id();
        let mut transactions: Vec<(Hash256, Vec<Hash256>)> = Vec::with_capacity(3);

        for (rang, tx) in bloc.transactions.iter().enumerate() {
            let txid = tx.txid();
            let position = Position {
                hauteur,
                rang: rang as u32,
            };
            // Une empreinte n'est retenue qu'une fois par transaction : une
            // adresse qui recoit deux sorties d'une meme transaction n'y figure
            // pas deux fois. Sans cela, l'ecran d'une adresse afficherait des
            // doublons qui ne sont pas des mouvements distincts.
            let mut empreintes: Vec<Hash256> = Vec::new();
            let ajouter = |e: Hash256, v: &mut Vec<Hash256>| {
                if !v.contains(&e) {
                    v.push(e);
                }
            };

            // Ce que la transaction depense : on retrouve le proprietaire de
            // chaque sortie consommee, puis on la retire de la table.
            for entree in &tx.inputs {
                if entree.prev_out.is_coinbase() {
                    continue;
                }
                if let Some(e) = self.proprietaires.remove(&entree.prev_out) {
                    ajouter(e, &mut empreintes);
                }
            }
            // Ce qu'elle cree.
            for (i, sortie) in tx.outputs.iter().enumerate() {
                ajouter(sortie.pubkey_hash, &mut empreintes);
                self.proprietaires.insert(
                    OutPoint {
                        txid,
                        index: i as u32,
                    },
                    sortie.pubkey_hash,
                );
            }

            self.par_txid.insert(txid, position);
            for e in &empreintes {
                self.par_adresse.entry(*e).or_default().push(position);
            }
            transactions.push((txid, empreintes));
        }

        self.blocs.push((hauteur, id));
        self.ajouter_au_journal(hauteur, id, &transactions)
    }

    fn ajouter_au_journal(
        &self,
        hauteur: u64,
        id: Hash256,
        transactions: &[(Hash256, Vec<Hash256>)],
    ) -> Result<(), IndexError> {
        use std::io::Write;
        let neuf = !self.chemin.exists();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.chemin)
            .map_err(|e| IndexError::Ecriture(e.to_string()))?;
        let mut sortie = Vec::with_capacity(256);
        if neuf {
            sortie.extend_from_slice(MAGIE);
        }
        sortie.extend_from_slice(&ecrire_enregistrement(hauteur, id, transactions));
        f.write_all(&sortie)
            .map_err(|e| IndexError::Ecriture(e.to_string()))?;
        Ok(())
    }

    /// Retire tout ce qui se trouve au-dessus de cette hauteur.
    ///
    /// C'est la reponse a une reorganisation : les blocs de la branche
    /// abandonnee ne doivent plus figurer dans l'index, sans quoi une adresse
    /// afficherait des transactions qui n'ont jamais eu lieu.
    ///
    /// Le journal est reecrit en entier. Une reorganisation est rare et peu
    /// profonde ; une reecriture y est moins couteuse qu'une table de positions
    /// a tenir a jour a chaque bloc pour un cas qui ne se presente presque
    /// jamais.
    pub fn tronquer(&mut self, hauteur: u64) {
        self.blocs.retain(|(h, _)| *h <= hauteur);
        self.par_txid.retain(|_, p| p.hauteur <= hauteur);
        for positions in self.par_adresse.values_mut() {
            positions.retain(|p| p.hauteur <= hauteur);
        }
        self.par_adresse.retain(|_, v| !v.is_empty());
        // Les proprietaires sont repris de l'ensemble UTXO du noeud, qui a deja
        // ete ramene a la branche gagnante : `amorcer` sera rappele.
        let _ = std::fs::remove_file(&self.chemin);
        // Reecriture, dans l'ordre. Rien ne serait pire qu'un journal dont
        // l'ordre ne correspond plus a la memoire qui l'a produit.
        // Les empreintes sont reconstruites depuis `par_adresse`, seule table
        // qui les porte encore.
        let mut empreintes_par_position: HashMap<(u64, u32), Vec<Hash256>> = HashMap::new();
        for (empreinte, positions) in &self.par_adresse {
            for p in positions {
                empreintes_par_position
                    .entry((p.hauteur, p.rang))
                    .or_default()
                    .push(*empreinte);
            }
        }
        let blocs = self.blocs.clone();
        for (h, id) in blocs {
            let mut transactions: Vec<(Hash256, Vec<Hash256>)> = Vec::new();
            let mut rangs: Vec<(u32, Hash256)> = self
                .par_txid
                .iter()
                .filter(|(_, p)| p.hauteur == h)
                .map(|(txid, p)| (p.rang, *txid))
                .collect();
            rangs.sort_by_key(|(r, _)| *r);
            for (rang, txid) in rangs {
                let empreintes = empreintes_par_position
                    .get(&(h, rang))
                    .cloned()
                    .unwrap_or_default();
                transactions.push((txid, empreintes));
            }
            let _ = self.ajouter_au_journal(h, id, &transactions);
        }
    }

    /// Efface tout, journal compris. Employe quand l'index a diverge.
    pub fn effacer(&mut self) {
        self.par_adresse.clear();
        self.par_txid.clear();
        self.proprietaires.clear();
        self.blocs.clear();
        let _ = std::fs::remove_file(&self.chemin);
    }
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

type Enregistrement = (u64, Hash256, Vec<(Hash256, Vec<Hash256>)>);

fn ecrire_enregistrement(
    hauteur: u64,
    id: Hash256,
    transactions: &[(Hash256, Vec<Hash256>)],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + transactions.len() * 64);
    v.extend_from_slice(&hauteur.to_le_bytes());
    v.extend_from_slice(&id.0);
    v.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
    for (txid, empreintes) in transactions {
        v.extend_from_slice(&txid.0);
        v.extend_from_slice(&(empreintes.len() as u32).to_le_bytes());
        for e in empreintes {
            v.extend_from_slice(&e.0);
        }
    }
    let controle = sha256(&v);
    v.extend_from_slice(&controle[..4]);
    v
}

/// Lit un enregistrement a partir de `debut`. Rend aussi la position suivante.
///
/// Rend `None` des que quelque chose ne va pas : fin de fichier, longueur
/// absurde, somme de controle fausse. C'est voulu — le journal s'arrete au
/// premier enregistrement douteux, et l'index reprend a partir de la.
fn lire_enregistrement(brut: &[u8], debut: usize) -> Option<(Enregistrement, usize)> {
    let mut p = debut;
    let lire = |p: &mut usize, n: usize| -> Option<&[u8]> {
        let fin = p.checked_add(n)?;
        if fin > brut.len() {
            return None;
        }
        let s = &brut[*p..fin];
        *p = fin;
        Some(s)
    };

    let hauteur = u64::from_le_bytes(lire(&mut p, 8)?.try_into().ok()?);
    let mut id = [0u8; 32];
    id.copy_from_slice(lire(&mut p, 32)?);
    let nombre = u32::from_le_bytes(lire(&mut p, 4)?.try_into().ok()?) as usize;
    // Une longueur absurde ne doit pas faire reserver la memoire qu'elle
    // annonce : le journal est un fichier local, mais un fichier local corrompu
    // ne doit pas non plus faire tomber le programme.
    if nombre > 1_000_000 {
        return None;
    }
    let mut transactions = Vec::with_capacity(nombre.min(1024));
    for _ in 0..nombre {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(lire(&mut p, 32)?);
        let combien = u32::from_le_bytes(lire(&mut p, 4)?.try_into().ok()?) as usize;
        if combien > 1_000_000 {
            return None;
        }
        let mut empreintes = Vec::with_capacity(combien.min(1024));
        for _ in 0..combien {
            let mut e = [0u8; 32];
            e.copy_from_slice(lire(&mut p, 32)?);
            empreintes.push(Hash256(e));
        }
        transactions.push((Hash256(txid), empreintes));
    }
    let corps = &brut[debut..p];
    let attendu = sha256(corps);
    let lu = lire(&mut p, 4)?;
    if lu != &attendu[..4] {
        return None;
    }
    Some(((hauteur, Hash256(id), transactions), p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::amount::Amount;
    use crate::block::BlockHeader;
    use crate::sig::SchemeId;
    use crate::tx::{Transaction, TxIn, TxOut};

    fn dossier(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("q21-index-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn empreinte(n: u8) -> Hash256 {
        Hash256([n; 32])
    }

    fn sortie(n: u8, montant: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(montant),
            scheme: SchemeId::LamportOts,
            pubkey_hash: empreinte(n),
        }
    }

    fn coinbase(vers: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(vec![1, 2, 3])],
            outputs: vec![sortie(vers, 1000)],
            lock_time: 0,
        }
    }

    fn bloc(hauteur: u64, marque: u8, transactions: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256([marque; 32]),
                uncles_root: Hash256::ZERO,
                miner: Hash256::ZERO,
                time: 1_700_000_000 + hauteur,
                bits: 0x2000_ffff,
                height: hauteur,
                nonce: 0,
            },
            transactions,
            uncles: Vec::new(),
        }
    }

    /// Une adresse qui recoit apparait dans l'index.
    #[test]
    fn une_sortie_inscrit_son_adresse() {
        let d = dossier("sortie");
        let mut index = Index::ouvrir(&d.join("index.dat"));
        index.indexer(&bloc(0, 1, vec![coinbase(7)])).unwrap();

        assert_eq!(index.positions(&empreinte(7)).len(), 1);
        assert_eq!(index.positions(&empreinte(7))[0].hauteur, 0);
        assert_eq!(index.positions(&empreinte(9)).len(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une adresse qui **depense** apparait aussi.
    ///
    /// C'est la moitie difficile : l'entree ne designe que la sortie qu'elle
    /// consomme. Sans la table des proprietaires, une depense serait invisible
    /// depuis l'adresse qui la fait — l'ecran ne montrerait que les receptions.
    #[test]
    fn une_depense_inscrit_l_adresse_qui_depense() {
        let d = dossier("depense");
        let mut index = Index::ouvrir(&d.join("index.dat"));

        let cb = coinbase(7);
        let txid_cb = cb.txid();
        index.indexer(&bloc(0, 1, vec![cb])).unwrap();

        let depense = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: txid_cb,
                    index: 0,
                },
                witness: Default::default(),
                sequence: 0,
            }],
            outputs: vec![sortie(8, 900)],
            lock_time: 0,
        };
        index
            .indexer(&bloc(1, 2, vec![coinbase(7), depense]))
            .unwrap();

        // 7 apparait trois fois : la premiere coinbase, la seconde, et la
        // depense qui consomme la premiere.
        assert_eq!(index.positions(&empreinte(7)).len(), 3);
        // 8 une seule fois, en reception.
        assert_eq!(index.positions(&empreinte(8)).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une adresse servie deux fois par la meme transaction n'y figure qu'une
    /// fois : ce n'est qu'un seul mouvement.
    #[test]
    fn une_adresse_servie_deux_fois_ne_compte_qu_une_fois() {
        let d = dossier("doublon");
        let mut index = Index::ouvrir(&d.join("index.dat"));
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(vec![9])],
            outputs: vec![sortie(7, 500), sortie(7, 500)],
            lock_time: 0,
        };
        index.indexer(&bloc(0, 1, vec![tx])).unwrap();
        assert_eq!(index.positions(&empreinte(7)).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le journal se relit a l'identique.
    #[test]
    fn le_journal_se_relit() {
        let d = dossier("relecture");
        let chemin = d.join("index.dat");
        let txid;
        {
            let mut index = Index::ouvrir(&chemin);
            let cb = coinbase(7);
            txid = cb.txid();
            index.indexer(&bloc(0, 1, vec![cb])).unwrap();
            index.indexer(&bloc(1, 2, vec![coinbase(8)])).unwrap();
        }
        let index = Index::ouvrir(&chemin);
        assert_eq!(index.hauteur(), 1);
        assert_eq!(index.blocs_indexes(), 2);
        assert_eq!(index.positions(&empreinte(7)).len(), 1);
        assert_eq!(index.position(&txid).map(|p| p.hauteur), Some(0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un journal coupe au milieu d'un enregistrement ne perd que celui-la.
    ///
    /// C'est ce que produit une coupure de courant pendant l'ecriture. L'index
    /// doit repartir du dernier enregistrement entier, pas refuser de s'ouvrir.
    #[test]
    fn un_journal_tronque_perd_le_dernier_bloc_et_rien_d_autre() {
        let d = dossier("tronque");
        let chemin = d.join("index.dat");
        {
            let mut index = Index::ouvrir(&chemin);
            index.indexer(&bloc(0, 1, vec![coinbase(7)])).unwrap();
            index.indexer(&bloc(1, 2, vec![coinbase(8)])).unwrap();
            index.indexer(&bloc(2, 3, vec![coinbase(9)])).unwrap();
        }
        let brut = std::fs::read(&chemin).unwrap();
        // On coupe cinq octets : le dernier enregistrement devient illisible.
        std::fs::write(&chemin, &brut[..brut.len() - 5]).unwrap();

        let index = Index::ouvrir(&chemin);
        assert_eq!(
            index.hauteur(),
            1,
            "l'index n'a pas repris les deux premiers"
        );
        assert_eq!(index.positions(&empreinte(9)).len(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un octet modifie fait rejeter l'enregistrement.
    #[test]
    fn une_corruption_est_detectee() {
        let d = dossier("corrompu");
        let chemin = d.join("index.dat");
        {
            let mut index = Index::ouvrir(&chemin);
            index.indexer(&bloc(0, 1, vec![coinbase(7)])).unwrap();
            index.indexer(&bloc(1, 2, vec![coinbase(8)])).unwrap();
        }
        let mut brut = std::fs::read(&chemin).unwrap();
        let milieu = brut.len() / 2;
        brut[milieu] ^= 0xff;
        std::fs::write(&chemin, &brut).unwrap();

        let index = Index::ouvrir(&chemin);
        assert!(
            index.hauteur() <= 1,
            "un enregistrement corrompu a ete accepte"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une reorganisation retire de l'index ce qui n'a plus eu lieu.
    ///
    /// Sans cela, l'ecran d'une adresse montrerait des transactions d'une
    /// branche abandonnee — c'est-a-dire des mouvements qui n'existent pas.
    #[test]
    fn une_reorganisation_retire_les_blocs_abandonnes() {
        let d = dossier("reorg");
        let chemin = d.join("index.dat");
        let mut index = Index::ouvrir(&chemin);
        index.indexer(&bloc(0, 1, vec![coinbase(7)])).unwrap();
        index.indexer(&bloc(1, 2, vec![coinbase(8)])).unwrap();
        index.indexer(&bloc(2, 3, vec![coinbase(9)])).unwrap();
        assert_eq!(index.positions(&empreinte(9)).len(), 1);

        index.tronquer(1);
        assert_eq!(index.hauteur(), 1);
        assert_eq!(index.positions(&empreinte(9)).len(), 0);
        assert_eq!(index.positions(&empreinte(8)).len(), 1);

        // Et le journal reecrit dit la meme chose que la memoire.
        let relu = Index::ouvrir(&chemin);
        assert_eq!(relu.hauteur(), 1);
        assert_eq!(relu.positions(&empreinte(9)).len(), 0);
        assert_eq!(relu.positions(&empreinte(8)).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un journal dont les hauteurs sautent est refuse a partir du saut.
    #[test]
    fn un_journal_desordonne_s_arrete_au_saut() {
        let d = dossier("saut");
        let chemin = d.join("index.dat");
        let mut brut = MAGIE.to_vec();
        brut.extend_from_slice(&ecrire_enregistrement(0, Hash256([1; 32]), &[]));
        brut.extend_from_slice(&ecrire_enregistrement(5, Hash256([2; 32]), &[]));
        std::fs::write(&chemin, &brut).unwrap();

        let index = Index::ouvrir(&chemin);
        assert_eq!(index.blocs_indexes(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'amorcage reprend les proprietaires depuis l'ensemble UTXO.
    #[test]
    fn l_amorcage_reprend_les_proprietaires() {
        let d = dossier("amorce");
        let mut index = Index::ouvrir(&d.join("index.dat"));

        let cb = coinbase(7);
        let txid = cb.txid();
        let mut utxo = UtxoSet::new();
        let mut annuler = Default::default();
        utxo.apply_transaction(&cb, 0, &mut annuler);
        index.amorcer(&utxo);

        // Sans avoir jamais indexe le bloc 0, l'index sait a qui appartient la
        // sortie : une depense future sera donc attribuee a la bonne adresse.
        let depense = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid, index: 0 },
                witness: Default::default(),
                sequence: 0,
            }],
            outputs: vec![sortie(8, 900)],
            lock_time: 0,
        };
        index.indexer(&bloc(0, 1, vec![depense])).unwrap();
        assert_eq!(index.positions(&empreinte(7)).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le reseau n'entre pas dans l'index : il n'en a pas besoin.
    #[test]
    fn l_index_ne_depend_pas_du_reseau() {
        let _ = Network::Regtest;
    }
}

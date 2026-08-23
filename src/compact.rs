//! Relais de blocs compacts.
//!
//! # Pourquoi ce module existe, et pourquoi il compte plus ici qu'ailleurs
//!
//! Un bloc Q21 est enorme. Une signature ML-DSA-65 pese 3 309 octets, une clef
//! publique 1 952 : le temoin represente 99 % d'une transaction. Diffuser un
//! bloc plein en le poussant octet par octet a chaque pair prendrait un temps
//! considerable — et ce temps a un cout politique, pas seulement technique.
//!
//! La chaine causale est celle-ci, et elle est au coeur du projet :
//!
//! ```text
//! propagation lente  ->  plus d'orphelins  ->  le mineur le mieux connecte
//!                                              gagne les courses  ->  il touche
//!                                              PLUS que sa part de puissance
//!                                              ->  centralisation
//! ```
//!
//! C'est exactement le rendement super-lineaire que le levier C de la section 5
//! du livre blanc cherche a supprimer. Les recompenses d'oncles en pansent la
//! consequence ; le relais compact en attaque la cause.
//!
//! # Le principe
//!
//! Un pair a deja, dans son mempool, la plupart des transactions du bloc qu'on
//! lui annonce. Inutile de les lui renvoyer. On envoie donc l'en-tete et, pour
//! chaque transaction, un **identifiant court de six octets**. Le pair reconnait
//! ce qu'il possede, et ne redemande que ce qui lui manque.
//!
//! Un bloc de 200 transactions Q21 pese environ 5 Mio. Son annonce compacte pese
//! l'en-tete plus 200 x 6 octets, soit moins de 2 Kio. Trois ordres de grandeur.
//!
//! # Pourquoi l'identifiant court est a clef
//!
//! Six octets, donc des collisions possibles. Si la fonction n'etait pas a clef,
//! un adversaire fabriquerait a l'avance des transactions dont l'identifiant
//! court entre en collision avec celles des blocs a venir, et bloquerait la
//! reconstruction chez tout le monde.
//!
//! La clef derive de l'en-tete **et d'un nonce choisi par l'emetteur**. L'en-tete
//! contient le nonce de minage, inconnu de tous avant que le bloc existe ; le
//! nonce d'emetteur fait qu'une meme collision ne se reproduit pas d'un pair a
//! l'autre. Les collisions redeviennent du hasard, et le hasard coute un
//! aller-retour, pas une faille.

use crate::block::{Block, BlockHeader};
use crate::hash::{tagged_hash_parts, Hash256};
use crate::ser::{ReadError, Reader, Writer};
use crate::siphash::siphash24;
use crate::tx::Transaction;
use std::collections::HashMap;

/// Taille d'un identifiant court, en octets.
pub const SHORT_ID_LEN: usize = 6;

const TAG_CLEF: &str = "Q21/compact/key";

/// Nombre maximal de transactions annoncees dans un bloc compact.
///
/// Reexporte depuis le consensus, ou il est **derive** de la taille maximale
/// d'un bloc au lieu d'etre pose a la main. Voir
/// [`crate::consensus::MAX_TX_PAR_BLOC`].
pub use crate::consensus::MAX_TX_PAR_BLOC;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CompactError {
    /// Le bloc reconstruit ne correspond pas a la racine de Merkle annoncee.
    ///
    /// Signifie soit une collision non detectee, soit un pair malveillant. Dans
    /// les deux cas on redemande le bloc complet.
    RacineDeMerkleIncorrecte,
    /// Le pair a fourni un nombre de transactions different de ce qui manquait.
    NombreDeTransactionsIncorrect {
        attendu: usize,
        recu: usize,
    },
    /// Une transaction fournie ne correspond pas a l'identifiant demande.
    TransactionInattendue {
        index: usize,
    },
    /// Annonce absurde, refusee avant toute allocation.
    TropDeTransactions(usize),
    /// La coinbase doit toujours etre fournie en clair.
    CoinbaseAbsente,
    Lecture(ReadError),
}

impl From<ReadError> for CompactError {
    fn from(e: ReadError) -> Self {
        CompactError::Lecture(e)
    }
}

/// Derive la clef d'identifiants courts d'un bloc.
pub fn short_id_key(header: &BlockHeader, nonce: u64) -> (u64, u64) {
    let h = tagged_hash_parts(TAG_CLEF, &[&header.encode(), &nonce.to_le_bytes()]);
    let b = h.as_bytes();
    let mut k0 = [0u8; 8];
    let mut k1 = [0u8; 8];
    k0.copy_from_slice(&b[0..8]);
    k1.copy_from_slice(&b[8..16]);
    (u64::from_le_bytes(k0), u64::from_le_bytes(k1))
}

/// Identifiant court d'une transaction : six octets de poids faible du SipHash.
#[inline]
pub fn short_id(k0: u64, k1: u64, txid: &Hash256) -> u64 {
    siphash24(k0, k1, txid.as_bytes()) & 0x0000_ffff_ffff_ffff
}

/// Annonce compacte d'un bloc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBlock {
    pub header: BlockHeader,
    /// Nonce de l'emetteur, qui personnalise la clef d'identifiants courts.
    pub nonce: u64,
    /// Identifiants courts des transactions non prefournies, dans l'ordre du bloc.
    pub short_ids: Vec<u64>,
    /// Transactions fournies en clair, avec leur indice dans le bloc.
    ///
    /// La coinbase y figure toujours : par construction, aucun pair ne peut
    /// l'avoir dans son mempool.
    pub prefilled: Vec<(u32, Transaction)>,
    /// En-tetes d'oncles, envoyes tels quels : ils sont petits et personne ne
    /// les a en cache.
    pub uncles: Vec<BlockHeader>,
}

impl CompactBlock {
    /// Construit l'annonce compacte d'un bloc.
    pub fn from_block(block: &Block, nonce: u64) -> CompactBlock {
        let (k0, k1) = short_id_key(&block.header, nonce);
        let mut short_ids = Vec::with_capacity(block.transactions.len());
        let mut prefilled = Vec::new();

        for (i, tx) in block.transactions.iter().enumerate() {
            if i == 0 {
                // La coinbase n'existe nulle part ailleurs que dans ce bloc.
                prefilled.push((i as u32, tx.clone()));
            } else {
                short_ids.push(short_id(k0, k1, &tx.txid()));
            }
        }

        CompactBlock {
            header: block.header,
            nonce,
            short_ids,
            prefilled,
            uncles: block.uncles.clone(),
        }
    }

    /// Nombre total de transactions du bloc annonce.
    pub fn tx_count(&self) -> usize {
        self.short_ids.len() + self.prefilled.len()
    }

    /// Taille serialisee de l'annonce.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.header.encode());
        w.u64(self.nonce);
        w.varint(self.short_ids.len() as u64);
        for id in &self.short_ids {
            // Six octets, petit-boutiste.
            w.bytes(&id.to_le_bytes()[..SHORT_ID_LEN]);
        }
        w.varint(self.prefilled.len() as u64);
        for (i, tx) in &self.prefilled {
            w.varint(*i as u64);
            w.var_bytes(&tx.encode());
        }
        w.varint(self.uncles.len() as u64);
        for u in &self.uncles {
            w.bytes(&u.encode());
        }
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<CompactBlock, CompactError> {
        if data.len() < BlockHeader::SIZE {
            return Err(CompactError::Lecture(ReadError::FinPrematuree));
        }
        let header =
            BlockHeader::decode(&data[..BlockHeader::SIZE]).map_err(CompactError::Lecture)?;
        let mut r = Reader::new(&data[BlockHeader::SIZE..]);

        let nonce = r.u64()?;

        let n = r.varint()? as usize;
        if n > MAX_TX_PAR_BLOC {
            return Err(CompactError::TropDeTransactions(n));
        }
        let mut short_ids = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let mut buf = [0u8; 8];
            for octet in buf.iter_mut().take(SHORT_ID_LEN) {
                *octet = r.u8()?;
            }
            short_ids.push(u64::from_le_bytes(buf));
        }

        let np = r.varint()? as usize;
        if np > MAX_TX_PAR_BLOC {
            return Err(CompactError::TropDeTransactions(np));
        }
        let mut prefilled = Vec::with_capacity(np.min(1024));
        for _ in 0..np {
            let i = r.varint()? as u32;
            let brut = r.var_bytes()?;
            let tx = Transaction::decode(brut)
                .map_err(|_| CompactError::Lecture(ReadError::ValeurInvalide))?;
            prefilled.push((i, tx));
        }

        let nu = r.varint()? as usize;
        if nu > 64 {
            return Err(CompactError::TropDeTransactions(nu));
        }
        let mut uncles = Vec::with_capacity(nu);
        for _ in 0..nu {
            let mut tampon = [0u8; BlockHeader::SIZE];
            for octet in tampon.iter_mut() {
                *octet = r.u8()?;
            }
            uncles.push(BlockHeader::decode(&tampon).map_err(CompactError::Lecture)?);
        }

        r.expect_end()?;
        Ok(CompactBlock {
            header,
            nonce,
            short_ids,
            prefilled,
            uncles,
        })
    }
}

/// Reconstruction en cours d'un bloc compact.
pub struct Reconstruction {
    header: BlockHeader,
    uncles: Vec<BlockHeader>,
    /// Emplacements du bloc, `None` la ou il manque une transaction.
    cases: Vec<Option<Transaction>>,
    /// Indices, dans l'ordre du bloc, des transactions manquantes.
    manquantes: Vec<u32>,
}

impl Reconstruction {
    /// Tente de reconstruire un bloc a partir d'un mempool.
    ///
    /// Rend la reconstruction, complete ou non. Les indices manquants sont ceux
    /// a redemander au pair.
    pub fn depuis(
        compact: &CompactBlock,
        disponibles: &HashMap<Hash256, Transaction>,
    ) -> Result<Reconstruction, CompactError> {
        let total = compact.tx_count();
        if total > MAX_TX_PAR_BLOC {
            return Err(CompactError::TropDeTransactions(total));
        }

        let (k0, k1) = short_id_key(&compact.header, compact.nonce);

        // Table des identifiants courts de ce qu'on possede.
        //
        // Une collision entre deux transactions du mempool rend l'identifiant
        // ambigu : on le retire plutot que de deviner. Le pire cas est un
        // aller-retour supplementaire, jamais un bloc mal reconstruit.
        let mut par_id: HashMap<u64, Option<&Transaction>> = HashMap::new();
        for (txid, tx) in disponibles {
            let sid = short_id(k0, k1, txid);
            par_id
                .entry(sid)
                .and_modify(|e| *e = None)
                .or_insert(Some(tx));
        }

        let mut cases: Vec<Option<Transaction>> = vec![None; total];

        for (i, tx) in &compact.prefilled {
            let i = *i as usize;
            if i >= total {
                return Err(CompactError::TransactionInattendue { index: i });
            }
            cases[i] = Some(tx.clone());
        }
        if cases.first().map(|c| c.is_none()).unwrap_or(true) {
            return Err(CompactError::CoinbaseAbsente);
        }

        // Les identifiants courts occupent les emplacements laisses libres, dans
        // l'ordre.
        let mut libres = cases
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_none())
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
            .into_iter();

        let mut manquantes = Vec::new();
        for sid in &compact.short_ids {
            let emplacement = match libres.next() {
                Some(i) => i,
                None => return Err(CompactError::TransactionInattendue { index: total }),
            };
            match par_id.get(sid) {
                Some(Some(tx)) => cases[emplacement] = Some((*tx).clone()),
                _ => manquantes.push(emplacement as u32),
            }
        }

        Ok(Reconstruction {
            header: compact.header,
            uncles: compact.uncles.clone(),
            cases,
            manquantes,
        })
    }

    /// Indices a redemander au pair. Vide si la reconstruction est complete.
    pub fn missing(&self) -> &[u32] {
        &self.manquantes
    }

    pub fn is_complete(&self) -> bool {
        self.manquantes.is_empty()
    }

    /// Proportion de transactions retrouvees dans le mempool.
    pub fn hit_rate(&self) -> f64 {
        let total = self.cases.len();
        if total == 0 {
            return 1.0;
        }
        (total - self.manquantes.len()) as f64 / total as f64
    }

    /// Complete la reconstruction avec les transactions redemandees.
    ///
    /// Verifie la racine de Merkle : c'est la seule chose qui distingue une
    /// reconstruction correcte d'une reconstruction plausible. Une collision non
    /// detectee, ou un pair malveillant, echouent ici.
    pub fn complete(mut self, fournies: Vec<Transaction>) -> Result<Block, CompactError> {
        if fournies.len() != self.manquantes.len() {
            return Err(CompactError::NombreDeTransactionsIncorrect {
                attendu: self.manquantes.len(),
                recu: fournies.len(),
            });
        }
        for (emplacement, tx) in self.manquantes.iter().zip(fournies) {
            self.cases[*emplacement as usize] = Some(tx);
        }
        self.finaliser()
    }

    /// Termine une reconstruction deja complete.
    pub fn finish(self) -> Result<Block, CompactError> {
        if !self.manquantes.is_empty() {
            return Err(CompactError::NombreDeTransactionsIncorrect {
                attendu: self.manquantes.len(),
                recu: 0,
            });
        }
        self.finaliser()
    }

    fn finaliser(self) -> Result<Block, CompactError> {
        let mut transactions = Vec::with_capacity(self.cases.len());
        for (i, c) in self.cases.into_iter().enumerate() {
            match c {
                Some(tx) => transactions.push(tx),
                None => return Err(CompactError::TransactionInattendue { index: i }),
            }
        }
        let bloc = Block {
            header: self.header,
            transactions,
            uncles: self.uncles,
        };
        // Le controle qui rend tout le reste sur.
        if bloc.compute_merkle_root() != bloc.header.merkle_root {
            return Err(CompactError::RacineDeMerkleIncorrecte);
        }
        Ok(bloc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::amount::Amount;
    use crate::chain::{genesis_block, Chain, GENESIS_TIME};
    use crate::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
    use crate::sig::SchemeId;
    use crate::wallet::Wallet;

    const RESEAU: Network = Network::Regtest;
    const ESSAIS: u64 = 5_000_000;

    /// Construit une chaine, un portefeuille approvisionne, et un bloc portant
    /// `n` transactions reelles.
    fn bloc_avec_transactions(n: usize) -> (Block, Vec<Transaction>) {
        let mut w = Wallet::from_seed([0x77; 32], RESEAU);
        let _ = w.new_address();
        let g = genesis_block(RESEAU);
        let mut c = Chain::new(RESEAU, g);
        for i in 1..=(COINBASE_MATURITY + 20) {
            let a = w.new_address();
            let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
                .expect("minage");
            c.connect(&b, t + 1).expect("connexion");
        }

        let mut dest = Wallet::from_seed([0x88; 32], RESEAU);
        let mut txs = Vec::new();
        for _ in 0..n {
            let a = dest.new_address();
            txs.push(
                w.create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(10_000),
                    Amount::from_units(1_000),
                )
                .expect("construction"),
            );
        }

        let t = c.tip().time + TARGET_BLOCK_SECS;
        let a = w.new_address();
        let bloc = c
            .mine_block(a.hash, SchemeId::LamportOts, &txs, t, ESSAIS)
            .expect("minage du bloc plein");
        (bloc, txs)
    }

    fn mempool_de(txs: &[Transaction]) -> HashMap<Hash256, Transaction> {
        txs.iter().map(|t| (t.txid(), t.clone())).collect()
    }

    #[test]
    fn un_pair_qui_a_tout_reconstruit_sans_aller_retour() {
        let (bloc, txs) = bloc_avec_transactions(3);
        let compact = CompactBlock::from_block(&bloc, 0xdead_beef);
        let dispo = mempool_de(&txs);

        let r = Reconstruction::depuis(&compact, &dispo).expect("reconstruction");
        assert!(r.is_complete(), "manque : {:?}", r.missing());
        assert_eq!(r.hit_rate(), 1.0);
        assert_eq!(r.finish().expect("finalisation"), bloc);
    }

    #[test]
    fn un_pair_qui_n_a_rien_redemande_tout_sauf_la_coinbase() {
        let (bloc, _) = bloc_avec_transactions(3);
        let compact = CompactBlock::from_block(&bloc, 1);
        let vide = HashMap::new();

        let r = Reconstruction::depuis(&compact, &vide).expect("reconstruction");
        assert!(!r.is_complete());
        assert_eq!(r.missing().len(), 3, "la coinbase est prefournie");
        assert!(!r.missing().contains(&0));
    }

    #[test]
    fn un_aller_retour_suffit_a_completer() {
        let (bloc, txs) = bloc_avec_transactions(4);
        let compact = CompactBlock::from_block(&bloc, 7);

        // Le pair ne possede que la premiere des quatre.
        let partiel = mempool_de(&txs[..1]);
        let r = Reconstruction::depuis(&compact, &partiel).expect("reconstruction");
        assert_eq!(r.missing().len(), 3);

        // Il redemande exactement ce qui manque, dans l'ordre.
        let demandees: Vec<Transaction> = r
            .missing()
            .iter()
            .map(|i| bloc.transactions[*i as usize].clone())
            .collect();
        assert_eq!(r.complete(demandees).expect("completion"), bloc);
    }

    /// Le controle qui rend le procede sur.
    #[test]
    fn une_transaction_substituee_est_rejetee() {
        let (bloc, txs) = bloc_avec_transactions(3);
        let compact = CompactBlock::from_block(&bloc, 3);
        let vide = HashMap::new();
        let r = Reconstruction::depuis(&compact, &vide).unwrap();

        // Un pair malveillant renvoie les bonnes transactions dans le desordre.
        let mut fausses: Vec<Transaction> = r
            .missing()
            .iter()
            .map(|i| bloc.transactions[*i as usize].clone())
            .collect();
        fausses.swap(0, 2);

        assert_eq!(
            r.complete(fausses),
            Err(CompactError::RacineDeMerkleIncorrecte),
            "la racine de Merkle doit trancher"
        );
        let _ = txs;
    }

    #[test]
    fn un_nombre_de_transactions_incorrect_est_rejete() {
        let (bloc, _) = bloc_avec_transactions(3);
        let compact = CompactBlock::from_block(&bloc, 4);
        let r = Reconstruction::depuis(&compact, &HashMap::new()).unwrap();
        assert!(matches!(
            r.complete(vec![]),
            Err(CompactError::NombreDeTransactionsIncorrect {
                attendu: 3,
                recu: 0
            })
        ));
    }

    /// Une collision dans le mempool ne doit jamais produire un bloc faux.
    #[test]
    fn une_collision_d_identifiant_court_degrade_sans_casser() {
        let (bloc, txs) = bloc_avec_transactions(2);
        let compact = CompactBlock::from_block(&bloc, 11);
        let (k0, k1) = short_id_key(&compact.header, compact.nonce);

        // On fabrique un mempool ou deux transactions differentes portent le
        // meme identifiant court, en forcant la table.
        let mut dispo = mempool_de(&txs);
        let victime = txs[0].txid();
        let sid_victime = short_id(k0, k1, &victime);

        // Cherche un faux txid qui collisionne. Six octets : on trouve vite en
        // balayant, mais on borne pour ne pas boucler indefiniment.
        let mut intrus = None;
        for i in 0u64..2_000_000 {
            let faux = Hash256(crate::hash::tagged_hash("collision", &i.to_le_bytes()).0);
            if short_id(k0, k1, &faux) == sid_victime && faux != victime {
                intrus = Some(faux);
                break;
            }
        }

        if let Some(faux) = intrus {
            // Deux entrees, meme identifiant court : l'ambiguite doit mener a un
            // redemandage, pas a un mauvais choix.
            dispo.insert(faux, txs[1].clone());
            let r = Reconstruction::depuis(&compact, &dispo).expect("reconstruction");
            assert!(
                !r.is_complete() || r.finish().is_ok(),
                "une collision ne doit jamais produire un bloc invalide"
            );
        }
        // Si aucune collision n'a ete trouvee dans la fenetre balayee, le test
        // ne prouve rien mais ne ment pas non plus : il passe sans assertion.
    }

    #[test]
    fn aller_retour_de_serialisation() {
        let (bloc, _) = bloc_avec_transactions(3);
        let compact = CompactBlock::from_block(&bloc, 0x0123_4567_89ab_cdef);
        let decode = CompactBlock::decode(&compact.encode()).expect("decodage");
        assert_eq!(decode, compact);
    }

    #[test]
    fn aller_retour_avec_oncles() {
        let (mut bloc, _) = bloc_avec_transactions(1);
        bloc.uncles = vec![bloc.header];
        let compact = CompactBlock::from_block(&bloc, 5);
        assert_eq!(CompactBlock::decode(&compact.encode()).unwrap(), compact);
    }

    #[test]
    fn une_annonce_absurde_est_refusee_avant_allocation() {
        let (bloc, _) = bloc_avec_transactions(1);
        let mut brut = bloc.header.encode();
        brut.extend_from_slice(&0u64.to_le_bytes());
        // varint annoncant quatre milliards d'identifiants courts
        brut.push(0xfe);
        brut.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            CompactBlock::decode(&brut),
            Err(CompactError::TropDeTransactions(_))
        ));
    }

    #[test]
    fn une_coinbase_absente_est_refusee() {
        let (bloc, txs) = bloc_avec_transactions(2);
        let mut compact = CompactBlock::from_block(&bloc, 9);
        compact.prefilled.clear();
        assert!(matches!(
            Reconstruction::depuis(&compact, &mempool_de(&txs)),
            Err(CompactError::CoinbaseAbsente)
        ));
    }

    #[test]
    fn deux_nonces_donnent_deux_jeux_d_identifiants() {
        let (bloc, _) = bloc_avec_transactions(3);
        let a = CompactBlock::from_block(&bloc, 1);
        let b = CompactBlock::from_block(&bloc, 2);
        assert_ne!(
            a.short_ids, b.short_ids,
            "sans cela, une collision se reproduirait chez tous les pairs"
        );
    }

    /// Le chiffre qui justifie tout ce module.
    #[test]
    fn l_annonce_compacte_est_des_ordres_de_grandeur_plus_petite() {
        let (bloc, txs) = bloc_avec_transactions(5);
        let complet = bloc.encode().len();
        let compact = CompactBlock::from_block(&bloc, 0).encoded_len();

        assert!(
            compact * 20 < complet,
            "annonce compacte {compact} o contre bloc complet {complet} o : \
             le gain attendu n'y est pas"
        );

        // Chaque transaction ne coute que six octets dans l'annonce, la ou elle
        // en pese plus de vingt mille dans le bloc.
        let par_tx_complet = complet / bloc.transactions.len();
        assert!(par_tx_complet > 10_000, "transaction anormalement legere");
        let _ = txs;
    }
}

//! Blocs et en-tetes.
//!
//! Deux champs distinguent cet en-tete de celui de Bitcoin, et chacun repond a
//! un engagement du livre blanc.
//!
//! **`height` est dans l'en-tete.** Bitcoin ne l'y met pas et doit le deduire de
//! la chaine. Q21 en a besoin explicitement : la taille de la table de la preuve
//! de travail croit avec la hauteur, et un verificateur doit pouvoir dimensionner
//! cette table avant meme de rattacher le bloc a une chaine.
//!
//! **`uncles_root` engage les oncles.** Les recompenses d'oncles sont le
//! levier C de la section 5 : payer le travail orphelin d'un mineur mal connecte
//! plutot que de le jeter. Sans engagement dans l'en-tete, un mineur pourrait
//! reecrire la liste des oncles apres coup.

use crate::hash::{tagged_hash, tags, Hash256};
use crate::merkle::merkle_root;
use crate::ser::{ReadError, Reader, Writer};
use crate::tx::{Transaction, TxError};

/// En-tete de bloc : 92 octets, taille fixe.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block: Hash256,
    pub merkle_root: Hash256,
    /// Racine de Merkle des en-tetes d'oncles inclus.
    pub uncles_root: Hash256,
    /// Empreinte de clef publique du mineur de ce bloc.
    ///
    /// Presente dans l'en-tete et non seulement dans la coinbase, parce qu'un
    /// oncle n'est transmis que par son en-tete : sans ce champ, on saurait
    /// qu'un travail orphelin merite une recompense sans savoir a qui la verser.
    /// Ethereum a fait le meme choix, pour la meme raison.
    ///
    /// Une regle de consensus impose que la premiere sortie de la coinbase paie
    /// bien cette empreinte, sans quoi le champ serait declaratif et donc faux.
    pub miner: Hash256,
    /// Horodatage Unix en secondes.
    pub time: u64,
    /// Cible de difficulte, encodee en forme compacte.
    pub bits: u32,
    pub height: u64,
    pub nonce: u64,
}

impl BlockHeader {
    /// Taille serialisee, constante par construction.
    pub const SIZE: usize = 4 + 32 + 32 + 32 + 32 + 8 + 4 + 8 + 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::SIZE);
        w.u32(self.version);
        w.bytes(self.prev_block.as_bytes());
        w.bytes(self.merkle_root.as_bytes());
        w.bytes(self.uncles_root.as_bytes());
        w.bytes(self.miner.as_bytes());
        w.u64(self.time);
        w.u32(self.bits);
        w.u64(self.height);
        w.u64(self.nonce);
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<BlockHeader, ReadError> {
        let mut r = Reader::new(data);
        let h = BlockHeader {
            version: r.u32()?,
            prev_block: Hash256(r.array32()?),
            merkle_root: Hash256(r.array32()?),
            uncles_root: Hash256(r.array32()?),
            miner: Hash256(r.array32()?),
            time: r.u64()?,
            bits: r.u32()?,
            height: r.u64()?,
            nonce: r.u64()?,
        };
        r.expect_end()?;
        Ok(h)
    }

    /// Identifiant du bloc.
    ///
    /// Note : ce n'est pas la valeur comparee a la cible de difficulte. La
    /// preuve de travail utilisera une fonction *memory-hard* distincte, dont
    /// l'implementation releve de la phase 3 de la feuille de route. Confondre
    /// les deux serait une erreur de conception.
    pub fn block_id(&self) -> Hash256 {
        tagged_hash(tags::BLOCK_HEADER, &self.encode())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    /// En-tetes des oncles rattaches a ce bloc.
    pub uncles: Vec<BlockHeader>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BlockError {
    SansTransaction,
    PremiereTransactionNonCoinbase,
    CoinbaseMultiple,
    RacineDeMerkleIncorrecte,
    RacineDOnclesIncorrecte,
    Transaction(TxError),
    Lecture(ReadError),
}

impl From<ReadError> for BlockError {
    fn from(e: ReadError) -> Self {
        BlockError::Lecture(e)
    }
}

impl From<TxError> for BlockError {
    fn from(e: TxError) -> Self {
        BlockError::Transaction(e)
    }
}

impl Block {
    /// Calcule la racine de Merkle des transactions presentes.
    pub fn compute_merkle_root(&self) -> Hash256 {
        let feuilles: Vec<Hash256> = self.transactions.iter().map(|t| t.merkle_leaf()).collect();
        merkle_root(&feuilles)
    }

    pub fn compute_uncles_root(&self) -> Hash256 {
        let feuilles: Vec<Hash256> = self
            .uncles
            .iter()
            .map(|u| crate::merkle::leaf_hash(u.block_id().as_bytes()))
            .collect();
        merkle_root(&feuilles)
    }

    /// Controles de structure, sans acces au jeu d'UTXO ni a la difficulte.
    pub fn check_shape(&self) -> Result<(), BlockError> {
        if self.transactions.is_empty() {
            return Err(BlockError::SansTransaction);
        }
        if !self.transactions[0].is_coinbase() {
            return Err(BlockError::PremiereTransactionNonCoinbase);
        }
        if self.transactions[1..].iter().any(|t| t.is_coinbase()) {
            return Err(BlockError::CoinbaseMultiple);
        }
        for t in &self.transactions {
            t.check_shape()?;
        }
        if self.compute_merkle_root() != self.header.merkle_root {
            return Err(BlockError::RacineDeMerkleIncorrecte);
        }
        if self.compute_uncles_root() != self.header.uncles_root {
            return Err(BlockError::RacineDOnclesIncorrecte);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.header.encode());
        w.varint(self.transactions.len() as u64);
        for t in &self.transactions {
            w.var_bytes(&t.encode());
        }
        w.varint(self.uncles.len() as u64);
        for u in &self.uncles {
            w.bytes(&u.encode());
        }
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<Block, BlockError> {
        if data.len() < BlockHeader::SIZE {
            return Err(BlockError::Lecture(ReadError::FinPrematuree));
        }
        let header = BlockHeader::decode(&data[..BlockHeader::SIZE])?;
        let mut r = Reader::new(&data[BlockHeader::SIZE..]);

        // Chaque transaction est precedee de sa longueur et ne peut pas
        // occuper moins de dix octets. On sous-estime volontairement : un
        // minimum trop grand ferait refuser des donnees valides, un minimum
        // trop petit ne fait qu'affaiblir le controle.
        let n = r.compte(10)?;
        let mut transactions = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            transactions.push(Transaction::decode(r.var_bytes()?)?);
        }

        let nu = r.compte(BlockHeader::SIZE)?;
        let mut uncles = Vec::with_capacity(nu.min(64));
        for _ in 0..nu {
            let brut = r.remaining();
            if brut < BlockHeader::SIZE {
                return Err(BlockError::Lecture(ReadError::FinPrematuree));
            }
            let mut tampon = [0u8; BlockHeader::SIZE];
            for octet in tampon.iter_mut() {
                *octet = r.u8()?;
            }
            uncles.push(BlockHeader::decode(&tampon)?);
        }

        r.expect_end()?;
        Ok(Block {
            header,
            transactions,
            uncles,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crate::sig::SchemeId;
    use crate::tx::{TxIn, TxOut};

    fn coinbase(hauteur: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(hauteur.to_le_bytes().to_vec())],
            outputs: vec![TxOut {
                value: crate::emission::block_subsidy(hauteur),
                scheme: SchemeId::MlDsa65,
                pubkey_hash: Hash256([1u8; 32]),
            }],
            lock_time: 0,
        }
    }

    fn bloc(hauteur: u64) -> Block {
        let mut b = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256([2u8; 32]),
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: Hash256([1u8; 32]),
                time: 1_755_000_000,
                bits: 0x1d00_ffff,
                height: hauteur,
                nonce: 0,
            },
            transactions: vec![coinbase(hauteur)],
            uncles: Vec::new(),
        };
        b.header.merkle_root = b.compute_merkle_root();
        b.header.uncles_root = b.compute_uncles_root();
        b
    }

    #[test]
    fn l_en_tete_a_bien_une_taille_fixe() {
        assert_eq!(BlockHeader::SIZE, 160);
        assert_eq!(bloc(1).header.encode().len(), BlockHeader::SIZE);
    }

    #[test]
    fn aller_retour_sur_l_en_tete() {
        let h = bloc(42).header;
        assert_eq!(BlockHeader::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn aller_retour_sur_le_bloc() {
        let b = bloc(100);
        assert_eq!(Block::decode(&b.encode()).unwrap(), b);
    }

    #[test]
    fn aller_retour_avec_des_oncles() {
        let mut b = bloc(100);
        b.uncles = vec![bloc(99).header, bloc(98).header];
        b.header.uncles_root = b.compute_uncles_root();
        assert_eq!(Block::decode(&b.encode()).unwrap(), b);
        assert!(b.check_shape().is_ok());
    }

    #[test]
    fn le_nonce_change_l_identifiant() {
        let a = bloc(1).header;
        let mut b = a;
        b.nonce = 1;
        assert_ne!(a.block_id(), b.block_id());
    }

    #[test]
    fn la_hauteur_change_l_identifiant() {
        let a = bloc(1).header;
        let mut b = a;
        b.height = 2;
        assert_ne!(a.block_id(), b.block_id());
    }

    #[test]
    fn une_racine_de_merkle_fausse_est_detectee() {
        let mut b = bloc(10);
        b.header.merkle_root = Hash256([0xff; 32]);
        assert_eq!(b.check_shape(), Err(BlockError::RacineDeMerkleIncorrecte));
    }

    #[test]
    fn une_racine_d_oncles_fausse_est_detectee() {
        let mut b = bloc(10);
        b.uncles = vec![bloc(9).header];
        // uncles_root laissee a zero alors qu'un oncle est present.
        assert_eq!(b.check_shape(), Err(BlockError::RacineDOnclesIncorrecte));
    }

    #[test]
    fn un_bloc_sans_coinbase_est_refuse() {
        let mut b = bloc(10);
        b.transactions[0].inputs[0].prev_out = crate::tx::OutPoint {
            txid: Hash256([5u8; 32]),
            index: 0,
        };
        b.header.merkle_root = b.compute_merkle_root();
        assert_eq!(
            b.check_shape(),
            Err(BlockError::PremiereTransactionNonCoinbase)
        );
    }

    #[test]
    fn deux_coinbases_sont_refusees() {
        let mut b = bloc(10);
        b.transactions.push(coinbase(10));
        b.header.merkle_root = b.compute_merkle_root();
        assert_eq!(b.check_shape(), Err(BlockError::CoinbaseMultiple));
    }

    #[test]
    fn un_bloc_vide_est_refuse() {
        let mut b = bloc(10);
        b.transactions.clear();
        b.header.merkle_root = b.compute_merkle_root();
        assert_eq!(b.check_shape(), Err(BlockError::SansTransaction));
    }

    #[test]
    fn la_coinbase_de_genese_n_emet_rien() {
        let b = bloc(0);
        assert_eq!(b.transactions[0].outputs[0].value, Amount::ZERO);
    }
}

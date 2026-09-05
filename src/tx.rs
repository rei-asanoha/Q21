//! Transactions.
//!
//! Modele UTXO, repris de Bitcoin sans modification conceptuelle : une
//! transaction consomme des sorties existantes et en cree de nouvelles.
//!
//! Une difference de structure compte, et elle est heritee de la lecon SegWit :
//! **le temoin ne participe pas a l'identifiant de transaction.** Le `txid` est
//! calcule sur la transaction depouillee de ses signatures. Sans cette
//! separation, une signature reencodee differemment changerait l'identifiant
//! d'une transaction deja diffusee, et casserait toute chaine de transactions
//! non confirmees qui s'appuie dessus. Bitcoin a mis six ans a corriger ce
//! defaut ; on part avec la correction.
//!
//! Avec des signatures ML-DSA de 3 309 octets, cette separation devient en outre
//! une necessite de dimensionnement : le temoin represente l'essentiel du poids
//! d'une transaction, et doit pouvoir etre pondere a part.

use crate::amount::Amount;
use crate::hash::{tagged_hash, tags, Hash256};
use crate::merkle::leaf_hash;
use crate::ser::{ReadError, Reader, Writer};
use crate::sig::SchemeId;

/// Reference vers une sortie de transaction anterieure.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Hash256,
    pub index: u32,
}

impl OutPoint {
    /// Point d'entree de la coinbase : ne reference aucune sortie reelle.
    pub const COINBASE: OutPoint = OutPoint {
        txid: Hash256::ZERO,
        index: u32::MAX,
    };

    pub fn is_coinbase(&self) -> bool {
        *self == OutPoint::COINBASE
    }
}

/// Temoin : ce qui prouve le droit de depenser.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Witness {
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Entree de transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxIn {
    pub prev_out: OutPoint,
    pub witness: Witness,
    /// Sequence, reservee aux verrous temporels relatifs.
    pub sequence: u32,
}

impl TxIn {
    pub fn coinbase(donnees: Vec<u8>) -> TxIn {
        TxIn {
            prev_out: OutPoint::COINBASE,
            witness: Witness {
                pubkey: Vec::new(),
                signature: donnees,
            },
            sequence: u32::MAX,
        }
    }
}

/// Sortie de transaction : un montant et le verrou qui le protege.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxOut {
    pub value: Amount,
    pub scheme: SchemeId,
    /// Empreinte de la clef publique autorisee a depenser.
    pub pubkey_hash: Hash256,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TxError {
    SansEntree,
    SansSortie,
    MontantHorsPlafond,
    SommeDesSortiesDeborde,
    SchemaInconnu(u8),
    Lecture(ReadError),
}

impl From<ReadError> for TxError {
    fn from(e: ReadError) -> Self {
        TxError::Lecture(e)
    }
}

impl Transaction {
    /// Serialisation sans les temoins, telle qu'elle circule sur le reseau.
    pub fn encode_without_witness(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.outputs.len() * 40);
        w.u32(self.version);
        w.varint(self.inputs.len() as u64);
        for i in &self.inputs {
            w.bytes(i.prev_out.txid.as_bytes());
            w.u32(i.prev_out.index);
            w.u32(i.sequence);
        }
        w.varint(self.outputs.len() as u64);
        for o in &self.outputs {
            w.u64(o.value.units());
            w.u8(o.scheme.as_u8());
            w.bytes(o.pubkey_hash.as_bytes());
        }
        w.u64(self.lock_time);
        w.finish()
    }

    /// Serialisation complete, temoins compris. Definit le `wtxid`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.encode_without_witness());
        for i in &self.inputs {
            w.var_bytes(&i.witness.pubkey);
            w.var_bytes(&i.witness.signature);
        }
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<Transaction, TxError> {
        let mut r = Reader::new(data);
        let version = r.u32()?;

        // Une entree occupe au minimum quarante octets avant son temoin :
        // trente-deux pour l'identifiant, quatre pour l'indice, quatre pour la
        // sequence. Annoncer plus d'entrees que le reste ne peut en porter est
        // refuse avant toute reservation.
        let n_in = r.compte(40)?;
        let mut prev: Vec<(OutPoint, u32)> = Vec::with_capacity(n_in.min(1024));
        for _ in 0..n_in {
            let txid = Hash256(r.array32()?);
            let index = r.u32()?;
            let sequence = r.u32()?;
            prev.push((OutPoint { txid, index }, sequence));
        }

        // Une sortie occupe exactement quarante et un octets : huit de
        // montant, un de schema, trente-deux d'empreinte.
        let n_out = r.compte(41)?;
        let mut outputs = Vec::with_capacity(n_out.min(1024));
        for _ in 0..n_out {
            let value = Amount::from_units(r.u64()?);
            let raw = r.u8()?;
            let scheme = SchemeId::from_u8(raw).ok_or(TxError::SchemaInconnu(raw))?;
            outputs.push(TxOut {
                value,
                scheme,
                pubkey_hash: Hash256(r.array32()?),
            });
        }

        let lock_time = r.u64()?;

        let mut inputs = Vec::with_capacity(prev.len());
        for (prev_out, sequence) in prev {
            let pubkey = r.var_bytes()?.to_vec();
            let signature = r.var_bytes()?.to_vec();
            inputs.push(TxIn {
                prev_out,
                witness: Witness { pubkey, signature },
                sequence,
            });
        }

        r.expect_end()?;
        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    /// Identifiant de transaction, insensible aux temoins.
    /// Identifiant de transaction.
    ///
    /// # L'exception de la coinbase, et pourquoi elle est necessaire
    ///
    /// Une coinbase n'a pas de signature : son « temoin » ne porte que des
    /// donnees libres, dont la hauteur du bloc. L'exclure du `txid` laissait les
    /// coinbases **sans aucun element d'unicite** : deux blocs du meme mineur
    /// versant le meme montant produisaient le meme `txid`, la seconde sortie
    /// ecrasait la premiere dans le jeu d'UTXO, et defaire la seconde detruisait
    /// la sortie de la premiere. Deux noeuds honnetes se retrouvaient alors avec
    /// la meme tete et des soldes differents — une scission silencieuse.
    ///
    /// C'est la faille que Bitcoin a connue (BIP 30) et refermee par BIP 34. Ce
    /// champ est donc engage dans le `txid` **pour la coinbase uniquement**, ou
    /// il n'est malleable par personne d'autre que le mineur lui-meme.
    ///
    /// Les transactions ordinaires gardent un `txid` insensible a leur temoin :
    /// c'est la propriete qui rend le chainage sur, puisqu'un tiers ne peut pas
    /// alterer une signature pour changer l'identifiant.
    ///
    /// L'encodage de fil, lui, n'a pas change : seule la preimage du condensat
    /// differe.
    pub fn txid(&self) -> Hash256 {
        let base = self.encode_without_witness();
        if self.is_coinbase() {
            let mut w = Writer::with_capacity(base.len() + 32);
            w.bytes(&base);
            w.var_bytes(&self.inputs[0].witness.signature);
            return tagged_hash(tags::TX, &w.finish());
        }
        tagged_hash(tags::TX, &base)
    }

    /// Identifiant complet, temoins compris.
    pub fn wtxid(&self) -> Hash256 {
        tagged_hash(tags::TX, &self.encode())
    }

    /// Condensat signe par le depensier.
    ///
    /// Couvre la transaction depouillee ainsi que l'indice de l'entree signee,
    /// pour qu'une signature ne puisse pas etre rejouee sur une autre entree.
    pub fn sighash(&self, input_index: u32) -> Hash256 {
        let mut w = Writer::new();
        w.bytes(&self.encode_without_witness());
        w.u32(input_index);
        tagged_hash(tags::SIGHASH, w.as_slice())
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev_out.is_coinbase()
    }

    /// Somme des sorties, en signalant tout debordement.
    pub fn total_output(&self) -> Result<Amount, TxError> {
        Amount::checked_sum(self.outputs.iter().map(|o| o.value))
            .ok_or(TxError::SommeDesSortiesDeborde)
    }

    /// Controles de forme, independants de l'etat de la chaine.
    ///
    /// Ne verifie pas les signatures ni l'existence des sorties consommees :
    /// c'est le role du validateur, qui a besoin du jeu d'UTXO.
    pub fn check_shape(&self) -> Result<(), TxError> {
        if self.inputs.is_empty() {
            return Err(TxError::SansEntree);
        }
        if self.outputs.is_empty() {
            return Err(TxError::SansSortie);
        }
        for o in &self.outputs {
            if !o.value.is_within_supply() {
                return Err(TxError::MontantHorsPlafond);
            }
        }
        let total = self.total_output()?;
        if !total.is_within_supply() {
            return Err(TxError::MontantHorsPlafond);
        }
        Ok(())
    }

    /// Condensat de feuille, pour l'arbre de Merkle d'un bloc.
    pub fn merkle_leaf(&self) -> Hash256 {
        leaf_hash(self.txid().as_bytes())
    }

    /// Poids de la transaction, temoin pondere a part.
    ///
    /// C'est la traduction du *witness discount* de la section 7 du livre blanc :
    /// sans lui, une signature ML-DSA de 3 309 octets ferait payer au reste de la
    /// transaction le prix de la cryptographie qu'elle transporte.
    ///
    /// Chaque sortie creee ajoute [`crate::consensus::POIDS_PAR_SORTIE`] : une
    /// sortie occupe le jeu d'UTXO de tous les noeuds tant qu'elle vit, la ou
    /// un octet de temoin est oublie des que le bloc est enfoui. Le poids
    /// tarife donc la ressource rare, pas seulement les octets sur le fil.
    pub fn weight(&self, witness_discount: u64) -> u64 {
        let base = self.encode_without_witness().len() as u64;
        let witness: u64 = self
            .inputs
            .iter()
            .map(|i| (i.witness.pubkey.len() + i.witness.signature.len()) as u64)
            .sum();
        let sorties = self.outputs.len() as u64 * crate::consensus::POIDS_PAR_SORTIE;
        base * witness_discount + witness + sorties
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sortie(v: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(v),
            scheme: SchemeId::MlDsa65,
            pubkey_hash: Hash256([7u8; 32]),
        }
    }

    fn tx_simple() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([1u8; 32]),
                    index: 0,
                },
                witness: Witness {
                    pubkey: vec![2u8; 1952],
                    signature: vec![3u8; 3309],
                },
                sequence: 0xffff_ffff,
            }],
            outputs: vec![sortie(50_000), sortie(25_000)],
            lock_time: 0,
        }
    }

    #[test]
    fn aller_retour_de_serialisation() {
        let tx = tx_simple();
        assert_eq!(Transaction::decode(&tx.encode()).unwrap(), tx);
    }

    #[test]
    fn aller_retour_avec_plusieurs_entrees() {
        let mut tx = tx_simple();
        tx.inputs.push(TxIn {
            prev_out: OutPoint {
                txid: Hash256([9u8; 32]),
                index: 3,
            },
            witness: Witness {
                pubkey: vec![4u8; 2592],
                signature: vec![5u8; 4627],
            },
            sequence: 7,
        });
        assert_eq!(Transaction::decode(&tx.encode()).unwrap(), tx);
    }

    /// Le point qui a coute six ans a Bitcoin.
    #[test]
    fn le_txid_ne_depend_pas_du_temoin() {
        let a = tx_simple();
        let mut b = a.clone();
        b.inputs[0].witness.signature = vec![0xaa; 3309];

        assert_eq!(a.txid(), b.txid(), "le temoin ne doit pas bouger le txid");
        assert_ne!(a.wtxid(), b.wtxid(), "le wtxid, lui, doit bouger");
    }

    #[test]
    fn le_txid_depend_des_sorties() {
        let a = tx_simple();
        let mut b = a.clone();
        b.outputs[0].value = Amount::from_units(50_001);
        assert_ne!(a.txid(), b.txid());
    }

    #[test]
    fn le_sighash_lie_la_signature_a_son_entree() {
        let tx = tx_simple();
        assert_ne!(
            tx.sighash(0),
            tx.sighash(1),
            "sinon une signature se rejoue d'une entree sur l'autre"
        );
    }

    #[test]
    fn le_sighash_differe_du_txid() {
        let tx = tx_simple();
        assert_ne!(tx.sighash(0).as_bytes(), tx.txid().as_bytes());
    }

    #[test]
    fn la_coinbase_est_reconnue() {
        let cb = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(b"bloc 1".to_vec())],
            outputs: vec![sortie(1_384_711_800)],
            lock_time: 0,
        };
        assert!(cb.is_coinbase());
        assert!(!tx_simple().is_coinbase());
        assert_eq!(Transaction::decode(&cb.encode()).unwrap(), cb);
    }

    #[test]
    fn les_transactions_malformees_sont_rejetees() {
        let mut vide = tx_simple();
        vide.inputs.clear();
        assert_eq!(vide.check_shape(), Err(TxError::SansEntree));

        let mut sans_sortie = tx_simple();
        sans_sortie.outputs.clear();
        assert_eq!(sans_sortie.check_shape(), Err(TxError::SansSortie));
    }

    #[test]
    fn on_ne_peut_pas_fabriquer_de_la_monnaie_par_debordement() {
        // Deux sorties dont la somme deborde u64 : le controle doit mordre.
        let mut tx = tx_simple();
        tx.outputs = vec![sortie(u64::MAX), sortie(u64::MAX)];
        assert!(matches!(
            tx.check_shape(),
            Err(TxError::MontantHorsPlafond) | Err(TxError::SommeDesSortiesDeborde)
        ));
    }

    #[test]
    fn une_sortie_au_dela_du_plafond_est_refusee() {
        let mut tx = tx_simple();
        tx.outputs = vec![sortie(crate::consensus::MAX_SUPPLY + 1)];
        assert_eq!(tx.check_shape(), Err(TxError::MontantHorsPlafond));
    }

    #[test]
    fn les_octets_en_trop_sont_refuses() {
        let mut b = tx_simple().encode();
        b.push(0x00);
        assert!(matches!(
            Transaction::decode(&b),
            Err(TxError::Lecture(ReadError::OctetsRestants(1)))
        ));
    }

    #[test]
    fn un_schema_inconnu_dans_une_sortie_est_refuse() {
        let tx = tx_simple();
        let mut b = tx.encode_without_witness();
        // Localise l'octet de schema de la premiere sortie et le corrompt.
        let pos = 4 + 1 + (32 + 4 + 4) + 1 + 8;
        b[pos] = 200;
        assert!(matches!(
            Transaction::decode(&b),
            Err(TxError::SchemaInconnu(200))
        ));
    }

    #[test]
    fn le_temoin_domine_le_poids_sans_ristourne() {
        let tx = tx_simple();
        let sans = tx.weight(1);
        let avec = tx.weight(4);
        assert!(avec > sans);
        // Une signature ML-DSA pese bien plus que le corps de la transaction.
        let base = tx.encode_without_witness().len() as u64;
        let temoin = (1952 + 3309) as u64;
        assert!(temoin > base * 20, "base={base} temoin={temoin}");
    }
}

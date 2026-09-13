//! Une chaine parent -> enfant dans un meme bloc.
//!
//! Le reservoir accepte une transaction qui depense une sortie encore non
//! confirmee, et la selection l'empaquette apres son parent. Le validateur
//! doit donc accepter un bloc `[coinbase, P, C]` ou C depense une sortie de
//! P — et continuer de refuser une double depense intra-bloc, ainsi qu'un
//! enfant place avant son parent.
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::lamport;
use q21_core::sig::{self, SchemeId};
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::validate::ValidationError;
use q21_core::Network;

const RESEAU: Network = Network::Regtest;
const GRAINE: [u8; 32] = [0x77; 32];

fn clef(i: u32) -> (lamport::SecretKey, Vec<u8>, Hash256) {
    let sk = lamport::SecretKey::from_seed(GRAINE, i);
    let pk = sk.public_key();
    let h = sig::pubkey_hash(SchemeId::LamportOts, &pk);
    (sk, pk, h)
}

fn sortie(valeur: u64, h: Hash256) -> TxOut {
    TxOut {
        value: Amount::from_units(valeur),
        scheme: SchemeId::LamportOts,
        pubkey_hash: h,
    }
}

fn tx_signee(entrees: &[(OutPoint, u32, TxOut)], sorties: Vec<TxOut>) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: entrees
            .iter()
            .map(|(o, _, _)| TxIn {
                prev_out: *o,
                witness: Witness::default(),
                sequence: 0xffff_ffff,
            })
            .collect(),
        outputs: sorties,
        lock_time: 0,
    };
    for (i, (_, idx, depensee)) in entrees.iter().enumerate() {
        let (sk, pk, _) = clef(*idx);
        let m = tx.sighash(i as u32, RESEAU, depensee);
        tx.inputs[i].witness = Witness {
            pubkey: pk,
            signature: sk.sign(&m),
        };
    }
    tx
}

/// Une chaine dont la coinbase du bloc 1 (clef 1) est mure.
fn chaine_financee() -> (Chain, (OutPoint, u32, TxOut)) {
    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    let (_, _, h1) = clef(1);
    let (_, _, puits) = clef(999);
    let mut source = None;
    for i in 0..(COINBASE_MATURITY + 1) {
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let benef = if i == 0 { h1 } else { puits };
        let b = c
            .mine_block(benef, SchemeId::LamportOts, &[], t, 5_000_000)
            .expect("minage");
        if i == 0 {
            let cb = &b.transactions[0];
            source = Some((
                OutPoint {
                    txid: cb.txid(),
                    index: 0,
                },
                1u32,
                cb.outputs[0],
            ));
        }
        c.connect(&b, t + 1).expect("connexion");
    }
    (c, source.unwrap())
}

fn miner_avec(c: &Chain, txs: &[Transaction]) -> q21_core::block::Block {
    let (_, _, puits) = clef(998);
    let t = c.tip().time + TARGET_BLOCK_SECS;
    c.mine_block(puits, SchemeId::LamportOts, txs, t, 5_000_000)
        .expect("minage du bloc d'epreuve")
}

#[test]
fn un_enfant_peut_suivre_son_parent_dans_le_meme_bloc() {
    let (mut c, source) = chaine_financee();
    let (_, _, h2) = clef(2);
    let (_, _, h3) = clef(3);
    let p = tx_signee(&[source], vec![sortie(50_000, h2)]);
    let p_out = (
        OutPoint {
            txid: p.txid(),
            index: 0,
        },
        2u32,
        p.outputs[0],
    );
    let enfant = tx_signee(&[p_out], vec![sortie(20_000, h3)]);
    let b = miner_avec(&c, &[p.clone(), enfant.clone()]);
    let t = b.header.time + 1;
    c.connect(&b, t)
        .expect("la chaine parent -> enfant est valide dans un seul bloc");
    // La sortie de P est consommee, celle de C existe.
    assert!(c.utxo.get(&p_out.0).is_none());
    assert!(c
        .utxo
        .get(&OutPoint {
            txid: enfant.txid(),
            index: 0
        })
        .is_some());
}

#[test]
fn une_double_depense_intra_bloc_reste_refusee() {
    let (mut c, source) = chaine_financee();
    let (_, _, h2) = clef(2);
    let (_, _, h4) = clef(4);
    let p = tx_signee(&[source], vec![sortie(50_000, h2)]);
    let p2 = tx_signee(&[source], vec![sortie(40_000, h4)]);
    let b = miner_avec(&c, &[p, p2]);
    let t = b.header.time + 1;
    match c.connect(&b, t) {
        Err(ValidationError::DoubleDepense(o)) => assert_eq!(o, source.0),
        autre => panic!("attendu DoubleDepense, obtenu {autre:?}"),
    }
}

#[test]
fn un_enfant_avant_son_parent_reste_refuse() {
    let (mut c, source) = chaine_financee();
    let (_, _, h2) = clef(2);
    let (_, _, h3) = clef(3);
    let p = tx_signee(&[source], vec![sortie(50_000, h2)]);
    let p_out = (
        OutPoint {
            txid: p.txid(),
            index: 0,
        },
        2u32,
        p.outputs[0],
    );
    let enfant = tx_signee(&[p_out], vec![sortie(20_000, h3)]);
    let b = miner_avec(&c, &[enfant, p]);
    let t = b.header.time + 1;
    match c.connect(&b, t) {
        Err(ValidationError::EntreeIntrouvable(o)) => assert_eq!(o, p_out.0),
        autre => panic!("attendu EntreeIntrouvable, obtenu {autre:?}"),
    }
}

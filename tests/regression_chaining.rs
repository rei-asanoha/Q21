//! A parent -> child chain within a single block.
//!
//! The mempool accepts a transaction that spends a still-unconfirmed output,
//! and block template selection packs it after its parent. The validator must
//! therefore accept a block `[coinbase, P, C]` where C spends an output of
//! P, and keep refusing an intra-block double spend, as well as a child
//! placed before its parent.
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::lamport;
use q21_core::sig::{self, SchemeId};
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::validate::ValidationError;
use q21_core::Network;

const NETWORK: Network = Network::Regtest;
const SEED: [u8; 32] = [0x77; 32];

fn key(i: u32) -> (lamport::SecretKey, Vec<u8>, Hash256) {
    let sk = lamport::SecretKey::from_seed(SEED, i);
    let pk = sk.public_key();
    let h = sig::pubkey_hash(SchemeId::LamportOts, &pk);
    (sk, pk, h)
}

fn output(value: u64, h: Hash256) -> TxOut {
    TxOut {
        value: Amount::from_units(value),
        scheme: SchemeId::LamportOts,
        pubkey_hash: h,
    }
}

fn signed_tx(inputs: &[(OutPoint, u32, TxOut)], outputs: Vec<TxOut>) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: inputs
            .iter()
            .map(|(o, _, _)| TxIn {
                prev_out: *o,
                witness: Witness::default(),
                sequence: 0xffff_ffff,
            })
            .collect(),
        outputs,
        lock_time: 0,
    };
    for (i, (_, idx, spent)) in inputs.iter().enumerate() {
        let (sk, pk, _) = key(*idx);
        let m = tx.sighash(i as u32, NETWORK, spent);
        tx.inputs[i].witness = Witness {
            pubkey: pk,
            signature: sk.sign(&m),
        };
    }
    tx
}

/// A chain in which the coinbase of block 1 (key 1) is mature.
fn funded_chain() -> (Chain, (OutPoint, u32, TxOut)) {
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    let (_, _, h1) = key(1);
    let (_, _, sink) = key(999);
    let mut source = None;
    for i in 0..(COINBASE_MATURITY + 1) {
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let payee = if i == 0 { h1 } else { sink };
        let b = c
            .mine_block(payee, SchemeId::LamportOts, &[], t, 5_000_000)
            .expect("mining");
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
        c.connect(&b, t + 1).expect("connect");
    }
    (c, source.unwrap())
}

fn mine_with(c: &Chain, txs: &[Transaction]) -> q21_core::block::Block {
    let (_, _, sink) = key(998);
    let t = c.tip().time + TARGET_BLOCK_SECS;
    c.mine_block(sink, SchemeId::LamportOts, txs, t, 5_000_000)
        .expect("mining the test block")
}

#[test]
fn a_child_can_follow_its_parent_in_the_same_block() {
    let (mut c, source) = funded_chain();
    let (_, _, h2) = key(2);
    let (_, _, h3) = key(3);
    let p = signed_tx(&[source], vec![output(50_000, h2)]);
    let p_out = (
        OutPoint {
            txid: p.txid(),
            index: 0,
        },
        2u32,
        p.outputs[0],
    );
    let child = signed_tx(&[p_out], vec![output(20_000, h3)]);
    let b = mine_with(&c, &[p.clone(), child.clone()]);
    let t = b.header.time + 1;
    c.connect(&b, t)
        .expect("the parent -> child chain is valid within a single block");
    // The output of P is consumed, the one of C exists.
    assert!(c.utxo.get(&p_out.0).is_none());
    assert!(c
        .utxo
        .get(&OutPoint {
            txid: child.txid(),
            index: 0
        })
        .is_some());
}

#[test]
fn an_intra_block_double_spend_is_still_refused() {
    let (mut c, source) = funded_chain();
    let (_, _, h2) = key(2);
    let (_, _, h4) = key(4);
    let p = signed_tx(&[source], vec![output(50_000, h2)]);
    let p2 = signed_tx(&[source], vec![output(40_000, h4)]);
    let b = mine_with(&c, &[p, p2]);
    let t = b.header.time + 1;
    match c.connect(&b, t) {
        Err(ValidationError::DoubleSpend(o)) => assert_eq!(o, source.0),
        other => panic!("expected DoubleSpend, got {other:?}"),
    }
}

#[test]
fn a_child_before_its_parent_is_still_refused() {
    let (mut c, source) = funded_chain();
    let (_, _, h2) = key(2);
    let (_, _, h3) = key(3);
    let p = signed_tx(&[source], vec![output(50_000, h2)]);
    let p_out = (
        OutPoint {
            txid: p.txid(),
            index: 0,
        },
        2u32,
        p.outputs[0],
    );
    let child = signed_tx(&[p_out], vec![output(20_000, h3)]);
    let b = mine_with(&c, &[child, p]);
    let t = b.header.time + 1;
    match c.connect(&b, t) {
        Err(ValidationError::MissingInput(o)) => assert_eq!(o, p_out.0),
        other => panic!("expected MissingInput, got {other:?}"),
    }
}

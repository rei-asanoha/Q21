//! ATTACK: inflation by undoing a block with intra-block chained spends.
//!
//! Red-team simulation (phase 8b). We reproduce exactly what an adversarial
//! miner controls: a block where a transaction spends an output created by a
//! previous transaction of the SAME block (parent-child chaining, allowed and
//! tested by `regression_chaining`). Then a reorg undoes that block.
//!
//! Attack hypothesis: `UtxoSet::undo` removes the created outputs and then
//! reinserts the consumed ones, without deduplication. The intra-block output
//! appears in both lists; removed as created, it is reinserted as consumed,
//! and survives: a phantom UTXO, spendable, extending no transaction of the
//! active chain. Money created out of nothing.

use q21_core::amount::Amount;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::utxo::{UndoRecord, UtxoSet};

fn output(v: u64, h: u8) -> TxOut {
    TxOut {
        value: Amount::from_units(v),
        scheme: SchemeId::LamportOts,
        pubkey_hash: Hash256([h; 32]),
    }
}

fn coinbase(v: u64, h: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(vec![9, 9, 9])],
        outputs: vec![output(v, h)],
        lock_time: 0,
    }
}

fn spend(txid: Hash256, index: u32, v: u64, h: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint { txid, index },
            witness: Witness::default(),
            sequence: 0,
        }],
        outputs: vec![output(v, h)],
        lock_time: 0,
    }
}

#[test]
fn undoing_a_block_with_intra_block_chaining_must_not_create_money() {
    let mut u = UtxoSet::new();

    // --- Starting state: a single coin of 10,000 held by the victim.
    let w = coinbase(10_000, 1);
    let mut undo_pre = UndoRecord::default();
    u.apply_transaction(&w, 1, &mut undo_pre);

    let value_before = u.total_value();
    let commitment_before = u.commitment();

    // --- The adversarial block: ONE SINGLE UndoRecord for the whole block, as
    //     `Chain::connect` does. Two transactions chained in the same block.
    let mut undo_block = UndoRecord::default();

    // tx1: spends W (10,000) -> Y = 9,000 on key hash 2
    let tx1 = spend(w.txid(), 0, 9_000, 2);
    u.apply_transaction(&tx1, 2, &mut undo_block);
    let y = OutPoint {
        txid: tx1.txid(),
        index: 0,
    };

    // tx2: spends Y (9,000) -> Z = 8,000 on key hash 3
    let tx2 = spend(tx1.txid(), 0, 8_000, 3);
    u.apply_transaction(&tx2, 2, &mut undo_block);

    // --- The reorg undoes the block.
    u.undo(&undo_block);

    // --- Verdicts. After the undo, the set must be BIT FOR BIT the one from
    //     before the block: a single coin of 10,000, nothing else.
    let phantom_present = u.contains(&y);
    let value_after = u.total_value();
    let commitment_after = u.commitment();

    println!("value before : {}", value_before.units());
    println!("value after  : {}", value_after.units());
    println!("phantom Y present after undo: {phantom_present}");
    println!(
        "identical commitment: {}",
        commitment_before == commitment_after
    );
    println!(
        "incremental commitment == recomputed: {}",
        u.commitment() == u.recomputed_commitment()
    );

    assert!(
        !phantom_present,
        "PHANTOM: the intra-block output Y survived the undo; a spendable UTXO created out of nothing"
    );
    assert_eq!(
        value_after.units(),
        value_before.units(),
        "INFLATION: the total value of the set increased after the undo"
    );
    assert_eq!(
        commitment_after, commitment_before,
        "DIVERGENCE: the state commitment differs from the one before the block; a freshly synced node will compute a different commitment"
    );
}

//! ATTACKS (red-team, 3rd campaign): money creation and signature replay.
//!
//! Three attacks carried out end to end against a real chain, each aiming at
//! the most serious objective: making a unit exist that should not have, or
//! spending what one does not hold.
//!
//! 1. A coinbase that claims one unit more than its subsidy.
//! 2. A coinbase that claims fees the block does not carry ("phantom
//!    fees"): the miner pockets subsidy + real fees + 1.
//! 3. Replaying the signature of one input on another input of the same
//!    transaction, both locked by the same key: without binding the index
//!    into the signed hash, a single signature would unlock both.
//!
//! All three must fail. This file proves that they fail.

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::{COINBASE_MATURITY, MIN_OUTPUT_VALUE, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::lamport::SecretKey;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow;
use q21_core::sig::{pubkey_hash, SchemeId};
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::validate::ValidationError;
use q21_core::wallet::Wallet;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn timestamp(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

/// Re-mines a block after it has been altered: otherwise the validator would
/// refuse it on the Merkle root, and the attack would turn green without
/// having proven anything.
fn remine(b: &mut q21_core::block::Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let table = PowTable::build(TableParams::for_network(NETWORK), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &table, ATTEMPTS).expect("re-mining");
}

// ---------------------------------------------------------------------------
// 1. A coinbase that claims one unit too many
// ---------------------------------------------------------------------------

#[test]
fn a_coinbase_claiming_one_unit_too_many_is_refused() {
    let mut w = Wallet::from_seed([0x31; 32], NETWORK);
    let a = w.new_address();
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=3u64 {
        let t = timestamp(i);
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }

    let h = c.height() + 1;
    let t = timestamp(h);
    let mut block = c
        .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining");

    // The attack: one indivisible unit more than the allowed subsidy.
    block.transactions[0].outputs[0].value =
        Amount::from_units(block.transactions[0].outputs[0].value.units() + 1);
    remine(&mut block);

    assert!(
        matches!(
            c.connect(&block, t + 1),
            Err(ValidationError::ExcessiveSubsidy { .. })
        ),
        "a coinbase that claims more than its subsidy must be refused"
    );
}

// ---------------------------------------------------------------------------
// 2. Phantom fees
// ---------------------------------------------------------------------------

/// A block carries a real transaction with fee `F`. The coinbase is therefore
/// entitled to `subsidy + F`. The attack claims `subsidy + F + 1`: the miner
/// tries to pocket a fee that no one paid. The bound is exact, to the unit.
#[test]
fn a_coinbase_cannot_claim_phantom_fees() {
    let mut alice = Wallet::from_seed([0x32; 32], NETWORK);
    let _ = alice.new_address();
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for _ in 0..(COINBASE_MATURITY + 3) {
        let a = alice.new_address();
        let h = c.height() + 1;
        let t = timestamp(h);
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }

    // A real spend, with real fees.
    let mut bob = Wallet::from_seed([0xb2; 32], NETWORK);
    let addr_bob = bob.new_address();
    let fee = Amount::from_units(7_000);
    let tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(50_000),
            fee,
        )
        .expect("building the spend");

    let h = c.height() + 1;
    let t = timestamp(h);
    let addr_miner = alice.new_address();
    let mut block = c
        .mine_block(addr_miner.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining");

    // The coinbase has already pocketed the real fees. We add ONE more: a
    // fee that the block does not carry.
    block.transactions[0].outputs[0].value =
        Amount::from_units(block.transactions[0].outputs[0].value.units() + 1);
    remine(&mut block);

    assert!(
        matches!(
            c.connect(&block, t + 1),
            Err(ValidationError::ExcessiveSubsidy { .. })
        ),
        "the claimed fees cannot exceed the fees actually paid"
    );
}

// ---------------------------------------------------------------------------
// 3. Replaying a signature from one input onto another
// ---------------------------------------------------------------------------

/// Two outputs locked by **the same key**. One transaction spends both. Can
/// the signature of input 0 be replayed on input 1?
///
/// It must not be: the signed hash commits to the input index
/// (`Transaction::sighash`). Without that binding, a single signature would
/// unlock as many inputs as the same key locks: a theft of one's own funds,
/// admittedly, but above all an opening for constructions where a signature
/// counts for an input it never targeted.
#[test]
fn a_signature_does_not_replay_from_one_input_to_the_other() {
    // One Lamport key, two coinbases paid to it: two UTXOs behind the same
    // lock. (One-time Lamport only makes sense on the confidentiality side;
    // consensus allows it on the regtest network, and it is the only scheme
    // that does not require the `mldsa` feature to sign in a test.)
    let sk = SecretKey::from_seed([0x33; 32], 0);
    let lock = pubkey_hash(SchemeId::LamportOts, &sk.public_key());

    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for _ in 0..(COINBASE_MATURITY + 4) {
        let h = c.height() + 1;
        let t = timestamp(h);
        let b = c
            .mine_block(lock, SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }

    // Two mature outputs, locked by `lock`.
    let height = c.height();
    let mut mature: Vec<(OutPoint, TxOut)> = c
        .utxo
        .iter()
        .filter(|(_, e)| {
            e.is_coinbase && height >= e.height + COINBASE_MATURITY && e.output.pubkey_hash == lock
            // not the genesis, locked elsewhere
        })
        .map(|(o, e)| (*o, e.output))
        .collect();
    mature.sort_by_key(|(o, _)| *o);
    assert!(mature.len() >= 4, "at least four mature outputs are needed");
    let (u0, out0) = mature[0];
    let (u1, out1) = mature[1];

    // A transaction with two inputs, each signed at its own index.
    let build = |u0: OutPoint, u1: OutPoint| Transaction {
        version: 1,
        inputs: vec![
            TxIn {
                prev_out: u0,
                witness: Witness::default(),
                sequence: u32::MAX,
            },
            TxIn {
                prev_out: u1,
                witness: Witness::default(),
                sequence: u32::MAX,
            },
        ],
        outputs: vec![TxOut {
            value: Amount::from_units(MIN_OUTPUT_VALUE),
            scheme: SchemeId::LamportOts,
            pubkey_hash: Hash256([0x99; 32]),
        }],
        lock_time: 0,
    };

    // --- The control case: the honest spend, each input signed at its index.
    let mut tx = build(u0, u1);
    let msg0 = tx.sighash(0, NETWORK, &out0);
    let msg1 = tx.sighash(1, NETWORK, &out1);
    assert_ne!(msg0, msg1, "the two inputs do not share their hash");
    tx.inputs[0].witness = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg0),
    };
    tx.inputs[1].witness = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg1),
    };
    let h = c.height() + 1;
    let t = timestamp(h);
    let block = c
        .mine_block(lock, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining the control case");
    assert!(
        c.connect(&block, t + 1).is_ok(),
        "the honest two-input spend must be accepted"
    );

    // --- The attack: two OTHER outputs, same key, but we sign ONLY input 0
    // and copy its signature onto input 1.
    let (u2, out2) = mature[2];
    let (u3, _out3) = mature[3];
    let mut attack = build(u2, u3);
    let msg2 = attack.sighash(0, NETWORK, &out2);
    let witness0 = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg2),
    };
    attack.inputs[0].witness = witness0.clone();
    // The replay: the same signature, the same key, on input 1.
    attack.inputs[1].witness = witness0;

    let h = c.height() + 1;
    let t = timestamp(h);
    let block = c
        .mine_block(lock, SchemeId::LamportOts, &[attack], t, ATTEMPTS)
        .expect("mining the attack");
    let r = c.connect(&block, t + 1);
    assert!(
        r.is_err(),
        "a signature replayed from one input onto the other must NEVER be accepted (got {r:?})"
    );
    assert!(
        matches!(r, Err(ValidationError::Signature(_))),
        "the replay must be refused for an invalid signature, got {r:?}"
    );
}

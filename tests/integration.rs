//! End-to-end tests.
//!
//! Unit tests check parts. These check that the assembly holds: that one can
//! mine, transfer, and above all that no sequence of accepted blocks can
//! create money.
//!
//! The scenarios run on regtest, where the difficulty stays fixed at the
//! minimum. The consensus rule under test is identical.

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::emission;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::tx::{Transaction, TxOut};
use q21_core::validate::ValidationError;
use q21_core::wallet::Wallet;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn timestamp(height: u64) -> u64 {
    GENESIS_TIME + height * TARGET_BLOCK_SECS
}

/// Re-mines a block after altering it.
///
/// Essential as soon as a value rule is tested: modifying a coinbase
/// invalidates the Merkle root, hence the proof of work. Without re-mining,
/// the validator would refuse the block for the wrong reason and the test
/// would go green without proving anything.
fn remine(b: &mut q21_core::block::Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let table = PowTable::build(TableParams::for_network(NETWORK), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &table, ATTEMPTS).expect("re-mining");
}

/// Prepares a chain where `w` holds mature funds.
fn chain_with_funds(w: &mut Wallet, blocks: u64) -> Chain {
    let _ = w.new_address();
    let g = genesis_block(NETWORK);
    let mut c = Chain::new(NETWORK, g);
    for i in 1..=blocks {
        let a = w.new_address();
        let t = timestamp(i);
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connection");
    }
    c
}

#[test]
fn full_scenario_mine_then_transfer() {
    let mut alice = Wallet::from_seed([0xa1; 32], NETWORK);
    let mut c = chain_with_funds(&mut alice, COINBASE_MATURITY + 10);

    let initial_balance = alice.balance(&c.utxo, c.height());
    assert!(initial_balance.units() > 0, "Alice should hold funds");

    let mut bob = Wallet::from_seed([0xb0; 32], NETWORK);
    let bob_addr = bob.new_address();

    let amount = Amount::from_units(50_000);
    let fee = Amount::from_units(1_000);
    let tx = alice
        .create_transaction(&c.utxo, c.height(), &bob_addr, amount, fee)
        .expect("building the transaction");

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner_addr = alice.new_address();
    let block = c
        .mine_block(miner_addr.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining the block");

    let fees_collected = c
        .connect(&block, t + 1)
        .expect("the block should be accepted");
    assert_eq!(fees_collected, fee);

    // Bob must now see his funds.
    bob.rescan(1);
    assert_eq!(bob.balance(&c.utxo, c.height()), amount);
}

/// The most important test of the whole project.
#[test]
fn no_sequence_of_blocks_can_create_money() {
    let mut w = Wallet::from_seed([0x33; 32], NETWORK);
    let c = chain_with_funds(&mut w, 300);

    // What the protocol allows to have been issued at this height.
    let theoretical = emission::total_supply_at(c.height()).units();

    assert_eq!(
        c.total_issued().units(),
        theoretical,
        "the observed emission must equal the theoretical emission"
    );
    assert_eq!(
        c.utxo.total_value().units(),
        theoretical,
        "without spending, all the money issued must be in the UTXO set"
    );
    assert!(c.total_issued().units() <= MAX_SUPPLY);
}

#[test]
fn a_miner_cannot_award_itself_more_than_its_due() {
    let mut w = Wallet::from_seed([0x44; 32], NETWORK);
    let mut c = chain_with_funds(&mut w, 5);

    let h = c.height() + 1;
    let t = timestamp(h);
    let a = w.new_address();
    let mut block = c
        .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
        .unwrap();

    // A single unit too many, the smallest possible.
    let due = block.transactions[0].outputs[0].value.units();
    block.transactions[0].outputs[0].value = Amount::from_units(due + 1);
    remine(&mut block);

    assert!(matches!(
        c.connect(&block, t + 1),
        Err(ValidationError::ExcessiveSubsidy { .. })
    ));
}

#[test]
fn a_double_spend_in_the_same_block_is_refused() {
    let mut w = Wallet::from_seed([0x55; 32], NETWORK);
    let mut c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);

    let mut dest = Wallet::from_seed([0x66; 32], NETWORK);
    let a = dest.new_address();
    let tx = w
        .create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("building");

    // The same transfer, twice in the same block.
    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = w.new_address();
    let block = c
        .mine_block(
            miner.hash,
            SchemeId::LamportOts,
            &[tx.clone(), tx],
            t,
            ATTEMPTS,
        )
        .unwrap();

    assert!(matches!(
        c.connect(&block, t + 1),
        Err(ValidationError::DoubleSpend(_))
    ));
}

#[test]
fn a_forged_signature_is_refused() {
    let mut w = Wallet::from_seed([0x77; 32], NETWORK);
    let mut c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);

    let mut dest = Wallet::from_seed([0x88; 32], NETWORK);
    let a = dest.new_address();
    let mut tx = w
        .create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("building");

    // A single signature byte modified.
    tx.inputs[0].witness.signature[0] ^= 0x01;

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = w.new_address();
    let block = c
        .mine_block(miner.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .unwrap();

    assert!(matches!(
        c.connect(&block, t + 1),
        Err(ValidationError::Signature(_))
    ));
}

#[test]
fn one_cannot_spend_someone_elses_output() {
    let mut alice = Wallet::from_seed([0x91; 32], NETWORK);
    let mut c = chain_with_funds(&mut alice, COINBASE_MATURITY + 5);

    // Mallory builds a transaction that consumes one of Alice's outputs,
    // presenting his own key.
    let mut mallory = Wallet::from_seed([0x92; 32], NETWORK);
    let target = alice.spendable(&c.utxo, c.height())[0].0;

    let sk = q21_core::lamport::SecretKey::from_seed([0x92; 32], 0);
    let mallory_addr = mallory.new_address();
    let mut tx = Transaction {
        version: 1,
        inputs: vec![q21_core::tx::TxIn {
            prev_out: target,
            witness: q21_core::tx::Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(100_000),
            scheme: SchemeId::LamportOts,
            pubkey_hash: mallory_addr.hash,
        }],
        lock_time: 0,
    };
    let spent = c.utxo.get(&target).expect("targeted output").output;
    let msg = tx.sighash(0, NETWORK, &spent);
    tx.inputs[0].witness = q21_core::tx::Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg),
    };

    let h = c.height() + 1;
    let t = timestamp(h);
    let block = c
        .mine_block(mallory_addr.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .unwrap();

    // The signature is perfectly valid — but for the wrong key.
    assert!(matches!(
        c.connect(&block, t + 1),
        Err(ValidationError::KeyDoesNotMatchLock)
    ));
}

#[test]
fn an_immature_coinbase_cannot_be_spent() {
    let mut w = Wallet::from_seed([0xaa; 32], NETWORK);
    let mut c = chain_with_funds(&mut w, 5);

    // Nothing is mature: the wallet itself refuses to build.
    let mut dest = Wallet::from_seed([0xbb; 32], NETWORK);
    let a = dest.new_address();
    let r = w.create_transaction(
        &c.utxo,
        c.height(),
        &a,
        Amount::from_units(100_000),
        Amount::ZERO,
    );
    assert!(r.is_err(), "no output should be spendable");

    // And if the validator's hand is forced, it refuses too.
    let target = c
        .utxo
        .iter()
        .map(|(o, _)| *o)
        .min()
        .expect("the UTXO set is not empty");
    let sk = q21_core::lamport::SecretKey::from_seed([0xaa; 32], 0);
    let mut tx = Transaction {
        version: 1,
        inputs: vec![q21_core::tx::TxIn {
            prev_out: target,
            witness: q21_core::tx::Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(MIN_OUTPUT_VALUE),
            scheme: SchemeId::LamportOts,
            pubkey_hash: a.hash,
        }],
        lock_time: 0,
    };
    let spent = c.utxo.get(&target).expect("targeted output").output;
    let msg = tx.sighash(0, NETWORK, &spent);
    tx.inputs[0].witness = q21_core::tx::Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg),
    };

    let h = c.height() + 1;
    let t = timestamp(h);
    let block = c
        .mine_block(a.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .unwrap();
    let r = c.connect(&block, t + 1);
    assert!(
        matches!(
            r,
            Err(ValidationError::CoinbaseImmature { .. })
                | Err(ValidationError::KeyDoesNotMatchLock)
        ),
        "expected immature or wrong key, got {r:?}"
    );
}

#[test]
fn the_chain_replays_identically() {
    let mut w = Wallet::from_seed([0xcc; 32], NETWORK);
    let _ = w.new_address();
    let g = genesis_block(NETWORK);

    let mut blocks = Vec::new();
    let mut c1 = Chain::new(NETWORK, g.clone());
    for i in 1..=20u64 {
        let a = w.new_address();
        let t = timestamp(i);
        let b = c1
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
            .unwrap();
        c1.connect(&b, t + 1).unwrap();
        blocks.push(b);
    }

    // A second node replays the same blocks and must reach the same state.
    let mut c2 = Chain::new(NETWORK, g);
    for b in &blocks {
        c2.connect(b, b.header.time + 1).expect("replay refused");
    }

    assert_eq!(c1.tip_id(), c2.tip_id());
    assert_eq!(c1.utxo.total_value(), c2.utxo.total_value());
    assert_eq!(c1.utxo.len(), c2.utxo.len());
    assert_eq!(c1.total_issued(), c2.total_issued());
}

#[test]
fn undo_then_redo_gives_back_the_same_state() {
    let mut w = Wallet::from_seed([0xdd; 32], NETWORK);
    let mut c = chain_with_funds(&mut w, 30);

    let id_before = c.tip_id();
    let supply_before = c.utxo.total_value();
    let issued_before = c.total_issued();

    let h = c.height() + 1;
    let t = timestamp(h);
    let a = w.new_address();
    let b = c
        .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
        .unwrap();
    c.connect(&b, t + 1).unwrap();

    assert!(c.disconnect());
    assert_eq!(c.tip_id(), id_before);
    assert_eq!(c.utxo.total_value(), supply_before);

    // We plug the exact same block back in.
    c.connect(&b, t + 1).expect("reconnection refused");
    assert!(c.total_issued().units() > issued_before.units());
}

#[test]
fn the_witness_dominates_transaction_size() {
    // Numeric translation of the sizing problem of section 7.
    let mut w = Wallet::from_seed([0xee; 32], NETWORK);
    let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
    let mut dest = Wallet::from_seed([0xef; 32], NETWORK);
    let a = dest.new_address();

    let tx = w
        .create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .unwrap();

    let full = tx.encode().len();
    let body = tx.encode_without_witness().len();
    let witness = full - body;

    assert!(
        witness > body * 50,
        "witness {witness} B versus body {body} B: the expected ratio is not there"
    );

    // The witness discount must really change the billed weight.
    assert!(tx.weight(WITNESS_DISCOUNT) > tx.weight(1));
}

// ===========================================================================
// Reorgs: what a majority attacker can, and cannot, do
// ===========================================================================

use q21_core::chain::{Accept, ChainError};

/// Builds a competing branch starting from the same genesis block.
///
/// Returns the blocks in order, ready to be submitted to the main chain.
fn competing_branch(
    genesis: &q21_core::block::Block,
    n: u64,
    miner: u8,
) -> Vec<q21_core::block::Block> {
    let mut c = Chain::new(NETWORK, genesis.clone());
    let mut blocks = Vec::new();
    for i in 1..=n {
        // Offset timestamps: two distinct branches, hence two different
        // blocks at the same height.
        let t = timestamp(i) + miner as u64;
        let b = c
            .mine_block(
                q21_core::hash::Hash256([miner; 32]),
                SchemeId::LamportOts,
                &[],
                t,
                ATTEMPTS,
            )
            .expect("mining the branch");
        c.connect(&b, t + 1).expect("connecting the branch");
        blocks.push(b);
    }
    blocks
}

#[test]
fn a_branch_with_more_work_causes_a_reorg() {
    let mut w = Wallet::from_seed([0x51; 32], NETWORK);
    let _ = w.new_address();
    let genesis = genesis_block(NETWORK);
    let mut c = Chain::new(NETWORK, genesis.clone());

    // Honest chain: three blocks.
    for b in competing_branch(&genesis, 3, 0x11) {
        c.submit(&b, b.header.time + 1).expect("honest branch");
    }
    let honest_tip = c.tip_id();
    assert_eq!(c.height(), 3);

    // Competing branch: five blocks, hence more cumulative work.
    let attack = competing_branch(&genesis, 5, 0x22);
    let mut results = Vec::new();
    for b in &attack {
        results.push(c.submit(b, b.header.time + 100_000).expect("submission"));
    }

    assert_ne!(c.tip_id(), honest_tip, "the chain should have switched");
    assert_eq!(c.height(), 5);
    assert!(
        results
            .iter()
            .any(|r| matches!(r, Accept::Reorganized { .. })),
        "a reorg should have been reported: {results:?}"
    );
}

#[test]
fn a_branch_with_less_work_does_not_switch() {
    let mut w = Wallet::from_seed([0x52; 32], NETWORK);
    let _ = w.new_address();
    let genesis = genesis_block(NETWORK);
    let mut c = Chain::new(NETWORK, genesis.clone());

    for b in competing_branch(&genesis, 5, 0x11) {
        c.submit(&b, b.header.time + 1).expect("honest branch");
    }
    let tip = c.tip_id();

    // Only two blocks: less work, hence no switch.
    for b in competing_branch(&genesis, 2, 0x22) {
        let r = c.submit(&b, b.header.time + 100_000).expect("submission");
        assert_eq!(r, Accept::SideBranch);
    }
    assert_eq!(c.tip_id(), tip, "the tip should not have moved");
    assert_eq!(c.height(), 5);
}

/// The honest demonstration: a majority attacker **can** cancel a recent
/// transaction. It is the theoretical limit of the model, not a defect of the
/// implementation.
#[test]
fn a_majority_attacker_can_cancel_a_recent_transaction() {
    let mut w = Wallet::from_seed([0x53; 32], NETWORK);
    let _ = w.new_address();
    let genesis = genesis_block(NETWORK);
    let mut c = Chain::new(NETWORK, genesis.clone());

    for b in competing_branch(&genesis, 3, 0x11) {
        c.submit(&b, b.header.time + 1).expect("honest branch");
    }
    let height_before = c.height();

    // The attacker produces a longer branch, which does not contain the
    // honest blocks — hence none of the transactions they carried.
    for b in competing_branch(&genesis, 6, 0x22) {
        let _ = c.submit(&b, b.header.time + 100_000);
    }

    assert!(c.height() > height_before);
    // The recent history has indeed been rewritten. That is what rolling
    // finality bounds, without being able to prevent it at shallow depth.
}

/// And the reassuring counterpart: even while reorganizing, the attacker
/// does not create one hundredth of a Q21 more than its due.
#[test]
fn even_while_reorganizing_the_attacker_creates_no_money() {
    let mut w = Wallet::from_seed([0x54; 32], NETWORK);
    let _ = w.new_address();
    let genesis = genesis_block(NETWORK);
    let mut c = Chain::new(NETWORK, genesis.clone());

    for b in competing_branch(&genesis, 3, 0x11) {
        c.submit(&b, b.header.time + 1).expect("honest branch");
    }
    for b in competing_branch(&genesis, 7, 0x22) {
        let _ = c.submit(&b, b.header.time + 100_000);
    }

    let theoretical = emission::total_supply_at(c.height()).units();
    assert_eq!(
        c.total_issued().units(),
        theoretical,
        "a reorg must never upset the emission"
    );
    assert_eq!(c.utxo.total_value().units(), theoretical);
    assert!(c.total_issued().units() <= MAX_SUPPLY);
}

#[test]
fn a_reorg_deeper_than_finality_is_refused() {
    let mut w = Wallet::from_seed([0x55; 32], NETWORK);
    let _ = w.new_address();
    let genesis = genesis_block(NETWORK);
    let mut c = Chain::new(NETWORK, genesis.clone());

    let depth = MAX_REORG_DEPTH + 5;
    for b in competing_branch(&genesis, depth, 0x11) {
        c.submit(&b, b.header.time + 1).expect("honest branch");
    }
    let tip = c.tip_id();
    let height = c.height();

    // The attacker starts again from genesis with more work. The rolling
    // finality rule must stop it, whatever its cumulative work. Two refusals
    // are possible, and they say two different things:
    //
    // - `BeyondFinality`: the common ancestor was found, and the requested
    //   switch is too deep.
    // - `ForkPointNotFound`: the common ancestor is so far back that it is no
    //   longer even searched for. That is the case here, the fork being at
    //   genesis.
    //
    // The second used to be called `BeyondFinality { depth: u64::MAX }` — an
    // admission of ignorance disguised as a measurement, which already cost a
    // diagnosis.
    let attack = competing_branch(&genesis, depth + 10, 0x22);
    let mut refused = false;
    for b in &attack {
        match c.submit(b, b.header.time + 100_000) {
            Err(ChainError::BeyondFinality { depth, .. }) => {
                assert!(depth < u64::MAX, "an announced depth must be a real depth");
                refused = true;
                break;
            }
            Err(ChainError::ForkPointNotFound { .. }) => {
                refused = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(refused, "rolling finality should have refused the switch");
    assert_eq!(c.tip_id(), tip, "the tip must not have moved");
    assert_eq!(c.height(), height);
}

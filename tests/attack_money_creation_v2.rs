//! EXECUTED ATTACK: campaign of September 22, 2026.
//!
//! We no longer read the code: we attack it. Each test plays an adversarial
//! miner who fully controls the content of a block, mines a real proof of
//! work (minimum difficulty of the regtest network), then tries to get a
//! block accepted that creates money or cheats on the work.
//!
//! The test PASSES (green) when the attack FAILS, that is, when the node
//! refuses the block for the right reason. A red test here would be a real,
//! exploitable vulnerability.

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::block::Block;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::tx::TxOut;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn timestamp(height: u64) -> u64 {
    GENESIS_TIME + height * TARGET_BLOCK_SECS
}

/// Re-mines a block after altering it: without this, the alteration would
/// invalidate the proof of work and the block would be refused for the wrong
/// reason.
fn remine(b: &mut Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let table = PowTable::build(TableParams::for_network(NETWORK), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &table, ATTEMPTS).expect("re-mining");
}

fn new_chain() -> Chain {
    Chain::new(NETWORK, genesis_block(NETWORK))
}

/// Mines an honest block at the next height.
fn honest_block(c: &Chain, h: u64) -> Block {
    let t = timestamp(h);
    c.mine_block(Hash256([7; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("honest mining")
}

// ---------------------------------------------------------------------------
// ATTACK 1: paying yourself more than the subsidy (inflated coinbase).
// ---------------------------------------------------------------------------
#[test]
fn attack_inflated_coinbase_is_refused() {
    let mut c = new_chain();
    let mut b = honest_block(&c, 1);

    // The miner doubles their reward.
    let due = b.transactions[0].outputs[0].value.units();
    b.transactions[0].outputs[0].value = Amount::from_units(due + 1_000_000_000);
    remine(&mut b);

    let r = c.connect(&b, timestamp(1) + 1);
    assert!(
        r.is_err(),
        "ATTACK SUCCEEDED: an inflated coinbase was accepted"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 2: adding a second output to the coinbase to capture more.
// ---------------------------------------------------------------------------
#[test]
fn attack_second_coinbase_output_is_refused() {
    let mut c = new_chain();
    let mut b = honest_block(&c, 1);

    b.transactions[0].outputs.push(TxOut {
        value: Amount::from_units(500_000),
        scheme: SchemeId::LamportOts,
        pubkey_hash: Hash256([42; 32]),
    });
    remine(&mut b);

    let r = c.connect(&b, timestamp(1) + 1);
    assert!(
        r.is_err(),
        "ATTACK SUCCEEDED: a coinbase with two outputs was accepted"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 3: false proof of work: we tamper without re-mining.
// ---------------------------------------------------------------------------
#[test]
fn attack_without_proof_of_work_is_refused() {
    let mut c = new_chain();
    let mut b = honest_block(&c, 1);

    // We inflate the coinbase BUT do not re-mine: the nonce is now worthless.
    let due = b.transactions[0].outputs[0].value.units();
    b.transactions[0].outputs[0].value = Amount::from_units(due + 1_000_000_000);
    b.header.merkle_root = b.compute_merkle_root();
    // no remine: the proof of work is now false.

    let r = c.connect(&b, timestamp(1) + 1);
    assert!(
        r.is_err(),
        "ATTACK SUCCEEDED: a block without a valid proof of work was accepted"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 4: announcing an easier difficulty than the consensus one.
// ---------------------------------------------------------------------------
#[test]
fn attack_false_difficulty_is_refused() {
    let mut c = new_chain();
    let mut b = honest_block(&c, 1);

    // We weaken the announced target (bits) then re-mine at that easy target.
    // The consensus target does not change: the node must refuse.
    b.header.bits = b.header.bits.wrapping_add(0x0010_0000);
    let table = PowTable::build(TableParams::for_network(NETWORK), epoch_of(b.header.height));
    b.header.merkle_root = b.compute_merkle_root();
    b.header.nonce = 0;
    let _ = pow::mine_with_table(&mut b.header, &table, ATTEMPTS);

    let r = c.connect(&b, timestamp(1) + 1);
    assert!(
        r.is_err(),
        "ATTACK SUCCEEDED: a false difficulty was accepted"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 5: coinbase without a height marker (BIP30/34 attack).
// ---------------------------------------------------------------------------
#[test]
fn attack_coinbase_without_height_is_refused() {
    let mut c = new_chain();
    let mut b = honest_block(&c, 1);

    // We erase the height marker from the coinbase signature.
    b.transactions[0].inputs[0].witness.signature = vec![0xAB; 8];
    remine(&mut b);

    let r = c.connect(&b, timestamp(1) + 1);
    assert!(
        r.is_err(),
        "ATTACK SUCCEEDED: a coinbase without a height was accepted"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 6: replaying a block from another network (wrong genesis).
// ---------------------------------------------------------------------------
#[test]
fn attack_block_from_another_network_is_refused() {
    // A block mined on testnet must not chain onto the regtest genesis.
    let ct = Chain::new(Network::Testnet, genesis_block(Network::Testnet));
    let t = timestamp(1);
    let b_testnet = ct
        .mine_block(Hash256([7; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("testnet mining");

    let mut c = new_chain();
    let r = c.connect(&b_testnet, t + 1);
    assert!(
        r.is_err(),
        "ATTACK SUCCEEDED: a block from another network was accepted"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 7: fees must not count as new money.
// Accounting check: after an honest chain, the cumulative emission matches
// the schedule exactly, never more.
// ---------------------------------------------------------------------------
#[test]
fn attack_accounting_emission_follows_the_schedule() {
    let mut c = new_chain();
    for h in 1..=30 {
        let b = honest_block(&c, h);
        c.connect(&b, timestamp(h) + 1).expect("honest connect");
    }
    // The money actually issued (genesis included) must equal, to the last
    // unit, the official schedule. One unit more would be inflation.
    let issued = c.total_issued().units();
    let expected = q21_core::emission::total_supply_at(30).units();
    assert_eq!(
        issued, expected,
        "ACCOUNTING DIVERGENCE: issued={issued} expected={expected}; money appeared or disappeared"
    );
    assert!(
        issued <= MAX_SUPPLY,
        "CAP EXCEEDED: {issued} > {MAX_SUPPLY}"
    );
}

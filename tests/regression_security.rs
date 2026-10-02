//! Regression tests from the phase 8 adversarial audit.
//!
//! Every test in this file first existed as an **exploit**, written by an
//! auditor who was trying to break Q21, and who succeeded. The test was then
//! turned around: it now checks that the attack fails.
//!
//! A fix without the test that comes with it is not a fix: it is a bet that
//! no one will reintroduce the defect.

use q21_core::address::Network;
use q21_core::block::{Block, BlockHeader};
use q21_core::chain::{genesis_block, Chain, ChainError, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::emission::block_subsidy;
use q21_core::hash::Hash256;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow::{self, PowEngine, Q21Pow};
use q21_core::sig::SchemeId;
use q21_core::validate::{self, BlockContext, ValidationError};
use std::collections::{HashMap, HashSet};

const NETWORK: Network = Network::Regtest;

/// In-memory body provider: plays the role of the block file.
struct ChainBodies(HashMap<Hash256, Block>);
impl q21_core::chain::BodySource for ChainBodies {
    fn body(&self, id: &Hash256) -> Option<Block> {
        self.0.get(id).cloned()
    }
}
const ATTEMPTS: u64 = 50_000_000;

fn timestamp(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn remine(b: &mut Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let t = PowTable::build(TableParams::for_network(NETWORK), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &t, ATTEMPTS).expect("re-mining");
}

fn chain(n: u64) -> Chain {
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=n {
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }
    c
}

/// Uncle header fabricated without any computation: near-maximal target,
/// nonce at zero. This is exactly what the audit exploited.
fn fake_uncle(prev: Hash256, uncle_height: u64, salt: u8) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: prev,
        merkle_root: Hash256([salt; 32]),
        uncles_root: Hash256::ZERO,
        miner: Hash256([0xaa; 32]),
        time: timestamp(uncle_height),
        bits: 0x2100_ffff,
        height: uncle_height,
        nonce: 0,
    }
}

/// A chain of height `n`, plus an **authentic** uncle at height `n`: a real
/// block, actually mined, that lost the propagation race.
///
/// We mine two competing blocks on the same parent, connect one of them, and
/// the other becomes the orphan that the next block could claim.
fn chain_with_uncle(n: u64) -> (Chain, BlockHeader) {
    let mut c = chain(n - 1);
    let t = timestamp(n);

    let loser = c
        .mine_block(Hash256([0xbb; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining the loser");
    let winner = c
        .mine_block(Hash256([0x2a; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining the winner");
    assert_ne!(loser.header.block_id(), winner.header.block_id());

    c.connect(&winner, t + 1).expect("connecting the winner");
    (c, loser.header)
}

// ---------------------------------------------------------------------------
// 1. An uncle must carry the difficulty of its height
// ---------------------------------------------------------------------------

/// The original exploit: `pow.check(uncle)` validated the work against
/// `uncle.bits`, a field that its author fills in. With a near-maximal
/// target, a header with a zero nonce passed, and got paid.
/// Since the mechanism was removed, **every** uncle is refused, the authentic
/// one as well as the forged one. The validation surface that had carried
/// three defects can no longer be reached.
#[test]
fn every_uncle_is_refused_authentic_and_forged_alike() {
    // An authentic uncle: real work, on a real branch.
    let (mut c, authentic) = chain_with_uncle(4);
    let height = c.height() + 1;
    let t = timestamp(height);
    let b = c
        .mine_block_with_uncles(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            &[authentic],
            t,
            ATTEMPTS,
        )
        .expect("mining");
    assert!(
        matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::TooManyUncles { max: 0, .. })
        ),
        "an authentic uncle must be refused like the others"
    );

    // A forged uncle: target chosen by the attacker, no work.
    let parent = c.tip_id();
    let forged = fake_uncle(parent, height - 1, 0);
    // Since red-team 8b, the difficulty floor is applied INSIDE the work
    // function: the easy target chosen by the attacker (0x2100_ffff, easier
    // than INITIAL_BITS) is now refused by `check` itself, in addition to
    // being refused by the uncle rule below.
    assert_eq!(
        Q21Pow::new(NETWORK).check(&forged),
        Err(pow::PowError::TargetTooEasy),
        "the floor must refuse the attacker's easy target"
    );
    let b = c
        .mine_block_with_uncles(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            &[forged],
            t,
            ATTEMPTS,
        )
        .expect("mining");
    assert!(matches!(
        c.connect(&b, t + 1),
        Err(ValidationError::TooManyUncles { max: 0, .. })
    ));
}

// ---------------------------------------------------------------------------
// 2. A block issues exactly its subsidy, uncles included
// ---------------------------------------------------------------------------

/// The most serious flaw of the audit: the uncle shares were **added** to the
/// subsidy. A block could issue 210% of what it was due, and the protocol's
/// real maximum emission came to 44,099,999 Q21.
#[test]
fn a_block_issues_exactly_its_subsidy_even_with_uncles() {
    for n_uncles in 0..=MAX_UNCLES {
        let r = validate::uncle_rewards(1_000, n_uncles);
        let total = r.miner_share + r.per_uncle * n_uncles as u64;
        assert_eq!(
            total,
            block_subsidy(1_000).units(),
            "with {n_uncles} uncle(s), the total issued must remain the subsidy"
        );
    }
}

/// The same property, measured on a real chain.
#[test]
fn actual_emission_never_exceeds_the_subsidy() {
    let mut c = chain(4);

    let height = c.height() + 1;
    let before = c.total_issued().units();
    let t = timestamp(height);
    let b = c
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining");
    c.connect(&b, t + 1).expect("connect");

    let issued = c.total_issued().units() - before;
    assert_eq!(
        issued,
        block_subsidy(height).units(),
        "a block issued {issued} instead of its subsidy"
    );
}

// ---------------------------------------------------------------------------
// 3. The absolute cap
// ---------------------------------------------------------------------------

/// The last line of defense: whatever the emission schedule and the uncles
/// claim, no block can bring the cumulative emission beyond 21,000,001 Q21.
#[test]
fn no_block_crosses_the_absolute_cap() {
    let c = chain(2);
    let height = c.height() + 1;
    let t = timestamp(height);
    let b = c
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining");

    let emission = b.transactions[0].total_output().unwrap().units();
    assert!(emission > 0);

    let times: Vec<u64> = vec![t - 1];
    let anc: Vec<Hash256> = vec![c.tip_id()];
    let claimed: HashSet<Hash256> = HashSet::new();
    let mut bits = HashMap::new();
    bits.insert(c.tip_id(), INITIAL_BITS);

    // Just under the cap: the block passes.
    let ctx_ok = BlockContext {
        network: NETWORK,
        height,
        prev_id: c.tip_id(),
        recent_times: &times,
        expected_bits: INITIAL_BITS,
        now: t + 1,
        ancestors: &anc,
        claimed_uncles: &claimed,
        uncle_expected_bits: &bits,
        cumulative_issued: MAX_SUPPLY - emission,
    };
    assert!(
        validate::check_block(&b, &c.utxo, &ctx_ok, &Q21Pow::new(NETWORK)).is_ok(),
        "the block that reaches exactly the cap must pass"
    );

    // A single satoshi more: refused.
    let ctx_ko = BlockContext {
        cumulative_issued: MAX_SUPPLY - emission + 1,
        ..ctx_ok
    };
    match validate::check_block(&b, &c.utxo, &ctx_ko, &Q21Pow::new(NETWORK)) {
        Err(ValidationError::CapExceeded { cap, .. }) => {
            assert_eq!(cap, MAX_SUPPLY);
        }
        other => panic!("the cap must be impossible to cross: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Uniqueness of coinbase identifiers (BIP 30 / BIP 34)
// ---------------------------------------------------------------------------

/// Two coinbases from the same miner, for the same amount, produced the same
/// `txid`. The second overwrote the first in the UTXO set, and undoing it
/// destroyed the output of the first: two honest nodes ended up with the
/// same tip and different balances.
#[test]
fn two_coinbases_at_different_heights_have_different_identifiers() {
    let mut c = chain(3);
    let mut seen: HashSet<Hash256> = HashSet::new();

    for _ in 0..5 {
        let height = c.height() + 1;
        let t = timestamp(height);
        // Same payee, same claimed amount: everything is identical except the
        // height, which is now committed to in the identifier.
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        let txid = b.transactions[0].txid();
        assert!(
            seen.insert(txid),
            "two coinbases share the identifier {txid}: BIP 30 is open"
        );
        c.connect(&b, t + 1).expect("connect");
    }
}

/// And the rule that guarantees this uniqueness is checked, not hoped for.
#[test]
fn a_coinbase_without_height_is_refused() {
    let mut c = chain(2);
    let height = c.height() + 1;
    let t = timestamp(height);
    let mut b = c
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining");

    b.transactions[0].inputs[0].witness.signature = b"not the height".to_vec();
    remine(&mut b);

    assert!(matches!(
        c.connect(&b, t + 1),
        Err(ValidationError::CoinbaseWithoutHeight)
    ));
}

// ---------------------------------------------------------------------------
// 5. A side branch must cost work
// ---------------------------------------------------------------------------

/// Without a difficulty check, `submit` indexed headers fabricated with a
/// near-maximal target: memory exhausted for free, and eviction of the
/// bodies that reorgs depend on.
#[test]
fn a_side_branch_without_work_is_refused() {
    let mut c = chain(5);
    // We fork from an old block: this is the "side branch" path of `submit`,
    // the one the attack exploited.
    let parent = c.active_at(2).expect("ancestor");
    let height = 3;
    let known_before = c.known_blocks();

    for k in 0..50u8 {
        let header = BlockHeader {
            version: 1,
            prev_block: parent,
            merkle_root: Hash256([k; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([0xcc; 32]),
            time: timestamp(height),
            bits: 0x2100_ffff,
            height,
            nonce: u64::from(k),
        };
        let block = Block {
            header,
            transactions: vec![],
            uncles: vec![],
        };
        assert!(
            matches!(
                c.submit(&block, timestamp(height) + 1),
                Err(ChainError::Validation(
                    ValidationError::BadDifficulty { .. }
                ))
            ),
            "a branch without work must never enter the index"
        );
    }
    assert_eq!(
        c.known_blocks(),
        known_before,
        "the index grew despite the refusal"
    );
}

/// A body that does not match its header must never be stored.
///
/// `check_block` (shape, size, Merkle roots) only ran on the connect path. A
/// side branch therefore entered the index **and the disk** with a header
/// carrying authentic work but an arbitrary body: the node stored that body,
/// then **served it to its peers**. Bitcoin applies `CheckBlock` to every
/// block before storing it; Q21 strictly deferred more.
#[test]
fn an_inconsistent_body_does_not_enter_the_index_on_a_side_branch() {
    let mut c = chain(5);

    // A sister chain that shares the first two blocks, to produce an
    // authentic block at height 3 on a side branch.
    let c2 = chain(2);
    let t = timestamp(3);
    let mut block = c2
        .mine_block(Hash256([0x33; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining the sibling");

    // The header stays authentic: right difficulty, real work. Only the body
    // is replaced, so the Merkle root no longer covers it.
    block.transactions.clear();

    let known_before = c.known_blocks();
    assert!(
        c.submit(&block, t + 1).is_err(),
        "a body that does not match its header must never be stored"
    );
    assert_eq!(
        c.known_blocks(),
        known_before,
        "the index grew despite an inconsistent body"
    );
}

/// A branch that can **never** be adopted must not be retained.
///
/// Rolling finality already refuses any reorg whose fork point is more than
/// `MAX_REORG_DEPTH` below the tip. But admission accepted these branches: it
/// indexed them, kept their body and recorded them in the journal, forever,
/// since the index is never pruned.
///
/// That was the denial-of-service lever: the floor difficulty of the first
/// blocks makes a sibling of the genesis almost free, and nothing bounded the
/// number of siblings retained. A few hundred hashes bought a permanent entry
/// in memory **and** a record on disk.
#[test]
fn a_branch_beyond_finality_reach_is_refused() {
    // A chain long enough for the genesis to leave the window.
    let mut c = chain(MAX_REORG_DEPTH + 5);

    // An authentic sibling of block 2, forking at the very bottom.
    let c2 = chain(1);
    let t = timestamp(2);
    let block = c2
        .mine_block(Hash256([0x44; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining the sibling");

    let known_before = c.known_blocks();
    assert!(
        matches!(
            c.submit(&block, timestamp(MAX_REORG_DEPTH + 6)),
            Err(ChainError::BeyondFinality { .. })
        ),
        "a branch beyond finality reach must not enter the index"
    );
    assert_eq!(
        c.known_blocks(),
        known_before,
        "the index grew for a branch that can never win"
    );
}

// ---------------------------------------------------------------------------
// 6. `disconnect` corrupts nothing when it refuses
// ---------------------------------------------------------------------------

/// The faulty version overwrote the emission counter **before** noticing that
/// no undo data was available.
#[test]
fn a_refused_disconnect_touches_nothing() {
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    let issued_before = c.total_issued();
    let height_before = c.height();
    let utxo_before = c.utxo.clone();

    // At the genesis, there is nothing to undo.
    assert!(!c.disconnect());

    assert_eq!(c.total_issued(), issued_before, "emission modified");
    assert_eq!(c.height(), height_before, "height modified");
    assert_eq!(c.utxo, utxo_before, "UTXO set modified");
}

// ---------------------------------------------------------------------------
// 7. No infinite reorg loop
// ---------------------------------------------------------------------------

/// `try_reorg` discarded the return value of `disconnect`. After a resume
/// from a state snapshot, the restore loop never made progress and the node
/// spun forever, holding the chain lock.
///
/// The test runs in a separate thread with a timeout: if it loops, it fails.
#[test]
fn an_impossible_reorg_fails_instead_of_looping() {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // A node that has just resumed from a state snapshot: its undo window
        // only covers what it has replayed.
        let full = chain(6);
        let snapshot = full.snapshot_at_depth(1).expect("snapshot");
        let headers: Vec<BlockHeader> = (0..=full.height())
            .filter_map(|h| full.active_at(h))
            .filter_map(|id| full.header_of(&id))
            .collect();
        let r = Chain::from_snapshot(NETWORK, snapshot, &headers).expect("resume");
        let mut c = r.chain;
        // Like a real node: the old bodies remain readable on disk.
        c.set_body_source(std::sync::Arc::new(ChainBodies(
            (0..=full.height())
                .filter_map(|h| full.active_at(h))
                .filter_map(|id| full.block_by_id(&id).map(|b| (id, b)))
                .collect(),
        )));
        for id in &r.to_replay {
            let b = full.block_by_id(id).expect("body");
            c.connect(&b, b.header.time + 1).expect("replay");
        }
        assert_eq!(c.undo_window(), 1, "undo window of a single block");

        // The competing branch must be made of **authentic** blocks: since
        // admission applies `check_shape`, a body without a coinbase would be
        // discarded on its shape and would never reach `try_reorg`, the loop
        // we want to exercise here. So we mine a real sister chain that forks
        // at height 3 and takes the lead.
        let parent = c.active_at(3).expect("ancestor");
        let mut sister = chain(3);
        assert_eq!(
            sister.tip_id(),
            parent,
            "the sister must share the first three blocks"
        );

        let mut branch = Vec::new();
        for h in 4..=8u64 {
            let t = timestamp(h);
            let b = sister
                .mine_block(Hash256([0xdd; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
                .expect("mining the branch");
            sister.connect(&b, t + 1).expect("connecting the branch");
            branch.push(b);
        }

        let mut refused = false;
        for b in &branch {
            if let Err(e) = c.submit(b, timestamp(9)) {
                refused = matches!(e, ChainError::UndoWindowTooShort { .. });
            }
        }
        let _ = sender.send(refused);
    });

    match receiver.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(refused) => assert!(
            refused,
            "the impossible reorg should have been refused explicitly"
        ),
        Err(_) => panic!("try_reorg loops forever: the thread never returned"),
    }
}

// ---------------------------------------------------------------------------
// 8. An uncle already paid stays paid after a restart from a state snapshot
// ---------------------------------------------------------------------------

/// The anti-double-payment rule read the block bodies **in memory**. After a
/// resume from a state snapshot they are absent: the set of already claimed
/// uncles was incomplete, and a freshly restarted node accepted what a full
/// node refused. Two honest nodes, two verdicts: a chain split.
/// A node resumed from a state snapshot returns the same verdict as a full
/// node when facing a block that carries an uncle. This is where the old
/// mechanism had made two honest nodes diverge; the refusal must be
/// identical on both sides, whatever each one has in memory.
#[test]
fn a_resumed_node_refuses_an_uncle_like_a_full_node() {
    let (mut full, uncle) = chain_with_uncle(4);
    let t5 = timestamp(5);
    let b5 = full
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t5, ATTEMPTS)
        .expect("mining");
    full.connect(&b5, t5 + 1).expect("connect");
    let t6 = timestamp(6);
    let b6 = full
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t6, ATTEMPTS)
        .expect("mining");
    full.connect(&b6, t6 + 1).expect("connect");

    let t7 = timestamp(7);
    let with_uncle = full
        .mine_block_with_uncles(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            &[uncle],
            t7,
            ATTEMPTS,
        )
        .expect("mining");
    assert!(matches!(
        full.connect(&with_uncle, t7 + 1),
        Err(ValidationError::TooManyUncles { .. })
    ));

    // A node resumed from a state snapshot must return the SAME verdict.
    let snapshot = full.snapshot_at_depth(1).expect("snapshot");
    let headers: Vec<BlockHeader> = (0..=full.height())
        .filter_map(|h| full.active_at(h))
        .filter_map(|id| full.header_of(&id))
        .collect();
    let r = Chain::from_snapshot(NETWORK, snapshot, &headers).expect("resume");
    let mut resumed = r.chain;
    resumed.set_body_source(std::sync::Arc::new(ChainBodies(
        (0..=full.height())
            .filter_map(|h| full.active_at(h))
            .filter_map(|id| full.block_by_id(&id).map(|b| (id, b)))
            .collect(),
    )));
    for id in &r.to_replay {
        let b = full.block_by_id(id).expect("body");
        resumed.connect(&b, b.header.time + 1).expect("replay");
    }
    assert_eq!(resumed.height(), full.height());

    match resumed.connect(&with_uncle, t7 + 1) {
        Err(ValidationError::TooManyUncles { .. }) => {}
        other => panic!(
            "a resumed node returned a different verdict from a full node: {other:?}; \
             this is exactly how a chain splits"
        ),
    }
}

// ---------------------------------------------------------------------------
// 9. The number of transactions per block is derived, not set by hand
// ---------------------------------------------------------------------------

/// The bound was 500,000, chosen arbitrarily: a three-megabyte compact
/// announcement triggered an allocation of several tens of megabytes. It now
/// follows from the maximum block size.
#[test]
fn the_number_of_transactions_per_block_is_bounded_by_the_block_size() {
    assert_eq!(MAX_TX_PER_BLOCK, MAX_BLOCK_SIZE / MIN_TX_SIZE);
    // Checked at compile time: these are invariants on constants, not
    // observations at run time.
    const _: () = assert!(MAX_TX_PER_BLOCK * MIN_TX_SIZE <= MAX_BLOCK_SIZE);
    // The allocation an adversary can trigger stays of the same order as what
    // they send: six bytes of short identifier per announced entry.
    const _: () = assert!(MAX_TX_PER_BLOCK <= 100_000);
}

// ---------------------------------------------------------------------------
// 9. Dust is refused, coinbase included
// ---------------------------------------------------------------------------

/// Creating an output cost nothing: no value floor, and no charge beyond one
/// unit per thousand weight units. A block full of tiny outputs imposed
/// twenty gigabytes of RAM per day on every node, for a few thousand units.
/// And a miner, who pays their own fees to themselves, was held back by
/// nothing.
///
/// The floor [`MIN_OUTPUT_VALUE`] is a consensus rule, applied to ordinary
/// transactions as well as to the coinbase. Here, a miner splits their reward
/// into a dust output: the block is refused; the same reward split above the
/// floor passes.
#[test]
fn a_coinbase_that_scatters_dust_is_refused() {
    let mut c = chain(2);
    let height = c.height() + 1;
    let t = timestamp(height);
    let b = c
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .expect("mining");
    let reward = b.transactions[0].outputs[0].value.units();
    assert!(reward > 2 * MIN_OUTPUT_VALUE, "fixture: reward too low");

    // A dust output, taken from the reward.
    let mut dust = b.clone();
    let main_output = &mut dust.transactions[0].outputs[0];
    main_output.value = q21_core::amount::Amount::from_units(reward - (MIN_OUTPUT_VALUE - 1));
    let template = *main_output;
    dust.transactions[0].outputs.push(q21_core::tx::TxOut {
        value: q21_core::amount::Amount::from_units(MIN_OUTPUT_VALUE - 1),
        ..template
    });
    remine(&mut dust);
    assert!(
        matches!(
            c.connect(&dust, t + 1),
            Err(ValidationError::DustOutput { .. })
        ),
        "an output below the floor must get the block refused"
    );
}

/// The same floor for an ordinary transaction: a payment one unit below the
/// floor is refused by validation, a payment at the floor passes. And the
/// wallet never returns dust change: when the remainder falls below the
/// floor, it goes to the fees.
#[test]
fn a_dust_payment_is_refused_and_dust_change_goes_to_fees() {
    use q21_core::amount::Amount;
    use q21_core::wallet::Wallet;

    let mut w = Wallet::from_seed([0x77; 32], NETWORK);
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    let mine_range = |c: &mut Chain, w: &mut Wallet, from: u64, to: u64| {
        for i in from..=to {
            let address = w.new_address();
            let t = timestamp(i);
            let b = c
                .mine_block(address.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
        }
    };
    // A single mature coin to start with: the one from block 1.
    mine_range(&mut c, &mut w, 1, COINBASE_MATURITY + 1);
    let mut dest = Wallet::from_seed([0x78; 32], NETWORK);
    let a = dest.new_address();
    let fee = Amount::from_units(1_000);

    let validate_tx = |c: &Chain, tx: &q21_core::tx::Transaction| {
        let mut seen = HashSet::new();
        validate::check_transaction(tx, &c.utxo, NETWORK, c.height() + 1, &mut seen)
    };

    // 1. Dust change: an amount that leaves, on the single mature coin, a
    //    remainder one unit below the floor. It must go to the fees, not into
    //    an output.
    let coins = w.spendable(&c.utxo, c.height());
    assert_eq!(coins.len(), 1, "fixture: a single mature coin expected");
    let coin = coins[0].1.value.units();
    let amount = coin - fee.units() - (MIN_OUTPUT_VALUE - 1);
    let tx = w
        .create_transaction(&c.utxo, c.height(), &a, Amount::from_units(amount), fee)
        .expect("building");
    let f = validate_tx(&c, &tx).expect("valid");
    assert_eq!(
        tx.outputs.len(),
        1,
        "no change output below the floor must be created"
    );
    assert_eq!(
        f.units(),
        fee.units() + (MIN_OUTPUT_VALUE - 1),
        "the remainder below the floor goes to the fees"
    );

    // Two more coins (blocks 2 and 3): each build consumes the one-time key
    // of the coin it spends.
    mine_range(&mut c, &mut w, COINBASE_MATURITY + 2, COINBASE_MATURITY + 3);

    // 2. A payment one unit below the floor: the wallet refuses before
    //    signing; it does not burn a key for a transaction that the network
    //    will reject.
    let r = w.create_transaction(
        &c.utxo,
        c.height(),
        &a,
        Amount::from_units(MIN_OUTPUT_VALUE - 1),
        fee,
    );
    assert!(matches!(
        r,
        Err(q21_core::wallet::WalletError::AmountBelowFloor { .. })
    ));

    // 3. At the floor: legitimate. And if dust is forced into a signed
    //    transaction, validation refuses it **before** even looking at the
    //    signature; the cheap check comes first.
    let at_floor = w
        .create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(MIN_OUTPUT_VALUE),
            fee,
        )
        .expect("building");
    validate_tx(&c, &at_floor).expect("a payment at the floor is legitimate");
    let mut forced = at_floor.clone();
    forced.outputs[0].value = Amount::from_units(MIN_OUTPUT_VALUE - 1);
    assert!(matches!(
        validate_tx(&c, &forced),
        Err(ValidationError::DustOutput { .. })
    ));
}

// ---------------------------------------------------------------------------
// 10. A side branch respects the timestamp rules
// ---------------------------------------------------------------------------

/// The timestamp checks (median of the eleven ancestors, tolerance toward the
/// future) only applied at connect time. A side branch could therefore carry
/// very spread-out timestamps, lower the LWMA difficulty along its branch,
/// and cheaply produce bodies that the node kept and served. The same block,
/// with an acceptable timestamp, enters normally.
#[test]
fn a_side_branch_with_an_out_of_bounds_timestamp_is_refused() {
    let mut c = chain(12);
    let parent = c.active_at(8).expect("ancestor");
    let height = 9;
    let now = timestamp(13);
    let known_before = c.known_blocks();

    let bits = c.next_bits_after(parent);
    let block_with = |time: u64, salt: u8| {
        let mut b = Block {
            header: BlockHeader {
                version: 1,
                prev_block: parent,
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: Hash256([0xcc; 32]),
                time,
                bits,
                height,
                nonce: 0,
            },
            transactions: vec![q21_core::tx::Transaction {
                version: 1,
                inputs: vec![q21_core::tx::TxIn::coinbase(
                    [height.to_le_bytes().as_slice(), &[salt]].concat(),
                )],
                outputs: vec![q21_core::tx::TxOut {
                    value: q21_core::amount::Amount::from_units(MIN_OUTPUT_VALUE),
                    scheme: SchemeId::LamportOts,
                    pubkey_hash: Hash256([0xcc; 32]),
                }],
                lock_time: 0,
            }],
            uncles: vec![],
        };
        remine(&mut b);
        b
    };

    // Too far in the future.
    let future = block_with(now + MAX_FUTURE_TIME + 1, 1);
    assert!(
        matches!(
            c.submit(&future, now),
            Err(ChainError::Validation(
                ValidationError::TimestampInFuture { .. }
            ))
        ),
        "a side branch in the future must not enter the index"
    );

    // No later than the median of its ancestors.
    let old = block_with(timestamp(3), 2);
    assert!(
        matches!(
            c.submit(&old, now),
            Err(ChainError::Validation(
                ValidationError::TimestampTooOld { .. }
            ))
        ),
        "a side branch older than the median must not enter the index"
    );
    assert_eq!(
        c.known_blocks(),
        known_before,
        "the index grew despite the refusal"
    );

    // The same block, at an acceptable date: an ordinary side branch.
    let good = block_with(timestamp(height) + 30, 3);
    assert!(
        matches!(
            c.submit(&good, now),
            Ok(q21_core::chain::Accept::SideBranch)
        ),
        "an acceptable timestamp must enter as a side branch"
    );
}

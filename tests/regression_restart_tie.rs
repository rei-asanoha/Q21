//! A node that restarts during a tie of equal work keeps its payments.
//!
//! In the load test of 25 October 2026, a node stopped on one of two blocks of
//! equal work came back on the other: the rebuild of the block tree took the
//! smallest id, a running node keeps the first one seen. No reorganization
//! happened, so the transactions of the block it left went back nowhere, 1502
//! saved payments chained on them were dropped at the reload, and the wallet
//! spent their coins a second time.
//!
//! The start now keeps the tip the node stopped on, and treats any other tip
//! change as a reorganization: the left blocks' transactions go back to the
//! pool before the saved pool is reloaded.

#![cfg(feature = "mldsa")]

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::block::Block;
use q21_core::chain::{genesis_block, Chain};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::mempool::Mempool;
use q21_core::sig::SchemeId;
use q21_core::state::StateStore;
use q21_core::store::{BlockArchive, HeaderStore};
use q21_core::tx::Transaction;
use q21_core::wallet::Wallet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const NET: Network = Network::Regtest;
const TRIES: u64 = 5_000_000;
const BURN: Hash256 = Hash256([2u8; 32]);

fn test_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("q21-restart-tie-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn state_store_in(d: &Path) -> StateStore {
    StateStore::new_sealed(d.join("state.dat"), [3u8; 32])
}

/// Mines the next block of `c` paying `to`, with `txs`; connects it.
fn mine(c: &mut Chain, to: Hash256, scheme: SchemeId, txs: &[Transaction]) -> Block {
    let t = c.tip().time + TARGET_BLOCK_SECS;
    let b = c.mine_block(to, scheme, txs, t, TRIES).expect("mining");
    c.connect(&b, t + 1).expect("connect");
    b
}

/// What the node held when it stopped, during a tie.
struct Stopped {
    dir: PathBuf,
    wallet: Wallet,
    /// The coin `pay` spent, confirmed only in `left`.
    coin: q21_core::tx::OutPoint,
    /// The block the node was on: it holds `pay`.
    left: Hash256,
    /// A rival block of equal work, with a smaller id.
    rival: Hash256,
    /// The saved pool: a payment chained on `pay`'s change.
    saved: Vec<Transaction>,
    pay: Transaction,
    /// The rival branch, to extend it.
    rival_chain: Chain,
}

/// Builds the files of a node stopped on `left` while `rival` ties with it.
fn stopped_during_a_tie(name: &str) -> Stopped {
    let dir = test_dir(name);
    let (archive, _, _) = BlockArchive::open(dir.join("blocks.dat"), NET).unwrap();
    archive.append(&genesis_block(NET)).unwrap();

    // One coin for the wallet, mature, then a common history.
    let mut w = Wallet::from_seed_scheme([0x41; 32], NET, SchemeId::MlDsa87).unwrap();
    let mut c = Chain::new(NET, genesis_block(NET));
    let mut rival_chain = Chain::new(NET, genesis_block(NET));
    let a = w.new_address();
    let mut base = vec![mine(&mut c, a.hash, a.scheme, &[])];
    for _ in 0..(COINBASE_MATURITY + 2) {
        base.push(mine(&mut c, BURN, SchemeId::LamportOts, &[]));
    }
    for b in &base {
        archive.append(b).unwrap();
        rival_chain.connect(b, b.header.time + 1).unwrap();
    }

    // A payment, confirmed in the block the node ends up on.
    let other = Wallet::from_seed([0x42; 32], NET).new_address();
    let prepared = w
        .prepare_spend(
            &c.utxo,
            c.height(),
            &[(other, Amount::from_units(20_000))],
            Amount::from_units(2_000),
        )
        .unwrap();
    let pay = w.sign_spend(&c.utxo, prepared).unwrap();
    let coin = pay.inputs[0].prev_out;

    // The block the node ends up on (`left`, holding `pay`) and a rival at the
    // same height and of the same work, with a smaller id: the rule without a
    // record picks it. Block ids are random below the target, so candidates
    // for both are drawn in turn until a pair is in that order. Searching on
    // one side only can take arbitrarily long when the other side's id
    // happens to be very small; with both sides drawn, the chance of no such
    // pair after 16 rounds is about one in a hundred million.
    let base_time = c.tip().time + TARGET_BLOCK_SECS;
    let mut lefts: Vec<Block> = Vec::new();
    let mut rivals: Vec<Block> = Vec::new();
    let mut chosen = None;
    for round in 0..16u64 {
        lefts.push(
            c.mine_block(
                BURN,
                SchemeId::LamportOts,
                std::slice::from_ref(&pay),
                base_time + round,
                TRIES,
            )
            .expect("mining"),
        );
        let mut payee = [3u8; 32];
        payee[..8].copy_from_slice(&round.to_le_bytes());
        rivals.push(
            rival_chain
                .mine_block(
                    Hash256(payee),
                    SchemeId::LamportOts,
                    &[],
                    base_time + round,
                    TRIES,
                )
                .expect("mining"),
        );
        let top = lefts.iter().max_by_key(|b| b.header.block_id()).unwrap();
        let low = rivals.iter().min_by_key(|b| b.header.block_id()).unwrap();
        if low.header.block_id() < top.header.block_id() {
            chosen = Some((top.clone(), low.clone()));
            break;
        }
    }
    let (left, rival) = chosen.expect("no rival with a smaller id in 16 rounds");
    c.connect(&left, left.header.time + 1).expect("connect");
    rival_chain
        .connect(&rival, rival.header.time + 1)
        .expect("connect");
    archive.append(&left).unwrap();
    archive.append(&rival).unwrap();

    // The saved pool: a payment spending the change confirmed in `left`.
    let prepared = w
        .prepare_spend(
            &c.utxo,
            c.height(),
            &[(other, Amount::from_units(10_000))],
            Amount::from_units(2_000),
        )
        .unwrap();
    let child = w.sign_spend(&c.utxo, prepared).unwrap();
    assert!(
        child.inputs.iter().any(|i| i.prev_out.txid == pay.txid()),
        "the saved payment spends the change of the confirmed one"
    );
    let mut pool = Mempool::new();
    pool.accept_local(&child, &c.utxo, NET, c.height()).unwrap();

    state_store_in(&dir)
        .save(&c.snapshot_at_depth(5).expect("snapshot"))
        .unwrap();
    Stopped {
        dir,
        wallet: w,
        coin,
        left: left.header.block_id(),
        rival: rival.header.block_id(),
        saved: pool.ordered_transactions(),
        pay,
        rival_chain,
    }
}

/// The node's start: chain from the files keeping `last_tip`, then the left
/// blocks' transactions and the saved pool back in a fresh pool.
fn restart(s: &Stopped, last_tip: Option<Hash256>) -> (Chain, Mempool, (usize, usize)) {
    let (archive, headers, _) = BlockArchive::open(s.dir.join("blocks.dat"), NET).unwrap();
    let archive = Arc::new(archive);
    let chain = q21_core::pruning::resume_chain_preferring(
        NET,
        &archive,
        headers,
        &HeaderStore::new(s.dir.join("headers.dat")),
        &state_store_in(&s.dir),
        last_tip,
    )
    .expect("restart");
    let abandoned = match last_tip {
        Some(t) if t != chain.tip_id() => chain.abandoned_since(&t, &|id| archive.read(id)),
        _ => Vec::new(),
    };
    let mut pool = Mempool::new();
    let counts = pool.restore_at_startup(
        &abandoned,
        &s.saved,
        &|_| true,
        &chain.utxo,
        NET,
        chain.height(),
    );
    (chain, pool, counts)
}

/// Stopped during a tie, the node comes back on the tip it was on, and every
/// saved payment is back in its pool.
#[test]
fn a_restart_during_a_tie_keeps_the_tip_and_every_saved_payment() {
    let s = stopped_during_a_tie("keep");
    assert!(s.rival < s.left, "the rival wins on the id alone");
    let (chain, pool, (_, restored)) = restart(&s, Some(s.left));
    assert_eq!(chain.tip_id(), s.left, "the node left the tip it was on");
    assert_eq!(
        restored,
        s.saved.len(),
        "saved payments were dropped at the reload"
    );
    assert_eq!(pool.len(), s.saved.len());
    let _ = std::fs::remove_dir_all(&s.dir);
}

/// When the tip does change at startup — here the rival branch has grown
/// heavier — the left block's transactions go back to the pool, and the saved
/// payments chained on them with them.
#[test]
fn a_tip_change_at_startup_gives_the_left_block_back_to_the_pool() {
    let mut s = stopped_during_a_tie("change");
    let longer = mine(&mut s.rival_chain, BURN, SchemeId::LamportOts, &[]);
    {
        let (archive, _, _) = BlockArchive::open(s.dir.join("blocks.dat"), NET).unwrap();
        archive.append(&longer).unwrap();
    }
    let (chain, pool, (returned, restored)) = restart(&s, Some(s.left));
    assert_eq!(chain.tip_id(), longer.header.block_id());
    assert_eq!(returned, 1, "the left block's payment is back");
    assert!(pool.contains(&s.pay.txid()));
    assert_eq!(
        restored,
        s.saved.len(),
        "saved payments chained on the left block were dropped"
    );
    let _ = std::fs::remove_dir_all(&s.dir);
}

/// After a tip change at startup, the wallet does not take back as spendable
/// a coin a payment of the left block spent: that payment is in the pool
/// again, and the next send would double-spend it.
#[test]
fn after_a_tip_change_at_startup_the_wallet_does_not_spend_a_coin_twice() {
    let mut s = stopped_during_a_tie("wallet");
    let longer = mine(&mut s.rival_chain, BURN, SchemeId::LamportOts, &[]);
    {
        let (archive, _, _) = BlockArchive::open(s.dir.join("blocks.dat"), NET).unwrap();
        archive.append(&longer).unwrap();
    }
    let (chain, pool, _) = restart(&s, Some(s.left));
    assert!(
        chain.utxo.contains(&s.coin),
        "on the new tip the coin is unspent on chain"
    );
    // As the RPC sends: what the pool spends is avoided.
    let to = Wallet::from_seed([0x43; 32], NET).new_address();
    let next = s.wallet.prepare_spend_avoiding(
        &chain.utxo,
        chain.height(),
        &[(to, Amount::from_units(10_000))],
        Amount::from_units(2_000),
        &|o| pool.spends(o),
        &[],
    );
    if let Ok(p) = next {
        let tx = s.wallet.sign_spend(&chain.utxo, p).unwrap();
        assert!(
            tx.inputs.iter().all(|i| i.prev_out != s.coin),
            "the wallet spent again a coin its earlier payment spends"
        );
    }
    let _ = std::fs::remove_dir_all(&s.dir);
}

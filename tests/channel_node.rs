//! Two in-process nodes open and operate a payment channel over the real
//! engine messages, with a real regtest chain and wallet funding.
//!
//! The two [`ChannelManager`]s exchange the exact bytes they would send over
//! the network (channel id, kind, body), routed by a small pump. The funding,
//! cooperative close and penalty transactions go onto a shared regtest chain
//! through the managers' hooks, and the on-chain outcomes are checked to the
//! unit.

#![cfg(feature = "mldsa")]

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::channel::machine::Phase;
use q21_core::channel::manager::{ChannelManager, Hooks, CLOSE_FEE};
use q21_core::consensus::{COINBASE_MATURITY, MIN_OUTPUT_VALUE, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::tx::{OutPoint, Transaction, TxOut};
use q21_core::wallet::Wallet;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const NET: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;
const DELAY: u16 = 12;
const DEPTH: u16 = 2;
const RATE: u64 = 10;
const FUND_FEE: u64 = 50_000;

// Peer ids each node uses for the other.
const A_PEER: u64 = 1; // the funder's id for the acceptor
const F_PEER: u64 = 0; // the acceptor's id for the funder

fn timestamp(height: u64) -> u64 {
    GENESIS_TIME + height * TARGET_BLOCK_SECS
}

/// A shared regtest chain, mined on demand.
struct SharedChain {
    chain: Chain,
    miner: Hash256,
    /// The transactions of the most recently connected block, as the node's
    /// block hook would see them.
    last_txs: Vec<Transaction>,
}

impl SharedChain {
    fn mine(&mut self, txs: &[Transaction]) {
        let h = self.chain.height() + 1;
        let t = timestamp(h);
        let b = self
            .chain
            .mine_block(self.miner, SchemeId::MlDsa87, txs, t, ATTEMPTS)
            .expect("mining");
        self.chain.connect(&b, t + 1).expect("connect");
        self.last_txs = b.transactions.clone();
    }
    fn height(&self) -> u64 {
        self.chain.height()
    }
    /// The confirmation depth of an unspent outpoint (`1` in the tip), as the
    /// node's depth oracle computes it.
    fn depth_of(&self, op: &OutPoint) -> Option<(u64, TxOut)> {
        let h = self.chain.height();
        self.chain
            .utxo
            .get(op)
            .map(|e| (h.saturating_sub(e.height).saturating_add(1), e.output))
    }
}

/// Builds the funder wallet with mature funds and the shared chain.
fn setup(funder_seed: [u8; 32]) -> (Arc<Mutex<Wallet>>, Arc<Mutex<SharedChain>>) {
    let mut w = Wallet::from_seed_scheme(funder_seed, NET, SchemeId::MlDsa87).unwrap();
    let miner = w.new_address().hash;
    let mut chain = Chain::new(NET, genesis_block(NET));
    for i in 1..=(COINBASE_MATURITY + 40) {
        let a = w.new_address();
        let t = timestamp(i);
        let b = chain
            .mine_block(a.hash, SchemeId::MlDsa87, &[], t, ATTEMPTS)
            .expect("mining");
        chain.connect(&b, t + 1).expect("connect");
    }
    (
        Arc::new(Mutex::new(w)),
        Arc::new(Mutex::new(SharedChain {
            chain,
            miner,
            last_txs: Vec::new(),
        })),
    )
}

/// Drives one manager the way the node's block hook does: it hands the current
/// tip's transactions, the chain height and a depth oracle to the manager, and
/// returns the frames (peer, bytes) it wants sent. It settles the tip fully,
/// looping while the manager's own broadcasts (a sweep, a penalty) grow the
/// chain, so a transaction broadcast now is reacted to on the next pass.
fn drive(mgr: &ChannelManager, chain: &Arc<Mutex<SharedChain>>) -> Vec<(u64, Vec<u8>)> {
    let mut all = Vec::new();
    loop {
        let (txs, height) = {
            let c = chain.lock().unwrap();
            (c.last_txs.clone(), c.height())
        };
        let frames = {
            let c = chain.clone();
            let depth_of = move |op: &OutPoint| chain_depth(&c, op);
            mgr.on_connected_block(&txs, height, &depth_of)
        };
        all.extend(frames);
        // If the manager broadcast a transaction, the hook mined it and the tip
        // moved; run again so the new tip is reacted to. Otherwise we are done.
        if chain.lock().unwrap().height() == height {
            break;
        }
    }
    all
}

fn chain_depth(chain: &Arc<Mutex<SharedChain>>, op: &OutPoint) -> Option<(u64, TxOut)> {
    chain.lock().unwrap().depth_of(op)
}

/// Builds one manager (a funder's hooks) on `dir`, as a node would at startup.
fn one_manager(
    seed: [u8; 32],
    wallet: Arc<Mutex<Wallet>>,
    chain: Arc<Mutex<SharedChain>>,
    dir: &std::path::Path,
) -> ChannelManager {
    std::fs::create_dir_all(dir).unwrap();
    ChannelManager::new(
        NET,
        RATE,
        seed,
        dir.to_path_buf(),
        DELAY,
        DEPTH,
        funder_hooks(wallet, chain),
    )
}

/// The funder's hooks: build/sign/broadcast funding from its wallet and chain,
/// and broadcast closes/penalties by mining them.
fn funder_hooks(wallet: Arc<Mutex<Wallet>>, chain: Arc<Mutex<SharedChain>>) -> Hooks {
    let w1 = wallet.clone();
    let c1 = chain.clone();
    let fund = Box::new(
        move |_cid: Hash256, funding_output: TxOut| -> Result<Transaction, String> {
            let mut w = w1.lock().unwrap();
            let c = c1.lock().unwrap();
            let prepared = w
                .prepare_funding(
                    &c.chain.utxo,
                    c.chain.height(),
                    funding_output,
                    Amount::from_units(FUND_FEE),
                    &|_| false,
                    &[],
                )
                .map_err(|e| format!("{e:?}"))?;
            w.sign_spend(&c.chain.utxo, prepared)
                .map_err(|e| format!("{e:?}"))
        },
    );
    let c2 = chain.clone();
    let broadcast = Box::new(move |tx: &Transaction| -> Result<(), String> {
        c2.lock().unwrap().mine(std::slice::from_ref(tx));
        Ok(())
    });
    Hooks {
        fund,
        broadcast,
        sweep_address: Box::new(|| FUNDER_PAYOUT),
        payout_address: Box::new(|| FUNDER_PAYOUT),
        replace: mining_replace(chain),
    }
}

/// The funder's cooperative-close / sweep payout address in these tests.
const FUNDER_PAYOUT: Hash256 = Hash256([0xf0; 32]);
/// The acceptor's cooperative-close payout address in these tests.
const ACCEPTOR_PAYOUT: Hash256 = Hash256([0xa0; 32]);

/// The acceptor's hooks: it never funds; it broadcasts penalties/claims.
fn acceptor_hooks(chain: Arc<Mutex<SharedChain>>, sweep: Hash256) -> Hooks {
    let c = chain.clone();
    Hooks {
        fund: Box::new(|_, _| Err("acceptor does not fund".into())),
        broadcast: Box::new(move |tx: &Transaction| {
            c.lock().unwrap().mine(std::slice::from_ref(tx));
            Ok(())
        }),
        sweep_address: Box::new(move || sweep),
        payout_address: Box::new(|| ACCEPTOR_PAYOUT),
        replace: mining_replace(chain),
    }
}

/// A replacement hook that mines the new version at once, as the broadcast
/// hooks here do.
fn mining_replace(chain: Arc<Mutex<SharedChain>>) -> Box<q21_core::channel::manager::ReplaceFn> {
    Box::new(move |_old: &Transaction, new: &Transaction| {
        chain.lock().unwrap().mine(std::slice::from_ref(new));
        Ok(())
    })
}

struct Pair {
    funder: ChannelManager,
    acceptor: ChannelManager,
    queue: VecDeque<(u64, Vec<u8>)>, // (destination node: 0 funder / 1 acceptor, frame)
}

impl Pair {
    /// The funding output of `cid` as the funder's channel defines it.
    fn funder_funding_output(&self, cid: Hash256) -> TxOut {
        self.funder.funding_output_of(cid).expect("a channel")
    }

    /// Rebuilds the funder's manager from its journal directory, as a crash and
    /// restart would — the reloaded manager replays its channels from disk.
    fn reload_funder(
        &mut self,
        seed: [u8; 32],
        wallet: Arc<Mutex<Wallet>>,
        chain: Arc<Mutex<SharedChain>>,
        dir: &std::path::Path,
    ) {
        self.funder = ChannelManager::new(
            NET,
            RATE,
            seed,
            dir.join("funder"),
            DELAY,
            DEPTH,
            funder_hooks(wallet, chain),
        );
    }

    /// Drives every queued frame to quiescence, asserting no misconduct.
    fn pump(&mut self) {
        let mut steps = 0;
        while let Some((to, frame)) = self.queue.pop_front() {
            steps += 1;
            assert!(steps < 1000, "protocol did not settle");
            let r = if to == 1 {
                self.acceptor.deliver(F_PEER, "", &frame)
            } else {
                self.funder.deliver(A_PEER, "", &frame)
            };
            assert_eq!(r.penalize, 0, "a frame was treated as misconduct");
            let reply_to = if to == 1 { 0 } else { 1 };
            for f in r.frames {
                self.queue.push_back((reply_to, f));
            }
        }
    }
}

fn managers(
    funder_seed: [u8; 32],
    acceptor_seed: [u8; 32],
    wallet: Arc<Mutex<Wallet>>,
    chain: Arc<Mutex<SharedChain>>,
    sweep: Hash256,
    dir: &std::path::Path,
) -> Pair {
    let funder = ChannelManager::new(
        NET,
        RATE,
        funder_seed,
        dir.join("funder"),
        DELAY,
        DEPTH,
        funder_hooks(wallet, chain.clone()),
    );
    let acceptor = ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        dir.join("acceptor"),
        DELAY,
        DEPTH,
        acceptor_hooks(chain, sweep),
    );
    std::fs::create_dir_all(dir.join("funder")).unwrap();
    std::fs::create_dir_all(dir.join("acceptor")).unwrap();
    Pair {
        funder,
        acceptor,
        queue: VecDeque::new(),
    }
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("q21chan-node-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn two_nodes_open_pay_and_cooperatively_close() {
    let funder_seed = [0x11u8; 32];
    let acceptor_seed = [0x22u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let sweep = Hash256([0x5e; 32]);
    let dir = tmpdir("coop");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        sweep,
        &dir,
    );

    // Capacity the funder can afford.
    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        let bal = w.balance(&c.chain.utxo, c.chain.height()).units();
        assert!(bal > 2_000_000, "funder must hold funds: {bal}");
        (bal / 4).max(2 * MIN_OUTPUT_VALUE)
    };

    // Open: funder sends Hello; the pump drives key exchange, Open/Accept,
    // funding (built, signed and mined by the hook), funding_signed.
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();

    let cid = p.funder.list()[0].channel_id;
    let info = p.funder.info(cid).expect("channel exists");
    assert_eq!(info.capacity, capacity);
    assert_eq!(info.local_balance, capacity);
    assert_eq!(info.remote_balance, 0);
    assert!(info.funding.is_some(), "funding broadcast");

    // Bury the funding to the agreed depth, then both signal ready.
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p.funder.funding_confirmed(cid).unwrap();
    let ra = p.acceptor.funding_confirmed(cid).unwrap();
    p.queue.push_back((1, rf));
    p.queue.push_back((0, ra));
    p.pump();

    // Payments both ways.
    let pay1 = p.funder.pay(cid, 1_000_000).unwrap();
    p.queue.push_back((1, pay1));
    p.pump();
    let pay2 = p.funder.pay(cid, 500_000).unwrap();
    p.queue.push_back((1, pay2));
    p.pump();
    // Acceptor pays some back.
    let back = p.acceptor.pay(cid, 400_000).unwrap();
    p.queue.push_back((0, back));
    p.pump();

    let fi = p.funder.info(cid).unwrap();
    let ai = p.acceptor.info(cid).unwrap();
    assert_eq!(fi.local_balance, capacity - 1_100_000);
    assert_eq!(fi.remote_balance, 1_100_000);
    assert_eq!(ai.local_balance, 1_100_000);
    assert_eq!(ai.remote_balance, capacity - 1_100_000);

    // Cooperative close: the funder proposes; the pump completes it and the
    // hook mines the close transaction.
    let before_h = chain.lock().unwrap().height();
    let close = p.funder.close(cid).unwrap().expect("a close frame");
    p.queue.push_back((1, close));
    p.pump();
    let after_h = chain.lock().unwrap().height();
    assert!(after_h > before_h, "close mined");

    // On-chain outcomes: each side's **payout** (wallet) output, not its
    // channel key — the funder's less the close fee — exact to the unit.
    let got = |hash: Hash256| -> u64 {
        let c = chain.lock().unwrap();
        c.chain
            .utxo
            .iter()
            .filter(|(_, e)| e.output.scheme == SchemeId::MlDsa87 && e.output.pubkey_hash == hash)
            .map(|(_, e)| e.output.value.units())
            .sum()
    };
    let gf = got(FUNDER_PAYOUT);
    let ga = got(ACCEPTOR_PAYOUT);
    assert_eq!(
        gf,
        capacity - 1_100_000 - CLOSE_FEE,
        "funder payout on chain"
    );
    assert_eq!(ga, 1_100_000, "acceptor payout on chain");
    assert_eq!(gf + ga + CLOSE_FEE, capacity, "conserved to the unit");
}

#[test]
#[cfg(feature = "audit")]
fn a_revoked_broadcast_is_punished_before_the_delay() {
    let funder_seed = [0x33u8; 32];
    let acceptor_seed = [0x44u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let sweep = Hash256([0x7au8; 32]);
    let dir = tmpdir("penalty");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        sweep,
        &dir,
    );

    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        (w.balance(&c.chain.utxo, c.chain.height()).units() / 4).max(2 * MIN_OUTPUT_VALUE)
    };
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p.funder.funding_confirmed(cid).unwrap();
    let ra = p.acceptor.funding_confirmed(cid).unwrap();
    p.queue.push_back((1, rf));
    p.queue.push_back((0, ra));
    p.pump();

    // A few payments so there is an old, revoked state.
    for amt in [700_000u64, 700_000, 700_000] {
        let m = p.funder.pay(cid, amt).unwrap();
        p.queue.push_back((1, m));
        p.pump();
    }
    let state = p.funder.info(cid).unwrap().state_number; // current
    let revoked = p
        .funder
        .signed_commitment(cid, state - 1)
        .expect("a retained revoked commitment");

    // The funder cheats: broadcasts the revoked commitment.
    let broadcast_h = {
        let mut c = chain.lock().unwrap();
        c.mine(std::slice::from_ref(&revoked));
        c.height()
    };

    // The acceptor's watcher sees the spend and punishes it.
    let penalty = p
        .acceptor
        .on_funding_spend(cid, &revoked)
        .expect("a penalty was built and broadcast");
    let after = chain.lock().unwrap().height();
    assert!(after > broadcast_h, "penalty mined in the next block");
    // The penalty landed well before the funder's to-self delay.
    assert!(
        after < broadcast_h + DELAY as u64,
        "penalty must win before the delay"
    );

    // The acceptor's swept output exists on chain and is non-trivial.
    let swept: u64 = {
        let c = chain.lock().unwrap();
        c.chain
            .utxo
            .iter()
            .filter(|(_, e)| e.output.scheme == SchemeId::MlDsa87 && e.output.pubkey_hash == sweep)
            .map(|(_, e)| e.output.value.units())
            .sum()
    };
    assert!(
        swept >= MIN_OUTPUT_VALUE,
        "the acceptor recovered the to_local"
    );
    assert_eq!(penalty.outputs[0].pubkey_hash, sweep);
}

#[test]
fn reestablish_after_a_clean_reconnect_resends_nothing() {
    let funder_seed = [0x55u8; 32];
    let acceptor_seed = [0x66u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("reest");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        Hash256([0x9a; 32]),
        &dir,
    );
    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        (w.balance(&c.chain.utxo, c.chain.height()).units() / 4).max(2 * MIN_OUTPUT_VALUE)
    };
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p.funder.funding_confirmed(cid).unwrap();
    let ra = p.acceptor.funding_confirmed(cid).unwrap();
    p.queue.push_back((1, rf));
    p.queue.push_back((0, ra));
    p.pump();
    let m = p.funder.pay(cid, 600_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();

    // Reconnect: both sides exchange reestablish; since they are in sync, the
    // pump produces no further protocol messages and both agree.
    for f in p.funder.reestablish(A_PEER) {
        p.queue.push_back((1, f));
    }
    for f in p.acceptor.reestablish(F_PEER) {
        p.queue.push_back((0, f));
    }
    p.pump();
    let fi = p.funder.info(cid).unwrap();
    let ai = p.acceptor.info(cid).unwrap();
    assert_eq!(fi.local_balance, ai.remote_balance);
    assert_eq!(fi.remote_balance, ai.local_balance);
    assert_eq!(fi.state_number, ai.state_number);
}

/// Sums the value of every ML-DSA-87 output paying `hash` in the UTXO set.
fn paid_to(chain: &Arc<Mutex<SharedChain>>, hash: Hash256) -> u64 {
    let c = chain.lock().unwrap();
    c.chain
        .utxo
        .iter()
        .filter(|(_, e)| e.output.scheme == SchemeId::MlDsa87 && e.output.pubkey_hash == hash)
        .map(|(_, e)| e.output.value.units())
        .sum()
}

/// D1: two real managers reach `open` purely because the node's block hook
/// detected the funding buried to the agreed depth. No test code calls
/// `funding_confirmed`; both sides detect their own depth independently.
#[test]
fn two_nodes_reach_open_through_the_block_hook() {
    let funder_seed = [0x1au8; 32];
    let acceptor_seed = [0x2bu8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("d1-open");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        Hash256([0x5e; 32]),
        &dir,
    );
    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        (w.balance(&c.chain.utxo, c.chain.height()).units() / 4).max(2 * MIN_OUTPUT_VALUE)
    };
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    // The funder sits in `Funded`, the acceptor in `Opening`; neither is open
    // until the block hook confirms the funding.
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Funded);
    assert_ne!(p.acceptor.info(cid).unwrap().phase, Phase::Open);
    assert!(p.acceptor.info(cid).unwrap().funding.is_some());

    // Mine blocks over the funding; after each, the block hook drives both
    // managers, which confirm their own funding and exchange `ready`.
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
        for (_, f) in drive(&p.funder, &chain) {
            p.queue.push_back((1, f));
        }
        for (_, f) in drive(&p.acceptor, &chain) {
            p.queue.push_back((0, f));
        }
        p.pump();
    }
    assert_eq!(
        p.funder.info(cid).unwrap().phase,
        Phase::Open,
        "funder opened by the block hook"
    );
    assert_eq!(
        p.acceptor.info(cid).unwrap().phase,
        Phase::Open,
        "acceptor opened by the block hook"
    );
}

/// D2: a unilateral (force) close is swept through the node block hook, and the
/// sweep is broadcast only after the to-self delay, then settles the channel.
#[test]
fn a_unilateral_close_is_swept_after_the_delay() {
    let funder_seed = [0x3cu8; 32];
    let acceptor_seed = [0x4du8; 32];
    let (wallet, chain) = setup(funder_seed);
    // The funder force-closes and sweeps to its own payout address.
    let sweep = FUNDER_PAYOUT;
    let dir = tmpdir("d2-sweep");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        sweep,
        &dir,
    );
    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        (w.balance(&c.chain.utxo, c.chain.height()).units() / 4).max(2 * MIN_OUTPUT_VALUE)
    };
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p.funder.funding_confirmed(cid).unwrap();
    let ra = p.acceptor.funding_confirmed(cid).unwrap();
    p.queue.push_back((1, rf));
    p.queue.push_back((0, ra));
    p.pump();
    let pay = p.funder.pay(cid, 1_000_000).unwrap();
    p.queue.push_back((1, pay));
    p.pump();

    // The funder force-closes: its commitment is broadcast (mined) by the hook.
    p.funder.force_close(cid).unwrap();
    let hc = chain.lock().unwrap().height();
    drive(&p.funder, &chain);
    assert_eq!(
        p.funder.info(cid).unwrap().phase,
        Phase::Forcing,
        "force close recorded"
    );
    assert_eq!(paid_to(&chain, sweep), 0, "nothing swept before the delay");

    for _ in 0..DELAY {
        assert!(
            chain.lock().unwrap().height() < hc + DELAY as u64,
            "still inside the delay window"
        );
        assert_eq!(
            paid_to(&chain, sweep),
            0,
            "the sweep must wait out the delay"
        );
        chain.lock().unwrap().mine(&[]);
        drive(&p.funder, &chain);
    }
    assert_eq!(
        p.funder.info(cid).unwrap().phase,
        Phase::Closed,
        "the channel closed once the sweep confirmed"
    );
    assert!(
        paid_to(&chain, sweep) >= MIN_OUTPUT_VALUE,
        "the delayed sweep recovered the to_local output"
    );
}

/// D7: a manager rebuilt on the same journal directory reloads its channels,
/// with the same state and the watcher armed, instead of forgetting them.
#[test]
fn a_manager_reloads_its_channels_on_restart() {
    let funder_seed = [0x5eu8; 32];
    let acceptor_seed = [0x6fu8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("d7-reload");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        Hash256([0x5e; 32]),
        &dir,
    );
    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        (w.balance(&c.chain.utxo, c.chain.height()).units() / 4).max(2 * MIN_OUTPUT_VALUE)
    };
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p.funder.funding_confirmed(cid).unwrap();
    let ra = p.acceptor.funding_confirmed(cid).unwrap();
    p.queue.push_back((1, rf));
    p.queue.push_back((0, ra));
    p.pump();
    let pay = p.funder.pay(cid, 700_000).unwrap();
    p.queue.push_back((1, pay));
    p.pump();

    let before = p.funder.info(cid).expect("channel is live");
    let funding = before.funding.expect("funding known");

    // Drop the funder's manager and build a fresh one on the same directory, as
    // a restart would. The channel must come back with the same state.
    drop(p);
    let reloaded = one_manager(
        funder_seed,
        wallet.clone(),
        chain.clone(),
        &dir.join("funder"),
    );
    let after = reloaded.info(cid).expect("channel reloaded");
    assert_eq!(after.phase, before.phase, "phase survived the restart");
    assert_eq!(
        after.local_balance, before.local_balance,
        "balance survived"
    );
    assert_eq!(after.remote_balance, before.remote_balance);
    assert_eq!(
        after.state_number, before.state_number,
        "state number survived"
    );
    assert_eq!(after.capacity, before.capacity);
    assert!(
        reloaded
            .watched_funding()
            .iter()
            .any(|(_, o)| *o == funding),
        "the watcher is armed on the reloaded channel"
    );
}

/// D3: after a message is dropped mid-update, a reconnect (the node's
/// handshake hook calling `on_peer_connected`) resyncs both sides to the same
/// state through the engine's reestablish.
#[test]
fn reestablish_recovers_a_dropped_update() {
    let funder_seed = [0x7au8; 32];
    let acceptor_seed = [0x8bu8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("d3-reest");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        Hash256([0x5e; 32]),
        &dir,
    );
    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        (w.balance(&c.chain.utxo, c.chain.height()).units() / 4).max(2 * MIN_OUTPUT_VALUE)
    };
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p.funder.funding_confirmed(cid).unwrap();
    let ra = p.acceptor.funding_confirmed(cid).unwrap();
    p.queue.push_back((1, rf));
    p.queue.push_back((0, ra));
    p.pump();
    // One completed payment so there is a settled state to build on.
    let m = p.funder.pay(cid, 500_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();

    // A second payment, but the acceptor's acknowledgement is dropped on the
    // wire: the two sides are now out of step.
    let upd = p.funder.pay(cid, 300_000).unwrap();
    let dropped = p.acceptor.deliver(F_PEER, "", &upd);
    assert_eq!(dropped.penalize, 0, "the update was well formed");
    assert!(!dropped.frames.is_empty(), "the acceptor produced an ack");
    // ... and we deliberately do not deliver it.

    // Reconnect: the node's handshake hook asks each side to resync.
    for f in p.funder.on_peer_connected(A_PEER, "") {
        p.queue.push_back((1, f));
    }
    for f in p.acceptor.on_peer_connected(F_PEER, "") {
        p.queue.push_back((0, f));
    }
    p.pump();

    let fi = p.funder.info(cid).unwrap();
    let ai = p.acceptor.info(cid).unwrap();
    assert_eq!(fi.state_number, ai.state_number, "both at the same state");
    assert_eq!(fi.local_balance, ai.remote_balance, "balances agree");
    assert_eq!(fi.remote_balance, ai.local_balance);
    assert_eq!(
        fi.local_balance,
        capacity - 800_000,
        "the dropped payment completed after reestablish"
    );
}

/// D11-residual: a channel reloaded while an update was in flight (proposed but
/// not acknowledged) reconciles on reconnect — both sides reach the same latest
/// state and the channel keeps working — instead of jamming on "already in
/// flight" / "not open".
#[test]
fn a_reloaded_channel_reconciles_an_incomplete_update() {
    let funder_seed = [0xd1u8; 32];
    let acceptor_seed = [0xd2u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("reload-midupdate");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        Hash256([0x5e; 32]),
        &dir,
    );
    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        (w.balance(&c.chain.utxo, c.chain.height()).units() / 4).max(2 * MIN_OUTPUT_VALUE)
    };
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p.funder.funding_confirmed(cid).unwrap();
    let ra = p.acceptor.funding_confirmed(cid).unwrap();
    p.queue.push_back((1, rf));
    p.queue.push_back((0, ra));
    p.pump();
    // One settled payment.
    let m = p.funder.pay(cid, 500_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();

    // The funder proposes another update but it is NOT delivered (the funder
    // crashes right after persisting its side of it).
    let _stuck = p.funder.pay(cid, 300_000).unwrap();
    // Reload the funder from its journal: the in-flight proposal is on disk.
    p.reload_funder(funder_seed, wallet.clone(), chain.clone(), &dir);

    // Reconnect: both sides exchange reestablish; the engine resends the one
    // in-flight message and both converge.
    for f in p.funder.on_peer_connected(A_PEER, "") {
        p.queue.push_back((1, f));
    }
    for f in p.acceptor.on_peer_connected(F_PEER, "") {
        p.queue.push_back((0, f));
    }
    p.pump();

    let fi = p.funder.info(cid).unwrap();
    let ai = p.acceptor.info(cid).unwrap();
    assert_eq!(fi.state_number, ai.state_number, "both at the same state");
    assert_eq!(fi.local_balance, ai.remote_balance, "balances agree");
    assert_eq!(fi.remote_balance, ai.local_balance);

    // The channel still works: a further payment settles on both sides.
    let before = ai.local_balance;
    let pay = p.funder.pay(cid, 100_000).unwrap();
    p.queue.push_back((1, pay));
    p.pump();
    assert_eq!(
        p.acceptor.info(cid).unwrap().local_balance,
        before + 100_000,
        "the reloaded channel keeps working after reconciliation"
    );
    assert_eq!(
        p.funder.info(cid).unwrap().state_number,
        p.acceptor.info(cid).unwrap().state_number
    );
}

/// An open channel: the pair, the funder's wallet, the chain, the journal
/// directory, the channel id and its capacity.
type Opened = (
    Pair,
    Arc<Mutex<Wallet>>,
    Arc<Mutex<SharedChain>>,
    std::path::PathBuf,
    Hash256,
    u64,
);

/// Opens a channel between two fresh managers and buries its funding, so it is
/// `open` on both sides. Returns the pair, the chain, the channel id and its
/// capacity.
fn open_channel(funder_seed: [u8; 32], acceptor_seed: [u8; 32], tag: &str) -> Opened {
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir(tag);
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        Hash256([0x5e; 32]),
        &dir,
    );
    let capacity = {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        (w.balance(&c.chain.utxo, c.chain.height()).units() / 4).max(2 * MIN_OUTPUT_VALUE)
    };
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p.funder.funding_confirmed(cid).unwrap();
    let ra = p.acceptor.funding_confirmed(cid).unwrap();
    p.queue.push_back((1, rf));
    p.queue.push_back((0, ra));
    p.pump();
    (p, wallet, chain, dir, cid, capacity)
}

/// Both sides exchange reestablish over a fresh connection, as the node's
/// handshake hook does, and the pump settles what each owes.
fn reconnect(p: &mut Pair) {
    for f in p.funder.on_peer_connected(A_PEER, "") {
        p.queue.push_back((1, f));
    }
    for f in p.acceptor.on_peer_connected(F_PEER, "") {
        p.queue.push_back((0, f));
    }
    p.pump();
}

/// What a payout address holds on chain.
fn held(chain: &Arc<Mutex<SharedChain>>, hash: Hash256) -> u64 {
    let c = chain.lock().unwrap();
    c.chain
        .utxo
        .iter()
        .filter(|(_, e)| e.output.scheme == SchemeId::MlDsa87 && e.output.pubkey_hash == hash)
        .map(|(_, e)| e.output.value.units())
        .sum()
}

/// D11: a payment journaled but never delivered before a crash is in flight
/// in the reloaded channel. A second payment is refused until the reestablish
/// has run — stacking it on the unacknowledged one made the peer refuse it as
/// misconduct and drop the link — and both then settle.
#[test]
fn a_reloaded_unsent_payment_blocks_a_second_until_reestablish() {
    let funder_seed = [0xe1u8; 32];
    let acceptor_seed = [0xe2u8; 32];
    let (mut p, wallet, chain, dir, cid, capacity) =
        open_channel(funder_seed, acceptor_seed, "d11-unsent");
    let m = p.funder.pay(cid, 500_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    let _never_delivered = p.funder.pay(cid, 300_000).unwrap();
    p.reload_funder(funder_seed, wallet, chain, &dir);

    assert!(
        p.funder.pay(cid, 100_000).is_err(),
        "a payment stacked on the reloaded, unacknowledged one"
    );
    reconnect(&mut p);
    assert_eq!(
        p.acceptor.info(cid).unwrap().local_balance,
        800_000,
        "the journaled payment completed on reestablish"
    );
    let m = p.funder.pay(cid, 100_000).expect("payments resume");
    p.queue.push_back((1, m));
    p.pump();
    let fi = p.funder.info(cid).unwrap();
    let ai = p.acceptor.info(cid).unwrap();
    assert_eq!(ai.local_balance, 900_000);
    assert_eq!(fi.local_balance, capacity - 900_000);
    assert_eq!(fi.state_number, ai.state_number);
}

/// D11: a cooperative close asked for while a payment is still settling is
/// agreed at once and sent when the payment completes; the close pays both
/// sides the final balances, and the peer that did not broadcast it settles
/// when it confirms.
#[test]
fn a_close_asked_during_a_payment_follows_it_and_both_sides_settle() {
    let (mut p, _wallet, chain, _dir, cid, capacity) =
        open_channel([0xe3u8; 32], [0xe4u8; 32], "d11-close-follows");
    let m = p.funder.pay(cid, 600_000).unwrap();
    assert!(
        p.funder.close(cid).unwrap().is_none(),
        "the Close waits for the payment to settle"
    );
    assert!(p.funder.pay(cid, 1).is_err(), "no payment after the close");
    p.queue.push_back((1, m));
    p.pump();
    assert_eq!(held(&chain, ACCEPTOR_PAYOUT), 600_000);
    assert_eq!(held(&chain, FUNDER_PAYOUT), capacity - 600_000 - CLOSE_FEE);
    // Both learn of the close from the block that confirms it: the closer
    // stays closing until then, holding the close to broadcast again.
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Closing);
    drive(&p.funder, &chain);
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Closed);
    drive(&p.acceptor, &chain);
    assert_eq!(
        p.acceptor.info(cid).unwrap().phase,
        Phase::Closed,
        "the closer's peer settles when the close confirms"
    );
}

/// D11: a cooperative close whose `Close` was lost to a crash completes after
/// the restart, through the reestablish, with no force-close.
#[test]
fn a_close_lost_to_a_crash_completes_after_restart() {
    let funder_seed = [0xe5u8; 32];
    let (mut p, wallet, chain, dir, cid, capacity) =
        open_channel(funder_seed, [0xe6u8; 32], "d11-close-lost");
    let m = p.funder.pay(cid, 250_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    let _lost = p.funder.close(cid).unwrap().expect("a close frame");
    p.reload_funder(funder_seed, wallet, chain.clone(), &dir);
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Closing);
    reconnect(&mut p);
    assert_eq!(held(&chain, ACCEPTOR_PAYOUT), 250_000);
    assert_eq!(held(&chain, FUNDER_PAYOUT), capacity - 250_000 - CLOSE_FEE);
    drive(&p.funder, &chain);
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Closed);
}

/// D11: a peer that still tracks a channel we settled and forgot offers its
/// reestablish at every connection; that is not misconduct, or the link would
/// drop at every reconnect.
#[test]
fn a_reestablish_for_a_forgotten_channel_is_not_misconduct() {
    let (p, wallet, chain, _dir, _cid, _capacity) =
        open_channel([0xe7u8; 32], [0xe8u8; 32], "d11-forgotten");
    let stranger = one_manager([0xe9u8; 32], wallet, chain, &tmpdir("d11-stranger"));
    let frames = p.funder.on_peer_connected(A_PEER, "");
    assert!(!frames.is_empty());
    for f in frames {
        let r = stranger.deliver(F_PEER, "", &f);
        assert_eq!(r.penalize, 0, "a reestablish for an unknown channel");
        assert!(r.frames.is_empty());
    }
}

/// D11: a channel frame arriving on a connection the channel is not bound to,
/// with no identity tying it to the counterparty, is not acted on; a
/// reestablish whose proof verifies moves the binding to that connection.
#[test]
fn only_a_verified_reestablish_rebinds_a_channel_to_another_connection() {
    let (p, _wallet, _chain, _dir, cid, _capacity) =
        open_channel([0xeau8; 32], [0xebu8; 32], "d11-rebind");
    const OTHER: u64 = 77;
    let m = p.funder.pay(cid, 400_000).unwrap();
    let r = p.acceptor.deliver(OTHER, "", &m);
    assert_eq!(r.penalize, 0);
    assert!(r.frames.is_empty(), "a frame from an unbound connection");
    assert_eq!(p.acceptor.info(cid).unwrap().local_balance, 0);
    assert_eq!(p.acceptor.peer_of(cid), Some(F_PEER));

    // The funder reconnects on the other connection: its reestablish proves
    // its funding key, the acceptor re-binds there, and the dropped payment
    // completes.
    let mut queue: VecDeque<(u64, Vec<u8>)> = p
        .funder
        .reestablish(A_PEER)
        .into_iter()
        .map(|f| (1, f))
        .collect();
    let mut steps = 0;
    while let Some((to, frame)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 100, "did not settle");
        let r = if to == 1 {
            p.acceptor.deliver(OTHER, "", &frame)
        } else {
            p.funder.deliver(A_PEER, "", &frame)
        };
        assert_eq!(r.penalize, 0);
        queue.extend(r.frames.into_iter().map(|f| (1 - to, f)));
    }
    assert_eq!(p.acceptor.peer_of(cid), Some(OTHER));
    assert_eq!(p.acceptor.info(cid).unwrap().local_balance, 400_000);
    assert_eq!(
        p.funder.info(cid).unwrap().state_number,
        p.acceptor.info(cid).unwrap().state_number
    );
}

/// What a [`relaying_manager`] broadcast, in order: each transaction, with
/// the one it replaced for a fee bump.
type Sent = Arc<Mutex<Vec<(Option<Hash256>, Transaction)>>>;

/// A manager reloaded from `dir` whose hooks relay without mining, so what it
/// broadcasts stays unconfirmed until the test confirms it.
fn relaying_manager(
    seed: [u8; 32],
    dir: &std::path::Path,
    sweep: Hash256,
) -> (ChannelManager, Sent) {
    let sent: Sent = Arc::new(Mutex::new(Vec::new()));
    let (s1, s2) = (sent.clone(), sent.clone());
    let mgr = ChannelManager::new(
        NET,
        RATE,
        seed,
        dir.to_path_buf(),
        DELAY,
        DEPTH,
        Hooks {
            fund: Box::new(|_, _| Err("does not fund".into())),
            broadcast: Box::new(move |tx: &Transaction| {
                s1.lock().unwrap().push((None, tx.clone()));
                Ok(())
            }),
            sweep_address: Box::new(move || sweep),
            payout_address: Box::new(|| ACCEPTOR_PAYOUT),
            replace: Box::new(move |old: &Transaction, new: &Transaction| {
                s2.lock().unwrap().push((Some(old.txid()), new.clone()));
                Ok(())
            }),
        },
    );
    (mgr, sent)
}

/// M4: a penalty that stays unconfirmed climbs its fee ladder. The mempool has
/// no replacement by fee, so each tier replaces the previous one in the
/// node's own pool and is relayed; every tier pays the victim, its output never
/// falls below the dust floor, the ladder stops at the cheater's delay, and any
/// tier confirming settles the channel.
#[test]
#[cfg(feature = "audit")]
fn an_unconfirmed_penalty_is_replaced_by_a_higher_fee_tier() {
    use q21_core::channel::manager::{penalty_bump_interval, penalty_tier_fee};
    let funder_seed = [0xf1u8; 32];
    let acceptor_seed = [0xf2u8; 32];
    let (mut p, _wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, acceptor_seed, "m4-bump");
    for amt in [700_000u64, 700_000] {
        let m = p.funder.pay(cid, amt).unwrap();
        p.queue.push_back((1, m));
        p.pump();
    }
    let state = p.funder.info(cid).unwrap().state_number;
    let revoked = p.funder.signed_commitment(cid, state - 1).unwrap();

    // The victim's node, reloaded with hooks that relay without mining, as a
    // congested network would leave a penalty waiting.
    let sweep = Hash256([0x7bu8; 32]);
    let (victim, sent) = relaying_manager(acceptor_seed, &dir.join("acceptor"), sweep);
    let to_local = revoked
        .outputs
        .iter()
        .find(|o| o.scheme == SchemeId::Policy)
        .map(|o| o.value.units())
        .expect("the revoked commitment has a to_local");
    let fee_of = |t: &Transaction| to_local - t.outputs[0].value.units();
    let no_depth = |_: &OutPoint| None;

    // The revoked commitment confirms at height h: tier 0 goes out.
    let h = 1_000u64;
    victim.on_connected_block(std::slice::from_ref(&revoked), h, &no_depth);
    assert_eq!(sent.lock().unwrap().len(), 1);
    let tier0 = sent.lock().unwrap()[0].1.clone();
    assert_eq!(fee_of(&tier0), penalty_tier_fee(0));

    // Unconfirmed for less than the interval: nothing more.
    let every = penalty_bump_interval(DELAY);
    assert!(every >= 1 && 2 * every < u64::from(DELAY));
    for k in 1..every {
        victim.on_connected_block(&[], h + k, &no_depth);
    }
    assert_eq!(sent.lock().unwrap().len(), 1, "bumped too early");

    // After the interval, the next tier replaces it, paying more.
    victim.on_connected_block(&[], h + every, &no_depth);
    let (replaced, tier1) = sent.lock().unwrap()[1].clone();
    assert_eq!(replaced, Some(tier0.txid()), "tier 1 replaces tier 0");
    assert_eq!(tier1.inputs[0].prev_out, tier0.inputs[0].prev_out);
    assert!(fee_of(&tier1) > fee_of(&tier0), "a higher fee");
    assert_eq!(tier1.outputs[0].pubkey_hash, sweep);

    // And again, up to the top tier, never below the dust floor.
    victim.on_connected_block(&[], h + 2 * every, &no_depth);
    let (replaced, tier2) = sent.lock().unwrap()[2].clone();
    assert_eq!(replaced, Some(tier1.txid()));
    assert!(fee_of(&tier2) > fee_of(&tier1));
    assert!(tier2.outputs[0].value.units() >= MIN_OUTPUT_VALUE);
    for k in (2 * every + 1)..(u64::from(DELAY) + 4) {
        victim.on_connected_block(&[], h + k, &no_depth);
    }
    assert_eq!(sent.lock().unwrap().len(), 3, "the ladder has three tiers");

    // Why replace in our own pool: without replacement by fee, a pool holding
    // one tier refuses the next as a conflicting spend. Dropped first, the
    // higher tier is admitted.
    {
        use q21_core::mempool::{Mempool, MempoolError};
        let mut c = chain.lock().unwrap();
        c.mine(std::slice::from_ref(&revoked));
        let (utxo, height) = (&c.chain.utxo, c.chain.height());
        let mut pool = Mempool::new();
        pool.accept_local(&tier0, utxo, NET, height).unwrap();
        assert!(matches!(
            pool.accept_local(&tier1, utxo, NET, height),
            Err(MempoolError::SpendConflict(_))
        ));
        pool.remove(&tier0.txid());
        pool.accept_local(&tier1, utxo, NET, height)
            .expect("the higher tier once the lower one is dropped");
    }
    // Every tier is a valid spend on chain: the top one confirms.
    chain.lock().unwrap().mine(std::slice::from_ref(&tier2));
    // A lower tier confirming (still held by some other node) settles too.
    victim.on_connected_block(std::slice::from_ref(&tier0), h + 40, &no_depth);
    assert_eq!(victim.info(cid).unwrap().phase, Phase::Closed);
}

/// M5: the block holding the counterparty's latest commitment is disconnected
/// and a revoked commitment confirms in its place. The watcher, which had
/// started claiming from the first, reclassifies the spend and punishes the
/// second — whether or not it was told of the disconnection first.
#[test]
#[cfg(feature = "audit")]
fn a_revoked_commitment_that_replaces_a_reorged_spend_is_punished() {
    for told_of_disconnect in [true, false] {
        let funder_seed = [0xf3u8; 32];
        let acceptor_seed = [0xf4u8; 32];
        let tag = format!("m5-reorg-{told_of_disconnect}");
        let (mut p, _wallet, chain, dir, cid, _capacity) =
            open_channel(funder_seed, acceptor_seed, &tag);
        for amt in [700_000u64, 700_000, 700_000] {
            let m = p.funder.pay(cid, amt).unwrap();
            p.queue.push_back((1, m));
            p.pump();
        }
        let state = p.funder.info(cid).unwrap().state_number;
        let latest = p.funder.signed_commitment(cid, state).unwrap();
        let revoked = p.funder.signed_commitment(cid, state - 1).unwrap();
        assert_eq!(latest.inputs[0].prev_out, revoked.inputs[0].prev_out);

        let sweep = Hash256([0x7cu8; 32]);
        let (victim, sent) = relaying_manager(acceptor_seed, &dir.join("acceptor"), sweep);
        let no_depth = |_: &OutPoint| None;

        // The latest commitment confirms: the victim claims its to_remote.
        victim.on_connected_block(std::slice::from_ref(&latest), 500, &no_depth);
        assert_eq!(victim.info(cid).unwrap().phase, Phase::Forcing);
        assert_eq!(sent.lock().unwrap().len(), 1, "the to_remote claim");

        // A reorganization replaces it with the revoked one.
        if told_of_disconnect {
            victim.on_disconnected_block(std::slice::from_ref(&latest));
        }
        victim.on_connected_block(std::slice::from_ref(&revoked), 500, &no_depth);
        assert_eq!(
            victim.info(cid).unwrap().phase,
            Phase::Penalised,
            "the revoked replacement is punished (told_of_disconnect={told_of_disconnect})"
        );
        let penalty = sent.lock().unwrap().last().unwrap().1.clone();
        assert_eq!(penalty.outputs[0].pubkey_hash, sweep);
        assert!(revoked
            .outputs
            .iter()
            .enumerate()
            .any(|(i, _)| penalty.inputs[0].prev_out
                == OutPoint {
                    txid: revoked.txid(),
                    index: i as u32
                }));
        // Seen again in a later block (another reorganization), the same spend
        // is not punished twice.
        victim.on_connected_block(std::slice::from_ref(&revoked), 501, &no_depth);
        assert_eq!(sent.lock().unwrap().len(), 2);

        // The penalty is valid on chain against the revoked commitment.
        let mut c = chain.lock().unwrap();
        c.mine(std::slice::from_ref(&revoked));
        c.mine(std::slice::from_ref(&penalty));
    }
}

/// L6: opens waiting for the peer are bounded across peers and expire; a
/// Hello beyond the bound is left unanswered, without misconduct and without
/// allocating anything for it.
#[test]
fn pending_opens_are_bounded_and_expire() {
    use q21_core::channel::manager::MAX_PENDING_OPENS;
    let funder_seed = [0xa1u8; 32];
    let acceptor_seed = [0xa2u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("l6-pending");
    let p = managers(
        funder_seed,
        acceptor_seed,
        wallet,
        chain,
        Hash256([0x5e; 32]),
        &dir,
    );
    let capacity = 4 * MIN_OUTPUT_VALUE;
    // The funder side: its own opens in progress are bounded too.
    let mut hello = None;
    for peer in 0..MAX_PENDING_OPENS as u64 {
        hello = Some(p.funder.open(100 + peer, "", capacity, None, None).unwrap());
    }
    assert!(p.funder.open(999, "", capacity, None, None).is_err());
    assert_eq!(p.funder.pending_opens().0, MAX_PENDING_OPENS);
    // The acceptor side: Hellos from as many connections as it takes.
    let hello = hello.unwrap();
    for peer in 0..(MAX_PENDING_OPENS as u64 + 5) {
        let r = p.acceptor.deliver(200 + peer, "", &hello);
        assert_eq!(r.penalize, 0);
        assert_eq!(
            r.frames.is_empty(),
            peer >= MAX_PENDING_OPENS as u64,
            "Hello {peer} answered beyond the bound, or refused within it"
        );
    }
    assert_eq!(p.acceptor.pending_opens().1, MAX_PENDING_OPENS);
    // A Hello whose peer vanished does not hold its slot forever.
    p.acceptor.set_pending_open_ttl(std::time::Duration::ZERO);
    p.funder.set_pending_open_ttl(std::time::Duration::ZERO);
    assert_eq!(p.acceptor.pending_opens(), (0, 0));
    assert_eq!(p.funder.pending_opens(), (0, 0));
    p.acceptor
        .set_pending_open_ttl(q21_core::channel::manager::PENDING_OPEN_TTL);
    assert!(!p.acceptor.deliver(300, "", &hello).frames.is_empty());
}

/// L6: the channels one peer holds with a node are bounded, on both sides.
#[test]
fn channels_per_peer_are_bounded() {
    use q21_core::channel::manager::MAX_CHANNELS_PER_PEER;
    let funder_seed = [0xa3u8; 32];
    let acceptor_seed = [0xa4u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("l6-per-peer");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet.clone(),
        chain.clone(),
        Hash256([0x5e; 32]),
        &dir,
    );
    let capacity = 4 * MIN_OUTPUT_VALUE;
    for _ in 0..MAX_CHANNELS_PER_PEER {
        let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
        p.queue.push_back((1, hello));
        p.pump();
    }
    assert_eq!(p.funder.list().len(), MAX_CHANNELS_PER_PEER);
    assert_eq!(p.acceptor.list().len(), MAX_CHANNELS_PER_PEER);
    assert!(
        p.funder.open(A_PEER, "", capacity, None, None).is_err(),
        "one channel too many with this peer"
    );
    // A Hello arriving from that same peer is not answered by the acceptor.
    let elsewhere = one_manager([0xa5u8; 32], wallet, chain, &dir.join("elsewhere"));
    let hello = elsewhere.open(A_PEER, "", capacity, None, None).unwrap();
    let r = p.acceptor.deliver(F_PEER, "", &hello);
    assert_eq!(r.penalize, 0);
    assert!(r.frames.is_empty(), "a ninth channel with the same peer");
    assert_eq!(p.acceptor.pending_opens().1, 0);
    // Another peer is still served.
    assert!(!p
        .acceptor
        .deliver(F_PEER + 50, "", &hello)
        .frames
        .is_empty());
}

// --- Startup rescan: what confirmed while a node was down ---------------------

/// Restarts a manager from `dir` with `hooks` and runs its startup rescan
/// against the shared chain, as the node does before it connects to anyone.
fn restart_and_rescan(
    seed: [u8; 32],
    dir: &std::path::Path,
    hooks: Hooks,
    chain: &Arc<Mutex<SharedChain>>,
) -> ChannelManager {
    let mgr = ChannelManager::new(NET, RATE, seed, dir.to_path_buf(), DELAY, DEPTH, hooks);
    let tip = chain.lock().unwrap().height();
    let c1 = chain.clone();
    let txs_at = move |h: u64| c1.lock().unwrap().chain.block_at(h).map(|b| b.transactions);
    let c2 = chain.clone();
    let depth_of = move |op: &OutPoint| chain_depth(&c2, op);
    mgr.rescan(tip, &txs_at, &depth_of);
    mgr
}

/// The policy (to_local) output of a commitment.
fn to_local_of(tx: &Transaction) -> OutPoint {
    let i = tx
        .outputs
        .iter()
        .position(|o| o.scheme == SchemeId::Policy)
        .expect("a to_local output");
    OutPoint {
        txid: tx.txid(),
        index: i as u32,
    }
}

/// Whether some transaction in the chain's last `back` blocks spends `op`,
/// and the output it pays first.
fn spender_of(chain: &Arc<Mutex<SharedChain>>, op: &OutPoint, back: u64) -> Option<TxOut> {
    let c = chain.lock().unwrap();
    let tip = c.chain.height();
    (tip.saturating_sub(back)..=tip).find_map(|h| {
        c.chain.block_at(h).and_then(|b| {
            b.transactions
                .iter()
                .find(|t| t.inputs.iter().any(|i| i.prev_out == *op))
                .map(|t| t.outputs[0])
        })
    })
}

/// The victim's node is stopped when the cheater's revoked commitment
/// confirms. It restarts before the to-self delay: the startup rescan finds
/// the spend in the blocks it missed and the penalty confirms, the cheater
/// keeping nothing of its to_local.
#[test]
#[cfg(feature = "audit")]
fn an_offline_victim_punishes_a_revoked_commitment_on_restart() {
    let funder_seed = [0xb1u8; 32];
    let acceptor_seed = [0xb2u8; 32];
    let (mut p, _wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, acceptor_seed, "rescan-offline-victim");
    for amt in [700_000u64, 700_000, 700_000] {
        let m = p.funder.pay(cid, amt).unwrap();
        p.queue.push_back((1, m));
        p.pump();
    }
    let state = p.funder.info(cid).unwrap().state_number;
    let revoked = p.funder.signed_commitment(cid, state - 1).unwrap();
    // The victim stops; the cheater's revoked commitment confirms, and a few
    // blocks follow, fewer than the delay.
    let Pair { acceptor, .. } = p;
    drop(acceptor);
    let committed_at = {
        let mut c = chain.lock().unwrap();
        c.mine(std::slice::from_ref(&revoked));
        let h = c.height();
        for _ in 0..4 {
            c.mine(&[]);
        }
        h
    };
    let sweep = Hash256([0x7du8; 32]);
    let victim = restart_and_rescan(
        acceptor_seed,
        &dir.join("acceptor"),
        acceptor_hooks(chain.clone(), sweep),
        &chain,
    );
    let to_local = to_local_of(&revoked);
    let paid = spender_of(&chain, &to_local, 2).expect("the penalty confirmed");
    assert_eq!(
        paid.pubkey_hash, sweep,
        "the cheater's to_local went to the victim"
    );
    assert!(chain.lock().unwrap().height() < committed_at + u64::from(DELAY));
    drive(&victim, &chain);
    assert_eq!(victim.info(cid).unwrap().phase, Phase::Closed);
}

/// A node killed after broadcasting a penalty, before it confirmed, lost it
/// with its mempool. On restart the rescan rebuilds and broadcasts it, and it
/// confirms.
#[test]
#[cfg(feature = "audit")]
fn a_penalty_lost_in_a_crash_is_broadcast_again_on_restart() {
    let funder_seed = [0xb3u8; 32];
    let acceptor_seed = [0xb4u8; 32];
    let (mut p, _wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, acceptor_seed, "rescan-lost-penalty");
    for amt in [500_000u64, 500_000] {
        let m = p.funder.pay(cid, amt).unwrap();
        p.queue.push_back((1, m));
        p.pump();
    }
    let state = p.funder.info(cid).unwrap().state_number;
    let revoked = p.funder.signed_commitment(cid, state - 1).unwrap();
    let Pair { acceptor, .. } = p;
    drop(acceptor);
    // The victim sees the revoked commitment and broadcasts a penalty that
    // never confirms, then is killed.
    let (victim, sent) = relaying_manager(acceptor_seed, &dir.join("acceptor"), Hash256([1; 32]));
    let h = {
        let mut c = chain.lock().unwrap();
        c.mine(std::slice::from_ref(&revoked));
        c.height()
    };
    victim.on_connected_block(std::slice::from_ref(&revoked), h, &|_| None);
    assert_eq!(sent.lock().unwrap().len(), 1, "the penalty went out");
    drop(victim);
    chain.lock().unwrap().mine(&[]);
    let sweep = Hash256([0x7eu8; 32]);
    let victim = restart_and_rescan(
        acceptor_seed,
        &dir.join("acceptor"),
        acceptor_hooks(chain.clone(), sweep),
        &chain,
    );
    let paid = spender_of(&chain, &to_local_of(&revoked), 2).expect("the penalty confirmed");
    assert_eq!(paid.pubkey_hash, sweep);
    drive(&victim, &chain);
    assert_eq!(victim.info(cid).unwrap().phase, Phase::Closed);
}

/// A cooperative close confirms while one side is down — the side that only
/// signed it, or the closer, killed before it confirmed. On restart either
/// ends closed, its payout credited on chain.
#[test]
fn a_close_confirmed_while_down_settles_on_restart() {
    for closer_down in [false, true] {
        let funder_seed = [0xb5u8; 32];
        let acceptor_seed = [0xb6u8; 32];
        let tag = format!("rescan-close-{closer_down}");
        let (mut p, wallet, chain, dir, cid, capacity) =
            open_channel(funder_seed, acceptor_seed, &tag);
        let m = p.funder.pay(cid, 450_000).unwrap();
        p.queue.push_back((1, m));
        p.pump();
        // The close is signed by both; the funder's hook mines it at once.
        let close = p.funder.close(cid).unwrap().expect("a close frame");
        p.queue.push_back((1, close));
        p.pump();
        chain.lock().unwrap().mine(&[]);
        assert_eq!(held(&chain, ACCEPTOR_PAYOUT), 450_000);
        assert_eq!(held(&chain, FUNDER_PAYOUT), capacity - 450_000 - CLOSE_FEE);
        // Neither manager saw the confirming block; the one that was down
        // restarts.
        let Pair {
            funder, acceptor, ..
        } = p;
        drop(funder);
        drop(acceptor);
        let back = if closer_down {
            restart_and_rescan(
                funder_seed,
                &dir.join("funder"),
                funder_hooks(wallet, chain.clone()),
                &chain,
            )
        } else {
            restart_and_rescan(
                acceptor_seed,
                &dir.join("acceptor"),
                acceptor_hooks(chain.clone(), Hash256([0x5e; 32])),
                &chain,
            )
        };
        assert_eq!(
            back.info(cid).unwrap().phase,
            Phase::Closed,
            "closer_down={closer_down}"
        );
    }
}

/// The closer killed after the close was signed by both, before it confirmed,
/// with its mempool lost: on restart the close, rebuilt from the journal, is
/// broadcast again and confirms.
#[test]
fn an_unconfirmed_close_is_broadcast_again_on_restart() {
    let funder_seed = [0xb7u8; 32];
    let (mut p, wallet, chain, dir, cid, capacity) =
        open_channel(funder_seed, [0xb8u8; 32], "rescan-close-lost");
    let m = p.funder.pay(cid, 300_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    // The funder restarts with broadcasts that go nowhere: its close never
    // reaches a block.
    let (lost, _sent) = relaying_manager(funder_seed, &dir.join("funder"), Hash256([2; 32]));
    p.funder = lost;
    reconnect(&mut p);
    let close = p.funder.close(cid).unwrap().expect("a close frame");
    let signed = p.acceptor.deliver(F_PEER, "", &close);
    assert_eq!(signed.penalize, 0);
    for f in signed.frames {
        assert_eq!(p.funder.deliver(A_PEER, "", &f).penalize, 0);
    }
    assert_eq!(
        held(&chain, ACCEPTOR_PAYOUT),
        0,
        "the close did not confirm"
    );
    let Pair { funder, .. } = p;
    drop(funder);
    let back = restart_and_rescan(
        funder_seed,
        &dir.join("funder"),
        funder_hooks(wallet, chain.clone()),
        &chain,
    );
    assert_eq!(
        held(&chain, ACCEPTOR_PAYOUT),
        300_000,
        "the close confirmed"
    );
    assert_eq!(held(&chain, FUNDER_PAYOUT), capacity - 300_000 - CLOSE_FEE);
    drive(&back, &chain);
    assert_eq!(back.info(cid).unwrap().phase, Phase::Closed);
}

/// Our own commitment confirmed and the node went down: on restart past the
/// delay, the rescan schedules the delayed sweep and it is broadcast at once.
#[test]
fn our_commitment_confirmed_while_down_is_swept_on_restart() {
    let funder_seed = [0xb9u8; 32];
    let (mut p, wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, [0xbau8; 32], "rescan-own-commitment");
    let m = p.funder.pay(cid, 800_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    let commitment = p.funder.force_close(cid).unwrap();
    let Pair { funder, .. } = p;
    drop(funder);
    for _ in 0..DELAY {
        chain.lock().unwrap().mine(&[]);
    }
    let before = held(&chain, FUNDER_PAYOUT);
    let back = restart_and_rescan(
        funder_seed,
        &dir.join("funder"),
        funder_hooks(wallet, chain.clone()),
        &chain,
    );
    let swept = held(&chain, FUNDER_PAYOUT) - before;
    let to_local = commitment.outputs[to_local_of(&commitment).index as usize]
        .value
        .units();
    assert_eq!(swept, to_local - CLOSE_FEE, "the delayed sweep confirmed");
    drive(&back, &chain);
    assert_eq!(back.info(cid).unwrap().phase, Phase::Closed);
}

/// Our own commitment confirms, but it was a revoked one (a journal restored
/// from an old copy), and the counterparty's penalty takes its to_local before
/// the delay. The channel settles instead of waiting forever for a sweep that
/// can never confirm — and no sweep is attempted, live or in a startup rescan.
#[test]
#[cfg(feature = "audit")]
fn a_to_local_taken_by_a_penalty_settles_our_side() {
    let funder_seed = [0xbbu8; 32];
    let (mut p, _wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, [0xbcu8; 32], "taken-to-local");
    for amt in [600_000u64, 600_000] {
        let m = p.funder.pay(cid, amt).unwrap();
        p.queue.push_back((1, m));
        p.pump();
    }
    let state = p.funder.info(cid).unwrap().state_number;
    let revoked = p.funder.signed_commitment(cid, state - 1).unwrap();
    // The commitment confirms and the acceptor's penalty follows (its hook
    // mines it at once).
    let h = {
        let mut c = chain.lock().unwrap();
        c.mine(std::slice::from_ref(&revoked));
        c.height()
    };
    p.acceptor
        .on_funding_spend(cid, &revoked)
        .expect("the acceptor punishes");
    let penalty_block = chain.lock().unwrap().last_txs.clone();
    for _ in 0..DELAY {
        chain.lock().unwrap().mine(&[]);
    }
    let Pair { funder, .. } = p;
    drop(funder);
    // A copy of the funder's journals for the rescan variant below.
    let copy = dir.join("funder-copy");
    std::fs::create_dir_all(&copy).unwrap();
    for e in std::fs::read_dir(dir.join("funder")).unwrap().flatten() {
        std::fs::copy(e.path(), copy.join(e.file_name())).unwrap();
    }
    // Live: the funder sees its commitment, then the penalty, then the delay.
    let (live, sent) = relaying_manager(funder_seed, &dir.join("funder"), Hash256([3; 32]));
    live.on_connected_block(std::slice::from_ref(&revoked), h, &|_| None);
    live.on_connected_block(&penalty_block, h + 1, &|_| None);
    for k in 2..=u64::from(DELAY) + 2 {
        live.on_connected_block(&[], h + k, &|_| None);
    }
    assert_eq!(live.info(cid).unwrap().phase, Phase::Closed);
    assert!(sent.lock().unwrap().is_empty(), "a sweep of a spent output");
    drop(live);
    // And through a startup rescan of the same blocks.
    let (back, sent) = relaying_manager(funder_seed, &copy, Hash256([3; 32]));
    assert_eq!(back.info(cid).unwrap().phase, Phase::Open);
    let tip = chain.lock().unwrap().height();
    let c1 = chain.clone();
    let txs_at = move |h: u64| c1.lock().unwrap().chain.block_at(h).map(|b| b.transactions);
    let c2 = chain.clone();
    back.rescan(tip, &txs_at, &move |op: &OutPoint| chain_depth(&c2, op));
    assert!(sent.lock().unwrap().is_empty());
    assert_eq!(back.info(cid).unwrap().phase, Phase::Closed);
}

// --- Funding: broadcast only once the funder can get its capacity back -------

/// The funder signs the funding transaction when the acceptor accepts, but
/// broadcasts it only once it holds the acceptor's signature over its first
/// commitment; a replayed Accept funds nothing a second time.
#[test]
fn funding_is_broadcast_only_after_funding_signed_and_only_once() {
    let funder_seed = [0xc5u8; 32];
    let acceptor_seed = [0xc6u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("funding-order");
    std::fs::create_dir_all(dir.join("f")).unwrap();
    std::fs::create_dir_all(dir.join("a")).unwrap();
    let built = Arc::new(Mutex::new(0usize));
    let sent: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
    let real = funder_hooks(wallet, chain.clone());
    let (b1, s1) = (built.clone(), sent.clone());
    let fund = real.fund;
    let funder = ChannelManager::new(
        NET,
        RATE,
        funder_seed,
        dir.join("f"),
        DELAY,
        DEPTH,
        Hooks {
            fund: Box::new(move |cid, out| {
                *b1.lock().unwrap() += 1;
                fund(cid, out)
            }),
            broadcast: Box::new(move |tx| {
                s1.lock().unwrap().push(tx.clone());
                Ok(())
            }),
            sweep_address: real.sweep_address,
            payout_address: real.payout_address,
            replace: real.replace,
        },
    );
    let acceptor = ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        dir.join("a"),
        DELAY,
        DEPTH,
        acceptor_hooks(chain, Hash256([0x5e; 32])),
    );
    let one = |r: q21_core::channel::manager::Reaction| -> Vec<u8> {
        assert_eq!(r.penalize, 0);
        assert_eq!(r.frames.len(), 1);
        r.frames.into_iter().next().unwrap()
    };
    let hello = funder
        .open(A_PEER, "", 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    let hello_back = one(acceptor.deliver(F_PEER, "", &hello));
    let open = one(funder.deliver(A_PEER, "", &hello_back));
    let accept = one(acceptor.deliver(F_PEER, "", &open));
    let funding = one(funder.deliver(A_PEER, "", &accept));
    assert_eq!(*built.lock().unwrap(), 1);
    assert!(
        sent.lock().unwrap().is_empty(),
        "funding broadcast before FundingSigned"
    );
    // The same Accept again: the same Funding, nothing built or sent.
    let again = one(funder.deliver(A_PEER, "", &accept));
    assert_eq!(again, funding);
    assert_eq!(*built.lock().unwrap(), 1, "a replayed Accept funded again");
    assert!(sent.lock().unwrap().is_empty());
    let signed = one(acceptor.deliver(F_PEER, "", &funding));
    let r = funder.deliver(A_PEER, "", &signed);
    assert_eq!(r.penalize, 0);
    let first = {
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "the funding goes out after FundingSigned");
        sent[0].clone()
    };
    let cid = funder.list()[0].channel_id;
    assert_eq!(
        Some(first.txid()),
        funder.info(cid).and_then(|i| i.funding).map(|o| o.txid)
    );
    // Killed before the funding confirmed, its mempool lost: the restarted
    // funder broadcasts it again from its journal.
    drop(funder);
    let (back, again) = relaying_manager(funder_seed, &dir.join("f"), Hash256([4; 32]));
    back.rescan(500, &|_| None, &|_| None);
    assert_eq!(again.lock().unwrap().len(), 1);
    assert_eq!(again.lock().unwrap()[0].1, first);
}

/// The acceptor opens a channel only on the real funding output: when the
/// outpoint the funder named holds anything but the 2-of-2 policy output for
/// the whole capacity, the channel never opens, however deep it is buried.
#[test]
fn a_channel_opens_only_on_its_real_funding_output() {
    let funder_seed = [0xc7u8; 32];
    let acceptor_seed = [0xc8u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("fake-funding");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet,
        chain,
        Hash256([0x5e; 32]),
        &dir,
    );
    let capacity = 4 * MIN_OUTPUT_VALUE * 10;
    let hello = p.funder.open(A_PEER, "", capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.acceptor.list()[0].channel_id;
    let real = p.acceptor.list()[0].funding.is_some();
    assert!(real, "the acceptor learned the funding outpoint");
    let funding_output = TxOut {
        value: Amount::from_units(capacity),
        ..p.funder_funding_output(cid)
    };
    let wrong = [
        // An ordinary key output of the right value.
        TxOut {
            scheme: SchemeId::MlDsa87,
            ..funding_output
        },
        // The right policy, too little.
        TxOut {
            value: Amount::from_units(capacity - 1),
            ..funding_output
        },
        // Another policy.
        TxOut {
            pubkey_hash: Hash256([0x42; 32]),
            ..funding_output
        },
    ];
    for out in wrong {
        p.acceptor
            .on_connected_block(&[], 900, &|_| Some((50, out)));
        assert_eq!(p.acceptor.info(cid).unwrap().phase, Phase::Opening);
    }
    p.acceptor
        .on_connected_block(&[], 900, &|_| Some((50, funding_output)));
    assert_eq!(p.acceptor.info(cid).unwrap().phase, Phase::Open);
}

/// A connection that merely announces the counterparty's identity gets
/// nothing acted on — not even an unsigned Close — and a reestablish captured
/// from an earlier exchange, replayed on another connection or after a
/// restart, binds nothing: only the answer to a challenge we issued on that
/// connection does.
#[test]
fn only_an_answered_challenge_authenticates_a_connection() {
    let funder_seed = [0xedu8; 32];
    let (mut p, wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, [0xeeu8; 32], "auth-challenge");
    const IMPOSTOR: u64 = 66;
    // The impostor claims the acceptor's identity. Its Close is ignored.
    // Whatever the funder challenges it with, it cannot answer.
    let _ = p.funder.on_peer_connected(IMPOSTOR, "acceptor-node");
    let close = [
        cid.as_bytes().as_slice(),
        &[0u8],
        &q21_core::channel::Message::Close { fee: 20_000 }.encode(),
    ]
    .concat();
    let r = p.funder.deliver(IMPOSTOR, "acceptor-node", &close);
    assert_eq!(r.penalize, 0);
    assert!(r.frames.is_empty());
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Open);
    assert_eq!(p.funder.peer_of(cid), Some(A_PEER));

    // A real reconnect: capture the acceptor's answer to the funder's
    // challenge, and let the exchange complete.
    let mut captured = None;
    let mut queue: VecDeque<(u64, Vec<u8>)> = p
        .funder
        .on_peer_connected(A_PEER, "")
        .into_iter()
        .map(|f| (1, f))
        .collect();
    while let Some((to, frame)) = queue.pop_front() {
        let r = if to == 1 {
            p.acceptor.deliver(F_PEER, "", &frame)
        } else {
            if frame[32] == 0 && captured.is_none() && frame.len() > 1000 {
                captured = Some(frame.clone());
            }
            p.funder.deliver(A_PEER, "", &frame)
        };
        assert_eq!(r.penalize, 0);
        queue.extend(r.frames.into_iter().map(|f| (1 - to, f)));
    }
    let captured = captured.expect("the acceptor's reestablish");
    // Replayed on another connection: ignored, nothing rebound.
    let r = p.funder.deliver(IMPOSTOR, "acceptor-node", &captured);
    assert!(r.frames.is_empty());
    assert_eq!(p.funder.peer_of(cid), Some(A_PEER));
    // Replayed to the funder after its restart, even on the same id: the
    // funder never issued that challenge, so it binds nothing.
    p.reload_funder(funder_seed, wallet, chain, &dir);
    let r = p.funder.deliver(A_PEER, "", &captured);
    assert!(r.frames.is_empty());
    assert_ne!(p.funder.peer_of(cid), Some(A_PEER));
    assert!(p.funder.pay(cid, 1).is_err(), "unauthenticated");
}

// --- Hello spam -------------------------------------------------------------

/// Hellos that never lead to a channel spend nothing persistent: no key index
/// and no wallet address each. A flood of them used to push a real channel's
/// key index past the reload search, losing the channel at the next restart;
/// the index is now derived, journaled, and found directly.
#[test]
fn hello_spam_spends_nothing_and_a_real_channel_still_reloads() {
    let funder_seed = [0xd5u8; 32];
    let acceptor_seed = [0xd6u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("hello-spam");
    std::fs::create_dir_all(dir.join("a")).unwrap();
    let addresses = Arc::new(Mutex::new(0usize));
    let counted = |chain: Arc<Mutex<SharedChain>>| {
        let n = addresses.clone();
        let mut h = acceptor_hooks(chain, Hash256([0x5e; 32]));
        h.payout_address = Box::new(move || {
            *n.lock().unwrap() += 1;
            ACCEPTOR_PAYOUT
        });
        h
    };
    let acceptor = ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        dir.join("a"),
        DELAY,
        DEPTH,
        counted(chain.clone()),
    );
    acceptor.set_pending_open_ttl(std::time::Duration::ZERO);
    let spammer = one_manager([0xd7u8; 32], wallet.clone(), chain.clone(), &dir.join("s"));
    let hello = spammer
        .open(1, "", 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    for conn in 0..1_200u64 {
        let r = acceptor.deliver(10_000 + conn, "", &hello);
        assert_eq!(r.penalize, 0);
    }
    assert_eq!(
        *addresses.lock().unwrap(),
        1,
        "one spare address, offered again"
    );
    acceptor.set_pending_open_ttl(q21_core::channel::manager::PENDING_OPEN_TTL);

    // A real channel after the flood.
    let funder = one_manager(funder_seed, wallet, chain.clone(), &dir.join("f"));
    let mut p = Pair {
        funder,
        acceptor,
        queue: VecDeque::new(),
    };
    let hello = p
        .funder
        .open(A_PEER, "", 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    assert!(p.acceptor.info(cid).is_some());
    let Pair { acceptor, .. } = p;
    drop(acceptor);
    let back = ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        dir.join("a"),
        DELAY,
        DEPTH,
        counted(chain),
    );
    assert!(
        back.info(cid).is_some(),
        "the channel reloads after the flood"
    );
}

/// Opens in progress are bounded per announced identity too, whatever the
/// number of connections it comes on.
#[test]
fn pending_opens_are_bounded_per_identity() {
    use q21_core::channel::manager::MAX_PENDING_PER_IDENTITY;
    let (wallet, chain) = setup([0xd8u8; 32]);
    let dir = tmpdir("hello-identity");
    let acceptor = one_manager([0xd9u8; 32], wallet.clone(), chain.clone(), &dir.join("a"));
    let spammer = one_manager([0xdau8; 32], wallet, chain, &dir.join("s"));
    let hello = spammer
        .open(1, "", 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    for conn in 0..(MAX_PENDING_PER_IDENTITY as u64 + 3) {
        let r = acceptor.deliver(50 + conn, "the-same-node", &hello);
        assert_eq!(r.penalize, 0);
        assert_eq!(
            r.frames.is_empty(),
            conn >= MAX_PENDING_PER_IDENTITY as u64,
            "connection {conn}"
        );
    }
    assert_eq!(acceptor.pending_opens().1, MAX_PENDING_PER_IDENTITY);
}

// --- Unfunded channels ------------------------------------------------------

/// A channel whose funding never comes is forgotten after a while, its
/// journal deleted, when nothing of ours is at stake: on the acceptor's side,
/// and on the funder's before it ever broadcast the funding. A funder that
/// did broadcast keeps it.
#[test]
fn unfunded_channels_expire_when_nothing_is_at_stake() {
    let funder_seed = [0xdbu8; 32];
    let acceptor_seed = [0xdcu8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("unfunded-expiry");
    let p = managers(
        funder_seed,
        acceptor_seed,
        wallet,
        chain,
        Hash256([0x5e; 32]),
        &dir,
    );
    let one = |r: q21_core::channel::manager::Reaction| -> Vec<u8> {
        assert_eq!(r.penalize, 0);
        r.frames.into_iter().next().expect("a frame")
    };
    // Opened as far as the acceptor's Accept; the funder never answers.
    let hello = p
        .funder
        .open(A_PEER, "", 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    let hello_back = one(p.acceptor.deliver(F_PEER, "", &hello));
    let open = one(p.funder.deliver(A_PEER, "", &hello_back));
    let _accept = one(p.acceptor.deliver(F_PEER, "", &open));
    let cid = p.acceptor.list()[0].channel_id;
    let journals = |side: &str| {
        std::fs::read_dir(dir.join(side))
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "jrnl"))
            .count()
    };
    assert_eq!((journals("acceptor"), journals("funder")), (1, 1));
    // Not yet expired.
    p.acceptor.on_connected_block(&[], 900, &|_| None);
    assert!(p.acceptor.info(cid).is_some());
    // Expired: forgotten on both sides, journals gone.
    p.acceptor.set_unfunded_ttl(std::time::Duration::ZERO);
    p.funder.set_unfunded_ttl(std::time::Duration::ZERO);
    p.acceptor.on_connected_block(&[], 901, &|_| None);
    p.funder.on_connected_block(&[], 901, &|_| None);
    assert!(p.acceptor.info(cid).is_none());
    assert!(p.funder.info(cid).is_none());
    assert_eq!((journals("acceptor"), journals("funder")), (0, 0));
}

/// A funder that broadcast its funding keeps the channel, however long the
/// funding takes: its commitment is how the capacity comes back.
#[test]
fn a_broadcast_funding_is_never_forgotten() {
    let funder_seed = [0xddu8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("unfunded-kept");
    std::fs::create_dir_all(dir.join("funder")).unwrap();
    std::fs::create_dir_all(dir.join("acceptor")).unwrap();
    let acceptor = ChannelManager::new(
        NET,
        RATE,
        [0xdeu8; 32],
        dir.join("acceptor"),
        DELAY,
        DEPTH,
        acceptor_hooks(chain.clone(), Hash256([0x5e; 32])),
    );
    // Broadcasts go nowhere: the funding never confirms.
    let funder = ChannelManager::new(
        NET,
        RATE,
        funder_seed,
        dir.join("funder"),
        DELAY,
        DEPTH,
        Hooks {
            broadcast: Box::new(|_| Ok(())),
            ..funder_hooks(wallet, chain)
        },
    );
    let mut p = Pair {
        funder,
        acceptor,
        queue: VecDeque::new(),
    };
    let hello = p
        .funder
        .open(A_PEER, "", 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Funded);
    p.funder.set_unfunded_ttl(std::time::Duration::ZERO);
    p.funder.on_connected_block(&[], 901, &|_| None);
    assert!(
        p.funder.info(cid).is_some(),
        "a broadcast funding was forgotten"
    );
}

/// The channels waiting for their funding are bounded across all peers.
#[test]
fn unfunded_channels_are_bounded() {
    use q21_core::channel::manager::MAX_UNFUNDED_CHANNELS;
    let (wallet, chain) = setup([0xdfu8; 32]);
    let dir = tmpdir("unfunded-cap");
    let acceptor = one_manager([0xe0u8; 32], wallet.clone(), chain.clone(), &dir.join("a"));
    let spammer = one_manager([0xe3u8; 32], wallet, chain, &dir.join("s"));
    let mut opened = 0;
    for k in 0..(MAX_UNFUNDED_CHANNELS as u64 + 3) {
        let hello = spammer.open(k, "", 4 * MIN_OUTPUT_VALUE * 10, None, None);
        let Ok(hello) = hello else { break };
        let r = acceptor.deliver(1_000 + k, "", &hello);
        let Some(back) = r.frames.into_iter().next() else {
            continue;
        };
        let r = spammer.deliver(k, "", &back);
        if let Some(open) = r.frames.into_iter().next() {
            if !acceptor.deliver(1_000 + k, "", &open).frames.is_empty() {
                opened += 1;
            }
        }
    }
    assert_eq!(opened, MAX_UNFUNDED_CHANNELS);
    assert_eq!(acceptor.list().len(), MAX_UNFUNDED_CHANNELS);
}

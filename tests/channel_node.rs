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
use q21_core::channel::keys::{funding_key_seed, ChannelKey, Signer};
use q21_core::channel::machine::{channel_id, Phase};
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
    fn depth_of(&self, op: &OutPoint) -> Option<u64> {
        let h = self.chain.height();
        self.chain
            .utxo
            .get(op)
            .map(|e| h.saturating_sub(e.height).saturating_add(1))
    }
}

fn chan_hash(seed: &[u8; 32], index: u32) -> Hash256 {
    ChannelKey::from_seed(&funding_key_seed(seed, index)).pubkey_hash()
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

fn chain_depth(chain: &Arc<Mutex<SharedChain>>, op: &OutPoint) -> Option<u64> {
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
        move |_cid: Hash256, funding_output: TxOut| -> Result<OutPoint, String> {
            let mut w = w1.lock().unwrap();
            let mut c = c1.lock().unwrap();
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
            let tx = w
                .sign_spend(&c.chain.utxo, prepared)
                .map_err(|e| format!("{e:?}"))?;
            let txid = tx.txid();
            c.mine(std::slice::from_ref(&tx));
            Ok(OutPoint { txid, index: 0 })
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
        sweep_address: Box::new(|| Hash256([0x5e; 32])),
    }
}

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
    }
}

struct Pair {
    funder: ChannelManager,
    acceptor: ChannelManager,
    queue: VecDeque<(u64, Vec<u8>)>, // (destination node: 0 funder / 1 acceptor, frame)
}

impl Pair {
    /// Drives every queued frame to quiescence, asserting no misconduct.
    fn pump(&mut self) {
        let mut steps = 0;
        while let Some((to, frame)) = self.queue.pop_front() {
            steps += 1;
            assert!(steps < 1000, "protocol did not settle");
            let r = if to == 1 {
                self.acceptor.deliver(F_PEER, &frame)
            } else {
                self.funder.deliver(A_PEER, &frame)
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();

    let cid = channel_id(&[chan_hash(&funder_seed, 0), chan_hash(&acceptor_seed, 0)]);
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
    let close = p.funder.close(cid).unwrap();
    p.queue.push_back((1, close));
    p.pump();
    let after_h = chain.lock().unwrap().height();
    assert!(after_h > before_h, "close mined");

    // On-chain outcomes: the funder's channel-key output less the close fee,
    // the acceptor's channel-key output, exact to the unit.
    let f_hash = chan_hash(&funder_seed, 0);
    let a_hash = chan_hash(&acceptor_seed, 0);
    let got = |hash: Hash256| -> u64 {
        let c = chain.lock().unwrap();
        c.chain
            .utxo
            .iter()
            .filter(|(_, e)| e.output.scheme == SchemeId::MlDsa87 && e.output.pubkey_hash == hash)
            .map(|(_, e)| e.output.value.units())
            .sum()
    };
    let gf = got(f_hash);
    let ga = got(a_hash);
    assert_eq!(gf, capacity - 1_100_000 - CLOSE_FEE, "funder on chain");
    assert_eq!(ga, 1_100_000, "acceptor on chain");
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = channel_id(&[chan_hash(&funder_seed, 0), chan_hash(&acceptor_seed, 0)]);
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = channel_id(&[chan_hash(&funder_seed, 0), chan_hash(&acceptor_seed, 0)]);
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = channel_id(&[chan_hash(&funder_seed, 0), chan_hash(&acceptor_seed, 0)]);
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
    let sweep = Hash256([0x5e; 32]);
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = channel_id(&[chan_hash(&funder_seed, 0), chan_hash(&acceptor_seed, 0)]);
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = channel_id(&[chan_hash(&funder_seed, 0), chan_hash(&acceptor_seed, 0)]);
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = channel_id(&[chan_hash(&funder_seed, 0), chan_hash(&acceptor_seed, 0)]);
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
    let dropped = p.acceptor.deliver(F_PEER, &upd);
    assert_eq!(dropped.penalize, 0, "the update was well formed");
    assert!(!dropped.frames.is_empty(), "the acceptor produced an ack");
    // ... and we deliberately do not deliver it.

    // Reconnect: the node's handshake hook asks each side to resync.
    for f in p.funder.on_peer_connected(A_PEER) {
        p.queue.push_back((1, f));
    }
    for f in p.acceptor.on_peer_connected(F_PEER) {
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

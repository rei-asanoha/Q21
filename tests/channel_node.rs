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

/// Buries the tip to the funding depth, driving each manager at every block:
/// a channel's last transaction settles it only once that deep.
fn bury(mgrs: &[&ChannelManager], chain: &Arc<Mutex<SharedChain>>) {
    for _ in 1..DEPTH {
        chain.lock().unwrap().mine(&[]);
        for m in mgrs {
            drive(m, chain);
        }
    }
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
    let broadcast = mining_broadcast(chain.clone());
    Hooks {
        fund,
        broadcast,
        sweep_address: Box::new(|| FUNDER_PAYOUT),
        payout_address: Box::new(|| FUNDER_PAYOUT),
        reserve: wallet_reserve(wallet),
    }
}

/// A broadcast hook that mines the transaction at once when it is valid
/// against the chain, and refuses it otherwise, as a mempool would: one
/// announced again after it confirmed spends what is already spent.
fn mining_broadcast(
    chain: Arc<Mutex<SharedChain>>,
) -> Box<q21_core::channel::manager::BroadcastFn> {
    Box::new(move |tx: &Transaction| {
        let mut c = chain.lock().unwrap();
        if tx
            .inputs
            .iter()
            .any(|i| c.chain.utxo.get(&i.prev_out).is_none())
        {
            return Err("missing input".into());
        }
        c.mine(std::slice::from_ref(tx));
        Ok(())
    })
}

/// Feeds a manager every block from `from` to the tip, as the node's block
/// hook does, and returns the frames it wants sent.
fn catch_up(mgr: &ChannelManager, chain: &Arc<Mutex<SharedChain>>, from: u64) {
    let mut h = from;
    loop {
        let (txs, tip) = {
            let c = chain.lock().unwrap();
            (
                c.chain.block_at(h).map(|b| b.transactions),
                c.chain.height(),
            )
        };
        if h > tip {
            break;
        }
        let c = chain.clone();
        let depth_of = move |op: &OutPoint| chain_depth(&c, op);
        mgr.on_connected_block(&txs.unwrap_or_default(), h, &depth_of);
        h += 1;
    }
}

/// What a victim recovered from a revoked two-output commitment: the
/// penalty's output (the cheater's to_local) and the claim of its own
/// to_remote, both paying `sweep`. Asserts the claim recovered the victim's
/// own balance less the claim fee.
fn assert_victim_made_whole(
    chain: &Arc<Mutex<SharedChain>>,
    revoked: &Transaction,
    sweep: Hash256,
) {
    let own = revoked
        .outputs
        .iter()
        .position(|o| o.scheme != SchemeId::Policy)
        .expect("the victim's to_remote");
    let own_value = revoked.outputs[own].value.units();
    let back = chain.lock().unwrap().height();
    let claim = spender_of(
        chain,
        &OutPoint {
            txid: revoked.txid(),
            index: own as u32,
        },
        back,
    )
    .expect("the victim's own to_remote was claimed");
    assert_eq!(claim.pubkey_hash, sweep, "claimed to the wallet");
    assert_eq!(claim.value.units(), own_value - CLOSE_FEE);
    let penalty = spender_of(chain, &to_local_of(revoked), back).expect("the penalty confirmed");
    assert_eq!(penalty.pubkey_hash, sweep);
    assert_eq!(
        paid_to(chain, sweep),
        claim.value.units() + penalty.value.units(),
        "the victim's wallet holds both"
    );
}

/// The reserve hook a node installs: the funding's coins locked in the
/// wallet, or released.
fn wallet_reserve(wallet: Arc<Mutex<Wallet>>) -> Box<q21_core::channel::manager::ReserveFn> {
    Box::new(move |tx: &Transaction, hold: bool| {
        let coins: Vec<OutPoint> = tx.inputs.iter().map(|i| i.prev_out).collect();
        let mut w = wallet.lock().unwrap();
        if hold {
            w.lock_coins(&coins);
        } else {
            w.unlock_coins(&coins);
        }
    })
}

/// The funder's cooperative-close / sweep payout address in these tests.
const FUNDER_PAYOUT: Hash256 = Hash256([0xf0; 32]);
/// The acceptor's cooperative-close payout address in these tests.
const ACCEPTOR_PAYOUT: Hash256 = Hash256([0xa0; 32]);

/// The acceptor's hooks: it never funds; it broadcasts penalties/claims.
fn acceptor_hooks(chain: Arc<Mutex<SharedChain>>, sweep: Hash256) -> Hooks {
    Hooks {
        fund: Box::new(|_, _| Err("acceptor does not fund".into())),
        broadcast: mining_broadcast(chain),
        sweep_address: Box::new(move || sweep),
        payout_address: Box::new(|| ACCEPTOR_PAYOUT),
        reserve: Box::new(|_, _| {}),
    }
}

struct Pair {
    funder: ChannelManager,
    acceptor: ChannelManager,
    queue: VecDeque<(u64, Vec<u8>)>, // (destination node: 0 funder / 1 acceptor, frame)
}

/// A fresh session binding value, as the transport derives one per session:
/// never the same twice.
fn next_binding() -> [u8; 32] {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    q21_core::hash::tagged_hash_parts(
        "test/binding",
        &[&n.to_le_bytes(), &std::process::id().to_le_bytes()],
    )
    .0
}

/// A node id for test peer number `n`.
fn id_of(n: u64) -> String {
    format!("{n:064x}")
}

/// Registers a session on connection `peer` of `mgr`, authenticated as
/// `identity`, as the transport does once a handshake completes. Returns the
/// reestablish frames the manager wants sent on it.
fn session(mgr: &ChannelManager, peer: u64, identity: &str) -> Vec<Vec<u8>> {
    mgr.on_session(peer, identity, "", next_binding())
}

impl Pair {
    /// A new session between the two, as the transport establishes one after
    /// a (re)connection: each learns the other's node id and the session's
    /// binding, and the reestablish frames both produce are queued.
    fn reconnect(&mut self) {
        let binding = next_binding();
        let (fid, aid) = (self.funder.node_id(), self.acceptor.node_id());
        for f in self.funder.on_session(A_PEER, &aid, "", binding) {
            self.queue.push_back((1, f));
        }
        for f in self.acceptor.on_session(F_PEER, &fid, "", binding) {
            self.queue.push_back((0, f));
        }
    }

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
    let mut p = Pair {
        funder,
        acceptor,
        queue: VecDeque::new(),
    };
    p.reconnect();
    p.reconnect();
    p
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
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
    // And its own balance in that state, from its channel key to its wallet.
    assert_victim_made_whole(&chain, &revoked, sweep);
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
    p.reconnect();
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
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
    bury(&[&p.funder], &chain);
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
/// new session registered with `on_session`) resyncs both sides to the same
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
    let dropped = p.acceptor.deliver(F_PEER, &upd);
    assert_eq!(dropped.penalize, 0, "the update was well formed");
    assert!(!dropped.frames.is_empty(), "the acceptor produced an ack");
    // ... and we deliberately do not deliver it.

    // Reconnect: the node's handshake hook asks each side to resync.
    p.reconnect();
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
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
    p.reconnect();
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
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
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
    p.reconnect();
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
    assert_eq!(p.funder.info(cid).unwrap().close_txid, None);
    drive(&p.funder, &chain);
    drive(&p.acceptor, &chain);
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Closing);
    // Both name the close and its height, for the wallet to count its
    // confirmations; the same transaction on both sides.
    let fi = p.funder.info(cid).unwrap();
    let ai = p.acceptor.info(cid).unwrap();
    assert!(fi.close_txid.is_some() && fi.close_height.is_some());
    assert_eq!(fi.close_txid, ai.close_txid);
    assert_eq!(fi.close_height, ai.close_height);
    assert!(fi.close_height.unwrap() <= chain.lock().unwrap().height());
    assert_eq!(fi.funding_depth, ai.funding_depth);
    bury(&[&p.funder, &p.acceptor], &chain);
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Closed);
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
    bury(&[&p.funder], &chain);
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
    let binding = next_binding();
    let frames = p
        .funder
        .on_session(A_PEER, &p.acceptor.node_id(), "", binding);
    assert!(!frames.is_empty());
    stranger.on_session(F_PEER, &p.funder.node_id(), "", binding);
    for f in frames {
        let r = stranger.deliver(F_PEER, &f);
        assert_eq!(r.penalize, 0, "a reestablish for an unknown channel");
        assert!(r.frames.is_empty());
    }
}

/// D11: a channel frame arriving on a session authenticated as another node
/// is not acted on, whatever connection it uses; a new session authenticated
/// as the counterparty, on another connection, takes the channel over once
/// its reestablish verifies, and the dropped payment completes there.
#[test]
fn only_the_counterpartys_session_moves_a_channel_to_another_connection() {
    let (p, _wallet, _chain, _dir, cid, _capacity) =
        open_channel([0xeau8; 32], [0xebu8; 32], "d11-rebind");
    const OTHER: u64 = 77;
    let m = p.funder.pay(cid, 400_000).unwrap();
    let _ = session(&p.acceptor, OTHER, &"ab".repeat(32));
    let r = p.acceptor.deliver(OTHER, &m);
    assert_eq!(r.penalize, 0);
    assert!(r.frames.is_empty(), "a frame from another node's session");
    assert_eq!(p.acceptor.info(cid).unwrap().local_balance, 0);
    assert_eq!(p.acceptor.peer_of(cid), Some(F_PEER));

    // The funder reconnects on the other connection: its reestablish proves
    // its funding key over the new session, the acceptor moves the channel
    // there, and the dropped payment completes.
    let binding = next_binding();
    let mut queue: VecDeque<(u64, Vec<u8>)> = p
        .acceptor
        .on_session(OTHER, &p.funder.node_id(), "", binding)
        .into_iter()
        .map(|f| (0, f))
        .chain(
            p.funder
                .on_session(A_PEER, &p.acceptor.node_id(), "", binding)
                .into_iter()
                .map(|f| (1, f)),
        )
        .collect();
    let mut steps = 0;
    while let Some((to, frame)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 100, "did not settle");
        let r = if to == 1 {
            p.acceptor.deliver(OTHER, &frame)
        } else {
            p.funder.deliver(A_PEER, &frame)
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

/// What a [`relaying_manager`] broadcast, in order.
type Sent = Arc<Mutex<Vec<Transaction>>>;

/// A manager reloaded from `dir` whose hooks relay without mining, so what it
/// broadcasts stays unconfirmed until the test confirms it.
fn relaying_manager(
    seed: [u8; 32],
    dir: &std::path::Path,
    sweep: Hash256,
) -> (ChannelManager, Sent) {
    let sent: Sent = Arc::new(Mutex::new(Vec::new()));
    let s1 = sent.clone();
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
                s1.lock().unwrap().push(tx.clone());
                Ok(())
            }),
            sweep_address: Box::new(move || sweep),
            payout_address: Box::new(|| ACCEPTOR_PAYOUT),
            reserve: Box::new(|_, _| {}),
        },
    );
    (mgr, sent)
}

/// M4: the network relays no replacement by fee, so a penalty cannot climb a
/// fee ladder outside the node that built it: the first version other pools
/// hold keeps every later one out. It pays the top fee from its first
/// broadcast instead, is announced again at every block while unconfirmed,
/// and settles once the revoked output is spent — by it, or by a version built
/// before a restart that pays another address.
#[test]
#[cfg(feature = "audit")]
fn an_unconfirmed_penalty_pays_the_top_fee_at_once_and_is_announced_again() {
    use q21_core::channel::txbuild::{penalty_fee, MAX_COMMIT_FEE_RATE, SWEEP_FEE};
    use q21_core::consensus::WITNESS_DISCOUNT;
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

    // The revoked commitment confirms at height h: the penalty goes out at
    // the top fee, not at a tier it could never climb from.
    let h = 1_000u64;
    victim.on_connected_block(std::slice::from_ref(&revoked), h, &no_depth);
    // With it, the claim of the victim's own to_remote there.
    assert_eq!(sent.lock().unwrap().len(), 2);
    let is_penalty = |t: &Transaction| t.inputs[0].prev_out == to_local_of(&revoked);
    let penalty = sent.lock().unwrap()[0].clone();
    let claim = sent.lock().unwrap()[1].clone();
    assert!(is_penalty(&penalty) && !is_penalty(&claim));
    let fee = fee_of(&penalty);
    assert!(fee > SWEEP_FEE, "more than a plain sweep");
    assert_eq!(fee, penalty_fee(&penalty));
    assert_eq!(
        fee * 1000 / penalty.weight(WITNESS_DISCOUNT),
        MAX_COMMIT_FEE_RATE,
        "the highest rate any commitment may pay"
    );
    assert_eq!(penalty.outputs[0].pubkey_hash, sweep);

    // Unconfirmed: the same transaction is announced again at every block,
    // past the cheater's delay too, never a conflicting version.
    let blocks = u64::from(DELAY) + 3;
    for k in 1..=blocks {
        victim.on_connected_block(&[], h + k, &no_depth);
    }
    let all = sent.lock().unwrap().clone();
    assert_eq!(
        all.len() as u64,
        2 * (1 + blocks),
        "both announced at every block"
    );
    assert!(all
        .iter()
        .all(|t| t.txid() == penalty.txid() || t.txid() == claim.txid()));
    assert_eq!(victim.info(cid).unwrap().phase, Phase::Penalised);

    // Both are valid spends on chain.
    chain.lock().unwrap().mine(std::slice::from_ref(&revoked));
    chain.lock().unwrap().mine(std::slice::from_ref(&penalty));
    chain.lock().unwrap().mine(std::slice::from_ref(&claim));
    assert_victim_made_whole(&chain, &revoked, sweep);

    // A penalty built before a restart, paying another address, settles it
    // just the same, without an alert.
    drop(victim);
    let (other, other_sent) =
        relaying_manager(acceptor_seed, &dir.join("acceptor"), Hash256([0x7c; 32]));
    other.on_connected_block(std::slice::from_ref(&revoked), h, &no_depth);
    let rebuilt = other_sent.lock().unwrap()[0].clone();
    assert_ne!(rebuilt.txid(), penalty.txid());
    // The penalty alone does not settle it: the claim is still awaited, and
    // announced again.
    other.on_connected_block(std::slice::from_ref(&penalty), h + 1, &no_depth);
    assert_eq!(other.info(cid).unwrap().phase, Phase::Penalised);
    assert_eq!(other_sent.lock().unwrap().len(), 3, "the claim, again");
    other.on_connected_block(std::slice::from_ref(&claim), h + 2, &no_depth);
    for k in 1..u64::from(DEPTH) {
        other.on_connected_block(&[], h + 2 + k, &no_depth);
    }
    assert_eq!(other.info(cid).unwrap().phase, Phase::Closed);
    assert_eq!(
        other_sent.lock().unwrap().len(),
        3,
        "nothing more once settled"
    );
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
        // Reclassified: the penalty of the cheater's to_local, and the claim
        // of the victim's own to_remote in the revoked commitment.
        let out = sent.lock().unwrap()[1..].to_vec();
        assert_eq!(out.len(), 2, "the penalty and the claim");
        let spends = |t: &Transaction, op: OutPoint| t.inputs[0].prev_out == op;
        let own = OutPoint {
            txid: revoked.txid(),
            index: revoked
                .outputs
                .iter()
                .position(|o| o.scheme != SchemeId::Policy)
                .unwrap() as u32,
        };
        let penalty = out
            .iter()
            .find(|t| spends(t, to_local_of(&revoked)))
            .expect("the penalty")
            .clone();
        let claim = out
            .iter()
            .find(|t| spends(t, own))
            .expect("the claim of the victim's own to_remote")
            .clone();
        assert_eq!(penalty.outputs[0].pubkey_hash, sweep);
        assert_eq!(claim.outputs[0].pubkey_hash, sweep);
        // Seen again in a later block (another reorganization), the same spend
        // is not punished twice.
        victim.on_connected_block(std::slice::from_ref(&revoked), 501, &no_depth);
        assert_eq!(sent.lock().unwrap().len(), 3);

        // Both are valid on chain against the revoked commitment, and the
        // victim's wallet ends with both.
        {
            let mut c = chain.lock().unwrap();
            c.mine(std::slice::from_ref(&revoked));
            c.mine(std::slice::from_ref(&penalty));
            c.mine(std::slice::from_ref(&claim));
        }
        assert_victim_made_whole(&chain, &revoked, sweep);
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
        session(&p.funder, 100 + peer, &id_of(100 + peer));
        hello = Some(p.funder.open(100 + peer, capacity, None, None).unwrap());
    }
    session(&p.funder, 999, &id_of(999));
    assert!(p.funder.open(999, capacity, None, None).is_err());
    assert_eq!(p.funder.pending_opens().0, MAX_PENDING_OPENS);
    // The acceptor side: Hellos from as many connections as it takes.
    let hello = hello.unwrap();
    for peer in 0..(MAX_PENDING_OPENS as u64 + 5) {
        session(&p.acceptor, 200 + peer, &id_of(200 + peer));
        let r = p.acceptor.deliver(200 + peer, &hello);
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
    session(&p.acceptor, 300, &id_of(300));
    assert!(!p.acceptor.deliver(300, &hello).frames.is_empty());
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
        let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
        p.queue.push_back((1, hello));
        p.pump();
        // Funded and open: unfunded channels have a budget of their own.
        for _ in 0..DEPTH {
            chain.lock().unwrap().mine(&[]);
        }
        for (_, f) in drive(&p.funder, &chain) {
            p.queue.push_back((1, f));
        }
        for (_, f) in drive(&p.acceptor, &chain) {
            p.queue.push_back((0, f));
        }
        p.pump();
    }
    assert_eq!(p.funder.list().len(), MAX_CHANNELS_PER_PEER);
    assert_eq!(p.acceptor.list().len(), MAX_CHANNELS_PER_PEER);
    assert!(
        p.funder.open(A_PEER, capacity, None, None).is_err(),
        "one channel too many with this peer"
    );
    // A Hello arriving from that same peer is not answered by the acceptor.
    let elsewhere = one_manager([0xa5u8; 32], wallet, chain, &dir.join("elsewhere"));
    session(&elsewhere, A_PEER, &p.acceptor.node_id());
    let hello = elsewhere.open(A_PEER, capacity, None, None).unwrap();
    let r = p.acceptor.deliver(F_PEER, &hello);
    assert_eq!(r.penalize, 0);
    assert!(r.frames.is_empty(), "a ninth channel with the same peer");
    assert_eq!(p.acceptor.pending_opens().1, 0);
    // Another peer is still served.
    session(&p.acceptor, F_PEER + 50, &elsewhere.node_id());
    assert!(!p.acceptor.deliver(F_PEER + 50, &hello).frames.is_empty());
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
    assert!(chain.lock().unwrap().height() < committed_at + u64::from(DELAY));
    // Penalty and claim went out at the tip of the rescan: both credited.
    assert_victim_made_whole(&chain, &revoked, sweep);
    catch_up(&victim, &chain, committed_at + 5);
    bury(&[&victim], &chain);
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
    assert_eq!(
        sent.lock().unwrap().len(),
        2,
        "the penalty and the claim went out"
    );
    drop(victim);
    chain.lock().unwrap().mine(&[]);
    let sweep = Hash256([0x7eu8; 32]);
    let victim = restart_and_rescan(
        acceptor_seed,
        &dir.join("acceptor"),
        acceptor_hooks(chain.clone(), sweep),
        &chain,
    );
    assert_victim_made_whole(&chain, &revoked, sweep);
    catch_up(&victim, &chain, h + 2);
    bury(&[&victim], &chain);
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
    let signed = p.acceptor.deliver(F_PEER, &close);
    assert_eq!(signed.penalize, 0);
    for f in signed.frames {
        assert_eq!(p.funder.deliver(A_PEER, &f).penalize, 0);
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
    bury(&[&back], &chain);
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
    bury(&[&back], &chain);
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
    // Its penalty and its claim, each mined at once in a block of its own.
    let penalty_block = chain
        .lock()
        .unwrap()
        .chain
        .block_at(h + 1)
        .unwrap()
        .transactions;
    let claim_block = chain
        .lock()
        .unwrap()
        .chain
        .block_at(h + 2)
        .unwrap()
        .transactions;
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
    live.on_connected_block(&claim_block, h + 2, &|_| None);
    for k in 3..=u64::from(DELAY) + 2 {
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
            reserve: real.reserve,
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
    session(&funder, A_PEER, &acceptor.node_id());
    session(&acceptor, F_PEER, &funder.node_id());
    let hello = funder
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    let hello_back = one(acceptor.deliver(F_PEER, &hello));
    let open = one(funder.deliver(A_PEER, &hello_back));
    let accept = one(acceptor.deliver(F_PEER, &open));
    let funding = one(funder.deliver(A_PEER, &accept));
    assert_eq!(*built.lock().unwrap(), 1);
    assert!(
        sent.lock().unwrap().is_empty(),
        "funding broadcast before FundingSigned"
    );
    // The same Accept again: the same Funding, nothing built or sent.
    let again = one(funder.deliver(A_PEER, &accept));
    assert_eq!(again, funding);
    assert_eq!(*built.lock().unwrap(), 1, "a replayed Accept funded again");
    assert!(sent.lock().unwrap().is_empty());
    let signed = one(acceptor.deliver(F_PEER, &funding));
    let r = funder.deliver(A_PEER, &signed);
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
    assert_eq!(again.lock().unwrap()[0], first);
}

/// The acceptor opens a channel only on its real funding output: the 2-of-2
/// policy for the whole capacity. An outpoint names one output forever, so a
/// Funding that names any other — an existing coin, chosen by a stranger to
/// hold one of the bounded unfunded slots for good — is final: the channel is
/// forgotten at once, its journal deleted, as soon as a block shows it.
#[test]
fn a_channel_named_on_another_output_is_forgotten_at_once() {
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
    let journal_of = |cid: Hash256| dir.join("acceptor").join(format!("{}.jrnl", cid.to_hex()));
    let open_one = |p: &mut Pair| -> Hash256 {
        let before: Vec<Hash256> = p.acceptor.list().iter().map(|c| c.channel_id).collect();
        let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
        p.queue.push_back((1, hello));
        p.pump();
        let new = p
            .acceptor
            .list()
            .into_iter()
            .find(|c| !before.contains(&c.channel_id))
            .expect("a new channel");
        assert!(
            new.funding.is_some(),
            "the acceptor learned the funding outpoint"
        );
        new.channel_id
    };
    let wrongs = |real: TxOut| {
        [
            // An ordinary key output of the right value.
            TxOut {
                scheme: SchemeId::MlDsa87,
                ..real
            },
            // The right policy, too little.
            TxOut {
                value: Amount::from_units(capacity - 1),
                ..real
            },
            // Another policy.
            TxOut {
                pubkey_hash: Hash256([0x42; 32]),
                ..real
            },
        ]
    };
    for k in 0..3 {
        let cid = open_one(&mut p);
        let real = TxOut {
            value: Amount::from_units(capacity),
            ..p.funder_funding_output(cid)
        };
        let out = wrongs(real)[k];
        assert!(journal_of(cid).exists());
        p.acceptor.on_connected_block(&[], 900, &|_| Some((1, out)));
        assert!(p.acceptor.info(cid).is_none(), "forgotten at once");
        assert!(!journal_of(cid).exists(), "its journal deleted");
    }
    let cid = open_one(&mut p);
    let real = TxOut {
        value: Amount::from_units(capacity),
        ..p.funder_funding_output(cid)
    };
    p.acceptor
        .on_connected_block(&[], 900, &|_| Some((50, real)));
    assert_eq!(p.acceptor.info(cid).unwrap().phase, Phase::Open);
}

/// A session authenticated as another node gets nothing acted on — not even
/// a Close — whatever it claims, and a reestablish captured from one session,
/// replayed in another (even one authenticated as the counterparty, after a
/// restart), binds nothing: its proof covers the session it was made for.
#[test]
fn only_the_counterpartys_session_is_heard_and_a_reestablish_is_good_for_one_session() {
    let funder_seed = [0xedu8; 32];
    let (mut p, wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, [0xeeu8; 32], "auth-session");
    const IMPOSTOR: u64 = 66;
    let impostor = "cd".repeat(32);
    // The impostor's session claims, as its legacy id, what the acceptor's
    // would: a channel bound to a node id gives that no weight.
    let legacy = "00".repeat(16);
    assert!(p
        .funder
        .on_session(IMPOSTOR, &impostor, &legacy, next_binding())
        .is_empty());
    let close = [
        cid.as_bytes().as_slice(),
        &[0u8],
        &q21_core::channel::Message::Close {
            fee: 20_000,
            seq: 1,
            signature: vec![0; q21_core::channel::keys::CHANNEL_SCHEME.sig_len()],
        }
        .encode(),
    ]
    .concat();
    let r = p.funder.deliver(IMPOSTOR, &close);
    assert_eq!(r.penalize, 0);
    assert!(r.frames.is_empty());
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Open);
    assert_eq!(p.funder.peer_of(cid), Some(A_PEER));

    // A real reconnect: capture the acceptor's reestablish, and let the
    // exchange complete.
    let mut captured = None;
    let binding = next_binding();
    let (fid, aid) = (p.funder.node_id(), p.acceptor.node_id());
    let mut queue: VecDeque<(u64, Vec<u8>)> = p
        .funder
        .on_session(A_PEER, &aid, "", binding)
        .into_iter()
        .map(|f| (1, f))
        .chain(
            p.acceptor
                .on_session(F_PEER, &fid, "", binding)
                .into_iter()
                .map(|f| (0, f)),
        )
        .collect();
    while let Some((to, frame)) = queue.pop_front() {
        let r = if to == 1 {
            p.acceptor.deliver(F_PEER, &frame)
        } else {
            if frame[32] == 0 && captured.is_none() && frame.len() > 1000 {
                captured = Some(frame.clone());
            }
            p.funder.deliver(A_PEER, &frame)
        };
        assert_eq!(r.penalize, 0);
        queue.extend(r.frames.into_iter().map(|f| (1 - to, f)));
    }
    let captured = captured.expect("the acceptor's reestablish");
    // Replayed in the impostor's session: ignored, nothing rebound.
    let r = p.funder.deliver(IMPOSTOR, &captured);
    assert!(r.frames.is_empty());
    assert_eq!(p.funder.peer_of(cid), Some(A_PEER));
    // Replayed after the funder's restart, in a new session authenticated as
    // the acceptor: its proof covers the old session's binding, not this one.
    p.reload_funder(funder_seed, wallet, chain, &dir);
    let _ = session(&p.funder, A_PEER, &aid);
    let r = p.funder.deliver(A_PEER, &captured);
    assert_eq!(r.penalize, 0);
    assert!(r.frames.is_empty());
    assert_ne!(p.funder.peer_of(cid), Some(A_PEER));
    assert!(p.funder.pay(cid, 1).is_err(), "not resynchronized");
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
    session(&spammer, 1, &acceptor.node_id());
    let hello = spammer
        .open(1, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    for conn in 0..1_200u64 {
        // Each a node of its own, on a connection that then goes away.
        session(&acceptor, 10_000 + conn, &id_of(10_000 + conn));
        let r = acceptor.deliver(10_000 + conn, &hello);
        assert_eq!(r.penalize, 0);
        acceptor.on_session_closed(10_000 + conn);
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
    p.reconnect();
    let hello = p
        .funder
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
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
    session(&spammer, 1, &acceptor.node_id());
    let hello = spammer
        .open(1, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    for conn in 0..(MAX_PENDING_PER_IDENTITY as u64 + 3) {
        // The same node over many connections: its sessions all
        // authenticate the one node id.
        session(&acceptor, 50 + conn, &spammer.node_id());
        let r = acceptor.deliver(50 + conn, &hello);
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
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    let hello_back = one(p.acceptor.deliver(F_PEER, &hello));
    let open = one(p.funder.deliver(A_PEER, &hello_back));
    let _accept = one(p.acceptor.deliver(F_PEER, &open));
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
    p.reconnect();
    let hello = p
        .funder
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
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
    // Five spammers, each on its own connections, so neither the bound on
    // the opens each funds nor its bound on channels with one peer — the
    // acceptor, as each spammer's sessions authenticate it — stops them
    // first.
    let spammers: Vec<ChannelManager> = (0..5u8)
        .map(|i| {
            one_manager(
                [0xf0 + i; 32],
                wallet.clone(),
                chain.clone(),
                &dir.join(format!("s{i}")),
            )
        })
        .collect();
    let mut opened = 0;
    for k in 0..(MAX_UNFUNDED_CHANNELS as u64 + 3) {
        let spammer = &spammers[(k % 5) as usize];
        // Each connection a node of its own, as far as the acceptor knows.
        session(spammer, k, &acceptor.node_id());
        session(&acceptor, 1_000 + k, &id_of(1_000 + k));
        let hello = spammer.open(k, 4 * MIN_OUTPUT_VALUE * 10, None, None);
        let Ok(hello) = hello else { break };
        let r = acceptor.deliver(1_000 + k, &hello);
        let Some(back) = r.frames.into_iter().next() else {
            continue;
        };
        let r = spammer.deliver(k, &back);
        if let Some(open) = r.frames.into_iter().next() {
            if !acceptor.deliver(1_000 + k, &open).frames.is_empty() {
                opened += 1;
            }
        }
    }
    assert_eq!(opened, MAX_UNFUNDED_CHANNELS);
    assert_eq!(acceptor.list().len(), MAX_UNFUNDED_CHANNELS);
    // Channels others opened to us never block one we open.
    session(&acceptor, 9_999, &id_of(9_999));
    assert!(
        acceptor
            .open(9_999, 4 * MIN_OUTPUT_VALUE * 10, None, None)
            .is_ok(),
        "inbound unfunded channels block our own open"
    );
}

/// One peer — by its announced identity, over any number of connections —
/// holds only a few unfunded channels with us.
#[test]
fn unfunded_channels_are_budgeted_per_peer() {
    use q21_core::channel::manager::MAX_UNFUNDED_PER_PEER;
    let (wallet, chain) = setup([0xe5u8; 32]);
    let dir = tmpdir("unfunded-per-peer");
    let acceptor = one_manager([0xe6u8; 32], wallet.clone(), chain.clone(), &dir.join("a"));
    let spammer = one_manager([0xe7u8; 32], wallet, chain, &dir.join("s"));
    let mut opened = 0;
    for k in 0..8u64 {
        // One node, many connections: each session authenticates its id.
        session(&spammer, k, &acceptor.node_id());
        session(&acceptor, 1_000 + k, &spammer.node_id());
        let Ok(hello) = spammer.open(k, 4 * MIN_OUTPUT_VALUE * 10, None, None) else {
            break;
        };
        let r = acceptor.deliver(1_000 + k, &hello);
        let Some(back) = r.frames.into_iter().next() else {
            continue;
        };
        let r = spammer.deliver(k, &back);
        if let Some(open) = r.frames.into_iter().next() {
            if !acceptor.deliver(1_000 + k, &open).frames.is_empty() {
                opened += 1;
            }
        }
    }
    assert_eq!(opened, MAX_UNFUNDED_PER_PEER);
}

/// A channel we accepted whose Funding never came is forgotten after an
/// hour, not a day; one whose Funding came waits for its confirmation as
/// before.
#[test]
fn an_accepted_channel_without_its_funding_expires_within_the_hour() {
    use q21_core::channel::manager::{INBOUND_FUNDING_TTL, UNFUNDED_TTL};
    let funder_seed = [0xe8u8; 32];
    let acceptor_seed = [0xe9u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("inbound-ttl");
    let mut p = managers(
        funder_seed,
        acceptor_seed,
        wallet,
        chain,
        Hash256([0x5e; 32]),
        &dir,
    );
    let one = |r: q21_core::channel::manager::Reaction| -> Vec<u8> {
        r.frames.into_iter().next().expect("a frame")
    };
    // Up to the acceptor's Accept: no Funding follows.
    let hello = p
        .funder
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    let back = one(p.acceptor.deliver(F_PEER, &hello));
    let open = one(p.funder.deliver(A_PEER, &back));
    let _accept = one(p.acceptor.deliver(F_PEER, &open));
    let waiting = p.acceptor.list()[0].channel_id;
    // A second, complete up to the Funding (never broadcast here).
    let hello = p
        .funder
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let funded = p
        .acceptor
        .list()
        .into_iter()
        .map(|c| c.channel_id)
        .find(|c| *c != waiting)
        .unwrap();
    assert!(p.acceptor.info(funded).unwrap().funding.is_some());
    // Both journals last written past the hour, inside the day.
    assert!(INBOUND_FUNDING_TTL * 2 < UNFUNDED_TTL);
    let then = std::time::SystemTime::now() - INBOUND_FUNDING_TTL * 2;
    for cid in [waiting, funded] {
        let path = dir.join("acceptor").join(format!("{}.jrnl", cid.to_hex()));
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(then)
            .unwrap();
    }
    p.acceptor.on_connected_block(&[], 900, &|_| None);
    assert!(p.acceptor.info(waiting).is_none(), "no Funding: forgotten");
    assert!(
        p.acceptor.info(funded).is_some(),
        "Funding in: still waiting"
    );
}

/// A cooperative close is settled only once buried to the funding depth. One
/// confirmation, then a reorganization: the channel was not forgotten, it
/// reloads after a restart, and settles when the close confirms again and is
/// buried.
#[test]
fn a_close_settles_only_once_buried_and_survives_a_reorganization() {
    let funder_seed = [0xc5u8; 32];
    let acceptor_seed = [0xc6u8; 32];
    let (mut p, _wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, acceptor_seed, "settle-depth");
    let m = p.funder.pay(cid, 450_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    // Signed by both; the funder's hook mines it at once.
    let close = p.funder.close(cid).unwrap().expect("a close frame");
    p.queue.push_back((1, close));
    p.pump();
    let block = chain.lock().unwrap().last_txs.clone();
    let close_tx = block
        .iter()
        .find(|t| !t.is_coinbase())
        .expect("the close is mined")
        .clone();

    // One confirmation: not settled yet.
    drive(&p.acceptor, &chain);
    let phase = p.acceptor.info(cid).unwrap().phase;
    assert_ne!(phase, Phase::Closed, "closed at one confirmation");

    // A reorganization takes the close away, and the node restarts.
    {
        let mut c = chain.lock().unwrap();
        assert!(c.chain.disconnect());
    }
    p.acceptor.on_disconnected_block(&block);
    chain.lock().unwrap().mine(&[]);
    drop(p);
    let acceptor = restart_and_rescan(
        acceptor_seed,
        &dir.join("acceptor"),
        acceptor_hooks(chain.clone(), Hash256([0x5e; 32])),
        &chain,
    );
    let info = acceptor
        .info(cid)
        .expect("a channel whose close left the chain is reloaded");
    assert_ne!(info.phase, Phase::Closed);

    // The close confirms again, and settles once buried.
    chain.lock().unwrap().mine(std::slice::from_ref(&close_tx));
    drive(&acceptor, &chain);
    assert_ne!(acceptor.info(cid).unwrap().phase, Phase::Closed);
    for _ in 1..DEPTH {
        chain.lock().unwrap().mine(&[]);
        drive(&acceptor, &chain);
    }
    assert_eq!(acceptor.info(cid).unwrap().phase, Phase::Closed);
}

/// A penalty and the claim of the victim's own to_remote that confirmed,
/// then left the chain in a reorganization, are announced again: the channel
/// stays penalised, not closed, until both are buried.
#[test]
#[cfg(feature = "audit")]
fn a_reorganized_penalty_is_announced_again() {
    let funder_seed = [0xc7u8; 32];
    let acceptor_seed = [0xc8u8; 32];
    let (mut p, _wallet, _chain, dir, cid, _capacity) =
        open_channel(funder_seed, acceptor_seed, "settle-penalty");
    for amt in [700_000u64, 700_000] {
        let m = p.funder.pay(cid, amt).unwrap();
        p.queue.push_back((1, m));
        p.pump();
    }
    let state = p.funder.info(cid).unwrap().state_number;
    let revoked = p.funder.signed_commitment(cid, state - 1).unwrap();
    let (victim, sent) =
        relaying_manager(acceptor_seed, &dir.join("acceptor"), Hash256([0x7d; 32]));
    let no_depth = |_: &OutPoint| None;
    let h = 1_000u64;
    victim.on_connected_block(std::slice::from_ref(&revoked), h, &no_depth);
    let (penalty, claim) = {
        let sent = sent.lock().unwrap();
        (sent[0].clone(), sent[1].clone())
    };
    assert_eq!(penalty.inputs[0].prev_out, to_local_of(&revoked));

    // Both confirm: penalised, not yet closed.
    let both = [penalty.clone(), claim.clone()];
    victim.on_connected_block(&both, h + 1, &no_depth);
    assert_eq!(victim.info(cid).unwrap().phase, Phase::Penalised);

    // Either leaving the chain is awaited again, and only it is announced
    // at the next block.
    for gone in [&penalty, &claim] {
        victim.on_disconnected_block(std::slice::from_ref(gone));
        let before = sent.lock().unwrap().len();
        victim.on_connected_block(&[], h + 1, &no_depth);
        let sent_now = sent.lock().unwrap().clone();
        assert_eq!(sent_now.len(), before + 1, "announced again");
        assert_eq!(sent_now[before].txid(), gone.txid());
        // Confirmed again: settling once more.
        victim.on_connected_block(std::slice::from_ref(gone), h + 2, &no_depth);
        assert_eq!(victim.info(cid).unwrap().phase, Phase::Penalised);
    }

    // Buried: closed, and announced no more.
    for k in 1..u64::from(DEPTH) {
        victim.on_connected_block(&[], h + 2 + k, &no_depth);
    }
    assert_eq!(victim.info(cid).unwrap().phase, Phase::Closed);
    let n = sent.lock().unwrap().len();
    victim.on_connected_block(&[], h + 10, &no_depth);
    assert_eq!(sent.lock().unwrap().len(), n);
}

/// N6: a crash between creating a channel's journal and journaling its key
/// index left a journal no reload could match to its key — for an accepted
/// channel, whose index derives from the funder's key, never. The opening
/// record carries the index itself.
#[test]
fn a_journal_without_a_key_index_record_still_reloads() {
    use q21_core::channel::journal::{Journal, Record};
    let funder_seed = [0xd5u8; 32];
    let acceptor_seed = [0xd6u8; 32];
    let (p, _wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, acceptor_seed, "n6-index");
    drop(p);
    for side in ["funder", "acceptor"] {
        let path = dir.join(side).join(format!("{}.jrnl", cid.to_hex()));
        let (mut j, records) = Journal::open(&path).unwrap();
        let kept: Vec<Record> = records
            .into_iter()
            .filter(|r| !matches!(r, Record::KeyIndex { .. }))
            .collect();
        j.rewrite(&kept).unwrap();
    }
    let acceptor = ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        dir.join("acceptor"),
        DELAY,
        DEPTH,
        acceptor_hooks(chain.clone(), Hash256([0x5e; 32])),
    );
    assert_eq!(
        acceptor.info(cid).map(|i| i.phase),
        Some(Phase::Open),
        "the accepted channel reloads"
    );
}

/// N5: off regtest, a closed channel stays watched until its close is past
/// the deepest reorganization a node accepts, not merely as deep as its
/// funding had to be; on regtest the funding depth keeps tests short.
#[test]
fn a_close_settles_past_the_deepest_reorganization_off_regtest() {
    use q21_core::channel::manager::settle_depth;
    use q21_core::consensus::MAX_REORG_DEPTH;
    assert_eq!(settle_depth(Network::Regtest, DEPTH), u64::from(DEPTH));
    for net in [Network::Testnet, Network::Mainnet] {
        assert!(settle_depth(net, DEPTH) > MAX_REORG_DEPTH);
        assert!(settle_depth(net, 2016) >= 2016);
    }
}

/// [`unconfirmed_funding_pair`]: the pair, the funder's wallet, the chain,
/// the journal directory and what the funder broadcast.
type UnconfirmedPair = (
    Pair,
    Arc<Mutex<Wallet>>,
    Arc<Mutex<SharedChain>>,
    std::path::PathBuf,
    Arc<Mutex<Vec<Transaction>>>,
);

/// A funder whose broadcasts go nowhere, so its funding stays unconfirmed
/// until the test mines it, and an acceptor; both driven by hand.
fn unconfirmed_funding_pair(
    funder_seed: [u8; 32],
    acceptor_seed: [u8; 32],
    tag: &str,
) -> UnconfirmedPair {
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir(tag);
    std::fs::create_dir_all(dir.join("funder")).unwrap();
    std::fs::create_dir_all(dir.join("acceptor")).unwrap();
    let sent: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
    let s1 = sent.clone();
    let funder = ChannelManager::new(
        NET,
        RATE,
        funder_seed,
        dir.join("funder"),
        DELAY,
        DEPTH,
        Hooks {
            broadcast: Box::new(move |tx| {
                s1.lock().unwrap().push(tx.clone());
                Ok(())
            }),
            ..funder_hooks(wallet.clone(), chain.clone())
        },
    );
    let acceptor = ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        dir.join("acceptor"),
        DELAY,
        DEPTH,
        acceptor_hooks(chain.clone(), Hash256([0x5e; 32])),
    );
    let mut p = Pair {
        funder,
        acceptor,
        queue: VecDeque::new(),
    };
    p.reconnect();
    (p, wallet, chain, dir, sent)
}

/// N4: the funding is signed when the acceptor accepts and broadcast a round
/// trip later, after its FundingSigned. Meanwhile its coins were in no
/// mempool, and any other send chose them again, turning the funding into a
/// double spend. They are held back from signing until the funding confirms,
/// and again after a restart.
#[test]
fn funding_coins_are_held_back_until_the_funding_confirms() {
    let (p, wallet, chain, dir, sent) =
        unconfirmed_funding_pair([0xb1u8; 32], [0xb2u8; 32], "n4-hold");
    let one = |r: q21_core::channel::manager::Reaction| -> Vec<u8> {
        assert_eq!(r.penalize, 0);
        r.frames.into_iter().next().expect("a frame")
    };
    let hello = p
        .funder
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    let back = one(p.acceptor.deliver(F_PEER, &hello));
    let open = one(p.funder.deliver(A_PEER, &back));
    let accept = one(p.acceptor.deliver(F_PEER, &open));
    let funding = one(p.funder.deliver(A_PEER, &accept));
    let cid = p.funder.list()[0].channel_id;
    let txid = p.funder.info(cid).unwrap().funding.unwrap().txid;
    // Signed, not broadcast: a send now picks other coins.
    assert!(sent.lock().unwrap().is_empty());
    let spend_avoids_funding = |inputs: &[OutPoint]| {
        let w = wallet.lock().unwrap();
        let c = chain.lock().unwrap();
        let (chosen, _) = w
            .select_coins_avoiding(&c.chain.utxo, c.chain.height(), 1, &|_| false, &[])
            .expect("other coins");
        chosen.iter().all(|(o, _, _)| !inputs.contains(o)) && inputs.iter().all(|o| w.is_locked(o))
    };
    let signed = one(p.acceptor.deliver(F_PEER, &funding));
    assert_eq!(p.funder.deliver(A_PEER, &signed).penalize, 0);
    let tx = sent.lock().unwrap()[0].clone();
    assert_eq!(tx.txid(), txid);
    let inputs: Vec<OutPoint> = tx.inputs.iter().map(|i| i.prev_out).collect();
    assert!(
        spend_avoids_funding(&inputs),
        "the funding's coins chosen again"
    );

    // A restart, its locks lost with the process: held back again.
    wallet.lock().unwrap().unlock_coins(&inputs);
    let Pair { funder, .. } = p;
    drop(funder);
    let funder = restart_and_rescan(
        [0xb1u8; 32],
        &dir.join("funder"),
        Hooks {
            broadcast: Box::new(|_| Ok(())),
            ..funder_hooks(wallet.clone(), chain.clone())
        },
        &chain,
    );
    assert!(
        spend_avoids_funding(&inputs),
        "not held back after a restart"
    );

    // Confirmed: nothing left to hold.
    chain.lock().unwrap().mine(std::slice::from_ref(&tx));
    drive(&funder, &chain);
    assert!(inputs.iter().all(|o| !wallet.lock().unwrap().is_locked(o)));
}

/// N4: a coin our unconfirmed funding spends is spent on chain by something
/// else: the funding can never confirm, and once that spend is buried the
/// channel is given up — marked abandoned, its coins released, its journal
/// kept (M1).
#[test]
fn a_funding_whose_coin_is_spent_elsewhere_is_given_up() {
    let (mut p, wallet, chain, dir, sent) =
        unconfirmed_funding_pair([0xb3u8; 32], [0xb4u8; 32], "n4-conflict");
    let hello = p
        .funder
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    let funding = sent.lock().unwrap()[0].clone();
    // The same coin, spent by another transaction that confirms.
    let conflict = {
        let mut w = wallet.lock().unwrap();
        let coins: Vec<OutPoint> = funding.inputs.iter().map(|i| i.prev_out).collect();
        w.unlock_coins(&coins);
        let c = chain.lock().unwrap();
        let (utxo, height) = (&c.chain.utxo, c.chain.height());
        let to = w.new_address();
        let prepared = w
            .prepare_spend(
                utxo,
                height,
                &[(to, Amount::from_units(MIN_OUTPUT_VALUE))],
                Amount::from_units(FUND_FEE),
            )
            .unwrap();
        let tx = w.sign_spend(utxo, prepared).unwrap();
        assert!(tx.inputs.iter().any(|i| coins.contains(&i.prev_out)));
        // Held back again, as the node still holds them.
        w.lock_coins(&coins);
        tx
    };
    chain.lock().unwrap().mine(std::slice::from_ref(&conflict));
    let journal = dir.join("funder").join(format!("{}.jrnl", cid.to_hex()));
    drive(&p.funder, &chain);
    let phase = |p: &Pair| p.funder.info(cid).map(|i| i.phase);
    assert_eq!(
        phase(&p),
        Some(Phase::Funded),
        "not before the spend is buried"
    );
    for _ in 1..DEPTH {
        chain.lock().unwrap().mine(&[]);
        drive(&p.funder, &chain);
    }
    assert_eq!(phase(&p), Some(Phase::Closed), "given up");
    assert!(journal.exists(), "the journal is kept, marked abandoned");
    // Its coins are free again: the conflict spent one, the rest are back.
    let w = wallet.lock().unwrap();
    assert!(funding.inputs.iter().all(|i| !w.is_locked(&i.prev_out)));
}

/// An engine frame as the manager writes it: the channel id, the kind, the
/// message.
fn engine_frame(cid: Hash256, msg: &q21_core::channel::messages::Message) -> Vec<u8> {
    let mut f = cid.0.to_vec();
    f.push(0);
    f.extend(msg.encode());
    f
}

/// N1: a relay between the two ends of a channel — connected to each,
/// passing every frame on. Its sessions authenticate its own node id, never
/// the counterparty's: no channel is offered to it, and nothing it sends is
/// acted on. A Close made up and injected over the real counterparty's
/// session is refused too: control messages carry the funding key's
/// signature, whatever carried them.
#[test]
fn a_relay_cannot_close_a_channel_it_sits_in() {
    use q21_core::channel::messages::Message;
    let (mut p, _wallet, _chain, _dir, cid, _capacity) =
        open_channel([0xa7u8; 32], [0xa8u8; 32], "n1-relay");
    let m = p.funder.pay(cid, 300_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    // The relay's connections: 77 on the funder, 88 on the acceptor.
    const ON_F: u64 = 77;
    const ON_A: u64 = 88;
    let relay = "77".repeat(32);
    let mut to_f: VecDeque<Vec<u8>> = session(&p.acceptor, ON_A, &relay).into();
    let mut to_a: VecDeque<Vec<u8>> = session(&p.funder, ON_F, &relay).into();
    assert!(
        to_f.is_empty() && to_a.is_empty(),
        "a channel offered to it"
    );
    // It knows the channel id: it saw the earlier traffic. It passes along
    // the funder's last payment and every answer.
    to_a.push_back(p.funder.pay(cid, 1).unwrap_or_default());
    let mut steps = 0;
    while !(to_f.is_empty() && to_a.is_empty()) {
        steps += 1;
        assert!(steps < 100);
        if let Some(f) = to_f.pop_front() {
            to_a.extend(p.funder.deliver(ON_F, &f).frames);
        }
        if let Some(f) = to_a.pop_front() {
            to_f.extend(p.acceptor.deliver(ON_A, &f).frames);
        }
    }
    use q21_core::channel::keys::{ChannelKey, Signer, CHANNEL_SCHEME};
    let own = ChannelKey::from_seed(&[0x66; 32]);
    for sender in [0u8, 1] {
        let m = q21_core::channel::messages::control_message(
            cid,
            sender,
            1,
            q21_core::channel::messages::CONTROL_CLOSE,
            &CLOSE_FEE.to_le_bytes(),
        );
        for signature in [vec![0u8; CHANNEL_SCHEME.sig_len()], own.sign(&m)] {
            let forged = engine_frame(
                cid,
                &Message::Close {
                    fee: CLOSE_FEE,
                    seq: 1,
                    signature,
                },
            );
            let to = if sender == 1 { &p.funder } else { &p.acceptor };
            // Over its own session, and over the counterparty's.
            let (relayed, genuine) = if sender == 1 {
                (ON_F, A_PEER)
            } else {
                (ON_A, F_PEER)
            };
            let r = to.deliver(relayed, &forged);
            assert!(r.frames.is_empty());
            assert_eq!(r.penalize, 0, "ignored, not blamed");
            let r = to.deliver(genuine, &forged);
            assert!(r.frames.is_empty());
        }
    }
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Open, "funder");
    assert_eq!(p.acceptor.info(cid).unwrap().phase, Phase::Open, "acceptor");
    // The relayed payment was never acted on; the channel still pays.
    assert_eq!(p.acceptor.info(cid).unwrap().local_balance, 300_000);
    p.reconnect();
    p.pump();
    let m = p.funder.pay(cid, 1_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    assert!(p.acceptor.info(cid).unwrap().local_balance >= 301_000);
}

/// N1: a session tells a node who its peer is before any channel frame
/// moves: a session from another node is offered no reestablish, and so
/// learns no channel id, while the counterparty's gets one per channel.
#[test]
fn a_session_from_another_node_learns_no_channel() {
    let (p, _wallet, _chain, _dir, cid, _capacity) =
        open_channel([0xa9u8; 32], [0xaau8; 32], "n1-locator");
    assert!(session(&p.funder, 99, &"99".repeat(32)).is_empty());
    let frames = session(&p.funder, A_PEER, &p.acceptor.node_id());
    assert_eq!(frames.len(), 1);
    assert!(frames[0].windows(32).any(|w| w == cid.as_bytes()));
}

/// M1: we fund, and go down before the funding confirms: no funding height
/// is journaled. The funding confirms and the acceptor broadcasts its
/// commitment 0. On restart the channel must be rescanned — its funding's
/// coins are spent, by the funding itself — and our capacity claimed, never
/// taken for a funding beaten by a conflict, and the journal never deleted.
#[test]
fn a_funding_confirmed_while_we_were_down_is_claimed_not_given_up() {
    let funder_seed = [0xb5u8; 32];
    let acceptor_seed = [0xb6u8; 32];
    let (mut p, wallet, chain, dir, sent) =
        unconfirmed_funding_pair(funder_seed, acceptor_seed, "m1-offline-funder");
    let capacity = 4 * MIN_OUTPUT_VALUE * 10;
    let hello = p.funder.open(A_PEER, capacity, None, None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    let funding = sent.lock().unwrap()[0].clone();
    // The funder goes down; the funding confirms without it.
    let Pair {
        funder, acceptor, ..
    } = p;
    drop(funder);
    chain.lock().unwrap().mine(std::slice::from_ref(&funding));
    drive(&acceptor, &chain);
    bury(&[&acceptor], &chain);
    assert_eq!(acceptor.info(cid).unwrap().phase, Phase::Open);
    // The acceptor force-closes: its commitment 0 pays the funder's whole
    // balance to the funder's channel key.
    let commitment = acceptor.force_close(cid).unwrap();
    assert_eq!(chain.lock().unwrap().last_txs[1].txid(), commitment.txid());
    chain.lock().unwrap().mine(&[]);

    let before = held(&chain, FUNDER_PAYOUT);
    // Its broadcasts are mined when they are valid, refused otherwise, as a
    // mempool would.
    let c = chain.clone();
    let funder = restart_and_rescan(
        funder_seed,
        &dir.join("funder"),
        Hooks {
            broadcast: Box::new(move |tx: &Transaction| {
                let mut c = c.lock().unwrap();
                if tx
                    .inputs
                    .iter()
                    .any(|i| c.chain.utxo.get(&i.prev_out).is_none())
                {
                    return Err("missing input".into());
                }
                c.mine(std::slice::from_ref(tx));
                Ok(())
            }),
            ..funder_hooks(wallet, chain.clone())
        },
        &chain,
    );
    for _ in 0..(2 * DEPTH + 2) {
        chain.lock().unwrap().mine(&[]);
        drive(&funder, &chain);
    }
    let journal = dir.join("funder").join(format!("{}.jrnl", cid.to_hex()));
    assert!(journal.exists(), "the funder's journal was deleted");
    let claimed = held(&chain, FUNDER_PAYOUT) - before;
    assert!(
        claimed + 100_000 >= capacity,
        "the funder's capacity was not claimed ({claimed} of {capacity})"
    );
}

/// M2: our funding, signed for by the acceptor, may drop out of every pool
/// before it confirms. It is announced again at every block while it waits,
/// and its coins are released as soon as the channel leaves its opening —
/// here by a force-close — rather than held until a restart.
#[test]
fn an_unconfirmed_funding_is_announced_again_and_released_when_the_channel_ends() {
    let (mut p, wallet, chain, _dir, sent) =
        unconfirmed_funding_pair([0xb7u8; 32], [0xb8u8; 32], "m2-rebroadcast");
    let hello = p
        .funder
        .open(A_PEER, 4 * MIN_OUTPUT_VALUE * 10, None, None)
        .unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    let cid = p.funder.list()[0].channel_id;
    let funding = sent.lock().unwrap()[0].clone();
    for k in 1..=3 {
        chain.lock().unwrap().mine(&[]);
        drive(&p.funder, &chain);
        let all = sent.lock().unwrap().clone();
        assert_eq!(all.len(), 1 + k, "announced again at block {k}");
        assert!(all.iter().all(|t| t.txid() == funding.txid()));
    }
    let locked = |w: &Wallet| funding.inputs.iter().all(|i| w.is_locked(&i.prev_out));
    assert!(locked(&wallet.lock().unwrap()));
    // The channel ends before its funding confirmed.
    p.funder.force_close(cid).unwrap();
    chain.lock().unwrap().mine(&[]);
    drive(&p.funder, &chain);
    let w = wallet.lock().unwrap();
    assert!(
        funding.inputs.iter().all(|i| !w.is_locked(&i.prev_out)),
        "coins held after the channel ended"
    );
}

/// A payee's reported balance counts a payment only once the payer can no
/// longer undo it: once the payer has revoked the state before it. Until
/// then the payer could still broadcast that state, and the payment shows
/// as pending, not as balance. The payer's own balance drops at once.
#[test]
fn a_payment_counts_for_the_payee_only_once_it_is_irrevocable() {
    let (p, _wallet, _chain, _dir, cid, capacity) =
        open_channel([0xbbu8; 32], [0xbcu8; 32], "irrevocable");
    let one = |r: q21_core::channel::manager::Reaction| -> Vec<u8> {
        assert_eq!(r.penalize, 0);
        assert_eq!(r.frames.len(), 1);
        r.frames.into_iter().next().unwrap()
    };
    let update = p.funder.pay(cid, 300_000).unwrap();
    // The payee holds the signed update: not yet its balance.
    let ack = one(p.acceptor.deliver(F_PEER, &update));
    let a = p.acceptor.info(cid).unwrap();
    assert_eq!(a.local_balance, 0, "counted before the payer revoked");
    assert_eq!(a.pending_incoming, 300_000);
    assert!(a.in_flight);
    // The payer's side drops at once.
    let f = p.funder.info(cid).unwrap();
    assert_eq!(f.local_balance, capacity - 300_000);
    assert_eq!(f.pending_incoming, 0);
    // The payer revokes the old state: settled on its side ...
    let revoke = one(p.funder.deliver(A_PEER, &ack));
    let f = p.funder.info(cid).unwrap();
    assert!(!f.in_flight);
    assert_eq!(f.local_balance + f.remote_balance, capacity);
    // ... and, the revocation received, on the payee's.
    let r = p.acceptor.deliver(F_PEER, &revoke);
    assert_eq!(r.penalize, 0);
    let a = p.acceptor.info(cid).unwrap();
    assert_eq!(a.local_balance, 300_000);
    assert_eq!(a.pending_incoming, 0);
    assert!(!a.in_flight);
    assert_eq!(a.local_balance + a.remote_balance, capacity);
}

/// A channel journaled by 0.4.10 names its peer, beside the journal, by the
/// id that peer advertised then — a legacy id, which no user agent carries
/// any more. Each side's session signs its legacy id: after the upgrade both
/// ends find the channel by it, re-bind it once the reestablish proves the
/// funding keys, and name the node id from then on.
#[test]
fn a_channel_journaled_by_0_4_10_rebinds_through_the_legacy_ids() {
    let (funder_seed, acceptor_seed) = ([0xc5u8; 32], [0xc6u8; 32]);
    let (mut p, wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, acceptor_seed, "legacy-rebind");
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let (fid, aid) = (p.funder.node_id(), p.acceptor.node_id());
    let (fl, al) = (
        hex(&p.funder.identity().legacy_id()),
        hex(&p.acceptor.identity().legacy_id()),
    );
    let sidecar = |side: &str| dir.join(side).join(format!("{}.peer", cid.to_hex()));
    // As 0.4.10 left them.
    std::fs::write(sidecar("funder"), &al).unwrap();
    std::fs::write(sidecar("acceptor"), &fl).unwrap();
    p.reload_funder(funder_seed, wallet, chain.clone(), &dir);
    p.acceptor = ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        dir.join("acceptor"),
        DELAY,
        DEPTH,
        acceptor_hooks(chain, Hash256([0x5e; 32])),
    );
    let binding = next_binding();
    for f in p.funder.on_session(A_PEER, &aid, &al, binding) {
        p.queue.push_back((1, f));
    }
    for f in p.acceptor.on_session(F_PEER, &fid, &fl, binding) {
        p.queue.push_back((0, f));
    }
    p.pump();
    assert_eq!(std::fs::read_to_string(sidecar("funder")).unwrap(), aid);
    assert_eq!(std::fs::read_to_string(sidecar("acceptor")).unwrap(), fid);
    let m = p.funder.pay(cid, 1_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    assert_eq!(p.acceptor.info(cid).unwrap().local_balance, 1_000);
}

/// 0.5.3: the payments of a channel are kept as they settle, both sides see
/// them, and a closed channel stays in the archives — with what was put in,
/// what came back and how it ended — after a restart, when it is no longer
/// operated.
#[test]
fn history_and_archives_survive_a_restart() {
    use q21_core::channel::manager::ClosedHow;
    let (mut p, wallet, chain, dir, cid, capacity) =
        open_channel([0xa3u8; 32], [0xb4u8; 32], "history-archive");
    for (from_funder, amount) in [(true, 1_000_000u64), (true, 500_000), (false, 400_000)] {
        let (frame, to) = if from_funder {
            (p.funder.pay(cid, amount).unwrap(), 1)
        } else {
            (p.acceptor.pay(cid, amount).unwrap(), 0)
        };
        p.queue.push_back((to, frame));
        p.pump();
    }
    let deltas =
        |m: &ChannelManager| -> Vec<i128> { m.history(cid).iter().map(|e| e.delta).collect() };
    assert_eq!(deltas(&p.funder), [-1_000_000, -500_000, 400_000]);
    assert_eq!(deltas(&p.acceptor), [1_000_000, 500_000, -400_000]);
    assert!(p
        .funder
        .history(cid)
        .windows(2)
        .all(|w| w[0].state < w[1].state));
    assert!(
        p.funder.archived().is_empty(),
        "an open channel is not archived"
    );

    let close = p.funder.close(cid).unwrap().expect("a close frame");
    p.queue.push_back((1, close));
    p.pump();
    drive(&p.funder, &chain);
    drive(&p.acceptor, &chain);
    bury(&[&p.funder, &p.acceptor], &chain);
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Closed);
    let check = |a: &q21_core::channel::manager::ArchivedChannel, funder: bool| {
        assert_eq!(a.channel_id, cid);
        assert_eq!(a.capacity, capacity);
        assert_eq!(a.we_funded, funder);
        let (mine, theirs) = (capacity - 1_100_000, 1_100_000);
        assert_eq!(a.final_local, if funder { mine } else { theirs });
        assert_eq!(a.final_remote, if funder { theirs } else { mine });
        assert_eq!(a.how, ClosedHow::Cooperative);
        assert!(a.closed_height.is_some());
        assert!(a.closed_time > 1_700_000_000, "dated by the clock");
        assert_eq!(a.payments, 3);
    };
    let live = p.funder.archived();
    assert_eq!(live.len(), 1);
    check(&live[0], true);
    check(&p.acceptor.archived()[0], false);

    // A restart no longer loads the channel, and the archives still have it.
    drop(p);
    let reloaded = one_manager([0xa3u8; 32], wallet, chain, &dir.join("funder"));
    assert!(
        reloaded.info(cid).is_none(),
        "a closed channel is not reloaded"
    );
    let archived = reloaded.archived();
    assert_eq!(archived.len(), 1);
    check(&archived[0], true);
    assert_eq!(reloaded.history(cid).len(), 3, "its history is kept too");
}

/// 0.5.3: a channel remembers the identity address its peer's session
/// proved, so that the wallet names the contact it is with while the peer is
/// offline, after a restart and in the archives; and the archives date a
/// close by the first confirmation of its transaction.
#[test]
fn a_channel_remembers_whom_it_is_with_and_when_it_closed() {
    let (mut p, wallet, chain, dir, cid, _capacity) =
        open_channel([0xa7u8; 32], [0xb8u8; 32], "peer-owner");
    let owner = p.acceptor.own_owner();
    assert_eq!(
        p.funder.info(cid).unwrap().peer_owner,
        "",
        "no session owner seen yet"
    );
    // A session proving the peer's identity address fills it in.
    p.funder.set_session_owner(A_PEER, owner);
    assert_eq!(p.funder.list()[0].peer_owner, owner.to_hex());
    assert_eq!(p.funder.info(cid).unwrap().peer_owner, owner.to_hex());

    let close = p.funder.close(cid).unwrap().expect("a close frame");
    p.queue.push_back((1, close));
    p.pump();
    drive(&p.funder, &chain);
    drive(&p.acceptor, &chain);
    // The close is dated when its transaction is first seen confirmed, and
    // the archives keep that date, not the later one it is marked closed at.
    let seen = p.funder.info(cid).unwrap();
    let (at, when) = (
        seen.close_height.expect("confirmed"),
        seen.close_time.expect("dated"),
    );
    let dated =
        std::fs::read_to_string(dir.join("funder").join(format!("{}.closing", cid.to_hex())))
            .unwrap();
    assert_eq!(dated.trim(), format!("{at} {when}"));
    // Back-date the sidecar, as for a close seen long before it settles: the
    // archive's date must come from it.
    std::fs::write(
        dir.join("funder").join(format!("{}.closing", cid.to_hex())),
        format!("{at} 1700000000\n"),
    )
    .unwrap();
    bury(&[&p.funder, &p.acceptor], &chain);
    assert_eq!(p.funder.archived()[0].peer_owner, owner.to_hex());
    assert_eq!(p.funder.archived()[0].closed_time, 1_700_000_000);
    assert_eq!(p.funder.archived()[0].closed_height, Some(at));
    drop(p);
    let reloaded = one_manager([0xa7u8; 32], wallet, chain, &dir.join("funder"));
    assert_eq!(
        reloaded.archived()[0].peer_owner,
        owner.to_hex(),
        "kept across a restart"
    );
}

/// 0.5.3: a close without the peer broadcasts the highest fee tier, so that
/// it gets through a congested pool (there is no way to bump it later), and
/// the summary says what it costs before the holder decides.
#[test]
fn a_close_without_the_peer_pays_the_high_tier() {
    use q21_core::channel::txbuild::FeeTier;
    let (mut p, _wallet, chain, _dir, cid, capacity) =
        open_channel([0xa5u8; 32], [0xb6u8; 32], "force-high");
    let pay = p.funder.pay(cid, 1_000_000).unwrap();
    p.queue.push_back((1, pay));
    p.pump();
    let shown = p.funder.info(cid).unwrap().force_close_fee;
    assert_eq!(
        shown,
        p.acceptor.info(cid).unwrap().force_close_fee,
        "both sides agree"
    );
    let tx = p.funder.force_close(cid).unwrap();
    let out: u64 = tx.outputs.iter().map(|o| o.value.units()).sum();
    assert_eq!(capacity - out, shown, "the fee paid is the fee shown");
    let low = q21_core::channel::txbuild::tier_rate(RATE, FeeTier::Low);
    let high = q21_core::channel::txbuild::tier_rate(RATE, FeeTier::High);
    assert_eq!(high, 16 * low);
    assert_eq!(
        q21_core::channel::manager::FORCE_CLOSE_TIER as u8,
        FeeTier::High as u8
    );
    drive(&p.funder, &chain);
    assert_eq!(p.funder.info(cid).unwrap().phase, Phase::Forcing);
}

/// 0.5.3: the funder chooses the to-self delay, and it is how long the
/// acceptor may stay offline before a revoked state can no longer be
/// punished. An acceptor takes no less than its own default: a shorter one is
/// not answered, and no channel exists on either side.
#[test]
fn an_acceptor_refuses_a_delay_shorter_than_its_own() {
    let funder_seed = [0xa7u8; 32];
    let (wallet, chain) = setup(funder_seed);
    let dir = tmpdir("acceptor-delay");
    let mut p = managers(
        funder_seed,
        [0xb8u8; 32],
        wallet.clone(),
        chain.clone(),
        Hash256([0x5e; 32]),
        &dir,
    );
    assert_eq!(p.acceptor.acceptor_min_delay(), DELAY);
    let short = q21_core::channel::terms(NET).min_delay;
    assert!(short < DELAY);
    let hello = p.funder.open(A_PEER, 3_000_000, Some(short), None).unwrap();
    let r = p.acceptor.deliver(F_PEER, &hello);
    assert!(r.frames.is_empty(), "not answered");
    assert_eq!(r.penalize, 0, "a short delay is a choice, not misconduct");
    assert!(p.acceptor.list().is_empty() && p.funder.list().is_empty());
    let hello = p.funder.open(A_PEER, 3_000_000, Some(DELAY), None).unwrap();
    p.queue.push_back((1, hello));
    p.pump();
    assert_eq!(p.acceptor.list().len(), 1, "its own delay is accepted");
    assert_eq!(p.acceptor.list()[0].delay, DELAY);
}

/// Copies every file of `from` into `to`, replacing what is there: a data
/// folder restored from a backup.
fn restore_dir(from: &std::path::Path, to: &std::path::Path) {
    let _ = std::fs::remove_dir_all(to);
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// 0.5.3: a reestablish held up on a second session (a slower route) while
/// payments go on over the first arrives with counters older than the
/// channel's: it must not read as an older copy, nor close anything.
#[test]
fn a_reestablish_held_up_on_a_second_session_closes_nothing() {
    let (mut p, _wallet, chain, _dir, cid, _capacity) =
        open_channel([0x5au8; 32], [0x5bu8; 32], "race-second-session");
    const A2: u64 = 91;
    const F2: u64 = 92;
    let binding = next_binding();
    let to_acceptor = p.funder.on_session(A2, &p.acceptor.node_id(), "", binding);
    let to_funder = p.acceptor.on_session(F2, &p.funder.node_id(), "", binding);
    assert!(!to_acceptor.is_empty() && !to_funder.is_empty());
    // Payments go on over the first session meanwhile.
    for amount in [300_000u64, 200_000] {
        let m = p.funder.pay(cid, amount).unwrap();
        p.queue.push_back((1, m));
        p.pump();
    }
    let h0 = chain.lock().unwrap().height();
    // The held reestablishes arrive now, both ways.
    for f in to_acceptor {
        assert_eq!(p.acceptor.deliver(F2, &f).penalize, 0);
    }
    for f in to_funder {
        assert_eq!(p.funder.deliver(A2, &f).penalize, 0);
    }
    drive(&p.funder, &chain);
    drive(&p.acceptor, &chain);
    assert_eq!(chain.lock().unwrap().height(), h0, "nothing broadcast");
    for m in [&p.funder, &p.acceptor] {
        let i = m.info(cid).unwrap();
        assert_eq!(i.phase, Phase::Open);
        assert!(!i.behind && !i.peer_behind, "{i:?}");
    }
    assert_eq!(
        p.acceptor.peer_of(cid),
        Some(F_PEER),
        "the channel stays where it runs"
    );
    // And it still pays over the first session.
    let m = p.funder.pay(cid, 100_000).unwrap();
    p.queue.push_back((1, m));
    p.pump();
    assert_eq!(p.acceptor.info(cid).unwrap().local_balance, 600_000);
}

/// 0.5.3: two sessions opened at the same moment both carry what the peer's
/// copy was then: they are one sighting, not two. Only a session opened after
/// the first sighting confirms an older copy and closes the channel.
#[test]
fn two_sessions_opened_together_are_one_sighting() {
    let funder_seed = [0xc3u8; 32];
    let (mut p, wallet, chain, dir, cid, _capacity) =
        open_channel(funder_seed, [0xd4u8; 32], "older-copy-twin-sessions");
    let pay = p.funder.pay(cid, 1_000_000).unwrap();
    p.queue.push_back((1, pay));
    p.pump();
    let backup = dir.join("funder-backup");
    restore_dir(&dir.join("funder"), &backup);
    for amount in [2_000_000u64, 500_000] {
        let pay = p.funder.pay(cid, amount).unwrap();
        p.queue.push_back((1, pay));
        p.pump();
    }
    restore_dir(&backup, &dir.join("funder"));
    p.reload_funder(funder_seed, wallet.clone(), chain.clone(), &dir);
    p.acceptor.on_session_closed(F_PEER);
    let h0 = chain.lock().unwrap().height();
    // Two sessions, both established before either reestablish is read.
    const F2: u64 = 93;
    const F3: u64 = 94;
    let (b2, b3) = (next_binding(), next_binding());
    let _ = p.acceptor.on_session(F2, &p.funder.node_id(), "", b2);
    let _ = p.acceptor.on_session(F3, &p.funder.node_id(), "", b3);
    let r2 = p.funder.on_session(A_PEER, &p.acceptor.node_id(), "", b2);
    let r3 = p
        .funder
        .on_session(A_PEER + 100, &p.acceptor.node_id(), "", b3);
    for f in r2 {
        assert_eq!(p.acceptor.deliver(F2, &f).penalize, 0);
    }
    for f in r3 {
        assert_eq!(p.acceptor.deliver(F3, &f).penalize, 0);
    }
    assert!(p.acceptor.info(cid).unwrap().peer_behind, "seen");
    assert_eq!(
        chain.lock().unwrap().height(),
        h0,
        "one sighting, nothing broadcast"
    );
    // A session opened afterwards shows the same: now it is closed.
    const F4: u64 = 95;
    let b4 = next_binding();
    let _ = p.acceptor.on_session(F4, &p.funder.node_id(), "", b4);
    for f in p
        .funder
        .on_session(A_PEER + 200, &p.acceptor.node_id(), "", b4)
    {
        assert_eq!(p.acceptor.deliver(F4, &f).penalize, 0);
    }
    assert!(
        chain.lock().unwrap().height() > h0,
        "closed with the latest state"
    );
}

/// B4, the loss the 0.5.0 review reproduced: a data folder restored from a
/// copy taken two payments ago, then "close without the peer", broadcast a
/// revoked state and lost the whole channel to the penalty. Now the restored
/// side learns at the reestablish that its copy is older, refuses to pay, to
/// close and to close alone; the peer, which holds the latest state, closes
/// with it once a second session confirms what the first showed; and the restored side gets exactly its latest balance back, less
/// the claim fee. Nobody is penalised.
#[test]
fn a_channel_restored_from_an_older_copy_is_closed_by_the_peer_and_loses_nothing() {
    let funder_seed = [0xc1u8; 32];
    let (mut p, wallet, chain, dir, cid, capacity) =
        open_channel(funder_seed, [0xd2u8; 32], "restored-copy");
    let pay = p.funder.pay(cid, 1_000_000).unwrap();
    p.queue.push_back((1, pay));
    p.pump();
    // The copy: two payments ago.
    let backup = dir.join("funder-backup");
    restore_dir(&dir.join("funder"), &backup);
    for amount in [2_000_000u64, 500_000] {
        let pay = p.funder.pay(cid, amount).unwrap();
        p.queue.push_back((1, pay));
        p.pump();
    }
    let latest = p.funder.info(cid).unwrap().local_balance;
    assert_eq!(latest, capacity - 3_500_000);
    // The funder pays the commitment fee: the peer's commitment pays it its
    // balance less that fee.
    let commit_fee = p.funder.info(cid).unwrap().force_close_fee;

    // The funder's folder is restored from the copy, and the node restarts.
    restore_dir(&backup, &dir.join("funder"));
    p.reload_funder(funder_seed, wallet.clone(), chain.clone(), &dir);
    assert_eq!(
        p.funder.info(cid).unwrap().local_balance,
        capacity - 1_000_000,
        "the copy believes the older balance"
    );
    let h0 = chain.lock().unwrap().height();
    reconnect(&mut p);

    // The restored side knows, and refuses everything that signs or
    // broadcasts.
    let info = p.funder.info(cid).unwrap();
    assert!(info.behind, "the older copy is recognised");
    assert!(p.funder.pay(cid, 1).is_err());
    assert!(p.funder.close(cid).is_err());
    let refused = p.funder.force_close(cid).unwrap_err();
    assert!(refused.contains("older"), "{refused}");

    // The peer saw an older copy once: not proof enough — a reestablish held
    // up in transit looks the same — so it closes nothing yet, and says so.
    assert_eq!(
        chain.lock().unwrap().height(),
        h0,
        "nothing broadcast on one sighting"
    );
    assert!(p.acceptor.info(cid).unwrap().peer_behind);
    assert!(!p.funder.info(cid).unwrap().peer_behind);
    // The next session shows the same: the peer closes with the latest state.
    reconnect(&mut p);
    assert!(
        chain.lock().unwrap().height() > h0,
        "the peer's commitment is on chain"
    );
    drive(&p.acceptor, &chain);
    drive(&p.funder, &chain);
    assert_eq!(p.acceptor.info(cid).unwrap().phase, Phase::Forcing);
    for _ in 0..(DELAY as u64 + DEPTH as u64 + 2) {
        chain.lock().unwrap().mine(&[]);
        drive(&p.acceptor, &chain);
        drive(&p.funder, &chain);
    }
    // The restored side claimed its latest balance, to the unit, less the
    // commitment's fee (the funder's to pay) and the claim's; the peer swept
    // its own after the delay. No penalty.
    let funder_got = held(&chain, FUNDER_PAYOUT);
    let claim_fee = q21_core::channel::txbuild::SWEEP_FEE;
    assert_eq!(
        funder_got,
        latest - commit_fee - claim_fee,
        "the restored side lost nothing"
    );
    assert!(
        held(&chain, Hash256([0x5e; 32])) > 0,
        "the peer swept its side"
    );
    assert!(p
        .funder
        .info(cid)
        .is_none_or(|i| i.phase != Phase::Penalised));
    assert!(p
        .acceptor
        .info(cid)
        .is_none_or(|i| i.phase != Phase::Penalised));

    // A restart keeps the restored side refusing.
    p.reload_funder(funder_seed, wallet, chain.clone(), &dir);
    if let Some(i) = p.funder.info(cid) {
        assert!(i.behind || i.phase == Phase::Closed);
    }
}

/// The verdict over every pair of counters an honest channel can show:
/// the two copies differ by at most the state in flight, and then nothing
/// is suspected. Any copy two states older is recognised, from both sides.
#[test]
fn the_sync_verdict_suspects_no_honest_pair_of_counters() {
    use q21_core::channel::machine::{sync_verdict, SyncVerdict};
    // An honest history, step by step: [local, remote, sent, recv] as next
    // counters, both sides, through updates proposed by either side.
    let mut a = [1u64, 1, 0, 0];
    let mut b = [1u64, 1, 0, 0];
    let mut seen = vec![(a, b)];
    for round in 0..6 {
        let (p, q) = if round % 2 == 0 {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        // p proposes state n: it signs q's commitment n.
        p[1] += 1;
        seen.push((*p, *q));
        // q receives it, signs p's n, revokes its n-1.
        q[0] += 1;
        q[1] += 1;
        q[2] += 1;
        seen.push((*p, *q));
        // p receives the ack: holds n, receives q's revocation, revokes n-1.
        p[0] += 1;
        p[3] += 1;
        p[2] += 1;
        seen.push((*p, *q));
        // q receives p's revocation.
        q[3] += 1;
        seen.push((*p, *q));
    }
    for (x, y) in &seen {
        assert_eq!(sync_verdict(*x, *y), SyncVerdict::InStep, "{x:?} {y:?}");
        assert_eq!(sync_verdict(*y, *x), SyncVerdict::InStep, "{y:?} {x:?}");
    }
    // A copy taken two settled states before: recognised by both.
    let (old, _) = seen[0];
    let (_, now_b) = *seen.last().unwrap();
    assert_eq!(sync_verdict(old, now_b), SyncVerdict::WeAreBehind);
    assert_eq!(sync_verdict(now_b, old), SyncVerdict::PeerIsBehind);
}

/// The unspent outputs paying `hash`, as the node's block hook looks them up.
fn outputs_paying(chain: &Arc<Mutex<SharedChain>>, hash: &Hash256) -> Vec<(OutPoint, TxOut)> {
    let c = chain.lock().unwrap();
    let h = c.chain.height();
    c.chain
        .utxo
        .spendable_for(hash, h, COINBASE_MATURITY)
        .into_iter()
        .map(|(o, e)| (o, e.output))
        .collect()
}

/// B4, the other half: a wallet restored from its backup code knows none of
/// its channels. When the peer closes alone, our side of its commitment pays
/// our channel key, which nothing used to spend again. The node now derives
/// its channel keys from the seed and claims such outputs back to the
/// wallet — for a channel it accepted and for one it opened.
#[test]
fn a_wallet_restored_from_its_seed_recovers_what_a_peer_close_paid_it() {
    let acceptor_seed = [0xe4u8; 32];
    let funder_seed = [0xe3u8; 32];
    let (mut p, wallet, chain, dir, cid, capacity) =
        open_channel(funder_seed, acceptor_seed, "seed-restore");
    let pay = p.funder.pay(cid, 2_000_000).unwrap();
    p.queue.push_back((1, pay));
    p.pump();
    let commit_fee = p.funder.info(cid).unwrap().force_close_fee;

    // The acceptor's disk is lost: a node restored from the seed alone, on an
    // empty folder, knows nothing of the channel.
    let restored_sweep = Hash256([0x77; 32]);
    let fresh = dir.join("acceptor-restored");
    std::fs::create_dir_all(&fresh).unwrap();
    let restored = ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        fresh,
        DELAY,
        DEPTH,
        acceptor_hooks(chain.clone(), restored_sweep),
    );
    assert!(restored.list().is_empty());
    let h = chain.lock().unwrap().height();
    let find = |hash: &Hash256| outputs_paying(&chain, hash);
    assert_eq!(
        restored.recover_key_outputs(h, &find),
        0,
        "nothing to claim yet"
    );

    // The funder closes alone: the acceptor's 2 Q21 go to its channel key.
    p.funder.force_close(cid).unwrap();
    let h = chain.lock().unwrap().height();
    assert_eq!(restored.recover_key_outputs(h, &find), 1);
    assert_eq!(
        held(&chain, restored_sweep),
        2_000_000 - q21_core::channel::txbuild::SWEEP_FEE,
        "the restored wallet got its side back"
    );
    let h = chain.lock().unwrap().height();
    assert_eq!(restored.recover_key_outputs(h, &find), 0, "claimed once");

    // And the side that opened the channel: a second channel, which the
    // acceptor closes alone this time; the funder's folder is lost.
    drop(restored);
    let mut p2 = {
        let funder = ChannelManager::new(
            NET,
            RATE,
            funder_seed,
            dir.join("funder"),
            DELAY,
            DEPTH,
            funder_hooks(wallet.clone(), chain.clone()),
        );
        let acceptor = ChannelManager::new(
            NET,
            RATE,
            acceptor_seed,
            dir.join("acceptor2"),
            DELAY,
            DEPTH,
            acceptor_hooks(chain.clone(), Hash256([0x5e; 32])),
        );
        std::fs::create_dir_all(dir.join("acceptor2")).unwrap();
        let mut q = Pair {
            funder,
            acceptor,
            queue: VecDeque::new(),
        };
        q.reconnect();
        q.reconnect();
        q
    };
    drop(p);
    let hello = p2.funder.open(A_PEER, capacity / 2, None, None).unwrap();
    p2.queue.push_back((1, hello));
    p2.pump();
    let cid2 = p2
        .funder
        .list()
        .into_iter()
        .find(|c| c.channel_id != cid)
        .expect("a second channel")
        .channel_id;
    for _ in 0..DEPTH {
        chain.lock().unwrap().mine(&[]);
    }
    let rf = p2.funder.funding_confirmed(cid2).unwrap();
    let ra = p2.acceptor.funding_confirmed(cid2).unwrap();
    p2.queue.push_back((1, rf));
    p2.queue.push_back((0, ra));
    p2.pump();
    let pay = p2.funder.pay(cid2, 1_000_000).unwrap();
    p2.queue.push_back((1, pay));
    p2.pump();
    let funder_side = p2.funder.info(cid2).unwrap().local_balance;
    let fee2 = p2.funder.info(cid2).unwrap().force_close_fee;
    let gone = dir.join("funder-restored");
    std::fs::create_dir_all(&gone).unwrap();
    let funder_sweep = Hash256([0x78; 32]);
    let mut hooks = funder_hooks(wallet, chain.clone());
    hooks.sweep_address = Box::new(move || funder_sweep);
    let restored_funder = ChannelManager::new(NET, RATE, funder_seed, gone, DELAY, DEPTH, hooks);
    p2.acceptor.force_close(cid2).unwrap();
    let h = chain.lock().unwrap().height();
    assert_eq!(restored_funder.recover_key_outputs(h, &find), 1);
    assert_eq!(
        held(&chain, funder_sweep),
        funder_side - fee2 - q21_core::channel::txbuild::SWEEP_FEE,
        "the funder's side, less the commitment fee it pays and the claim's"
    );
    assert!(commit_fee > 0);
}

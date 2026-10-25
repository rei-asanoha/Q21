//! Node-level payment-channel tests: two real [`Node`]s with wallets, connected
//! over TCP, drive open → pay → close end to end. Channel frames travel sealed
//! in the transport session between the nodes ([`ChannelTransport`]) and
//! through the nodes' message handlers; the on-chain reactions run
//! through the nodes' real block hook. The point every test makes is about
//! **wallet funds**: a settled channel must leave each party spendable coin.

#![cfg(feature = "mldsa")]

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::channel::link::ChannelTransport;
use q21_core::channel::manager::{ChannelManager, Hooks};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::net::{Node, PeerInfo};
use q21_core::sig::SchemeId;
use q21_core::tx::{Transaction, TxOut};
use q21_core::wallet::Wallet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NET: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;
const DELAY: u16 = 6;
const DEPTH: u16 = 2;
const RATE: u64 = 10;
const FUND_FEE: u64 = 50_000;

/// Transactions a manager hook wants on chain, mined by the next `sync_mine`.
type Pending = Arc<Mutex<Vec<Transaction>>>;

/// Mines one block (with the pending channel transactions) on `a`'s chain, then
/// connects the identical block to `b`'s chain and runs both nodes' real block
/// hook — the same path a mined or received block takes in production.
fn sync_mine(a: &Node, b: &Node, pending: &Pending, miner: Hash256) {
    let txs = std::mem::take(&mut *pending.lock().unwrap());
    let block = a.with_chain(|c| {
        let h = c.height() + 1;
        let t = GENESIS_TIME + h * TARGET_BLOCK_SECS;
        c.mine_block(miner, SchemeId::MlDsa87, &txs, t, ATTEMPTS)
            .expect("mine")
    });
    let t = block.header.time + 1;
    a.with_chain(|c| c.connect(&block, t).expect("connect a"));
    b.with_chain(|c| c.connect(&block, t).expect("connect b"));
    a.note_local_block_for_channels(&block);
    a.scan_connected_blocks_for_channels();
    b.note_local_block_for_channels(&block);
    b.scan_connected_blocks_for_channels();
}

fn hooks(wallet: Arc<Mutex<Wallet>>, node: Node, pending: Pending, can_fund: bool) -> Hooks {
    let w_fund = wallet.clone();
    let n_fund = node.clone();
    let fund = Box::new(
        move |_cid: Hash256, funding_output: TxOut| -> Result<Transaction, String> {
            if !can_fund {
                return Err("this side does not fund".into());
            }
            let mut w = w_fund.lock().unwrap();
            n_fund.with_chain(|c| {
                let prepared = w
                    .prepare_funding(
                        &c.utxo,
                        c.height(),
                        funding_output,
                        Amount::from_units(FUND_FEE),
                        &|_| false,
                        &[],
                    )
                    .map_err(|e| format!("{e:?}"))?;
                w.sign_spend(&c.utxo, prepared)
                    .map_err(|e| format!("{e:?}"))
            })
        },
    );
    let p_b = pending.clone();
    // As a mempool would: one already held is not added twice, and one that
    // spends what a held one spends is refused.
    let broadcast = Box::new(move |tx: &Transaction| -> Result<(), String> {
        let mut p = p_b.lock().unwrap();
        if p.iter().any(|t| t.txid() == tx.txid()) {
            return Ok(());
        }
        if p.iter().any(|t| {
            t.inputs
                .iter()
                .any(|i| tx.inputs.iter().any(|j| j.prev_out == i.prev_out))
        }) {
            return Err("spend conflict".into());
        }
        p.push(tx.clone());
        Ok(())
    });
    let w_s = wallet.clone();
    let sweep_address = Box::new(move || w_s.lock().unwrap().new_address().hash);
    let w_p = wallet.clone();
    let payout_address = Box::new(move || w_p.lock().unwrap().new_address().hash);
    let w_r = wallet.clone();
    let reserve = Box::new(move |tx: &Transaction, hold: bool| {
        let coins: Vec<_> = tx.inputs.iter().map(|i| i.prev_out).collect();
        let mut w = w_r.lock().unwrap();
        if hold {
            w.lock_coins(&coins);
        } else {
            w.unlock_coins(&coins);
        }
    });
    Hooks {
        fund,
        broadcast,
        sweep_address,
        payout_address,
        reserve,
    }
}

struct Net {
    a: Node,
    b: Node,
    fmgr: Arc<ChannelManager>,
    amgr: Arc<ChannelManager>,
    fwallet: Arc<Mutex<Wallet>>,
    bwallet: Arc<Mutex<Wallet>>,
    pending: Pending,
    miner: Hash256,
    bid: u64, // A's connection id for B
    fseed: [u8; 32],
    aseed: [u8; 32],
    dir: std::path::PathBuf,
    b_listen: std::net::SocketAddr,
}

/// These tests each stand up two mining nodes; run serially so one test's
/// proof-of-work search never starves another's networking on the shared CPUs.
static SERIAL: Mutex<()> = Mutex::new(());

fn wait(cond: impl Fn() -> bool, secs: u64) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    cond()
}

fn setup(tag: &str, funder_seed: [u8; 32], acceptor_seed: [u8; 32]) -> Net {
    setup_as(tag, funder_seed, acceptor_seed, false)
}

/// `funder_dials`: when true the funder (A) dials the acceptor (B), so on A the
/// peer's durable identity is B's stable listen address — what a restart redials.
/// When false, A listens and B dials (the funder sees an inbound peer).
fn setup_as(tag: &str, funder_seed: [u8; 32], acceptor_seed: [u8; 32], funder_dials: bool) -> Net {
    let dir = std::env::temp_dir().join(format!("q21chan-net-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("f")).unwrap();
    std::fs::create_dir_all(dir.join("a")).unwrap();

    let fwallet = Arc::new(Mutex::new(
        Wallet::from_seed_scheme(funder_seed, NET, SchemeId::MlDsa87).unwrap(),
    ));
    let bwallet = Arc::new(Mutex::new(
        Wallet::from_seed_scheme(acceptor_seed, NET, SchemeId::MlDsa87).unwrap(),
    ));
    let a = Node::new(NET, Chain::new(NET, genesis_block(NET)));
    let b = Node::new(NET, Chain::new(NET, genesis_block(NET)));
    let pending: Pending = Arc::new(Mutex::new(Vec::new()));

    let fmgr = Arc::new(ChannelManager::new(
        NET,
        RATE,
        funder_seed,
        dir.join("f"),
        DELAY,
        DEPTH,
        hooks(fwallet.clone(), a.clone(), pending.clone(), true),
    ));
    let amgr = Arc::new(ChannelManager::new(
        NET,
        RATE,
        acceptor_seed,
        dir.join("a"),
        DELAY,
        DEPTH,
        hooks(bwallet.clone(), b.clone(), pending.clone(), false),
    ));
    a.set_channel_sink(ChannelTransport::new(fmgr.clone()));
    b.set_channel_sink(ChannelTransport::new(amgr.clone()));

    // Give the funder some coinbase, then mine enough burn blocks that ALL of
    // it is mature before the test starts. Test-phase blocks are mined to a
    // burn address (`miner`), so during a channel's lifecycle no coinbase
    // matures and no wallet is credited except by the channel itself — the
    // balance deltas a test measures are the channel's alone.
    let miner = Hash256([0xbb; 32]);
    for _ in 0..20 {
        let m = fwallet.lock().unwrap().new_address().hash;
        sync_mine(&a, &b, &pending, m);
    }
    for _ in 0..(COINBASE_MATURITY + 2) {
        sync_mine(&a, &b, &pending, miner);
    }

    // B always listens so a restarted funder has a stable address to redial.
    let b_listen = b.listen("127.0.0.1:0").expect("listen b");
    if funder_dials {
        a.connect(b_listen).expect("a dials b");
    } else {
        let a_listen = a.listen("127.0.0.1:0").expect("listen a");
        b.connect(a_listen).expect("b dials a");
    }
    assert!(
        wait(
            || a.peer_count_established() >= 1 && b.peer_count_established() >= 1,
            10
        ),
        "handshake did not complete"
    );
    let bid = *wait_vec(|| a.channel_peers(), 5)
        .first()
        .expect("A sees B as channel-capable");
    wait_sessions(&fmgr, &amgr, bid);

    Net {
        a,
        b,
        fmgr,
        amgr,
        fwallet,
        bwallet,
        pending,
        miner,
        bid,
        fseed: funder_seed,
        aseed: acceptor_seed,
        dir,
        b_listen,
    }
}

/// Waits until the funder's connection `bid` carries an established session
/// at both ends, authenticated as the right node each way.
fn wait_sessions(fmgr: &ChannelManager, amgr: &ChannelManager, bid: u64) {
    assert!(
        wait(
            || fmgr.peer_node_id(bid) == Some(amgr.node_id())
                && amgr.sessions().iter().any(|(_, id)| *id == fmgr.node_id()),
            10
        ),
        "the channel session did not come up"
    );
}

fn wait_vec(f: impl Fn() -> Vec<u64>, secs: u64) -> Vec<u64> {
    let start = Instant::now();
    loop {
        let v = f();
        if !v.is_empty() || start.elapsed() > Duration::from_secs(secs) {
            return v;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

impl Net {
    fn height(&self) -> u64 {
        self.a.height()
    }
    fn mine(&self) {
        sync_mine(&self.a, &self.b, &self.pending, self.miner);
    }
    fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
    /// Puts a raw transaction on chain at the next mine — a cheating funder
    /// broadcasting a revoked commitment, for instance.
    fn cheat_broadcast(&self, tx: &Transaction) {
        self.pending.lock().unwrap().push(tx.clone());
    }
    /// Spendable balance a wallet sees on its node's chain.
    fn balance(&self, wallet: &Arc<Mutex<Wallet>>, node: &Node) -> u64 {
        let w = wallet.lock().unwrap();
        node.with_chain(|c| w.balance(&c.utxo, c.height()).units())
    }
    fn f_balance(&self) -> u64 {
        self.balance(&self.fwallet, &self.a)
    }
    fn b_balance(&self) -> u64 {
        self.balance(&self.bwallet, &self.b)
    }

    /// Opens a channel A→B over the wire and drives it to `open` on both sides.
    fn open(&self, capacity: u64) -> Hash256 {
        let known: Vec<Hash256> = self.fmgr.list().iter().map(|c| c.channel_id).collect();
        let hello = self.fmgr.open(self.bid, capacity, None, None).unwrap();
        assert!(self.fmgr.send(self.bid, hello));
        let fresh = || {
            self.fmgr
                .list()
                .into_iter()
                .map(|c| c.channel_id)
                .find(|c| !known.contains(c))
        };
        assert!(
            wait(|| fresh().is_some(), 10),
            "the channel was not created"
        );
        let cid = fresh().unwrap();
        // Wait for funding to be built (pushed to pending by the fund hook) and
        // for both sides to have learned the funding outpoint (the handshake
        // reached the funding step), so the block hook can confirm it.
        assert!(
            wait(|| self.pending_len() >= 1, 10),
            "funding was not built"
        );
        self.mine(); // mines the funding transaction
        assert!(
            wait(
                || funding_known(&self.fmgr, cid) && funding_known(&self.amgr, cid),
                10
            ),
            "the funding handshake did not complete"
        );
        // Bury to depth; each mined block drives both nodes' block hook, which
        // confirms the funding and moves each side to `open`.
        for _ in 0..(DEPTH + 8) {
            if phase_is_open(&self.fmgr, cid) && phase_is_open(&self.amgr, cid) {
                break;
            }
            self.mine();
            std::thread::sleep(Duration::from_millis(30));
        }
        assert!(
            phase_is_open(&self.fmgr, cid) && phase_is_open(&self.amgr, cid),
            "channel did not open"
        );
        cid
    }

    /// Drops the funder's live links and redials, as a transient network flap
    /// would. The channel stays in memory; only the connection changes, so the
    /// node-id rebind must recover it. Returns the new connection id.
    fn flap_link(&mut self) -> u64 {
        self.a.disconnect_all_peers();
        assert!(
            wait(|| self.a.peer_count() == 0, 10),
            "the old link did not drop"
        );
        let bid2 = self
            .a
            .connect(self.b_listen)
            .expect("redial after the flap");
        assert!(
            wait(|| self.a.channel_peers().contains(&bid2), 10),
            "the link did not re-establish after the flap"
        );
        wait_sessions(&self.fmgr, &self.amgr, bid2);
        self.bid = bid2;
        bid2
    }

    /// Simulates a funder process restart: a fresh manager reloads the channels
    /// from the journal directory, is reinstalled on the node, and redials the
    /// acceptor's stable address. The handshake re-binds the reloaded channel to
    /// the new connection and sends reestablish. Returns the new connection id.
    fn restart_funder(&mut self) -> u64 {
        let fmgr2 = Arc::new(ChannelManager::new(
            NET,
            RATE,
            self.fseed,
            self.dir.join("f"),
            DELAY,
            DEPTH,
            hooks(
                self.fwallet.clone(),
                self.a.clone(),
                self.pending.clone(),
                true,
            ),
        ));
        self.a
            .set_channel_sink(ChannelTransport::new(fmgr2.clone()));
        self.fmgr = fmgr2;
        let bid2 = self.a.connect(self.b_listen).expect("redial the acceptor");
        assert!(
            wait(|| self.a.channel_peers().contains(&bid2), 10),
            "reconnect did not establish a channel-capable link"
        );
        wait_sessions(&self.fmgr, &self.amgr, bid2);
        self.bid = bid2;
        bid2
    }
}

fn phase_is_open(mgr: &ChannelManager, cid: Hash256) -> bool {
    use q21_core::channel::machine::Phase;
    mgr.info(cid)
        .map(|i| i.phase == Phase::Open)
        .unwrap_or(false)
}

fn funding_known(mgr: &ChannelManager, cid: Hash256) -> bool {
    mgr.info(cid).map(|i| i.funding.is_some()).unwrap_or(false)
}

/// D9: a cooperative close credits BOTH parties' wallets with spendable funds.
#[test]
fn cooperative_close_credits_both_wallets() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let net = setup("d9", [0x91u8; 32], [0x92u8; 32]);

    let cap = 4_000_000u64;
    let cid = net.open(cap);

    // Pay the acceptor; now the acceptor holds 1_000_000, the funder the rest.
    let paid = 1_000_000u64;
    let pay = net.fmgr.pay(cid, paid).unwrap();
    assert!(net.fmgr.send(net.bid, pay));
    assert!(
        wait(
            || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == paid,
            10
        ),
        "payment did not land"
    );

    // Balances just before the close; the channel's capacity is locked on chain.
    let f_before = net.f_balance();
    let b_before = net.b_balance();

    // Cooperative close, proposed by the funder.
    // `None`: a payment still settling; the Close follows it on its own.
    if let Some(close) = net.fmgr.close(cid).unwrap() {
        assert!(net.fmgr.send(net.bid, close));
    }
    assert!(
        wait(|| net.pending_len() >= 1, 10),
        "cooperative close was not signed and broadcast"
    );
    net.mine();

    let close_fee = q21_core::channel::manager::CLOSE_FEE;
    let f_after = net.f_balance();
    let b_after = net.b_balance();
    // Each wallet's spendable balance rises by its channel balance: the
    // acceptor's whole balance, the funder's less the close fee.
    assert_eq!(
        b_after - b_before,
        paid,
        "acceptor wallet gains its channel balance, spendable"
    );
    assert_eq!(
        f_after - f_before,
        (cap - paid) - close_fee,
        "funder wallet gains its channel balance less the close fee, spendable"
    );

    // The recovered coin is genuinely spendable: the wallet can select it to
    // send onward. Build and validate such a spend against the chain.
    let send_amount = paid - FUND_FEE;
    let dest = q21_core::address::Address {
        network: NET,
        scheme: SchemeId::MlDsa87,
        hash: Hash256([0xcd; 32]),
    };
    let spend = {
        let mut w = net.bwallet.lock().unwrap();
        net.b.with_chain(|c| {
            let prepared = w
                .prepare_spend(
                    &c.utxo,
                    c.height(),
                    &[(dest, Amount::from_units(send_amount))],
                    Amount::from_units(FUND_FEE),
                )
                .expect("prepare a spend of the payout");
            w.sign_spend(&c.utxo, prepared).expect("sign the spend")
        })
    };
    net.b.with_chain(|c| {
        let mut spent = std::collections::HashSet::new();
        q21_core::validate::check_transaction(&spend, &c.utxo, NET, c.height(), &mut spent)
            .expect("the acceptor's payout is spendable onward");
    });

    net.a.shutdown();
    net.b.shutdown();
}

/// D10: an honest force-close sweeps the to_local output to the funder's wallet
/// only after the delay, driven by the node's real block hook.
#[test]
fn force_close_sweeps_to_wallet_after_delay() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let net = setup("d10", [0x93u8; 32], [0x94u8; 32]);

    let cap = 4_000_000u64;
    let cid = net.open(cap);

    // Move some balance so the funder's to_local is well above dust.
    let paid = 1_000_000u64;
    let pay = net.fmgr.pay(cid, paid).unwrap();
    assert!(net.fmgr.send(net.bid, pay));
    assert!(
        wait(
            || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == paid,
            10
        ),
        "payment did not land"
    );

    // The funder's capacity is locked on chain; this is its wallet baseline.
    let f_locked = net.f_balance();

    // Funder force-closes: the commitment is broadcast and mined.
    net.fmgr.force_close(cid).unwrap();
    assert!(
        wait(|| net.pending_len() >= 1, 5),
        "commitment not broadcast"
    );
    net.mine();
    let commit_h = net.height();

    // Before the delay matures nothing is swept: the wallet balance does not move.
    for _ in 0..(DELAY as u64 - 1) {
        net.mine();
        assert_eq!(
            net.f_balance(),
            f_locked,
            "nothing may be swept before the delay matures"
        );
        assert!(net.height() < commit_h + DELAY as u64);
    }
    // Reaching commit_h + D, the block hook builds and broadcasts the sweep;
    // the next block confirms it and credits the funder's wallet.
    assert!(
        wait(
            || {
                net.mine();
                net.f_balance() > f_locked
            },
            15
        ),
        "the delayed sweep never credited the funder's wallet"
    );
    // The recovered coin is the funder's channel balance, less the sweep fee
    // and the (small) commitment fee the funder's commitment reserved.
    let close_fee = q21_core::channel::manager::CLOSE_FEE;
    let recovered = net.f_balance() - f_locked;
    let shortfall = (cap - paid) - recovered;
    assert!(
        shortfall >= close_fee && shortfall < close_fee + 10_000,
        "recovered {recovered} is the channel balance {} less sweep and commitment fees",
        cap - paid
    );
    use q21_core::channel::machine::Phase;
    // Settled once the sweep is buried to the funding depth.
    for _ in 1..DEPTH {
        net.mine();
    }
    assert!(
        wait(
            || net
                .fmgr
                .info(cid)
                .map(|i| i.phase == Phase::Closed)
                .unwrap_or(false),
            5
        ),
        "the channel settles to closed once the sweep confirms"
    );

    net.a.shutdown();
    net.b.shutdown();
}

/// D8/D5: a node that only ACCEPTED the connection can still open a channel back
/// to the dialer — the dialer's capability and height were recorded inbound.
#[test]
fn an_accepting_node_can_open_back_to_the_dialer() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    // Here A listens and B dials, so on A the peer B is *inbound*. We then make
    // A (the accepting side) the funder that opens back to B.
    let net = setup("d8", [0x95u8; 32], [0x96u8; 32]);

    // B is inbound on A. getpeers on A must show B channel-capable with a height.
    let listed: Vec<PeerInfo> = net.a.peer_list();
    let b_entry = listed
        .iter()
        .find(|p| !p.outbound)
        .expect("B is inbound on A");
    assert!(
        b_entry.supports_channels,
        "an inbound peer's channel capability must be recorded"
    );
    // The dialer completed the handshake after syncing, so its announced height
    // is recorded too (not left at zero).
    assert!(
        b_entry.height > 0,
        "an inbound peer's announced height must be recorded, got {}",
        b_entry.height
    );
    // The inbound peer advertised its stable channel node id, and it is the
    // acceptor manager's id — the durable identity that re-binds across ports.
    assert_eq!(
        b_entry.channel_id,
        net.amgr.node_id_hex(),
        "an inbound peer's stable channel node id must be recorded"
    );

    // A (accepting side) opens a channel to the inbound dialer, naming it by its
    // stable node id, and it reaches open.
    let cid = {
        assert_eq!(
            net.fmgr.peer_node_id(net.bid),
            Some(net.amgr.node_id()),
            "the session authenticated the acceptor's node id"
        );
        assert!(net.amgr.node_id().starts_with(&net.amgr.node_id_hex()));
        net.open(4_000_000)
    };
    assert!(phase_is_open(&net.fmgr, cid) && phase_is_open(&net.amgr, cid));

    net.a.shutdown();
    net.b.shutdown();
}

/// D11: a channel survives a funder restart. After the manager reloads from its
/// journal and the funder reconnects, reestablish re-binds the channel to the
/// new connection and a further payment goes through — the funds never froze.
#[test]
fn channelpay_survives_a_restart_and_reconnect() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    // Funder dials the acceptor, so its durable peer identity is the acceptor's
    // stable listen address — exactly what the restarted funder redials.
    let mut net = setup_as("d11a", [0x97u8; 32], [0x98u8; 32], true);
    let cap = 4_000_000u64;
    let cid = net.open(cap);

    // A settled payment, so there is persisted state to recover.
    let pay = net.fmgr.pay(cid, 500_000).unwrap();
    assert!(net.fmgr.send(net.bid, pay));
    assert!(
        wait(
            || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == 500_000,
            10
        ),
        "first payment did not land"
    );

    // Restart the funder: a fresh manager reloads the channel from disk.
    net.restart_funder();
    // The reloaded channel is back, open, at the same state.
    let info = net.fmgr.info(cid).expect("channel reloaded after restart");
    assert_eq!(info.local_balance, cap - 500_000, "state recovered");

    // A payment after the reconnect proves the channel is usable again: the
    // reload + reestablish re-bound it to the new connection with no loss.
    assert!(
        wait(
            || {
                net.fmgr
                    .pay(cid, 300_000)
                    .map(|f| net.fmgr.send(net.bid, f))
                    .unwrap_or(false)
            },
            10
        ),
        "could not send a payment after the restart"
    );
    assert!(
        wait(
            || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == 800_000,
            10
        ),
        "payment after restart did not land — the channel was frozen"
    );

    // And a cooperative close after the restart settles to both wallets — no
    // force-close needed, proving the reloaded channel is fully usable.
    let b_before = net.b_balance();
    let f_before = net.f_balance();
    let close = net
        .fmgr
        .close(cid)
        .expect("a reloaded channel can be cooperatively closed");
    // `None`: the payment is still settling; the Close follows it on its own.
    if let Some(close) = close {
        assert!(net.fmgr.send(net.bid, close));
    }
    assert!(
        wait(|| net.pending_len() >= 1, 10),
        "cooperative close after restart was not signed and broadcast"
    );
    net.mine();
    let close_fee = q21_core::channel::manager::CLOSE_FEE;
    assert_eq!(
        net.b_balance() - b_before,
        800_000,
        "acceptor wallet credited to the unit after a post-restart close"
    );
    assert_eq!(
        net.f_balance() - f_before,
        (cap - 800_000) - close_fee,
        "funder wallet credited to the unit after a post-restart close"
    );

    net.a.shutdown();
    net.b.shutdown();
}

/// D13 (SAFETY): a revoked commitment with a SINGLE to_local output (the
/// counterparty's balance was zero, so there is no to_remote) must still be
/// punished. The victim's watcher detects the spend, decodes the revoked state,
/// builds the penalty against the to_local policy branch and broadcasts it well
/// before the to-self delay, crediting the victim's wallet.
#[test]
fn a_revoked_single_output_commitment_is_punished() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    use q21_core::channel::machine::Phase;
    let net = setup("d13single", [0x99u8; 32], [0x9au8; 32]);
    let cap = 4_000_000u64;
    let cid = net.open(cap); // state 0: funder=cap, acceptor=0 (single to_local on funder's commitment)

    // Grab the funder's REVOKED state-0 commitment before advancing.
    let revoked = net
        .fmgr
        .signed_commitment(cid, 0)
        .expect("the funder retains its state-0 commitment");
    assert_eq!(
        revoked.outputs.len(),
        1,
        "state-0 commitment has a single to_local output (acceptor balance 0)"
    );

    // Pay the acceptor, revoking state 0.
    let pay = net.fmgr.pay(cid, 1_000_000).unwrap();
    assert!(net.fmgr.send(net.bid, pay));
    assert!(
        wait(
            || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == 1_000_000,
            10
        ),
        "payment did not land"
    );

    let b_before = net.b_balance();
    // The funder cheats: it broadcasts the revoked single-output commitment.
    net.cheat_broadcast(&revoked);
    net.mine();
    let cheat_h = net.height();

    // The victim's watcher must punish it within a few blocks — far inside D.
    assert!(
        wait(
            || {
                net.mine();
                net.b_balance() > b_before
            },
            15
        ),
        "the revoked single-output broadcast was NOT punished — funds stolen"
    );
    assert!(
        net.height() < cheat_h + DELAY as u64,
        "the penalty confirmed before the to-self delay"
    );
    assert!(
        net.b_balance() - b_before >= cap - 100_000,
        "the victim swept the cheater's whole balance"
    );
    assert!(
        wait(
            || matches!(
                net.amgr.info(cid).map(|i| i.phase),
                Some(Phase::Penalised) | Some(Phase::Closed)
            ),
            5
        ),
        "the channel moves to penalised/closed"
    );

    net.a.shutdown();
    net.b.shutdown();
}

/// D13, the two-output revoked case, for completeness: after a payment back and
/// forth there are both outputs, and a revoked broadcast is still punished.
#[test]
fn a_revoked_two_output_commitment_is_punished() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    use q21_core::channel::machine::Phase;
    let net = setup("d13two", [0x9bu8; 32], [0x9cu8; 32]);
    let cap = 4_000_000u64;
    let cid = net.open(cap);

    // Pay to state 1 (both outputs present), keep state-1 as the revoked one.
    let pay1 = net.fmgr.pay(cid, 1_500_000).unwrap();
    assert!(net.fmgr.send(net.bid, pay1));
    assert!(
        wait(
            || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == 1_500_000,
            10
        ),
        "first payment did not land"
    );
    let revoked = net
        .fmgr
        .signed_commitment(cid, 1)
        .expect("state-1 commitment");
    assert_eq!(
        revoked.outputs.len(),
        2,
        "state-1 commitment has both outputs"
    );

    // Advance to state 2, revoking state 1. The victim's balance counts the
    // payment only once the funder's revocation of state 1 is in: before it,
    // the cheat below would be the funder's latest unrevoked state, not a
    // revoked one, and the victim could only claim its own output. (Waiting
    // on the balance used to race the revocation under load.)
    let pay2 = net.fmgr.pay(cid, 500_000).unwrap();
    assert!(net.fmgr.send(net.bid, pay2));
    assert!(
        wait(
            || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == 2_000_000,
            10
        ),
        "second payment did not land"
    );
    let b = net.amgr.info(cid).unwrap();
    assert_eq!(b.pending_incoming, 0);
    assert!(!b.in_flight, "the funder's revocation of state 1 is in");

    // What the victim must end with in its wallet: the cheater's to_local,
    // less the penalty fee, and its own to_remote in the revoked state, less
    // the claim fee — that one pays its channel key, as in any commitment.
    let close_fee = q21_core::channel::manager::CLOSE_FEE;
    let value = |policy: bool| {
        revoked
            .outputs
            .iter()
            .find(|o| (o.scheme == SchemeId::Policy) == policy)
            .map(|o| o.value.units())
            .unwrap()
    };
    let (to_local, own) = (value(true), value(false));
    let at_least = to_local - 16 * close_fee + own - close_fee;
    let b_before = net.b_balance();
    net.cheat_broadcast(&revoked);
    net.mine();
    let cheat_h = net.height();
    assert!(
        wait(
            || {
                net.mine();
                net.b_balance() >= b_before + at_least
            },
            15
        ),
        "the victim was not made whole: {} of at least {at_least}",
        net.b_balance() - b_before
    );
    assert!(net.b_balance() - b_before <= to_local + own);
    assert!(
        net.height() < cheat_h + DELAY as u64,
        "penalty before the delay"
    );
    assert!(
        wait(
            || matches!(
                net.amgr.info(cid).map(|i| i.phase),
                Some(Phase::Penalised) | Some(Phase::Closed)
            ),
            5
        ),
        "the channel moves to penalised/closed"
    );

    net.a.shutdown();
    net.b.shutdown();
}

/// D12: an honest force-close of a channel whose counterparty balance is zero
/// (single to_local output) must still sweep the to_local to our wallet after
/// the delay, instead of freezing in `forcing`.
#[test]
fn a_single_output_force_close_is_swept() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    use q21_core::channel::machine::Phase;
    let net = setup("d12", [0x9du8; 32], [0x9eu8; 32]);
    let cap = 4_000_000u64;
    let cid = net.open(cap); // acceptor balance 0 → funder's commitment is single-output

    let f_locked = net.f_balance();
    net.fmgr.force_close(cid).unwrap();
    assert!(
        wait(|| net.pending_len() >= 1, 5),
        "commitment not broadcast"
    );
    net.mine();
    let commit_h = net.height();

    for _ in 0..(DELAY as u64 - 1) {
        net.mine();
        assert_eq!(net.f_balance(), f_locked, "nothing swept before the delay");
        assert!(net.height() < commit_h + DELAY as u64);
    }
    assert!(
        wait(
            || {
                net.mine();
                net.f_balance() > f_locked
            },
            15
        ),
        "the single-output to_local was never swept — funds frozen"
    );
    assert!(
        net.f_balance() - f_locked >= cap - 100_000,
        "the sweep recovered the whole channel balance"
    );
    // Settled once the sweep is buried to the funding depth.
    for _ in 1..DEPTH {
        net.mine();
    }
    assert!(
        wait(
            || net
                .fmgr
                .info(cid)
                .map(|i| i.phase == Phase::Closed)
                .unwrap_or(false),
            5
        ),
        "the channel settles to closed"
    );

    net.a.shutdown();
    net.b.shutdown();
}

/// D14 (symptom): a channel stays usable across repeated link flaps. The TCP
/// connection is dropped and re-established several times; each reconnect
/// re-binds the channel by the peer's stable node id (not the ephemeral port),
/// so channelpay keeps working and the channel does not become unreachable.
#[test]
fn a_channel_survives_repeated_link_flaps() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let mut net = setup_as("d14flap", [0xa1u8; 32], [0xa2u8; 32], true);
    let cap = 6_000_000u64;
    let cid = net.open(cap);

    let mut paid = 0u64;
    for _ in 0..3 {
        net.flap_link();
        // After the flap the channel re-binds by node id on both sides, so a
        // payment goes through without re-opening or forcing a close.
        paid += 400_000;
        assert!(
            wait(
                || net
                    .fmgr
                    .pay(cid, 400_000)
                    .map(|f| net.fmgr.send(net.bid, f))
                    .unwrap_or(false),
                10
            ),
            "channelpay was refused after a link flap — the channel was isolated"
        );
        assert!(
            wait(
                || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == paid,
                10
            ),
            "payment did not land after a link flap"
        );
    }

    // And a cooperative close still settles both wallets after the flaps.
    let b_before = net.b_balance();
    // `None`: a payment still settling; the Close follows it on its own.
    if let Some(close) = net.fmgr.close(cid).unwrap() {
        assert!(net.fmgr.send(net.bid, close));
    }
    assert!(wait(|| net.pending_len() >= 1, 10), "close not broadcast");
    net.mine();
    assert_eq!(
        net.b_balance() - b_before,
        paid,
        "acceptor credited to the unit after flaps + close"
    );

    net.a.shutdown();
    net.b.shutdown();
}

/// D14: both ends pay at the same instant, so each receives the other's
/// proposal for the state it proposed itself. That is a race on the wire, not
/// misconduct: the proposal is not acted on, and costs its sender nothing.
/// Charged as misconduct, it cost the link, then again at every reestablish,
/// which resends the same crossed proposals.
#[test]
fn crossed_payments_are_not_misconduct() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let net = setup("d14cross", [0xc1u8; 32], [0xc2u8; 32]);
    let cap = 4_000_000u64;
    let cid = net.open(cap);

    // Give the acceptor a balance to pay with.
    let first = net.fmgr.pay(cid, 1_000_000).unwrap();
    assert!(net.fmgr.send(net.bid, first));
    assert!(
        wait(
            || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == 1_000_000,
            10
        ),
        "the first payment did not land"
    );

    // Each side proposes the next state before hearing from the other.
    // The acceptor waits out the funder's revocation of the first state.
    let start = Instant::now();
    let from_acceptor = loop {
        if let Ok(frame) = net.amgr.pay(cid, 5_000) {
            break frame;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the acceptor could not propose"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    let from_funder = net.fmgr.pay(cid, 10_000).unwrap();

    // Each proposal reaches the other side.
    let b_peer = *net.b.channel_peers().first().expect("B sees A");
    let at_acceptor = net.amgr.deliver(b_peer, &from_funder);
    let at_funder = net.fmgr.deliver(net.bid, &from_acceptor);
    assert_eq!(at_acceptor.penalize, 0, "the acceptor charged the race");
    assert_eq!(at_funder.penalize, 0, "the funder charged the race");

    net.a.shutdown();
    net.b.shutdown();
}

/// D14: two wallets that dial each other hold two links to the same peer.
/// Once the second link's session is up and its reestablish verified, a
/// payment arriving on it settles and the channel stays usable, not waiting
/// for a reestablish that no one sends while both links stay up. A session
/// there authenticated as another node is not heard.
#[test]
fn a_payment_on_the_second_link_leaves_the_channel_usable() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let net = setup("d14second", [0xd1u8; 32], [0xd2u8; 32]);
    let cid = net.open(4_000_000);
    let (fid, aid) = (net.fmgr.node_id(), net.amgr.node_id());
    // The second link, at each end.
    let (second_a, second_f) = (1_000_001u64, 1_000_002u64);

    // A session there authenticated as another node: its Close is ignored.
    net.amgr
        .on_session(second_a, &"ee".repeat(32), "", [0x50; 32]);
    let close = net.amgr.deliver(
        second_a,
        &[
            cid.as_bytes().as_slice(),
            &[0u8],
            &q21_core::channel::Message::Close {
                fee: 20_000,
                seq: 1,
                signature: vec![0; q21_core::channel::keys::CHANNEL_SCHEME.sig_len()],
            }
            .encode(),
        ]
        .concat(),
    );
    assert_eq!(close.penalize, 0);
    assert!(close.frames.is_empty());
    assert_eq!(
        net.amgr.info(cid).map(|i| i.phase),
        Some(q21_core::channel::Phase::Open)
    );

    // The second link's own session, authenticated as each other's node id:
    // both reestablish over it.
    let binding = [0x51; 32];
    let mut to_f: Vec<Vec<u8>> = net.amgr.on_session(second_a, &fid, "", binding);
    let mut to_a: Vec<Vec<u8>> = net.fmgr.on_session(second_f, &aid, "", binding);
    for _ in 0..4 {
        for f in to_f.drain(..) {
            let r = net.fmgr.deliver(second_f, &f);
            assert_eq!(r.penalize, 0);
            to_a.extend(r.frames);
        }
        for f in to_a.drain(..) {
            let r = net.amgr.deliver(second_a, &f);
            assert_eq!(r.penalize, 0);
            to_f.extend(r.frames);
        }
    }

    // The funder's payment reaches the acceptor on the second link; the rest
    // of the exchange follows the same path.
    let update = net.fmgr.pay(cid, 1_000_000).unwrap();
    let ack = net.amgr.deliver(second_a, &update);
    assert_eq!(ack.penalize, 0);
    for frame in ack.frames {
        let revoke = net.fmgr.deliver(second_f, &frame);
        assert_eq!(revoke.penalize, 0);
        for frame in revoke.frames {
            assert_eq!(net.amgr.deliver(second_a, &frame).penalize, 0);
        }
    }
    assert_eq!(
        net.amgr.info(cid).map(|i| i.local_balance),
        Some(1_000_000),
        "the payment did not settle"
    );

    // The acceptor can pay back at once.
    net.amgr
        .pay(cid, 1_000)
        .expect("the channel waits for a reestablish after a payment on the second link");

    net.a.shutdown();
    net.b.shutdown();
}

/// Startup rescan, through a real node: the victim's process is down when the
/// cheater's revoked commitment confirms (its node holds the blocks but no
/// channel manager saw them). Restarted before the delay, the node's startup
/// rescan finds the spend and the penalty confirms, crediting the victim with
/// the cheater's whole to_local.
#[test]
fn an_offline_victim_node_punishes_on_restart() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    use q21_core::channel::machine::Phase;
    let mut net = setup("rescan-victim", [0xc1u8; 32], [0xc2u8; 32]);
    let cid = net.open(4_000_000);
    for (amount, total) in [(1_500_000u64, 1_500_000u64), (500_000, 2_000_000)] {
        let pay = net.fmgr.pay(cid, amount).unwrap();
        assert!(net.fmgr.send(net.bid, pay));
        assert!(
            wait(
                || net.amgr.info(cid).map(|i| i.local_balance).unwrap_or(0) == total,
                10
            ),
            "payment did not land"
        );
    }
    let revoked = net.fmgr.signed_commitment(cid, 1).expect("state 1");
    let to_local = revoked
        .outputs
        .iter()
        .find(|o| o.scheme == SchemeId::Policy)
        .map(|o| o.value.units())
        .expect("a to_local");
    let own = revoked
        .outputs
        .iter()
        .find(|o| o.scheme != SchemeId::Policy)
        .map(|o| o.value.units())
        .expect("the victim's own to_remote");

    // The victim's process stops: its blocks arrive, nobody watches them.
    net.amgr = Arc::new(ChannelManager::new(
        NET,
        RATE,
        [0u8; 32],
        net.dir.join("nobody"),
        DELAY,
        DEPTH,
        hooks(
            net.bwallet.clone(),
            net.b.clone(),
            net.pending.clone(),
            false,
        ),
    ));
    net.b
        .set_channel_sink(ChannelTransport::new(net.amgr.clone()));
    net.cheat_broadcast(&revoked);
    net.mine();
    let cheat_h = net.height();
    net.mine();
    net.mine();

    // Restart: the reloaded manager is installed and the node rescans.
    let b_before = net.b_balance();
    let victim = Arc::new(ChannelManager::new(
        NET,
        RATE,
        net.aseed,
        net.dir.join("a"),
        DELAY,
        DEPTH,
        hooks(
            net.bwallet.clone(),
            net.b.clone(),
            net.pending.clone(),
            false,
        ),
    ));
    net.b
        .set_channel_sink(ChannelTransport::new(victim.clone()));
    net.b.rescan_channels();
    assert!(net.pending_len() >= 1, "no penalty after the rescan");
    net.mine();
    assert!(
        net.height() < cheat_h + u64::from(DELAY),
        "before the delay"
    );
    let close_fee = q21_core::channel::manager::CLOSE_FEE;
    let gained = net.b_balance() - b_before;
    assert!(
        gained + 16 * close_fee + close_fee >= to_local + own,
        "the victim took the cheater's to_local and its own to_remote \
         ({gained} of {to_local} + {own})"
    );
    for _ in 1..DEPTH {
        net.mine();
    }
    assert!(matches!(
        victim.info(cid).map(|i| i.phase),
        Some(Phase::Closed)
    ));
    net.a.shutdown();
    net.b.shutdown();
}

/// Both ends pay at the same instant, over the real link, several times in a
/// row: each pair of crossed proposals merges into the next state with both
/// payments, the balances stay conserved, and the channel keeps paying —
/// where it used to stay "a payment is already in flight" forever.
#[test]
fn crossed_payments_merge_and_the_channel_keeps_paying() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let net = setup("crossmerge", [0xe1u8; 32], [0xe2u8; 32]);
    let cap = 4_000_000u64;
    let cid = net.open(cap);
    let b_peer = *net.b.channel_peers().first().expect("B sees A");
    let pay = |mgr: &ChannelManager, amount: u64| -> Vec<u8> {
        let start = Instant::now();
        loop {
            if let Ok(frame) = mgr.pay(cid, amount) {
                return frame;
            }
            assert!(start.elapsed() < Duration::from_secs(10), "could not pay");
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let first = pay(&net.fmgr, 1_000_000);
    assert!(net.fmgr.send(net.bid, first));
    let mut expect_b = 1_000_000u64;
    for round in 0..5u64 {
        // Both propose before either hears from the other.
        let from_funder = pay(&net.fmgr, 10_000 + round);
        let from_acceptor = pay(&net.amgr, 4_000 + round);
        assert!(net.fmgr.send(net.bid, from_funder));
        assert!(net.amgr.send(b_peer, from_acceptor));
        expect_b = expect_b + 10_000 + round - (4_000 + round);
        let settled = || {
            let (f, a) = (net.fmgr.info(cid), net.amgr.info(cid));
            matches!((f, a), (Some(f), Some(a))
                if a.local_balance == expect_b
                    && f.local_balance == cap - expect_b
                    && f.state_number == a.state_number)
        };
        assert!(
            wait(settled, 15),
            "round {round}: the crossed payments did not merge"
        );
    }
    // And the channel keeps paying, one side at a time.
    let last = pay(&net.amgr, 1_000);
    assert!(net.amgr.send(b_peer, last));
    assert!(wait(
        || net.fmgr.info(cid).map(|i| i.local_balance) == Some(cap - expect_b + 1_000),
        10
    ));
    net.a.shutdown();
    net.b.shutdown();
}

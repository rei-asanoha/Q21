//! Policy activation at a real height, on a testnet chain.
//!
//! The compiled-in testnet height is far above anything a test can mine, so
//! this process moves it to [`H`] (audit builds only, once, before anything
//! reads it). Everything else is the testnet itself: its genesis, its proof
//! of work, its difficulty rule, its signature schemes.
//!
//! The boundary: a block at `H - 1` refuses a policy output or spend, a block
//! at `H` accepts it; the mempool takes one only once the next block is at
//! `H`; a reorganization never lets one below `H`, in either direction.

#![cfg(feature = "audit")]

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::block::Block;
use q21_core::chain::{genesis_block, Accept, Chain, ChainError};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::memhard::{PowTable, TableParams};
use q21_core::mempool::{Mempool, MempoolError};
use q21_core::policy::{self, Policy};
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::tx::Transaction;
use q21_core::validate::ValidationError;
use q21_core::wallet::Wallet;
use std::sync::OnceLock;

const NET: Network = Network::Testnet;
/// The activation height of this process: the first block that may carry a
/// policy. Just past coinbase maturity, so the wallet has coins to fund one.
const H: u64 = COINBASE_MATURITY + 20;
const ATTEMPTS: u64 = 50_000_000;
const SEED: [u8; 32] = [0x5a; 32];
const FEE: u64 = 50_000;

fn activate() {
    policy::audit_set_activation_height(NET, H);
    assert_eq!(policy::activation_height(NET), H);
}

fn timestamp(height: u64) -> u64 {
    genesis_block(NET).header.time + height * TARGET_BLOCK_SECS
}

/// The blocks up to `H - 2`, each paying a fresh address of the wallet of
/// [`SEED`]. Mined once per process.
fn prefix() -> &'static [Block] {
    static BLOCKS: OnceLock<Vec<Block>> = OnceLock::new();
    BLOCKS.get_or_init(|| {
        activate();
        let mut w = wallet_with(0);
        let mut c = new_chain();
        let mut out = Vec::new();
        for h in 1..=H - 2 {
            let b = c
                .mine_block(
                    w.new_address().hash,
                    SchemeId::LamportOts,
                    &[],
                    timestamp(h),
                    ATTEMPTS,
                )
                .expect("mining");
            c.connect(&b, timestamp(h) + 1).expect("connect");
            out.push(b);
        }
        out
    })
}

/// A testnet chain at its genesis, sharing the one proof-of-work table of
/// the process: each chain building its own made every test pay for it.
fn new_chain() -> Chain {
    let c = Chain::new(NET, genesis_block(NET));
    c.adopt_table(table());
    c
}

fn table() -> std::sync::Arc<PowTable> {
    static TABLE: OnceLock<std::sync::Arc<PowTable>> = OnceLock::new();
    TABLE
        .get_or_init(|| std::sync::Arc::new(PowTable::build(TableParams::for_network(NET), 0)))
        .clone()
}

/// The wallet of [`SEED`] after `n` addresses were drawn from it.
fn wallet_with(n: u64) -> Wallet {
    let mut w = Wallet::from_seed_scheme(SEED, NET, SchemeId::LamportOts).expect("wallet");
    for _ in 0..n {
        w.new_address();
    }
    w
}

/// A testnet chain at `H - 2`, and the wallet that mined it.
fn at_h_minus_2() -> (Chain, Wallet) {
    activate();
    let blocks = prefix();
    let mut c = new_chain();
    for b in blocks {
        c.connect(b, b.header.time + 1).expect("replay");
    }
    assert_eq!(c.height(), H - 2);
    (c, wallet_with(blocks.len() as u64))
}

/// A policy the tests lock coins to. Never spent here: its key leaf needs
/// ML-DSA, see the `spends` module.
fn lock() -> Policy {
    Policy::All(vec![
        Policy::Key {
            scheme: SchemeId::MlDsa87,
            pubkey_hash: Hash256([0x11; 32]),
        },
        Policy::Older(1),
    ])
}

/// A wallet payment creating one policy output.
fn funding(c: &Chain, w: &mut Wallet, value: u64) -> Transaction {
    let out = lock().output(Amount::from_units(value));
    let prepared = w
        .prepare_funding(
            &c.utxo,
            c.height(),
            out,
            Amount::from_units(FEE),
            &|_| false,
            &[],
        )
        .expect("funding");
    w.sign_spend(&c.utxo, prepared).expect("sign")
}

fn mine(c: &Chain, txs: &[Transaction], miner: Hash256) -> Block {
    let h = c.height() + 1;
    c.mine_block(miner, SchemeId::LamportOts, txs, timestamp(h), ATTEMPTS)
        .expect("mining")
}

fn connect(c: &mut Chain, b: &Block) -> Result<(), ValidationError> {
    c.connect(b, b.header.time + 1).map(|_| ())
}

fn forbidden() -> ValidationError {
    ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy)
}

fn has_policy_output(c: &Chain) -> bool {
    c.utxo
        .iter()
        .any(|(_, e)| e.output.scheme == SchemeId::Policy)
}

#[test]
fn the_process_moved_only_testnet() {
    activate();
    assert_eq!(policy::activation_height(NET), H);
    assert!(policy::has_transition(NET));
    assert!(!policy::may_appear_on(Network::Mainnet));
    assert_eq!(
        policy::activation_height(Network::Regtest),
        policy::scheduled_activation(Network::Regtest)
    );
}

#[test]
fn a_block_at_h_minus_1_refuses_a_policy_output_and_a_block_at_h_accepts_it() {
    let (mut c, mut w) = at_h_minus_2();
    let miner = Hash256([0x22; 32]);
    let tx = funding(&c, &mut w, 1_000_000);

    let early = mine(&c, std::slice::from_ref(&tx), miner);
    assert_eq!(early.header.height, H - 1);
    assert_eq!(connect(&mut c, &early), Err(forbidden()));
    assert_eq!(c.height(), H - 2, "the refused block is not connected");

    let empty = mine(&c, &[], miner);
    connect(&mut c, &empty).expect("an ordinary block at H - 1");
    assert!(!has_policy_output(&c));

    let at_h = mine(&c, std::slice::from_ref(&tx), miner);
    assert_eq!(at_h.header.height, H);
    connect(&mut c, &at_h).expect("a policy output at H");
    assert!(has_policy_output(&c));
}

#[test]
fn a_coinbase_paying_a_policy_is_refused_at_h_minus_1_and_accepted_at_h() {
    let (mut c, _) = at_h_minus_2();
    let lock_hash = lock().lock_hash();
    let early = c
        .mine_block(lock_hash, SchemeId::Policy, &[], timestamp(H - 1), ATTEMPTS)
        .expect("mining");
    assert_eq!(connect(&mut c, &early), Err(forbidden()));
    let empty = mine(&c, &[], Hash256([0x22; 32]));
    connect(&mut c, &empty).unwrap();
    let at_h = c
        .mine_block(lock_hash, SchemeId::Policy, &[], timestamp(H), ATTEMPTS)
        .expect("mining");
    connect(&mut c, &at_h).expect("a policy coinbase at H");
    assert!(has_policy_output(&c));
}

/// The mempool is the next block: it takes a policy output once the tip is
/// at `H - 1`, not before.
#[test]
fn the_mempool_takes_a_policy_output_once_the_next_block_is_at_h() {
    let (mut c, mut w) = at_h_minus_2();
    let tx = funding(&c, &mut w, 1_000_000);
    let mut m = Mempool::new();
    assert_eq!(
        m.accept(&tx, &c.utxo, NET, c.height()),
        Err(MempoolError::Validation(forbidden())),
        "at H - 2 the next block is H - 1"
    );
    let b = mine(&c, &[], Hash256([0x22; 32]));
    connect(&mut c, &b).unwrap();
    let id = m
        .accept(&tx, &c.utxo, NET, c.height())
        .expect("at H - 1 the next block is H");
    // And what the pool offers a miner makes a valid block at H.
    let template = m.select_for_block(u64::MAX);
    assert_eq!(template.len(), 1);
    let at_h = mine(&c, &template, Hash256([0x22; 32]));
    connect(&mut c, &at_h).expect("the template is valid at H");
    m.on_block_connected(&at_h);
    assert!(!m.contains(&id));
}

/// A reorganization from a branch without policies to a branch that crosses
/// `H` with one: valid, adopted.
#[test]
fn a_reorganization_onto_a_branch_crossing_h_with_a_policy_is_adopted() {
    let (mut a, mut w) = at_h_minus_2();
    let (mut b, _) = at_h_minus_2();
    let tx = funding(&a, &mut w, 1_000_000);
    // A: H - 1, H, both empty.
    for _ in 0..2 {
        let blk = mine(&a, &[], Hash256([0xaa; 32]));
        connect(&mut a, &blk).unwrap();
    }
    // B: H - 1 empty, H with the policy output, H + 1: longer.
    let mut branch = Vec::new();
    for txs in [vec![], vec![tx], vec![]] {
        let blk = mine(&b, &txs, Hash256([0xbb; 32]));
        connect(&mut b, &blk).unwrap();
        branch.push(blk);
    }
    let mut last = None;
    for blk in &branch {
        last = Some(a.submit(blk, blk.header.time + 1).expect("valid branch"));
    }
    assert!(matches!(last, Some(Accept::Reorganized { .. })));
    assert_eq!(a.tip_id(), b.tip_id());
    assert!(has_policy_output(&a));
}

/// A branch whose policy block sits at `H - 1` is invalid, however much
/// work follows it: the chain stays where it is.
#[test]
fn a_branch_with_a_policy_below_h_is_never_adopted() {
    let (mut a, mut w) = at_h_minus_2();
    let (mut b, _) = at_h_minus_2();
    let tx = funding(&a, &mut w, 1_000_000);
    let blk = mine(&a, &[], Hash256([0xaa; 32]));
    connect(&mut a, &blk).unwrap();
    let before = a.tip_id();

    // B: the block at H - 1 carrying the policy output, then a block at H
    // on top of it, which makes B the branch of more work. `bad` cannot be
    // connected anywhere to mine on it, so its child is an honest block at
    // H moved onto it: same height, same coinbase, same difficulty (the two
    // parents share their time and target), mined again.
    let bad = mine(&b, std::slice::from_ref(&tx), Hash256([0xbb; 32]));
    assert_eq!(bad.header.height, H - 1);
    let good = mine(&b, &[], Hash256([0xbb; 32]));
    connect(&mut b, &good).unwrap();
    let mut child = mine(&b, &[], Hash256([0xcc; 32]));
    child.header.prev_block = bad.header.block_id();
    child.header.nonce = 0;
    pow::mine_with_table(&mut child.header, &table(), ATTEMPTS).expect("re-mining");

    let first = a.submit(&bad, bad.header.time + 1);
    assert_eq!(first, Ok(Accept::SideBranch), "equal work: only stored");
    let r = a.submit(&child, child.header.time + 1);
    assert!(
        matches!(
            r,
            Err(ChainError::Validation(
                ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy)
            ))
        ),
        "{r:?}"
    );
    assert_eq!(a.tip_id(), before, "the chain stays on its branch");
    assert_eq!(a.height(), H - 1);
    assert!(!has_policy_output(&a));
}

/// A reorganization off a branch that carried a policy at `H`, onto a
/// longer branch forked below `H`: the policy output leaves the chain, the
/// funding goes back to the pool, and the next block, still at `H` or above,
/// may confirm it again.
#[test]
fn a_reorganization_below_h_puts_the_policy_back_in_the_pool() {
    let (mut a, mut w) = at_h_minus_2();
    let (mut b, _) = at_h_minus_2();
    let tx = funding(&a, &mut w, 1_000_000);
    for txs in [vec![], vec![tx.clone()]] {
        let blk = mine(&a, &txs, Hash256([0xaa; 32]));
        connect(&mut a, &blk).unwrap();
    }
    assert!(has_policy_output(&a));
    let mut branch = Vec::new();
    for _ in 0..3 {
        let blk = mine(&b, &[], Hash256([0xbb; 32]));
        connect(&mut b, &blk).unwrap();
        branch.push(blk);
    }
    for blk in &branch {
        a.submit(blk, blk.header.time + 1).expect("valid branch");
    }
    assert_eq!(a.tip_id(), b.tip_id());
    assert!(!has_policy_output(&a));

    let mut m = Mempool::new();
    let abandoned = a.take_disconnected();
    assert_eq!(
        m.return_abandoned(&abandoned, &a.utxo, NET, a.height()),
        1,
        "the funding comes back: the next block is above H"
    );
    assert!(m.contains(&tx.txid()));
}

/// The tip going back below `H - 1` (a disconnected tip, a shorter branch of
/// more work) leaves the pool holding a policy output the next block can no
/// longer carry. The pool drops it, or every miner would build an invalid
/// block.
#[test]
fn the_pool_drops_its_policies_when_the_tip_goes_back_below_h_minus_1() {
    let (mut c, mut w) = at_h_minus_2();
    let blk = mine(&c, &[], Hash256([0x22; 32]));
    connect(&mut c, &blk).unwrap();
    let tx = funding(&c, &mut w, 1_000_000);
    // An ordinary payment beside it, which must stay.
    let plain = {
        let mut other = Wallet::from_seed_scheme([0x77; 32], NET, SchemeId::LamportOts).unwrap();
        let to = other.new_address();
        w.create_transaction(
            &c.utxo,
            c.height(),
            &to,
            Amount::from_units(10_000),
            Amount::from_units(FEE),
        )
        .expect("plain payment")
    };
    let mut m = Mempool::new();
    m.accept(&tx, &c.utxo, NET, c.height()).expect("at H - 1");
    m.accept(&plain, &c.utxo, NET, c.height()).expect("plain");

    m.revalidate(&c.utxo, NET, c.height());
    assert_eq!(m.len(), 2, "nothing changes while the next block is at H");

    assert!(c.disconnect());
    assert_eq!(c.height(), H - 2);
    m.revalidate(&c.utxo, NET, c.height());
    assert!(!m.contains(&tx.txid()), "the next block is at H - 1 again");
    assert!(m.contains(&plain.txid()));
    assert!(m
        .select_for_block(u64::MAX)
        .iter()
        .all(|t| t.outputs.iter().all(|o| o.scheme != SchemeId::Policy)));
}

/// Spends need an ML-DSA key leaf: a policy refuses a one-time key.
#[cfg(feature = "mldsa")]
mod spends {
    use super::*;
    use ml_dsa::{signature::Keypair, MlDsa87, Signer, SigningKey, B32};
    use q21_core::policy::Satisfaction;
    use q21_core::tx::{OutPoint, TxIn, TxOut, Witness};

    struct Key {
        sk: SigningKey<MlDsa87>,
        pk: Vec<u8>,
    }

    impl Key {
        fn new() -> Key {
            let sk = SigningKey::<MlDsa87>::from_seed(&B32::from([0x31; 32]));
            let pk = sk.verifying_key().encode()[..].to_vec();
            Key { sk, pk }
        }
        fn policy(&self) -> Policy {
            Policy::All(vec![
                Policy::Key {
                    scheme: SchemeId::MlDsa87,
                    pubkey_hash: q21_core::sig::pubkey_hash(SchemeId::MlDsa87, &self.pk),
                },
                Policy::Older(1),
            ])
        }
        fn spend(&self, op: OutPoint, spent: TxOut, to: TxOut) -> Transaction {
            let p = self.policy();
            let mut tx = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_out: op,
                    witness: Witness::default(),
                    sequence: u32::MAX,
                }],
                outputs: vec![to],
                lock_time: 0,
            };
            let m = policy::sighash(&tx, 0, NET, &spent, &p, 0, &p.choices_to(0));
            let s = Satisfaction::All(vec![
                Satisfaction::Key {
                    pubkey: self.pk.clone(),
                    signature: self.sk.sign(m.as_bytes()).encode()[..].to_vec(),
                },
                Satisfaction::Older,
            ]);
            tx.inputs[0].witness = policy::witness(&p, &s);
            tx
        }
    }

    /// Created at `H`, spent at `H + 1`: the whole rule is in force from `H`,
    /// and the spend obeys the ripeness rule of its `Older` lock in the pool.
    #[test]
    fn a_policy_created_at_h_is_spent_after_it() {
        let (mut c, mut w) = at_h_minus_2();
        let key = Key::new();
        let value = 1_000_000;
        let out = key.policy().output(Amount::from_units(value));
        let prepared = w
            .prepare_funding(
                &c.utxo,
                c.height(),
                out,
                Amount::from_units(FEE),
                &|_| false,
                &[],
            )
            .unwrap();
        let fund = w.sign_spend(&c.utxo, prepared).unwrap();
        let blk = mine(&c, &[], Hash256([0x22; 32]));
        connect(&mut c, &blk).unwrap();
        let mut m = Mempool::new();
        m.accept(&fund, &c.utxo, NET, c.height()).expect("funding");

        let op = OutPoint {
            txid: fund.txid(),
            index: fund
                .outputs
                .iter()
                .position(|o| o.scheme == SchemeId::Policy)
                .unwrap() as u32,
        };
        let to = TxOut {
            value: Amount::from_units(value - FEE),
            scheme: SchemeId::LamportOts,
            pubkey_hash: Hash256([0x44; 32]),
        };
        let spend = key.spend(op, out, to);
        // Its parent is still in the pool: an `Older` spend waits for it.
        assert!(matches!(
            m.accept(&spend, &c.utxo, NET, c.height()),
            Err(MempoolError::Validation(ValidationError::Policy(
                policy::PolicyError::TooEarly { .. }
            )))
        ));
        let at_h = mine(&c, &m.select_for_block(u64::MAX), Hash256([0x22; 32]));
        connect(&mut c, &at_h).unwrap();
        m.on_block_connected(&at_h);
        m.accept(&spend, &c.utxo, NET, c.height())
            .expect("ripe at H + 1");
        let after = mine(&c, &m.select_for_block(u64::MAX), Hash256([0x22; 32]));
        assert_eq!(after.header.height, H + 1);
        connect(&mut c, &after).expect("the spend at H + 1");
        assert!(!has_policy_output(&c));
    }
}

/// On the wire, a policy output is malformed — the 0.4.9 treatment: penalty
/// and disconnection — only where the content could not be mined: a block
/// below `H`, or a transaction from a peer that predates the activation
/// while our next block is below `H`.
mod wire {
    use super::*;
    use q21_core::net::{magic_for, policy_output_is_malformed, Asked, Node};
    use q21_core::wire::{Message, POLICY_ACTIVATION_VERSION};
    use std::io::Write;
    use std::time::{Duration, Instant};

    const OLD: u32 = 4;
    const NEW: u32 = POLICY_ACTIVATION_VERSION;

    fn creating_tx() -> Transaction {
        let (c, mut w) = at_h_minus_2();
        funding(&c, &mut w, 1_000_000)
    }

    #[test]
    fn a_block_is_judged_by_its_own_height() {
        let (c, mut w) = at_h_minus_2();
        let tx = funding(&c, &mut w, 1_000_000);
        let mut b = mine(&c, &[tx], Hash256([0x22; 32]));
        for version in [OLD, NEW] {
            for tip in [0, H - 2, H + 10] {
                b.header.height = H - 1;
                let early = Message::Block(Box::new(b.clone()));
                assert!(policy_output_is_malformed(
                    NET,
                    tip,
                    version,
                    Asked::No,
                    &early
                ));
                b.header.height = H;
                let due = Message::Block(Box::new(b.clone()));
                assert!(!policy_output_is_malformed(
                    NET,
                    tip,
                    version,
                    Asked::No,
                    &due
                ));
            }
        }
    }

    #[test]
    fn a_transaction_is_judged_by_our_next_block_and_the_peer_version() {
        let m = Message::Tx(Box::new(creating_tx()));
        // A peer that predates the activation: exactly 0.4.10 until our next
        // block is at H.
        assert!(policy_output_is_malformed(NET, H - 2, OLD, Asked::Tx, &m));
        assert!(!policy_output_is_malformed(NET, H - 1, OLD, Asked::No, &m));
        // A peer that follows it may be ahead of us: here H is within the
        // notice of any tip, so it is never malformed.
        assert!(!policy_output_is_malformed(NET, 0, NEW, Asked::No, &m));
        // Mainnet never opens the rule.
        assert!(policy_output_is_malformed(
            Network::Mainnet,
            H + 1,
            NEW,
            Asked::Tx,
            &m
        ));
    }

    /// A raw peer that completed the handshake with `version`, announcing
    /// `height`.
    fn peer(node: &Node, version: u32, height: u64) -> std::net::TcpStream {
        let addr = node.listen("127.0.0.1:0").expect("listen");
        let mut s = std::net::TcpStream::connect(addr).expect("connect");
        let magic = magic_for(NET);
        let hello = Message::Version {
            version,
            timestamp: 0,
            nonce: 0x0bad_cafe,
            user_agent: "q21:0.4".into(),
            start_height: height,
        };
        s.write_all(&hello.frame(magic)).unwrap();
        s.write_all(&Message::VerAck.frame(magic)).unwrap();
        assert!(
            wait(|| node.peer_list().iter().any(|p| p.handshake_complete)),
            "handshake"
        );
        s
    }

    fn wait(mut f: impl FnMut() -> bool) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(10) {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// A write the node may refuse by cutting the link: that is what some
    /// tests check, not an error.
    fn send(s: &mut std::net::TcpStream, m: &Message) {
        let _ = s.write_all(&m.frame(magic_for(NET)));
    }

    /// Our tip at `H - 2`. A peer that follows the activation and is ahead
    /// of us relays policy transactions: refused, since our next block
    /// cannot carry them, but the peer is not charged and stays — charged as
    /// invalid transactions, six of them would cut it. The same transaction
    /// from a peer that predates the activation is what 0.4.10 made of it:
    /// malformed, and the link is cut at the first.
    #[test]
    fn a_policy_transaction_costs_a_following_peer_nothing_and_an_older_one_the_link() {
        let tx = creating_tx();
        for (version, kept) in [(NEW, true), (OLD, false)] {
            let (c, _) = at_h_minus_2();
            let node = Node::new(NET, c);
            let mut s = peer(&node, version, H);
            // Distinct transactions, so none is skipped as already refused.
            // The changed value breaks no check that comes first: the output
            // scheme is refused before any signature is looked at.
            for i in 0..6 {
                let mut t = tx.clone();
                t.outputs[0].value = Amount::from_units(t.outputs[0].value.units() - i);
                send(&mut s, &Message::Tx(Box::new(t)));
            }
            if kept {
                std::thread::sleep(Duration::from_millis(500));
                assert_eq!(node.peer_count(), 1, "version {version} must stay");
                assert_eq!(node.mempool_len(), 0);
            } else {
                assert!(
                    wait(|| node.peer_count() == 0),
                    "version {version} must be cut"
                );
            }
            node.shutdown();
        }
    }

    /// Our tip at `H - 1`: a peer sends the block at `H` carrying a policy
    /// output. Whatever its version, the block is valid and adopted, and the
    /// peer is not charged.
    #[test]
    fn a_policy_block_at_h_is_adopted_from_any_peer() {
        for version in [NEW, OLD] {
            let (mut c, mut w) = at_h_minus_2();
            let tx = funding(&c, &mut w, 1_000_000);
            let b = mine(&c, &[], Hash256([0x22; 32]));
            connect(&mut c, &b).unwrap();
            let at_h = mine(&c, std::slice::from_ref(&tx), Hash256([0x22; 32]));
            let node = Node::new(NET, c);
            let mut s = peer(&node, version, H);
            send(&mut s, &Message::Block(Box::new(at_h.clone())));
            assert!(
                wait(|| node.tip_id() == at_h.header.block_id()),
                "the block at H is adopted from version {version}"
            );
            assert_eq!(node.peer_count(), 1);
            node.shutdown();
        }
    }
}

/// A peer that predates the activation reads a policy output as malformed
/// and cuts the link: it is never offered, nor sent, a policy transaction.
mod relay {
    use super::*;
    use q21_core::net::{magic_for, Node};
    use q21_core::wire::{InvItem, InvKind, Message, WireError, POLICY_ACTIVATION_VERSION};
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    fn peer(node: &Node, addr: std::net::SocketAddr, version: u32) -> std::net::TcpStream {
        let mut s = std::net::TcpStream::connect(addr).expect("connect");
        let magic = magic_for(NET);
        let before = node
            .peer_list()
            .iter()
            .filter(|p| p.handshake_complete)
            .count();
        let hello = Message::Version {
            version,
            timestamp: 0,
            nonce: 0x5eed_0000 + u64::from(version),
            user_agent: "q21:0.4".into(),
            start_height: H - 1,
        };
        s.write_all(&hello.frame(magic)).unwrap();
        s.write_all(&Message::VerAck.frame(magic)).unwrap();
        let t = Instant::now();
        while node
            .peer_list()
            .iter()
            .filter(|p| p.handshake_complete)
            .count()
            == before
        {
            assert!(t.elapsed() < Duration::from_secs(10), "handshake");
            std::thread::sleep(Duration::from_millis(20));
        }
        s
    }

    /// Every message the node sends `s` within `secs`.
    fn received(s: &mut std::net::TcpStream, secs: u64) -> Vec<Message> {
        let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
        let magic = magic_for(NET);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            match s.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => {}
            }
        }
        let mut out = Vec::new();
        loop {
            match Message::parse(&buf, magic) {
                Ok((m, used)) => {
                    buf.drain(..used);
                    out.push(m);
                }
                Err(WireError::Incomplete) => break,
                Err(e) => panic!("unreadable frame: {e:?}"),
            }
        }
        out
    }

    fn offers(msgs: &[Message], txid: &Hash256) -> bool {
        msgs.iter().any(|m| match m {
            Message::Inv(items) => items
                .iter()
                .any(|i| i.kind == InvKind::Tx && i.hash == *txid),
            _ => false,
        })
    }

    fn sends(msgs: &[Message], txid: &Hash256) -> bool {
        msgs.iter()
            .any(|m| matches!(m, Message::Tx(t) if t.txid() == *txid))
    }

    #[test]
    fn a_policy_transaction_reaches_only_the_peers_that_follow_the_activation() {
        let (mut c, mut w) = at_h_minus_2();
        let b = mine(&c, &[], Hash256([0x22; 32]));
        connect(&mut c, &b).unwrap();
        let policy_tx = funding(&c, &mut w, 1_000_000);
        let plain = {
            let mut other =
                Wallet::from_seed_scheme([0x78; 32], NET, SchemeId::LamportOts).unwrap();
            let to = other.new_address();
            w.create_transaction(
                &c.utxo,
                c.height(),
                &to,
                Amount::from_units(10_000),
                Amount::from_units(FEE),
            )
            .unwrap()
        };
        let node = Node::new(NET, c);
        let addr = node.listen("127.0.0.1:0").expect("listen");
        let mut old = peer(&node, addr, 4);
        let mut new = peer(&node, addr, POLICY_ACTIVATION_VERSION);
        // What the handshake offered: nothing yet, the pool is empty.
        let _ = received(&mut old, 1);
        let _ = received(&mut new, 1);

        for tx in [&policy_tx, &plain] {
            node.with_chain_and_mempool(|c, m| m.accept_local(tx, &c.utxo, NET, c.height()))
                .expect("accepted at H - 1");
            node.announce_tx(tx.txid());
        }
        node.announce_mempool();
        let to_old = received(&mut old, 2);
        let to_new = received(&mut new, 2);
        assert!(offers(&to_new, &policy_tx.txid()));
        assert!(offers(&to_new, &plain.txid()));
        assert!(!offers(&to_old, &policy_tx.txid()), "{to_old:?}");
        assert!(offers(&to_old, &plain.txid()), "the rest still flows");

        // Asked for it by id anyway: served to the one, not to the other.
        let ask = Message::GetData(vec![
            InvItem {
                kind: InvKind::Tx,
                hash: policy_tx.txid(),
            },
            InvItem {
                kind: InvKind::Tx,
                hash: plain.txid(),
            },
        ]);
        old.write_all(&ask.frame(magic_for(NET))).unwrap();
        new.write_all(&ask.frame(magic_for(NET))).unwrap();
        let to_old = received(&mut old, 2);
        let to_new = received(&mut new, 2);
        assert!(sends(&to_new, &policy_tx.txid()));
        assert!(!sends(&to_old, &policy_tx.txid()));
        assert!(sends(&to_old, &plain.txid()));
        assert_eq!(node.peer_count(), 2);
        node.shutdown();
    }
}

/// Within the notice before `H` — here from the genesis, `H` being closer
/// than the notice — each established peer that predates the activation is
/// warned about once per link; a peer that follows it never is.
mod warnings {
    use super::*;
    use q21_core::net::{magic_for, Node};
    use q21_core::wire::{Message, POLICY_ACTIVATION_VERSION};
    use std::io::Write;
    use std::time::{Duration, Instant};

    fn hello(
        node: &Node,
        addr: std::net::SocketAddr,
        version: u32,
        n: usize,
    ) -> std::net::TcpStream {
        let mut s = std::net::TcpStream::connect(addr).expect("connect");
        let magic = magic_for(NET);
        let v = Message::Version {
            version,
            timestamp: 0,
            nonce: 0x7a00 + n as u64,
            user_agent: "q21:0.4".into(),
            start_height: 0,
        };
        s.write_all(&v.frame(magic)).unwrap();
        s.write_all(&Message::VerAck.frame(magic)).unwrap();
        let t = Instant::now();
        while node
            .peer_list()
            .iter()
            .filter(|p| p.handshake_complete)
            .count()
            < n
        {
            assert!(t.elapsed() < Duration::from_secs(10), "handshake");
            std::thread::sleep(Duration::from_millis(20));
        }
        s
    }

    #[test]
    fn each_old_peer_is_warned_about_once() {
        activate();
        let node = Node::new(NET, new_chain());
        let addr = node.listen("127.0.0.1:0").expect("listen");
        let _new = hello(&node, addr, POLICY_ACTIVATION_VERSION, 1);
        assert_eq!(node.warn_peers_predating_activation(), 0);
        let _old = hello(&node, addr, 4, 2);
        assert_eq!(node.peers_predating_activation(), 1);
        assert_eq!(node.warn_peers_predating_activation(), 1);
        assert_eq!(node.warn_peers_predating_activation(), 0, "once per link");
        node.maintain_peers();
        assert_eq!(
            node.stats
                .peers_predating_activation_warned
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        node.shutdown();
    }
}

/// `channelstatus` and `getinfo` count down to `H` and turn active at it.
mod status {
    use super::*;
    use q21_core::net::Node;
    use q21_core::rpc::RpcContext;
    use std::sync::Arc;

    fn call(ctx: &RpcContext, method: &str) -> q21_core::json::Json {
        let raw = ctx.handle(&format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{}}}}"#
        ));
        q21_core::json::parse(&raw)
            .unwrap()
            .get("result")
            .cloned()
            .expect("result")
    }

    fn u(j: &q21_core::json::Json, k: &str) -> Option<u64> {
        j.get(k).and_then(|v| v.as_u64())
    }

    #[test]
    fn the_status_counts_down_to_h_and_turns_active_at_it() {
        let (mut c, _) = at_h_minus_2();
        let b = mine(&c, &[], Hash256([0x22; 32]));
        connect(&mut c, &b).unwrap();
        let next = mine(&c, &[], Hash256([0x22; 32]));
        let node = Arc::new(Node::new(NET, c));
        let ctx = RpcContext::read_only(node.clone(), NET);

        let s = call(&ctx, "channelstatus");
        assert_eq!(s.get("network").and_then(|v| v.as_str()), Some("Testnet"));
        assert_eq!(u(&s, "activation_height"), Some(H));
        assert_eq!(u(&s, "tip"), Some(H - 1));
        assert_eq!(s.get("active"), Some(&q21_core::json::Json::Bool(false)));
        assert_eq!(u(&s, "blocks_remaining"), Some(1));
        assert_eq!(u(&s, "eta_seconds"), Some(TARGET_BLOCK_SECS));
        let i = call(&ctx, "getinfo");
        let a = i.get("policy_activation").unwrap();
        assert_eq!(u(a, "activation_height"), Some(H));
        assert_eq!(u(a, "blocks_remaining"), Some(1));

        node.with_chain(|c| c.connect(&next, next.header.time + 1))
            .unwrap();
        let s = call(&ctx, "channelstatus");
        assert_eq!(u(&s, "tip"), Some(H));
        assert_eq!(s.get("active"), Some(&q21_core::json::Json::Bool(true)));
        assert_eq!(u(&s, "blocks_remaining"), Some(0));
        assert_eq!(u(&s, "eta_seconds"), Some(0));
    }
}

/// Channels open with the tip at `H`: before it no channel message leaves,
/// one received is ignored from a peer that follows the activation (it may
/// be ahead) and malformed from one that predates it, and the RPC that
/// opens, pays or closes refuses.
mod channels {
    use super::*;
    use q21_core::net::{magic_for, ChannelLink, ChannelOutcome, ChannelSink, Node};
    use q21_core::wire::{Message, POLICY_ACTIVATION_VERSION};
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct Counting(AtomicUsize);

    impl ChannelSink for Counting {
        fn deliver(&self, _peer: u64, _link: &ChannelLink, _bytes: &[u8]) -> ChannelOutcome {
            self.0.fetch_add(1, Ordering::SeqCst);
            ChannelOutcome::default()
        }
    }

    /// A node at `H - 1` running channels, and the block at `H` for it.
    fn node_before_h() -> (Node, Arc<Counting>, Block) {
        let (mut c, _) = at_h_minus_2();
        let b = mine(&c, &[], Hash256([0x22; 32]));
        connect(&mut c, &b).unwrap();
        let at_h = mine(&c, &[], Hash256([0x22; 32]));
        let node = Node::new(NET, c);
        let sink = Arc::new(Counting::default());
        node.set_channel_sink(sink.clone());
        (node, sink, at_h)
    }

    /// A raw channel-capable peer of `version`; returns its stream and id.
    fn chan_peer(node: &Node, version: u32) -> (std::net::TcpStream, u64) {
        let addr = node.listen("127.0.0.1:0").expect("listen");
        let mut s = std::net::TcpStream::connect(addr).expect("connect");
        let magic = magic_for(NET);
        let v = Message::Version {
            version,
            timestamp: 0,
            nonce: 0xc4a2 + u64::from(version),
            user_agent: format!(
                "q21:0.4{}0123456789abcdef0123456789abcdef",
                q21_core::wire::CHANNELS_CAPABILITY
            ),
            start_height: H - 1,
        };
        s.write_all(&v.frame(magic)).unwrap();
        s.write_all(&Message::VerAck.frame(magic)).unwrap();
        let t = Instant::now();
        loop {
            if let Some(p) = node
                .peer_list()
                .into_iter()
                // A peer below protocol 5 is no channel peer on testnet,
                // whatever its user agent: wait for the handshake alone.
                .find(|p| {
                    p.handshake_complete
                        && (p.supports_channels || version < POLICY_ACTIVATION_VERSION)
                })
            {
                return (s, p.id);
            }
            assert!(t.elapsed() < Duration::from_secs(10), "handshake");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn channel_frame() -> Vec<u8> {
        Message::Channel(vec![0u8; 40]).frame(magic_for(NET))
    }

    #[test]
    fn no_channel_message_moves_before_h() {
        let (node, sink, at_h) = node_before_h();
        let (mut s, id) = chan_peer(&node, POLICY_ACTIVATION_VERSION);
        assert!(
            !node.send_channel(id, vec![1, 2, 3]),
            "nothing leaves at H - 1"
        );
        let _ = s.write_all(&channel_frame());
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(sink.0.load(Ordering::SeqCst), 0, "ignored at H - 1");
        assert_eq!(node.peer_count(), 1, "a following peer may be ahead: kept");

        node.with_chain(|c| c.connect(&at_h, at_h.header.time + 1))
            .unwrap();
        assert!(node.send_channel(id, vec![1, 2, 3]), "open at H");
        let _ = s.write_all(&channel_frame());
        let t = Instant::now();
        while sink.0.load(Ordering::SeqCst) == 0 {
            assert!(t.elapsed() < Duration::from_secs(10), "delivered at H");
            std::thread::sleep(Duration::from_millis(20));
        }
        node.shutdown();
    }

    #[test]
    fn a_channel_message_from_an_older_peer_before_h_cuts_the_link() {
        let (node, sink, _) = node_before_h();
        let (mut s, id) = chan_peer(&node, 4);
        assert!(
            !node
                .peer_list()
                .iter()
                .any(|p| p.id == id && p.supports_channels),
            "a version-4 peer is no channel peer on testnet"
        );
        let _ = s.write_all(&channel_frame());
        let t = Instant::now();
        while node.peer_count() != 0 {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "malformed, as in 0.4.10"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(sink.0.load(Ordering::SeqCst), 0);
        node.shutdown();
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn the_channel_rpc_that_moves_funds_waits_for_h() {
        use q21_core::channel::manager::{ChannelManager, Hooks};
        use q21_core::json::Json;
        use q21_core::rpc::RpcContext;

        let (node, _, at_h) = node_before_h();
        let node = Arc::new(node);
        let dir = std::env::temp_dir().join(format!("q21-activation-rpc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = Arc::new(ChannelManager::new(
            NET,
            10,
            [0x61; 32],
            dir.clone(),
            q21_core::channel::terms(NET).default_delay,
            q21_core::channel::terms(NET).funding_depth,
            Hooks {
                fund: Box::new(|_, _| Err("no wallet here".into())),
                broadcast: Box::new(|_| Err("no relay here".into())),
                sweep_address: Box::new(|| Hash256([0x71; 32])),
                payout_address: Box::new(|| Hash256([0x72; 32])),
                reserve: Box::new(|_, _| {}),
            },
        ));
        let mut ctx = RpcContext::read_only(node.clone(), NET);
        ctx.channels = Some(mgr);
        let call = |m: &str, p: &str| -> Json {
            let raw = ctx.handle(&format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"{m}","params":{p}}}"#
            ));
            q21_core::json::parse(&raw).unwrap()
        };
        let cid = "00".repeat(32);
        let moving = [
            (
                "channelopen",
                r#"{"peer":7,"capacity":1000000}"#.to_string(),
            ),
            (
                "channelpay",
                format!(r#"{{"channel_id":"{cid}","amount":1000}}"#),
            ),
            ("channelclose", format!(r#"{{"channel_id":"{cid}"}}"#)),
        ];
        let message = |r: &Json| {
            r.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or_default()
                .to_string()
        };
        for (m, p) in &moving {
            let r = call(m, p);
            let text = message(&r);
            assert!(
                text.contains(&format!("at block {H}"))
                    && text.contains("1 blocks to go")
                    // What the wallet's Channels tab reads as "not active yet".
                    && text.contains("not active"),
                "{m} at H - 1: {r:?}"
            );
        }
        // Reading needs no wait.
        let r = call("channellist", "{}");
        assert_eq!(r.get("result"), Some(&Json::Array(Vec::new())), "{r:?}");
        let r = call("channelinfo", &format!(r#"{{"channel_id":"{cid}"}}"#));
        assert!(message(&r).contains("unknown channel"), "{r:?}");

        node.with_chain(|c| c.connect(&at_h, at_h.header.time + 1))
            .unwrap();
        for (m, p) in &moving {
            let r = call(m, p);
            let text = message(&r);
            assert!(!text.is_empty(), "{m}: no peer, no channel");
            assert!(!text.contains("blocks to go"), "{m} at H: {r:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The lab's switch: an audit build of the node takes the activation height
/// of a regtest or testnet process from the command line, never mainnet's.
mod node_option {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn q21() -> &'static str {
        env!("CARGO_BIN_EXE_q21")
    }

    fn dir(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("q21-activation-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn rpc(port: u16, method: &str) -> Option<String> {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        write!(
            s,
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        let mut resp = String::new();
        s.read_to_string(&mut resp).ok()?;
        let at = resp.find("\r\n\r\n")?;
        Some(resp[at + 4..].to_string())
    }

    /// The option names the network it moves; mainnet cannot even be named.
    #[test]
    fn the_option_needs_regtest_or_testnet() {
        for network in [None, Some("mainnet")] {
            let d = dir("unnamed");
            let mut args = vec!["node", "--no-bootstrap"];
            if let Some(n) = network {
                args.extend(["--network", n]);
            }
            args.extend(["--audit-policy-activation", "5", "--seconds", "1"]);
            let out = Command::new(q21())
                .arg("--datadir")
                .arg(&d)
                .args(&args)
                .stdin(Stdio::null())
                .output()
                .expect("q21");
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            assert!(!out.status.success(), "{network:?}: {err}");
            assert!(
                err.contains("requires --network regtest or testnet")
                    || err.contains("mainnet does not exist"),
                "{network:?}: {err}"
            );
        }
    }

    #[test]
    fn a_regtest_node_takes_the_lab_height() {
        let d = dir("regtest");
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut child = Command::new(q21())
            .arg("--datadir")
            .arg(&d)
            .args([
                "node",
                "--network",
                "regtest",
                "--no-bootstrap",
                "--audit-policy-activation",
                "50",
                "--rpc",
                &format!("127.0.0.1:{port}"),
                "--seconds",
                "60",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("q21");
        let t = Instant::now();
        let status = loop {
            if let Some(r) = rpc(port, "channelstatus") {
                break r;
            }
            assert!(
                t.elapsed() < Duration::from_secs(60),
                "the node does not start"
            );
            std::thread::sleep(Duration::from_millis(200));
        };
        let _ = child.kill();
        let _ = child.wait();
        assert!(status.contains("\"activation_height\":50"), "{status}");
        assert!(status.contains("\"blocks_remaining\":50"), "{status}");
        assert!(status.contains("\"active\":false"), "{status}");
    }
}

/// Channel sessions on a network with a transition: below `H` the transport
/// starts, answers and retries no handshake — the node would send none of
/// its frames — and at `H` the session comes up at once, whichever side of
/// the link reaches it first.
#[cfg(feature = "mldsa")]
mod sessions {
    use super::*;
    use q21_core::channel::link::ChannelTransport;
    use q21_core::channel::manager::{ChannelManager, Hooks};
    use q21_core::net::Node;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const MINER: Hash256 = Hash256([0x33; 32]);

    fn hooks() -> Hooks {
        Hooks {
            fund: Box::new(|_, _| Err("no funding here".into())),
            broadcast: Box::new(|_| Ok(())),
            sweep_address: Box::new(|| Hash256([1; 32])),
            payout_address: Box::new(|| Hash256([2; 32])),
            reserve: Box::new(|_, _| {}),
        }
    }

    struct Side {
        node: Node,
        mgr: Arc<ChannelManager>,
        t: Arc<ChannelTransport>,
    }

    /// A channel node with its tip at `H - 1`.
    fn side(seed: u8, tag: &str, at_h_minus_1: &Block) -> Side {
        let (mut c, _) = at_h_minus_2();
        connect(&mut c, at_h_minus_1).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "q21-activation-sessions-{}-{tag}-{seed}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = Arc::new(ChannelManager::new(
            NET,
            10,
            [seed; 32],
            dir,
            12,
            2,
            hooks(),
        ));
        let t = ChannelTransport::new(mgr.clone());
        let node = Node::new(NET, c);
        node.set_channel_sink(t.clone());
        Side { node, mgr, t }
    }

    /// The block at `H` connected, and handed to the channel component as
    /// the node's block hook does.
    fn reach_h(s: &Side, at_h: &Block) {
        s.node
            .with_chain(|c| c.connect(at_h, at_h.header.time + 1))
            .unwrap();
        s.node.note_local_block_for_channels(at_h);
        s.node.scan_connected_blocks_for_channels();
    }

    fn up(s: &Side, other: &Side) -> bool {
        s.mgr
            .sessions()
            .iter()
            .any(|(_, id)| *id == other.mgr.node_id())
    }

    #[test]
    fn no_handshake_before_h_and_a_session_as_soon_as_both_reach_it() {
        let (mut c, _) = at_h_minus_2();
        let b = mine(&c, &[], MINER);
        connect(&mut c, &b).unwrap();
        let at_h = mine(&c, &[], MINER);
        for (tag, dialer_first) in [("responder-first", false), ("dialer-first", true)] {
            // `a` is dialed, `b` dials: `b` starts the handshake.
            let a = side(0x41, tag, &b);
            let d = side(0x42, tag, &b);
            let addr = a.node.listen("127.0.0.1:0").expect("listen");
            d.node.connect(addr).expect("connect");
            let t = Instant::now();
            while a.node.channel_peers().is_empty() || d.node.channel_peers().is_empty() {
                assert!(t.elapsed() < Duration::from_secs(10), "{tag}: link");
                std::thread::sleep(Duration::from_millis(20));
            }
            // Maintenance rounds below `H`: no handshake, no retry.
            for _ in 0..15 {
                a.node.maintain_peers();
                d.node.maintain_peers();
                std::thread::sleep(Duration::from_millis(100));
            }
            assert_eq!(a.t.handshake_attempts(), 0, "{tag}: responder below H");
            assert_eq!(d.t.handshake_attempts(), 0, "{tag}: dialer below H");
            assert!(!up(&a, &d) && !up(&d, &a));

            // One side reaches `H`, the other a moment later. Its frames go
            // out; the other drops them until it gets there too.
            let (first, second) = if dialer_first { (&d, &a) } else { (&a, &d) };
            reach_h(first, &at_h);
            std::thread::sleep(Duration::from_millis(300));
            reach_h(second, &at_h);
            let t = Instant::now();
            while !(up(&a, &d) && up(&d, &a)) {
                assert!(
                    t.elapsed() < Duration::from_secs(1),
                    "{tag}: no session within a second of H"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            a.node.shutdown();
            d.node.shutdown();
        }
    }
}

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

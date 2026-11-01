//! FUZZ (red-team campaign 6, round 2): header and block acceptance, and
//! compact block reconstruction, on a real regtest chain.
//!
//! `tests/fuzz_decoders.rs` covers the bytes; this covers what a peer's
//! *well-formed* header or block reaches next: `Chain::check_header`,
//! `Chain::header_to_prove` and the work check done outside the lock,
//! `Chain::submit` (extension, side branch, reorganization and its rollback),
//! `Chain::connect`, and `Reconstruction` of a compact block. Blocks are
//! mutated at the structure level and then RE-MINED, so that the proof of
//! work and the Merkle roots pass and the mutation reaches the deep checks.
//!
//! Asserted, beyond "never panics":
//!
//! - a refused block or header leaves the chain exactly as it was (tip,
//!   height, total issued, UTXO commitment), including a reorganization that
//!   fails half-way;
//! - a block extending the tip with a known-invalid mutation is refused;
//! - the total issued always equals the coinbases of the active chain, and
//!   never exceeds the cap, across reorganizations;
//! - `check_header` accepts only a header that attaches at the right height
//!   with the imposed difficulty and a timestamp within the tolerance;
//! - a reconstructed compact block whose header is the original's is the
//!   original block, transaction for transaction.
//!
//! Rounds: `Q21_HEADER_FUZZ_ROUNDS` (defaults below).

use std::collections::HashMap;

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::block::{Block, BlockHeader};
use q21_core::chain::{genesis_block, Accept, Chain, GENESIS_TIME};
use q21_core::compact::{CompactBlock, Reconstruction};
use q21_core::consensus::{INITIAL_BITS, MAX_FUTURE_TIME, MAX_SUPPLY, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow::{self, PowEngine};
use q21_core::sig::SchemeId;
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::validate::uncle_rewards;

const NET: Network = Network::Regtest;
const MAX_TRIES: u64 = 50_000_000;
/// A re-mine that needs more than this is a mutated difficulty: give up.
const REMINE_TRIES: u64 = 200_000;

fn rounds(default: u64) -> u64 {
    std::env::var("Q21_HEADER_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    fn one_in(&mut self, n: u64) -> bool {
        n != 0 && self.next() % n == 0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 29) as u8
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for x in b.iter_mut() {
            *x = self.byte();
        }
        b
    }
    fn edge(&mut self, near: &[u64]) -> u64 {
        const FIXED: [u64; 9] = [
            0,
            1,
            u64::MAX,
            u64::MAX - 1,
            u32::MAX as u64,
            1 << 32,
            i64::MAX as u64,
            MAX_SUPPLY,
            MAX_SUPPLY + 1,
        ];
        if !near.is_empty() && self.one_in(2) {
            let b = near[self.below(near.len() as u64) as usize];
            match self.below(4) {
                0 => b,
                1 => b.wrapping_add(1),
                2 => b.wrapping_sub(1),
                _ => b.wrapping_add(self.below(2_000)),
            }
        } else {
            FIXED[self.below(FIXED.len() as u64) as usize]
        }
    }
}

fn ts(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn build_chain(n: u64) -> Chain {
    let mut c = Chain::new(NET, genesis_block(NET));
    for i in 1..=n {
        let b = c
            .mine_block(
                Hash256([i as u8; 32]),
                SchemeId::LamportOts,
                &[],
                ts(i),
                MAX_TRIES,
            )
            .expect("mining");
        c.connect(&b, ts(i) + 1).expect("connection");
    }
    c
}

fn coinbase(height: u64, miner: Hash256, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(height.to_le_bytes().to_vec())],
        outputs: vec![TxOut {
            value: Amount::from_units(value),
            scheme: SchemeId::LamportOts,
            pubkey_hash: miner,
        }],
        lock_time: 0,
    }
}

/// A valid, not yet mined block on `parent`, paying `miner`.
fn block_on(c: &Chain, parent: Hash256, miner: Hash256) -> Option<Block> {
    let ph = c.header_of(&parent)?;
    let height = ph.height + 1;
    let value = uncle_rewards(height, 0).miner_share;
    let mut b = Block {
        header: BlockHeader {
            version: 1,
            prev_block: parent,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner,
            time: ph.time + TARGET_BLOCK_SECS,
            bits: c.next_bits_after(parent),
            height,
            nonce: 0,
        },
        transactions: vec![coinbase(height, miner, value)],
        uncles: vec![],
    };
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    Some(b)
}

fn remine(b: &mut Block, table: &PowTable, roots: bool) -> bool {
    if roots {
        b.header.merkle_root = b.compute_merkle_root();
        b.header.uncles_root = b.compute_uncles_root();
    }
    b.header.nonce = 0;
    pow::mine_with_table(&mut b.header, table, REMINE_TRIES).is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    tip: Hash256,
    height: u64,
    issued: u64,
    commitment: Hash256,
}

fn state(c: &Chain) -> State {
    State {
        tip: c.tip_id(),
        height: c.height(),
        issued: c.total_issued().units(),
        commitment: c.utxo_commitment(),
    }
}

fn coinbase_total(b: &Block) -> u64 {
    b.transactions[0]
        .total_output()
        .map(|a| a.units())
        .unwrap_or(u64::MAX)
}

/// The issued total re-derived from the active chain.
fn issued_from_blocks(c: &Chain, genesis_issued: u64) -> Option<u64> {
    let mut total = genesis_issued;
    for h in 1..=c.height() {
        total = total.checked_add(coinbase_total(&c.block_at(h)?))?;
    }
    Some(total)
}

/// A random, structurally plausible transaction.
fn random_tx(rng: &mut Rng) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: Hash256(rng.bytes32()),
                index: rng.below(4) as u32,
            },
            witness: Witness {
                pubkey: vec![rng.byte(); 1 + rng.below(40) as usize],
                signature: vec![rng.byte(); 1 + rng.below(80) as usize],
            },
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(10_000 + rng.below(1_000_000)),
            scheme: SchemeId::MlDsa87,
            pubkey_hash: Hash256(rng.bytes32()),
        }],
        lock_time: 0,
    }
}

// ---------------------------------------------------------------------------
// Headers alone
// ---------------------------------------------------------------------------

#[test]
fn header_checks_never_panic_and_accept_only_what_attaches() {
    let c = build_chain(20);
    let table = PowTable::build(TableParams::for_network(NET), epoch_of(1));
    let mut rng = Rng(0x5150_2131_4EAD_0001);
    let ids: Vec<Hash256> = (0..=c.height()).filter_map(|h| c.active_at(h)).collect();

    // Seeds: the next block, siblings of recent blocks, and known headers.
    let mut seeds: Vec<BlockHeader> = Vec::new();
    for back in 0..6u64 {
        let parent = ids[(c.height() - back) as usize];
        if let Some(mut b) = block_on(&c, parent, Hash256([0x77; 32])) {
            if remine(&mut b, &table, true) {
                seeds.push(b.header);
            }
        }
    }
    for h in [1, 5, c.height()] {
        if let Some(b) = c.block_at(h) {
            seeds.push(b.header);
        }
    }
    let before = state(&c);
    let total = rounds(3_000);
    let mut accepted = 0u64;
    for round in 0..total {
        let mut h = seeds[rng.below(seeds.len() as u64) as usize];
        let now_base = ts(c.height() + 1) + 1;
        for _ in 0..=rng.below(2) {
            match rng.below(9) {
                0 => h.version = rng.next() as u32,
                1 => {
                    h.prev_block = if rng.one_in(2) {
                        ids[rng.below(ids.len() as u64) as usize]
                    } else {
                        Hash256(rng.bytes32())
                    }
                }
                2 => h.merkle_root = Hash256(rng.bytes32()),
                3 => h.miner = Hash256(rng.bytes32()),
                4 => h.time = rng.edge(&[h.time, now_base + MAX_FUTURE_TIME, GENESIS_TIME]),
                5 => {
                    h.bits = match rng.below(6) {
                        0 => 0,
                        1 => u32::MAX,
                        2 => INITIAL_BITS + 1,
                        3 => INITIAL_BITS - 1,
                        4 => 0x2100_ffff,
                        _ => rng.next() as u32,
                    }
                }
                6 => {
                    h.height =
                        rng.edge(&[h.height, c.height(), q21_core::consensus::POW_EPOCH_BLOCKS])
                }
                7 => h.nonce = rng.next(),
                _ => {
                    // Re-mine whatever the header now says, so the work
                    // check passes where it can (cheap at the floor only).
                    if h.bits == INITIAL_BITS {
                        h.nonce = 0;
                        let _ = pow::mine_with_table(&mut h, &table, 4_000);
                    }
                }
            }
        }
        let now = if rng.one_in(8) {
            GENESIS_TIME
        } else {
            now_base
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let checked = c.check_header(&h, now);
            let proved = c.header_to_prove(&h, now).map(|(engine, memo)| {
                let verdict = engine.check(&h);
                memo.record(h.block_id(), verdict);
                verdict
            });
            (checked, proved)
        }));
        let (checked, proved) = match r {
            Ok(x) => x,
            Err(_) => panic!("PANIC checking header at round {round}: {h:?} (now {now})"),
        };
        if checked.is_ok() {
            accepted += 1;
            if !c.has_block(&h.block_id()) {
                let parent = c
                    .header_of(&h.prev_block)
                    .expect("accepted header without parent");
                assert_eq!(
                    h.height,
                    parent.height + 1,
                    "accepted at the wrong height: {h:?}"
                );
                assert_eq!(
                    h.bits,
                    c.next_bits_after(h.prev_block),
                    "accepted another difficulty"
                );
                assert!(
                    h.time <= now + MAX_FUTURE_TIME,
                    "accepted a header from the future"
                );
                // The light check and the outside-the-lock check agree.
                assert!(matches!(proved, Some(Ok(())) | None), "{proved:?}");
            }
        }
        if let Some(Ok(())) = proved {
            // Work verified outside the lock is real work.
            assert!(
                Q21Check::new().check(&h).is_ok(),
                "a header recorded as proven fails the work check"
            );
        }
    }
    assert_eq!(state(&c), before, "checking headers changed the chain");
    eprintln!("headers: {total} rounds, {accepted} accepted by check_header");
}

/// The node's own verification engine, built the public way.
struct Q21Check(pow::Q21Pow);

impl Q21Check {
    fn new() -> Q21Check {
        Q21Check(pow::Q21Pow::new(NET))
    }
    fn check(&self, h: &BlockHeader) -> Result<(), pow::PowError> {
        self.0.check(h)
    }
}

// ---------------------------------------------------------------------------
// Whole blocks, re-mined after mutation
// ---------------------------------------------------------------------------

#[test]
fn mutated_blocks_never_corrupt_the_chain() {
    let mut c = build_chain(16);
    let table = PowTable::build(TableParams::for_network(NET), epoch_of(1));
    let mut rng = Rng(0x5150_2131_4EAD_0002);
    let mut issued_above_genesis = 0u64;
    for h in 1..=c.height() {
        issued_above_genesis += coinbase_total(&c.block_at(h).expect("body"));
    }
    let genesis_issued = c
        .total_issued()
        .units()
        .checked_sub(issued_above_genesis)
        .expect("the issued total is below the coinbases of the chain");
    let block1_coinbase = c.block_at(1).expect("block 1").transactions[0].txid();
    let mut side: Vec<Hash256> = Vec::new();
    let mut stats: HashMap<&'static str, (u64, u64)> = HashMap::new();
    let total = rounds(600);

    for round in 0..total {
        // A parent: the tip mostly, an ancestor or a side block sometimes.
        let parent = match rng.below(10) {
            0..=5 => c.tip_id(),
            6..=7 => {
                let back = rng.below(4).min(c.height());
                c.active_at(c.height() - back).expect("active")
            }
            _ => match side.get(rng.below(side.len() as u64 + 1) as usize) {
                Some(id) if c.has_block(id) => *id,
                _ => c.tip_id(),
            },
        };
        let miner = Hash256(rng.bytes32());
        let Some(mut b) = block_on(&c, parent, miner) else {
            continue;
        };
        let height = b.header.height;
        let value = b.transactions[0].outputs[0].value.units();
        let mut roots = true;
        let mut mined = true;
        // (name, certainly invalid)
        let (name, invalid): (&'static str, bool) = match rng.below(24) {
            0..=5 => ("valid", false),
            6 => {
                b.transactions[0].outputs[0].value = Amount::from_units(value + 1);
                ("coinbase+1", true)
            }
            7 => {
                b.transactions[0].outputs[0].value =
                    Amount::from_units(rng.edge(&[value, MAX_SUPPLY]).max(value + 1));
                ("coinbase-edge", true)
            }
            8 => {
                b.transactions[0].outputs[0].value = Amount::from_units(rng.below(10_000));
                ("coinbase-dust", true)
            }
            9 => {
                b.transactions[0].outputs.push(TxOut {
                    value: Amount::from_units(1_000_000),
                    scheme: SchemeId::LamportOts,
                    pubkey_hash: Hash256(rng.bytes32()),
                });
                ("coinbase-extra-output", true)
            }
            10 => {
                let s = match rng.below(4) {
                    0 => SchemeId::NameTag,
                    1 => SchemeId::NameKey,
                    2 => SchemeId::SphincsPlus,
                    _ => SchemeId::Policy,
                };
                b.transactions[0].outputs[0].scheme = s;
                ("coinbase-scheme", s != SchemeId::Policy)
            }
            11 => {
                let data = match rng.below(3) {
                    0 => Vec::new(),
                    1 => (height + 1).to_le_bytes().to_vec(),
                    _ => (height.wrapping_sub(1)).to_le_bytes().to_vec(),
                };
                b.transactions[0].inputs[0] = TxIn::coinbase(data);
                ("coinbase-height", true)
            }
            12 => {
                let mut data = height.to_le_bytes().to_vec();
                data.extend((0..rng.below(5_000)).map(|_| rng.byte()));
                b.transactions[0].inputs[0] = TxIn::coinbase(data);
                ("coinbase-long-data", false)
            }
            13 => {
                b.transactions.push(random_tx(&mut rng));
                ("spends-nothing", true)
            }
            14 => {
                let mut t = random_tx(&mut rng);
                t.inputs[0].prev_out = OutPoint {
                    txid: block1_coinbase,
                    index: 0,
                };
                b.transactions.push(t);
                ("spends-immature-coinbase", true)
            }
            15 => {
                let t = random_tx(&mut rng);
                b.transactions.push(t.clone());
                b.transactions.push(t);
                ("duplicate-tx", true)
            }
            16 => {
                b.transactions.push(coinbase(height, miner, 1));
                ("second-coinbase", true)
            }
            17 => {
                let mut t = random_tx(&mut rng);
                if rng.one_in(2) {
                    t.inputs.clear();
                } else {
                    t.outputs.clear();
                }
                b.transactions.push(t);
                ("empty-tx", true)
            }
            18 => {
                let mut t = random_tx(&mut rng);
                t.outputs.push(TxOut {
                    value: Amount::from_units(u64::MAX - 5),
                    scheme: SchemeId::MlDsa87,
                    pubkey_hash: Hash256::ZERO,
                });
                b.transactions.push(t);
                ("output-overflow", true)
            }
            19 => {
                // An uncle: a sibling of a recent block, or anything.
                let mut u = b.header;
                u.height = height.saturating_sub(1 + rng.below(3));
                u.prev_block = c
                    .active_at(u.height.saturating_sub(1))
                    .unwrap_or(Hash256::ZERO);
                u.miner = Hash256(rng.bytes32());
                u.nonce = 0;
                let _ = pow::mine_with_table(&mut u, &table, 20_000);
                for _ in 0..(1 + rng.below(3)) {
                    b.uncles.push(u);
                }
                ("uncles", true)
            }
            20 => {
                b.header.time = match rng.below(5) {
                    0 => 0,
                    1 => u64::MAX,
                    2 => GENESIS_TIME,
                    3 => b.header.time + MAX_FUTURE_TIME + 2,
                    _ => b.header.time - TARGET_BLOCK_SECS,
                };
                ("header-time", false)
            }
            21 => {
                b.header.bits = match rng.below(4) {
                    0 => INITIAL_BITS + 1,
                    1 => INITIAL_BITS - 1,
                    2 => 0,
                    _ => u32::MAX,
                };
                ("header-bits", true)
            }
            22 => {
                b.header.height = rng.edge(&[height]).max(height + 1);
                mined = false;
                ("header-height", true)
            }
            _ => {
                if rng.one_in(2) {
                    b.header.miner = Hash256(rng.bytes32());
                    ("header-miner", true)
                } else {
                    b.transactions[0].outputs[0].value = Amount::from_units(value - 1);
                    roots = false;
                    ("stale-merkle-root", true)
                }
            }
        };
        if mined {
            mined = remine(&mut b, &table, roots);
        }
        let extends_tip = parent == c.tip_id();
        let before = state(&c);
        let now = b.header.time.min(ts(c.height() + 50)).max(GENESIS_TIME) + 1;
        let now = if name == "header-time" {
            ts(height) + 1
        } else {
            now
        };
        let via_connect = extends_tip && rng.one_in(4);
        let id = b.header.block_id();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if via_connect {
                c.connect(&b, now)
                    .map(|_| Accept::Extended)
                    .map_err(|e| format!("{e:?}"))
            } else {
                c.submit(&b, now).map_err(|e| format!("{e:?}"))
            }
        }));
        let r = match outcome {
            Ok(r) => r,
            Err(_) => panic!(
                "PANIC accepting a block at round {round} (mutation {name}, mined {mined}, via connect {via_connect}): header {:?}, {} txs, {} uncles",
                b.header,
                b.transactions.len(),
                b.uncles.len()
            ),
        };
        let e = stats.entry(name).or_insert((0, 0));
        if r.is_ok() {
            e.0 += 1;
        } else {
            e.1 += 1;
        }
        match &r {
            Err(err) => {
                assert_eq!(
                    state(&c),
                    before,
                    "round {round}: a refused block ({name}: {err}) changed the chain"
                );
            }
            Ok(Accept::Extended) => {
                assert!(
                    !invalid,
                    "round {round}: an invalid block ({name}) extended the chain"
                );
                assert_eq!(c.tip_id(), id);
                assert_eq!(c.height(), before.height + 1);
            }
            Ok(Accept::SideBranch) | Ok(Accept::AlreadyKnown) => {
                assert_eq!(
                    state(&c),
                    before,
                    "round {round}: a side block moved the tip"
                );
                if matches!(r, Ok(Accept::SideBranch)) {
                    side.push(id);
                }
            }
            Ok(Accept::Reorganized { depth }) => {
                assert!(
                    !invalid,
                    "round {round}: an invalid block ({name}) won a reorganization"
                );
                assert_eq!(c.tip_id(), id);
                assert!(
                    *depth <= 8,
                    "reorganization deeper than any branch built here: {depth}"
                );
                let _ = c.take_disconnected();
                let _ = c.take_disconnected_txids();
            }
        }
        if extends_tip && invalid {
            assert!(
                r.is_err(),
                "round {round}: an invalid block ({name}) was accepted: {r:?}"
            );
        }
        if extends_tip && name == "valid" && mined {
            // Otherwise the harness builds nothing the chain takes, and the
            // fuzzing above proves little.
            assert!(
                r.is_ok(),
                "round {round}: a valid block on the tip was refused: {r:?}"
            );
        }
        assert!(
            c.total_issued().units() <= MAX_SUPPLY,
            "issued above the cap"
        );
        if round % 10 == 0 {
            if let Some(expected) = issued_from_blocks(&c, genesis_issued) {
                assert_eq!(
                    c.total_issued().units(),
                    expected,
                    "round {round}: the issued total no longer matches the active chain"
                );
            }
        }
        if side.len() > 64 {
            side.drain(..32);
        }
    }
    let mut names: Vec<_> = stats.into_iter().collect();
    names.sort();
    eprintln!("--- blocks: accepted / refused per mutation ---");
    for (n, (ok, err)) in names {
        eprintln!("  {n:<26} {ok:>5} / {err:>5}");
    }
    eprintln!("final height {}", c.height());
}

// ---------------------------------------------------------------------------
// Compact blocks
// ---------------------------------------------------------------------------

fn mutate_bytes(rng: &mut Rng, v: &mut Vec<u8>) {
    if v.is_empty() {
        v.push(rng.byte());
        return;
    }
    let i = rng.below(v.len() as u64) as usize;
    match rng.below(6) {
        0 => v[i] ^= 1u8 << rng.below(8),
        1 => v[i] = rng.byte(),
        2 => v.truncate(i),
        3 => v.extend((0..1 + rng.below(30)).map(|_| rng.byte())),
        4 => {
            if v.len() >= i + 4 {
                v[i..i + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            }
        }
        _ => v[i] = 0xfd + rng.below(3) as u8,
    }
}

#[test]
fn compact_reconstruction_never_panics_nor_rebuilds_another_block() {
    let c = build_chain(3);
    let mut rng = Rng(0x5150_2131_4EAD_0003);
    let total = rounds(20_000);
    let mut rebuilt = 0u64;
    for round in 0..total {
        // A block of random transactions (reconstruction checks no
        // validity, only the Merkle root).
        let n = rng.below(40) as usize;
        let mut b = block_on(&c, c.tip_id(), Hash256([0x55; 32])).expect("block");
        for _ in 0..n {
            b.transactions.push(random_tx(&mut rng));
        }
        b.header.merkle_root = b.compute_merkle_root();
        let original = b.clone();
        let mut pool: HashMap<Hash256, Transaction> = HashMap::new();
        for t in b.transactions.iter().skip(1) {
            if !rng.one_in(3) {
                pool.insert(t.txid(), t.clone());
            }
        }
        for _ in 0..rng.below(20) {
            let t = random_tx(&mut rng);
            pool.insert(t.txid(), t);
        }
        let mut cb = CompactBlock::from_block(&b, rng.next());
        let total_tx = cb.tx_count() as u64;
        for _ in 0..rng.below(3) {
            match rng.below(10) {
                0 => {
                    if !cb.short_ids.is_empty() {
                        let i = rng.below(cb.short_ids.len() as u64) as usize;
                        cb.short_ids.remove(i);
                    }
                }
                1 => cb.short_ids.push(rng.next() & 0xffff_ffff_ffff),
                2 => {
                    if let Some(x) = cb.short_ids.first().copied() {
                        cb.short_ids.push(x);
                    }
                }
                3 => {
                    if let Some(p) = cb.prefilled.first_mut() {
                        p.0 = match rng.below(4) {
                            0 => total_tx as u32,
                            1 => u32::MAX,
                            2 => total_tx.saturating_sub(1) as u32,
                            _ => rng.next() as u32,
                        };
                    }
                }
                4 => {
                    if !cb.prefilled.is_empty() {
                        cb.prefilled.remove(0);
                    }
                }
                5 => {
                    let i = rng.below(total_tx + 2) as u32;
                    cb.prefilled.push((i, random_tx(&mut rng)));
                }
                6 => {
                    if let Some(p) = cb.prefilled.first().cloned() {
                        cb.prefilled.push(p);
                    }
                }
                7 => cb.nonce = rng.next(),
                8 => {
                    for _ in 0..rng.below(70) {
                        cb.uncles.push(cb.header);
                    }
                }
                _ => {
                    let mut bytes = cb.encode();
                    mutate_bytes(&mut rng, &mut bytes);
                    if let Ok(d) = CompactBlock::decode(&bytes) {
                        cb = d;
                    }
                }
            }
        }
        let header_kept = cb.header == original.header;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let rec = match Reconstruction::from_compact(&cb, &pool) {
                Ok(r) => r,
                Err(_) => return None,
            };
            let _ = rec.hit_rate();
            let missing: Vec<u32> = rec.missing().to_vec();
            let result = if rec.is_complete() && rng.one_in(2) {
                rec.finish()
            } else {
                let mut supplied: Vec<Transaction> = Vec::with_capacity(missing.len());
                for i in &missing {
                    let t = match original.transactions.get(*i as usize) {
                        Some(t) => t.clone(),
                        None => random_tx(&mut rng),
                    };
                    supplied.push(t);
                }
                match rng.below(5) {
                    0 => {
                        supplied.pop();
                    }
                    1 => supplied.push(random_tx(&mut rng)),
                    2 => {
                        if let Some(s) = supplied.first_mut() {
                            *s = random_tx(&mut rng);
                        }
                    }
                    _ => {}
                }
                rec.complete(supplied)
            };
            Some(result)
        }));
        let result = match r {
            Ok(x) => x,
            Err(_) => panic!(
                "PANIC reconstructing a compact block at round {round}: {} short ids, prefilled indexes {:?}, {} uncles",
                cb.short_ids.len(),
                cb.prefilled.iter().map(|p| p.0).collect::<Vec<_>>(),
                cb.uncles.len()
            ),
        };
        if let Some(Ok(block)) = result {
            rebuilt += 1;
            assert_eq!(block.compute_merkle_root(), block.header.merkle_root);
            if header_kept {
                assert_eq!(
                    block.transactions, original.transactions,
                    "round {round}: a compact block rebuilt other transactions under the same header"
                );
            }
        }
    }
    eprintln!("compact: {total} rounds, {rebuilt} blocks rebuilt");
}

// ---------------------------------------------------------------------------
// Difficulty on any timestamps (testnet and mainnet: regtest stays at the
// floor, so the chain tests above never reach the LWMA)
// ---------------------------------------------------------------------------

#[test]
fn difficulty_never_panics_and_never_goes_below_the_floor() {
    let mut rng = Rng(0x5150_2131_4EAD_0004);
    let floor = pow::floor_target();
    let total = rounds(20_000);
    for round in 0..total {
        let n = rng.below(q21_core::consensus::LWMA_WINDOW as u64 + 8) as usize;
        let mut t = GENESIS_TIME;
        let mut headers = Vec::with_capacity(n);
        for i in 0..n {
            t = match rng.below(8) {
                0 => rng.edge(&[t]),
                1 => t.saturating_sub(rng.below(100_000)),
                2 => t.saturating_add(rng.below(100_000)),
                _ => t.saturating_add(TARGET_BLOCK_SECS),
            };
            let bits = match rng.below(10) {
                0 => rng.next() as u32,
                1 => 0x1d00_ffff,
                2 => 0x0300_0001,
                3 => 0x2100_ffff,
                _ => INITIAL_BITS,
            };
            headers.push(BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: Hash256::ZERO,
                time: t,
                bits,
                height: i as u64,
                nonce: 0,
            });
        }
        let r = std::panic::catch_unwind(|| q21_core::chain::next_bits(&headers));
        let bits = match r {
            Ok(b) => b,
            Err(_) => panic!(
                "PANIC in next_bits at round {round}: times {:?}, bits {:?}",
                headers.iter().map(|h| h.time).collect::<Vec<_>>(),
                headers.iter().map(|h| h.bits).collect::<Vec<_>>()
            ),
        };
        let target = pow::target_from_compact(bits).unwrap_or_else(|e| {
            panic!("round {round}: next_bits gave an invalid target {bits:#x}: {e:?}")
        });
        assert!(
            target <= floor && !target.is_zero(),
            "round {round}: next_bits went below the difficulty floor or to zero: {bits:#x}"
        );
    }
}

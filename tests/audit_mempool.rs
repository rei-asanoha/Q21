//! Adversarial audit — axis "transaction pool and resource exhaustion".
//!
//! These tests first served to **measure** nine congestion flaws — the lesson
//! the original protocol had not anticipated: a pool that can be filled at zero
//! cost with transactions that will never be mined. The fixes are in place (see
//! `src/mempool.rs`); these tests **now lock in the fixed behavior**: each one
//! would fail if one of the doors reopened. The cost tests (t02, t03, t08)
//! remain measurements.

use q21_core::amount::Amount;
use q21_core::consensus::{MIN_OUTPUT_VALUE, WITNESS_DISCOUNT};
use q21_core::hash::Hash256;
use q21_core::lamport;
use q21_core::mempool::{Mempool, MempoolError, MEMPOOL_MAX_BYTES, MIN_FEE_RATE};
use q21_core::sig::{self, SchemeId};
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::utxo::{UtxoEntry, UtxoSet};
use q21_core::Network;

use std::time::Instant;

const NETWORK: Network = Network::Regtest;
const SEED: [u8; 32] = [0x5a; 32];

// ---------------------------------------------------------------------------
// Tooling: build signed transactions at will, without mining.
// ---------------------------------------------------------------------------

/// Lamport key number `i` and its lock hash.
fn key(i: u32) -> (lamport::SecretKey, Vec<u8>, Hash256) {
    let sk = lamport::SecretKey::from_seed(SEED, i);
    let pk = sk.public_key();
    let h = sig::pubkey_hash(SchemeId::LamportOts, &pk);
    (sk, pk, h)
}

/// Synthetic UTXO set: `n` outputs of `value` units, each locked by a distinct
/// Lamport key. Also returns the list of outpoints.
fn synthetic_utxo(n: u32, value: u64, start: u32) -> (UtxoSet, Vec<(OutPoint, u32, TxOut)>) {
    let mut u = UtxoSet::new();
    let mut v = Vec::new();
    for i in 0..n {
        let idx = start + i;
        let (_, _, h) = key(idx);
        let o = OutPoint {
            txid: Hash256([(idx % 251) as u8; 32]),
            index: idx,
        };
        u.insert(
            o,
            UtxoEntry {
                output: TxOut {
                    value: Amount::from_units(value),
                    scheme: SchemeId::LamportOts,
                    pubkey_hash: h,
                },
                height: 1,
                is_coinbase: false,
            },
        );
        v.push((o, idx, u.get(&o).unwrap().output));
    }
    (u, v)
}

/// Builds and signs a transaction spending `inputs` to `outputs`.
///
/// Each input carries the output it spends: the signed hash commits to it, as
/// the network does.
fn signed_tx(
    inputs: &[(OutPoint, u32, TxOut)],
    outputs: Vec<TxOut>,
    lock_time: u64,
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: inputs
            .iter()
            .map(|(o, _, _)| TxIn {
                prev_out: *o,
                witness: Witness::default(),
                sequence: 0xffff_ffff,
            })
            .collect(),
        outputs,
        lock_time,
    };
    // The sighash does not cover the witnesses: we can sign afterwards.
    for (i, (_, idx, spent)) in inputs.iter().enumerate() {
        let (sk, pk, _) = key(*idx);
        let m = tx.sighash(i as u32, NETWORK, spent);
        tx.inputs[i].witness = Witness {
            pubkey: pk,
            signature: sk.sign(&m),
        };
    }
    tx
}

fn output(value: u64, h: Hash256) -> TxOut {
    TxOut {
        value: Amount::from_units(value),
        scheme: SchemeId::LamportOts,
        pubkey_hash: h,
    }
}

/// Arbitrary hash, with no key behind it (burned recipient).
fn sink(n: u8) -> Hash256 {
    Hash256([n; 32])
}

// ---------------------------------------------------------------------------
// 1. Asymmetric verification cost: the order of rejections
// ---------------------------------------------------------------------------

/// The fee filter applies **before** any cryptography.
///
/// The original defect did the opposite: 15.9 ms of computation for a zero-fee
/// rejection against 91 us for a shape rejection — a ratio of 175. An adversary
/// could burn processor time for the price of a mere send. The proof of the fix
/// depends on no clock: a transaction that is both **fee-less** and **with a
/// non-matching key** is rejected for its FEES. The filter therefore acted
/// before the key was even looked at.
#[test]
fn t01_the_fee_filter_precedes_signature_verification() {
    const K: u32 = 40;
    let (u, ops) = synthetic_utxo(K, 1_000, 0);

    // Zero fees: the sum of outputs equals the sum of inputs.
    let tx = signed_tx(&ops, vec![output(K as u64 * 1_000, sink(0xaa))], 0);

    let mut m = Mempool::new();
    let t0 = Instant::now();
    let r = m.accept(&tx, &u, NETWORK, 10);
    let expensive = t0.elapsed();

    // Same transaction, but a public key that matches no lock.
    let mut tx2 = tx.clone();
    for e in &mut tx2.inputs {
        e.witness.pubkey[0] ^= 0xff;
    }
    let mut m2 = Mempool::new();
    let t1 = Instant::now();
    let r2 = m2.accept(&tx2, &u, NETWORK, 10);
    let cheap = t1.elapsed();

    println!("--- t01: order of rejections ---");
    println!("  zero-fee rejection         : {r:?} in {expensive:?}");
    println!("  non-matching key rejection : {r2:?} in {cheap:?}");
    println!(
        "  cost ratio: x{:.2} (it was 175 before the fix)",
        expensive.as_secs_f64() / cheap.as_secs_f64().max(1e-9)
    );

    assert!(
        matches!(r, Err(MempoolError::FeeRateTooLow { .. })),
        "expected: rejection for insufficient fees, got {r:?}"
    );
    // Structural proof, without a clock: the forged key changes nothing in the
    // verdict. If signatures were verified first, `r2` would be a validation
    // error, not a fee error.
    assert!(
        matches!(r2, Err(MempoolError::FeeRateTooLow { .. })),
        "a non-matching key must change nothing: the fee filter comes \
         before cryptography. Got {r2:?}"
    );
}

/// Cost of the real ML-DSA-65 verification, and amplification per byte
/// received.
#[cfg(feature = "mldsa")]
#[test]
fn t02_real_mldsa_cost_and_amplification() {
    use q21_core::sig::verify;

    // An authentic ML-DSA-65 key/signature pair, through the wallet.
    let mut w = q21_core::Wallet::from_seed_scheme(SEED, NETWORK, SchemeId::MlDsa65).unwrap();
    let a = w.new_address();
    // We build a real transaction to get a real signature.
    let mut u = UtxoSet::new();
    let o = OutPoint {
        txid: Hash256([9u8; 32]),
        index: 0,
    };
    u.insert(
        o,
        UtxoEntry {
            output: TxOut {
                value: Amount::from_units(1_000_000),
                scheme: SchemeId::MlDsa65,
                pubkey_hash: a.hash,
            },
            height: 1,
            is_coinbase: false,
        },
    );
    let mut dest =
        q21_core::Wallet::from_seed_scheme([0x77; 32], NETWORK, SchemeId::MlDsa65).unwrap();
    let da = dest.new_address();
    let tx = w
        .create_transaction(
            &u,
            10,
            &da,
            Amount::from_units(50_000),
            Amount::from_units(100),
        )
        .expect("build");

    let pk = tx.inputs[0].witness.pubkey.clone();
    let sg = tx.inputs[0].witness.signature.clone();
    let spent = u.get(&tx.inputs[0].prev_out).unwrap().output;
    let msg = tx.sighash(0, NETWORK, &spent);
    assert!(verify(SchemeId::MlDsa65, &pk, &msg, &sg).is_ok());

    const N: u32 = 200;
    let t0 = Instant::now();
    for _ in 0..N {
        let _ = verify(SchemeId::MlDsa65, &pk, &msg, &sg);
    }
    let per_verify = t0.elapsed().as_secs_f64() / N as f64;

    // Does an invalid signature cost as much? (worst case for the node)
    let mut bad = sg.clone();
    bad[100] ^= 0x01;
    let t1 = Instant::now();
    for _ in 0..N {
        let _ = verify(SchemeId::MlDsa65, &pk, &msg, &bad);
    }
    let per_bad_verify = t1.elapsed().as_secs_f64() / N as f64;

    // Bytes an attacker must send to trigger a verification: the witness (key
    // + signature) plus the 44 bytes of the input.
    let bytes_per_input = pk.len() + sg.len() + 44 + 4;
    let us_per_kib = per_verify * 1e6 / (bytes_per_input as f64 / 1024.0);

    println!("--- t02: measured ML-DSA-65 cost ---");
    println!("  valid verification   : {:.1} us", per_verify * 1e6);
    println!("  invalid verification : {:.1} us", per_bad_verify * 1e6);
    println!("  bytes per input      : {bytes_per_input}");
    println!("  CPU cost per KiB received: {us_per_kib:.1} us/KiB");
    for rate_mbps in [10u64, 100, 1000] {
        let kib_per_sec = rate_mbps as f64 * 1e6 / 8.0 / 1024.0;
        let cpu_sec_per_sec = kib_per_sec * us_per_kib / 1e6;
        println!(
            "  at {rate_mbps} Mbit/s: {cpu_sec_per_sec:.1} s of CPU consumed per second \
             ({:.0} cores saturated)",
            cpu_sec_per_sec.ceil()
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Filling the mempool at zero cost
// ---------------------------------------------------------------------------

/// Real minimum fees to clear MIN_FEE_RATE, and total cost of a full mempool.
#[test]
fn t03_real_cost_of_saturating_the_pool() {
    // Typical transaction: 1 ML-DSA-65 input, 2 outputs.
    let base = 4 + 1 + 44 + 1 + 2 * 41 + 8u64;
    let witness = 1952 + 3309 + 6u64; // key + signature + varints
    let weight = base * WITNESS_DISCOUNT + witness;
    let size = base + witness;
    // fee * 1000 / weight >= MIN_FEE_RATE
    let min_fee = (MIN_FEE_RATE * weight).div_ceil(1000);
    let n = MEMPOOL_MAX_BYTES as u64 / size;

    println!("--- t03: saturation cost ---");
    println!("  typical ML-DSA-65 transaction: {size} bytes, weighted weight {weight}");
    println!(
        "  minimum accepted fees       : {min_fee} units = {:.10} Q21",
        min_fee as f64 / 1e8
    );
    println!("  transactions to saturate 64 MiB: {n}");
    println!(
        "  total cost of fees          : {} units = {:.8} Q21",
        n * min_fee,
        (n * min_fee) as f64 / 1e8
    );
    println!("  ... and these fees are due ONLY if the transactions are mined (see t04/t05)");

    // Empirical check of the threshold on a real Lamport transaction.
    let (u, ops) = synthetic_utxo(1, 1_000_000, 5_000);
    let mut m = Mempool::new();
    let t = signed_tx(&ops, vec![output(1_000_000 - 1, sink(1))], 0);
    let r = m.accept(&t, &u, NETWORK, 10);
    println!(
        "  1 unit of fee on a Lamport transaction of {} bytes: {r:?}",
        t.encode().len()
    );
    assert!(matches!(r, Err(MempoolError::FeeRateTooLow { .. })));
}

// ---------------------------------------------------------------------------
// 4. A transaction nobody can mine
// ---------------------------------------------------------------------------

/// A transaction heavier than the miner's budget is **refused at the door**: it
/// would never be selected, and accepting it would amount to offering free pool
/// space to someone with no intention of paying.
#[test]
fn t04_a_transaction_heavier_than_a_block_is_refused() {
    // The miner of the q21 binary calls select_for_block(2_000_000).
    const MINER_WEIGHT: u64 = 2_000_000;
    const K: u32 = 120; // 120 Lamport inputs ~ 3 MB, weight > 2,000,000

    let (u, ops) = synthetic_utxo(K, 1_000_000, 10_000);
    // Very high fees: maximum fee rate. That does not save it.
    let tx = signed_tx(&ops, vec![output(1, sink(2))], 0);
    let weight = tx.weight(WITNESS_DISCOUNT);

    let mut m = Mempool::new();
    let r = m.accept(&tx, &u, NETWORK, 10);

    println!("--- t04: unmineable transaction refused ---");
    println!("  weighted weight {weight} (miner budget {MINER_WEIGHT}) -> {r:?}");

    assert!(weight > MINER_WEIGHT);
    assert!(
        matches!(r, Err(MempoolError::Unmineable { .. })),
        "a transaction heavier than the budget must be refused, got {r:?}"
    );
    assert_eq!(m.len(), 0, "it never occupies the pool");
}

/// A transaction larger than MAX_BLOCK_SIZE: refused, since never mineable.
#[test]
fn t04b_a_transaction_larger_than_a_whole_block_is_refused() {
    const K: u32 = 200; // 200 * ~24.6 KiB ~ 4.9 MiB > MAX_BLOCK_SIZE (4 MiB)
    let (u, ops) = synthetic_utxo(K, 1_000_000, 20_000);
    let tx = signed_tx(&ops, vec![output(1, sink(3))], 0);
    let size = tx.encode().len();

    let mut m = Mempool::new();
    let r = m.accept(&tx, &u, NETWORK, 10);

    println!("--- t04b: transaction larger than a block ---");
    println!(
        "  size {size} bytes vs MAX_BLOCK_SIZE {} -> {r:?}",
        q21_core::consensus::MAX_BLOCK_SIZE
    );
    assert!(size > q21_core::consensus::MAX_BLOCK_SIZE);
    assert!(
        matches!(r, Err(MempoolError::Unmineable { .. })),
        "a transaction larger than a block must be refused at the door, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// 3/5. Manipulable eviction
// ---------------------------------------------------------------------------

/// The unmineable can no longer evict the honest: it is refused at the door.
///
/// The original attack filled the pool to **99.8%** with unmineable
/// transactions at a high fee rate — hence not evictable — for an actual cost
/// of **zero**, nothing ever being mined. Honest transactions were left with
/// only 107 KiB out of 64 MiB. The weight bound cuts the attack at the root:
/// none of these transactions enters the pool anymore.
#[test]
fn t05_the_unmineable_can_no_longer_evict_the_honest() {
    const PER_TX: u32 = 90; // ~2.23 M of weight > miner budget (2,000,000)
    let (u, ops) = synthetic_utxo(PER_TX, 1_000_000, 100_000);
    // One input, one output of 1 unit: nearly maximum fee rate — and yet
    // refused, because too heavy for a block.
    let large = signed_tx(&ops, vec![output(1, sink(4))], 0);
    let weight = large.weight(WITNESS_DISCOUNT);

    let mut m = Mempool::new();
    let r_attack = m.accept(&large, &u, NETWORK, 10);

    // The "thinnest" unmineable: few bytes, but a weight inflated by its
    // thousands of outputs. Refused as well.
    let (uf, opf) = synthetic_utxo(1, 1_000_000, 200_000);
    let mut outs: Vec<TxOut> = (0..12_100).map(|_| output(0, sink(4))).collect();
    outs[0] = output(1, sink(4));
    let thin = signed_tx(&opf, outs, 0);
    let r_thin = m.accept(&thin, &uf, NETWORK, 10);

    // An ordinary honest transaction, for its part, gets in unhindered.
    let (uh, oph) = synthetic_utxo(1, 1_000_000, 900_000);
    let honest = signed_tx(&oph, vec![output(900_000, sink(5))], 0);
    let r_honest = m.accept(&honest, &uh, NETWORK, 10);

    println!("--- t05: the unmineable is refused at the door ---");
    println!("  large (weight {weight}, nearly max rate) -> {r_attack:?}");
    println!(
        "  thin ({} bytes, weight {}) -> {r_thin:?}",
        thin.encode().len(),
        thin.weight(WITNESS_DISCOUNT)
    );
    println!("  honest -> {r_honest:?}");

    assert!(weight > 2_000_000);
    assert!(
        matches!(r_attack, Err(MempoolError::Unmineable { .. })),
        "the non-evictable attack must be refused, got {r_attack:?}"
    );
    assert!(
        matches!(r_thin, Err(MempoolError::Unmineable { .. })),
        "even the thinnest unmineable is refused, got {r_thin:?}"
    );
    assert!(
        r_honest.is_ok(),
        "a normal honest transaction must get in, got {r_honest:?}"
    );
    assert_eq!(m.len(), 1, "only the honest one occupies the pool");
}

// ---------------------------------------------------------------------------
// 4bis. Quadratic cost of package eviction
// ---------------------------------------------------------------------------

/// Builds a chain of `n` unconfirmed transactions.
fn mempool_chain(n: u32, m: &mut Mempool, base: u32) -> Hash256 {
    let (u, ops) = synthetic_utxo(1, 100_000_000, base);
    // Each link spends output 0 of the previous one.
    let mut current = ops[0];
    let mut root = Hash256::ZERO;
    for i in 0..n {
        let idx = base + 1 + i;
        let (_, _, h) = key(idx);
        // An output that stays spendable by the next key.
        let value = 100_000_000 - 1_000 * (i as u64 + 1);
        let tx = signed_tx(&[current], vec![output(value, h)], 0);
        let id = m.accept(&tx, &u, NETWORK, 10).expect("link");
        if i == 0 {
            root = id;
        }
        current = (OutPoint { txid: id, index: 0 }, idx, tx.outputs[0]);
    }
    root
}

/// Package removal of a chain is linear, not quadratic.
///
/// The defect: the walk of the descendants tested membership with
/// `Vec::contains`, a scan on each child — the audit had measured n^1.35, and
/// the 64 MiB cap allows chains of several thousand links. Membership now goes
/// through a set: removal is linear.
///
/// We do not prove it with an absolute clock — a slow CI machine would make any
/// fixed cap either lax or flaky — but with a RATIO, insensitive to the speed
/// of the machine. Removing a chain four times longer must cost on the order of
/// four times more (linear), not sixteen times more (quadratic). Going back to
/// the `Vec::contains` scan would clearly exceed the ratio cap.
///
/// # The trap this closes
///
/// A ratio is only insensitive to the machine if both measurements live in the
/// same memory regime. Each link carries an ML-DSA-87 signature, nearly 7 KiB:
/// a chain of 2,400 links weighs about fifteen MiB and overflows the last-level
/// cache of an old CI processor, whereas 600 links fit in it. On such a runner,
/// the large removal switched to slow memory accesses and cost twenty-four
/// times the small one — more than quadratic — while the algorithm, linear,
/// passed everywhere else. The test measured the memory hierarchy, not the
/// complexity. Both sizes therefore stay below that cliff (600 is proven fast
/// on the slowest runner): the ratio can no longer fail wrongly.
///
/// # What this stopwatch does not prove
///
/// The cost of the `Vec::contains` scan — 32-byte comparisons, in cache — stays
/// small compared with the linear cost of each removal (a transaction of nearly
/// 7 KiB to free) as long as the chain fits in cache. At these sizes, going
/// back to the scan would only push the ratio up to four or five: under the
/// cap. This stopwatch is therefore a safeguard against a gross degradation,
/// not a proof of linearity. The proof, deterministic, is `t06b`: the property
/// is read at its source.
#[test]
fn t06_package_removal_is_linear() {
    println!("--- t06: cost of remove() on a chain ---");

    // We measure several times and keep, for the small chain, the LARGEST time,
    // and for the large one, the SMALLEST. It is the cautious direction: it
    // rejects scheduling spikes that would artificially inflate the ratio, so
    // it protects against a wrong failure, not against a real defect.
    let measure = |n: u32, take_min: bool| -> std::time::Duration {
        let mut best: Option<std::time::Duration> = None;
        for _ in 0..5 {
            let mut m = Mempool::new();
            let root = mempool_chain(n, &mut m, 1_000_000 + n * 10);
            assert_eq!(m.len(), n as usize);
            let t0 = Instant::now();
            m.remove(&root);
            let d = t0.elapsed();
            assert!(m.is_empty());
            best = Some(match best {
                None => d,
                Some(b) if take_min => b.min(d),
                Some(b) => b.max(d),
            });
        }
        let d = best.unwrap();
        println!("  chain of {n:5}: remove() = {d:?}");
        d
    };

    // Both sizes fit in the last-level cache of any runner (see the trap
    // above): the ratio then measures only the algorithm.
    const SMALL: u32 = 150;
    const LARGE: u32 = 600; // four times longer
    let t_small = measure(SMALL, false); // the slowest of the five
    let t_large = measure(LARGE, true); // the fastest of the five

    // Expected ratio: ~4 (linear). A cap of 12 leaves a generous margin for
    // noise and the fixed cost of small sizes, while staying well below the
    // ~16 that a quadratic removal would impose.
    let factor = t_large.as_secs_f64() / t_small.as_secs_f64().max(1e-9);
    assert!(
        factor < 12.0,
        "remove() grows faster than the chain length: \
         {SMALL} -> {t_small:?}, {LARGE} -> {t_large:?} \
         (ratio {factor:.1}x; linear ~4x, quadratic ~16x)"
    );

    println!(
        "  ratio {LARGE}/{SMALL} = {factor:.1}x (linear ~4x); the 64 MiB cap \
         limits the chain to ~{} links",
        MEMPOOL_MAX_BYTES / 5_400
    );
}

/// Removal tests membership in a set, never by scanning.
///
/// This is the property `t06` would like to prove and cannot: a stopwatch
/// confuses the algorithm with the memory hierarchy as soon as a chain
/// overflows the cache, and does not see the scan as long as it fits (see
/// `t06`). The linearity of removal rests on a single decision — the
/// descendants are walked with a set — and that decision is read at its source.
/// It is locked in there, deterministically, on any machine.
#[test]
fn t06b_removal_tests_membership_in_a_set() {
    let source = include_str!("../src/mempool.rs");
    let start = source
        .find("pub fn remove(")
        .expect("Mempool::remove not found in the source");
    let body = &source[start..];
    let end = body.find("fn remove_one(").unwrap_or(body.len());
    let body = &body[..end];
    assert!(
        body.contains("HashSet<Hash256>"),
        "the descendants are no longer walked with a set"
    );
    assert!(
        !body.contains("to_remove.contains(") && !body.contains(".contains(&c)"),
        "removal went back to the Vec::contains scan: quadratic"
    );
}

/// `select_for_block` does not recompute the `txid` on each comparison of the
/// sort.
///
/// The defect: the comparator called `txid()` — a SHA-256 over the whole body —
/// on each comparison, hence O(n log n) times. The audit had measured **3.96
/// seconds to pick a single transaction**, under the node's global lock:
/// everything stopped during that time, on every block template. The txid and
/// the rate are now computed **only once**: the sort is cheap again, even on
/// transactions with a large body.
#[test]
fn t11_select_for_block_does_not_rehash_on_each_comparison() {
    const N: u32 = 400;
    // A body heavy to hash, but mineable: each output now weighs
    // WEIGHT_PER_OUTPUT on top of its bytes, and is worth at least the dust.
    const OUTPUTS: usize = 3_000;

    let mut m = Mempool::new();
    let mut u = UtxoSet::new();
    for i in 0..N {
        let (uu, ops) = synthetic_utxo(1, 100_000_000, 2_000_000 + i);
        for (o, _, _) in &ops {
            u.insert(*o, *uu.get(o).unwrap());
        }
        let outs: Vec<TxOut> = (0..OUTPUTS)
            .map(|_| output(MIN_OUTPUT_VALUE, sink(11)))
            .collect();
        let tx = signed_tx(&ops, outs, i as u64);
        if m.accept(&tx, &u, NETWORK, 10).is_err() {
            break;
        }
    }
    let n = m.len();
    assert!(n > 10, "a sizable pool is needed to measure: {n}");

    let t0 = Instant::now();
    let chosen = m.select_for_block(2_000_000);
    let d = t0.elapsed();

    println!("--- t11: cost of the select_for_block sort ---");
    println!("  pool: {n} transactions of {OUTPUTS} outputs");
    println!("  select_for_block = {d:?} for {} selected", chosen.len());

    // The defect cost SECONDS. A wide bound — a tenth of a second — sits far
    // above the real cost (tens of us) while catching any return to rehashing
    // per comparison, which would again be counted in seconds.
    assert!(
        d < std::time::Duration::from_millis(100),
        "the sort must not rehash on each comparison: {d:?}"
    );
}

/// Eviction only reasons on the **individual** fee rate. A lower-paying parent
/// takes all its descendants along, including those that pay the most.
#[test]
fn t12_eviction_destroys_well_paying_children_with_their_parent() {
    let (u, ops) = synthetic_utxo(1, 100_000_000, 3_000_000);
    let mut m = Mempool::new();

    // Parent at a low rate.
    let (_, _, h_child) = key(3_000_001);
    let parent = signed_tx(&ops, vec![output(99_999_000, h_child)], 0);
    let parent_id = m.accept(&parent, &u, NETWORK, 10).unwrap();
    // Child at a very high rate.
    let child = signed_tx(
        &[(
            OutPoint {
                txid: parent_id,
                index: 0,
            },
            3_000_001,
            parent.outputs[0],
        )],
        vec![output(MIN_OUTPUT_VALUE, sink(12))],
        0,
    );
    let child_id = m.accept(&child, &u, NETWORK, 10).unwrap();

    let rate = |t: &Transaction, fee: u64| fee * 1000 / t.weight(WITNESS_DISCOUNT);
    println!("--- t12: package eviction and the children's fees ---");
    println!("  parent: fee 1,000, rate {}", rate(&parent, 1_000));
    println!("  child: fee 99,998,999, rate {}", rate(&child, 99_998_999));

    // Removing the parent (what make_room does if it is lower-paying) takes the
    // child along, whatever the child pays.
    m.remove(&parent_id);
    println!(
        "  after removing the parent: child still there? {}",
        m.contains(&child_id)
    );
    assert!(
        !m.contains(&child_id),
        "the highest-paying child of the pool disappears with its parent"
    );
    println!("  make_room (src/mempool.rs) only looks at the individual rate:");
    println!("  no ancestor/descendant score, hence no CPFP and a pinning vector.");
}

// ---------------------------------------------------------------------------
// 5. revalidate
// ---------------------------------------------------------------------------

/// `revalidate` on an unchanged UTXO set is the identity.
///
/// The original defect validated each transaction against a view where the
/// spent set contained **its own inputs**: each one saw itself as its own double
/// spend and removed itself. Called on every connected block, the function
/// **emptied the pool entirely** — audit measurement: "before 50, after 0". It
/// now only checks the availability of the inputs and the maturity of
/// coinbases: nothing changes when nothing has changed.
#[test]
fn t07_revalidate_preserves_a_valid_pool() {
    let (u, ops) = synthetic_utxo(3, 1_000_000, 300_000);
    let mut m = Mempool::new();
    for (i, op) in ops.iter().enumerate() {
        let tx = signed_tx(&[*op], vec![output(900_000, sink(6))], i as u64);
        m.accept(&tx, &u, NETWORK, 10).expect("acceptance");
    }
    let before = m.len();

    // Nothing has changed: same UTXO set, same height.
    m.revalidate(&u, NETWORK, 10);
    let after = m.len();

    println!("--- t07: revalidate preserves ---");
    println!("  before {before}, after {after} (unchanged UTXO set)");

    assert_eq!(before, 3);
    assert_eq!(
        after, 3,
        "revalidate on an unchanged set must be the identity, not an emptying"
    );
}

/// Even on a chain of dependent transactions: everything survives.
#[test]
fn t07b_revalidate_preserves_chains() {
    let mut m = Mempool::new();
    let _ = mempool_chain(50, &mut m, 400_000);
    let before = m.len();
    // Links 2..n depend on the mempool; link 1 on the confirmed set.
    let (u, _) = synthetic_utxo(1, 100_000_000, 400_000);
    m.revalidate(&u, NETWORK, 10);
    println!("--- t07b: chain of 50 links ---");
    println!("  before {before}, after {}", m.len());
    assert_eq!(before, 50);
    assert_eq!(
        m.len(),
        50,
        "a chain of valid dependencies must survive revalidate"
    );
}

/// Cost of revalidate if the t07 defect were fixed by full revalidation: a
/// complete recheck of every signature of the pool, on every block.
#[test]
fn t08_latent_cost_of_revalidate_on_every_block() {
    use q21_core::validate;
    use std::collections::HashSet;

    const N: u32 = 300;
    let (u, ops) = synthetic_utxo(N, 1_000_000, 500_000);
    let txs: Vec<Transaction> = ops
        .iter()
        .map(|op| signed_tx(&[*op], vec![output(900_000, sink(7))], 0))
        .collect();
    let bytes: usize = txs.iter().map(|t| t.encode().len()).sum();

    let t0 = Instant::now();
    for t in &txs {
        let mut seen = HashSet::new();
        let _ = validate::check_transaction(t, &u, NETWORK, 11, &mut seen);
    }
    let d = t0.elapsed();
    let per_tx = d.as_secs_f64() / N as f64;
    let n_full = MEMPOOL_MAX_BYTES as f64 / (bytes as f64 / N as f64);

    println!("--- t08: cost of a full revalidation ---");
    println!("  {N} Lamport transactions ({bytes} bytes) revalidated in {d:?}");
    println!("  {:.0} us per transaction", per_tx * 1e6);
    println!(
        "  extrapolated to a full pool ({n_full:.0} tx): {:.2} s per block",
        n_full * per_tx
    );
    println!(
        "  with ML-DSA-65 (~192 us/input instead of ~{:.0} us): see t02",
        per_tx * 1e6
    );
}

// ---------------------------------------------------------------------------
// 6. Double acceptance / reinstatement
// ---------------------------------------------------------------------------

#[test]
fn t09_a_confirmed_transaction_cannot_come_back_and_the_rejection_is_cheap() {
    let (mut u, ops) = synthetic_utxo(1, 1_000_000, 600_000);
    let tx = signed_tx(&ops, vec![output(900_000, sink(8))], 0);

    let mut m = Mempool::new();
    m.accept(&tx, &u, NETWORK, 10).expect("acceptance");
    // Simulates the confirmation: the consumed output disappears from the set.
    u.remove(&ops[0].0);
    m.remove(&tx.txid());

    let t0 = Instant::now();
    let r = m.accept(&tx, &u, NETWORK, 11);
    let d = t0.elapsed();

    // Comparison: the same rejection but after signature verification.
    println!("--- t09: replay of a confirmed transaction ---");
    println!("  verdict: {r:?} in {d:?}");
    assert!(matches!(r, Err(MempoolError::UnconfirmedDependency(_))));

    // And an already present transaction?
    let (u2, ops2) = synthetic_utxo(1, 1_000_000, 610_000);
    let tx2 = signed_tx(&ops2, vec![output(900_000, sink(8))], 0);
    let mut m2 = Mempool::new();
    m2.accept(&tx2, &u2, NETWORK, 10).unwrap();
    let t1 = Instant::now();
    let r2 = m2.accept(&tx2, &u2, NETWORK, 10);
    println!("  duplicate: {r2:?} in {:?}", t1.elapsed());
    assert_eq!(r2, Err(MempoolError::AlreadyPresent));
}

// ---------------------------------------------------------------------------
// 8. Real memory cap
// ---------------------------------------------------------------------------

/// Real memory is bounded by the weight, not only by the bytes.
///
/// The defect: the cap only counted `tx.encode().len()`, whereas each output
/// creates an entry in the mempool's created-outputs map — real memory that no
/// serialized byte reflected. The weight bound closes this door indirectly: a
/// transaction with enough outputs to inflate memory weighs, through that same
/// number of outputs, more than the miner's budget. It is therefore refused.
#[test]
fn t10_the_number_of_outputs_is_bounded_by_the_weight() {
    const OUTPUTS: usize = 20_000;
    let (u, ops) = synthetic_utxo(1, 1_000_000_000, 700_000);
    let mut outs: Vec<TxOut> = (0..OUTPUTS)
        .map(|j| output(0, sink((j % 256) as u8)))
        .collect();
    outs[0] = output(1, sink(9));
    let tx = signed_tx(&ops, outs, 0);
    let weight = tx.weight(WITNESS_DISCOUNT);

    let mut m = Mempool::new();
    let r = m.accept(&tx, &u, NETWORK, 10);

    println!("--- t10: outputs bounded by the weight ---");
    println!("  {OUTPUTS} outputs -> weighted weight {weight} (miner budget 2,000,000)");
    println!("  {} serialized bytes -> {r:?}", tx.encode().len());

    assert!(
        weight > 2_000_000,
        "20,000 outputs must weigh more than the budget: {weight}"
    );
    assert!(
        matches!(r, Err(MempoolError::Unmineable { .. })),
        "a transaction that inflates memory through its outputs is refused, got {r:?}"
    );
    assert_eq!(m.len(), 0);
}

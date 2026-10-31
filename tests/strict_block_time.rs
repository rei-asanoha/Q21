//! 0.5.4: a block's timestamp must be strictly greater than its parent's,
//! from a scheduled height (`validate::strict_time_at`).
//!
//! Two parts. A numerical simulation on the production difficulty rule
//! (`chain::next_bits`) shows what the rule closes: a minority miner dating
//! its blocks back, as far as the median allows, slowed the chain down; with
//! the rule, it can no longer. Then the rule itself, on a real regtest chain
//! whose activation an audit build moves to a low height: refused at and
//! after the activation, accepted before, and the node's own candidate
//! respects it even when its clock lags behind the tip.
//!
//! How to run:
//!   cargo test --release --features mldsa,audit --test strict_block_time -- --nocapture

use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::chain::{self, genesis_block, Chain, ChainError, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::validate::{self, ValidationError};

// ---------------------------------------------------------------------------
// 1. The attack, simulated
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn expo(&mut self, m: f64) -> f64 {
        -m * self.unit().max(1e-15).ln()
    }
}

fn target_f64(bits: u32) -> f64 {
    let exponent = (bits >> 24) as i32;
    let mantissa = (bits & 0x007f_ffff) as f64;
    mantissa * 2f64.powi(8 * (exponent - 3))
}

fn difficulty(bits: u32) -> f64 {
    target_f64(INITIAL_BITS) / target_f64(bits)
}

fn bits_for_difficulty(d: f64) -> u32 {
    let t0 = pow::target_from_compact(INITIAL_BITS).unwrap();
    pow::target_to_compact(t0.checked_div_u64(d as u64).unwrap())
}

fn header(time: u64, bits: u32, height: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: Hash256::ZERO,
        merkle_root: Hash256::ZERO,
        uncles_root: Hash256::ZERO,
        miner: Hash256::ZERO,
        time,
        bits,
        height,
        nonce: 0,
    }
}

/// The average real interval between blocks, in seconds, over the second
/// half of `n` blocks, when a miner holding `share` of the hashrate dates
/// each of its blocks as early as the rules let it, and everyone else dates
/// theirs honestly. `strict`: the parent rule is in force.
fn average_interval(n: usize, share: f64, strict: bool, seed: u64) -> f64 {
    let d0 = 1000.0f64;
    let bits0 = bits_for_difficulty(d0);
    let rate = d0 / TARGET_BLOCK_SECS as f64;
    let mut rng = Rng(seed | 1);
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(n + 200);
    let t0 = 1_800_000_000u64;
    for i in 0..200u64 {
        headers.push(header(t0 + i * TARGET_BLOCK_SECS, bits0, i));
    }
    let mut real = (t0 + 199 * TARGET_BLOCK_SECS) as f64;
    let (mut start, mut counted) = (0.0, 0usize);
    for i in 0..n {
        let bits = chain::next_bits(&headers);
        let dt = rng.expo(difficulty(bits) / rate);
        real += dt;
        let parent = headers.last().unwrap().time;
        let recent: Vec<u64> = headers
            .iter()
            .rev()
            .take(MEDIAN_TIME_SPAN)
            .map(|h| h.time)
            .collect();
        let floor = if strict {
            (validate::median_time(&recent) + 1).max(parent + 1)
        } else {
            validate::median_time(&recent) + 1
        };
        let attacker = rng.unit() < share;
        let wanted = if attacker { floor } else { real as u64 };
        let t = wanted.max(floor).min(real as u64 + MAX_FUTURE_TIME);
        headers.push(header(t, bits, 200 + i as u64));
        if i == n / 2 {
            start = real - dt;
        }
        if i >= n / 2 {
            counted += 1;
        }
    }
    (real - start) / counted as f64
}

#[test]
fn a_minority_miner_can_no_longer_slow_the_chain_by_dating_back() {
    let target = TARGET_BLOCK_SECS as f64;
    let mut before = Vec::new();
    let mut after = Vec::new();
    for share in [0.10, 0.20, 0.30] {
        let b = average_interval(6_000, share, false, 0x51);
        let a = average_interval(6_000, share, true, 0x51);
        println!(
            "{:>3.0}% dating back: {:.1} min per block before the rule, {:.1} min with it",
            share * 100.0,
            b / 60.0,
            a / 60.0
        );
        before.push(b);
        after.push(a);
    }
    // Before: the chain slows down, more as the share grows.
    assert!(before[0] > 1.3 * target, "10%: {:.0} s", before[0]);
    assert!(before[2] > 3.0 * target, "30%: {:.0} s", before[2]);
    // With the rule: within about a tenth of the target, whatever the share
    // (what is left is the one second a block must now add to its parent).
    for (i, a) in after.iter().enumerate() {
        assert!(
            (*a - target).abs() < 0.15 * target,
            "with the rule, case {i}: {a:.0} s per block"
        );
    }
    // And honest miners alone keep the target either way.
    let honest = average_interval(6_000, 0.0, true, 0x51);
    assert!((honest - target).abs() < 0.1 * target, "{honest:.0} s");
}

// ---------------------------------------------------------------------------
// 2. The rule on a real chain
// ---------------------------------------------------------------------------

const NET: Network = Network::Regtest;
const ACTIVATION: u64 = 5;
const TRIES: u64 = 50_000_000;

fn miner() -> Hash256 {
    Hash256([7u8; 32])
}

/// A block on `c`'s tip, dated `time` exactly: assembled by the node, then
/// its time set and its work done again.
fn block_at(c: &Chain, time: u64) -> q21_core::block::Block {
    let mut b = c
        .mine_block(miner(), SchemeId::LamportOts, &[], time, TRIES)
        .expect("mined");
    if b.header.time != time {
        b.header.time = time;
        pow::mine(&pow::Q21PowMemoized::new(NET), &mut b.header, TRIES).expect("mined again");
    }
    b
}

#[test]
fn a_block_not_after_its_parent_is_refused_from_the_activation_on() {
    validate::audit_set_strict_time_activation(NET, ACTIVATION);
    assert!(!validate::strict_time_at(NET, ACTIVATION - 1));
    assert!(validate::strict_time_at(NET, ACTIVATION));
    // The other networks keep their own schedule.
    assert!(validate::strict_time_at(Network::Mainnet, 1));
    assert!(!validate::strict_time_at(
        Network::Testnet,
        STRICT_TIME_ACTIVATION_TESTNET - 1
    ));
    assert!(validate::strict_time_at(
        Network::Testnet,
        STRICT_TIME_ACTIVATION_TESTNET
    ));

    let mut c = Chain::new(NET, genesis_block(NET));
    let now = GENESIS_TIME + 1_000_000;
    // Blocks 1 to 3, spaced; block 4 then shares its parent's second, which
    // the median alone allows: before the activation, accepted.
    for h in 1..=3u64 {
        let b = block_at(&c, GENESIS_TIME + h * TARGET_BLOCK_SECS * 10);
        c.submit(&b, now).expect("block before the activation");
    }
    let same = c.tip().time;
    let b4 = block_at(&c, same);
    assert_eq!(b4.header.height, ACTIVATION - 1);
    c.submit(&b4, now)
        .expect("same second as the parent, before the activation");

    // Block 5, at the activation: the same second as its parent, after the
    // median still, is refused, by the header check and by the block's
    // validation alike.
    let b5 = block_at(&c, same);
    assert_eq!(b5.header.height, ACTIVATION);
    let expected = ValidationError::TimestampNotAfterParent {
        parent: same,
        received: same,
    };
    match c.check_header(&b5.header, now) {
        Err(ChainError::Validation(e)) => assert_eq!(e, expected),
        other => panic!("header: {other:?}"),
    }
    match c.submit(&b5, now) {
        Err(ChainError::Validation(e)) => assert_eq!(e, expected),
        other => panic!("block: {other:?}"),
    }
    // One second later: accepted.
    let b5 = block_at(&c, same + 1);
    c.submit(&b5, now).expect("one second after the parent");

    // The node's own candidate, with a clock behind the tip, still comes
    // after its parent.
    let tip = c.tip().time;
    let b6 = c
        .mine_block(miner(), SchemeId::LamportOts, &[], tip - 500, TRIES)
        .expect("mined");
    assert!(b6.header.time > tip, "{} after {tip}", b6.header.time);
    c.submit(&b6, now).expect("the node's own candidate");
}

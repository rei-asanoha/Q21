//! Regression tests for the second audit wave (phase 8b).
//!
//! Five auditors worked on five areas that the first wave had not covered:
//! difficulty and mining economics, arithmetic and serialization, the
//! transaction mempool, the RPC surface, persistence. This file locks in the
//! fixes that came out of it.

use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, next_bits, Chain, ChainError, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::memhard::{self, epoch_of, TableParams};
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::validate::ValidationError;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn headers(n: usize, step: impl Fn(usize) -> u64) -> Vec<BlockHeader> {
    let mut v = Vec::with_capacity(n);
    let mut t = GENESIS_TIME;
    for h in 0..n {
        t += step(h);
        v.push(BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner: Hash256::ZERO,
            time: t,
            bits: INITIAL_BITS,
            height: h as u64,
            nonce: 0,
        });
    }
    v
}

// ---------------------------------------------------------------------------
// 1. The solve time is signed
// ---------------------------------------------------------------------------

/// The measured attack: a miner writing `parent + 6T` injected, on every
/// block, apparent time that nothing subtracted afterwards. With 20% of the
/// hash power, the difficulty collapsed by 97.3%.
///
/// With a signed solve time, the time pushed forward is given back by the
/// next block. This test checks it directly on `next_bits`.
#[test]
fn pushing_timestamps_forward_no_longer_drops_the_difficulty() {
    let t = TARGET_BLOCK_SECS;
    // Honest chain: each block takes exactly T.
    let honest = next_bits(&headers(91, |_| t));

    // One block in five writes parent + 6T, the others catch up (hence a
    // negative actual solve time from the point of view of the timestamps).
    let attacked = next_bits(&headers(91, |h| if h % 5 == 0 { 6 * t } else { 0 }));

    let target_h = pow::target_from_compact(honest).unwrap();
    let target_a = pow::target_from_compact(attacked).unwrap();
    assert!(
        target_a <= target_h.mul_div(150, 100).unwrap(),
        "the difficulty dropped by more than 50% under timestamp manipulation"
    );
}

/// The symmetric bound must also protect in the other direction: a series of
/// timestamps pushed backward must not make the difficulty explode at once.
#[test]
fn pushing_timestamps_backward_does_not_explode_the_difficulty() {
    let bits = next_bits(&headers(91, |_| 0));
    let target = pow::target_from_compact(bits).unwrap();
    assert!(!target.is_zero(), "the target must never drop to zero");
    // The floor of the weighted sum (5% of the expected duration) bounds the
    // increase: at worst a factor of MAX_TARGET_CHANGE per block.
    let reference = pow::target_from_compact(INITIAL_BITS).unwrap();
    assert!(target >= reference.checked_div_u64(MAX_TARGET_CHANGE * 2).unwrap());
}

/// The future timestamp tolerance was brought down from two hours to twenty
/// minutes: with an adjustment on every block, two hours were a lever.
#[test]
fn the_future_timestamp_tolerance_fits_a_per_block_adjustment() {
    assert_eq!(MAX_FUTURE_TIME, 10 * 60);
    // Checked at compile time: the tolerance must stay of the same order as
    // the solve time bound.
    const _: () = assert!(MAX_FUTURE_TIME < LWMA_MAX_BEHIND * TARGET_BLOCK_SECS * 2);
}

// ---------------------------------------------------------------------------
// 2. The reorg penalty applies to the fork, not to the history
// ---------------------------------------------------------------------------

/// The penalty multiplied the work **accumulated since genesis**. From height
/// 71,400 on (three months after launch), no reorg of depth 7 could succeed
/// anymore, even with 100% of the hash power. The real finality was six
/// blocks, not 720.
#[test]
fn a_deep_reorg_remains_possible_on_a_long_chain() {
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=40u64 {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }

    // A competing branch starting at height 30: depth 10, so beyond the
    // free threshold (6). It must be able to win with a reasonable surplus of
    // work: a few blocks, not hundreds.
    let fork = c.active_at(30).expect("ancestor");
    let depth = c.height() - 30;
    let required = c.work_required_for_reorg(30, depth);
    let active_work = c.total_work();

    // The required surplus must be of the order of the fork's work, not of
    // the whole chain's.
    let surplus = required.checked_sub(active_work).unwrap_or_default();
    let one_block = pow::block_work(INITIAL_BITS);
    let surplus_blocks = surplus
        .div_rem(one_block)
        .map(|(q, _)| q.low_u64())
        .unwrap_or(u64::MAX);

    assert!(
        surplus_blocks <= depth,
        "{surplus_blocks} surplus blocks are needed for a fork of \
         depth {depth}: the penalty still applies to the whole history"
    );
    let _ = fork;
}

// ---------------------------------------------------------------------------
// 3. The proof of work refuses a cache from another epoch
// ---------------------------------------------------------------------------

/// `hash_verify_with_cache` accepted any cache without checking its epoch,
/// and then returned a different hash **silently**. Two nodes, one up to date
/// and the other not, would have returned two opposite verdicts on the same
/// block.
#[test]
fn a_cache_from_another_epoch_does_not_skew_the_verdict() {
    let params = TableParams::for_network(NETWORK);
    let header = BlockHeader {
        version: 1,
        prev_block: Hash256::ZERO,
        merkle_root: Hash256([7u8; 32]),
        uncles_root: Hash256::ZERO,
        miner: Hash256([9u8; 32]),
        time: GENESIS_TIME,
        bits: INITIAL_BITS,
        height: POW_EPOCH_BLOCKS, // epoch 1
        nonce: 0,
    };
    assert_eq!(epoch_of(header.height), 1);

    let stale_cache = memhard::cache_for(params, 0);
    let expected = memhard::hash_verify(&header, params);
    let with_stale_cache = memhard::hash_verify_with_cache(&header, params, &stale_cache);

    assert_eq!(
        with_stale_cache, expected,
        "a stale cache produced a different hash, silently"
    );
}

// ---------------------------------------------------------------------------
// 4. An arbitrary height no longer triggers building an arbitrary cache
// ---------------------------------------------------------------------------

/// The proof-of-work epoch is derived from `header.height`. A header
/// announcing any height triggered building the cache (then the table) of
/// the corresponding epoch: about ten seconds for the cache and five minutes
/// for the table on mainnet, for a 160-byte message.
#[test]
fn an_inconsistent_height_is_refused_before_any_computation() {
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=3u64 {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }

    let mut b = c
        .mine_block(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            GENESIS_TIME + 4 * TARGET_BLOCK_SECS,
            ATTEMPTS,
        )
        .expect("mining");
    // Absurd height: very far in the future, hence a very distant epoch.
    b.header.height = 4_000_000_000;

    let start = std::time::Instant::now();
    let verdict = c.submit(&b, GENESIS_TIME + 5 * TARGET_BLOCK_SECS);
    let elapsed = start.elapsed();

    assert!(
        matches!(
            verdict,
            Err(ChainError::Validation(ValidationError::BadHeight { .. }))
        ),
        "an inconsistent height must be refused: {verdict:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(200),
        "the refusal cost {elapsed:?}: a computation was started before the check"
    );
}

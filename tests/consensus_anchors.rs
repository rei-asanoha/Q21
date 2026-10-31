//! 0.5.4: anchored blocks (`validate::anchors`). At an anchored height a
//! chain may carry only the anchored block, and finality never binds below
//! the last anchor: a node alone with a peer that hands it a chain of its own
//! can no longer be bound to it, and a false branch forking below an anchor
//! can never pass it.
//!
//! The anchors are those of the testnet; on regtest an audit build sets them
//! for this process.

use q21_core::address::Network;
use q21_core::chain::{genesis_block, Chain, ChainError, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::validate::{self, ValidationError};

const NET: Network = Network::Regtest;
const TRIES: u64 = 50_000_000;

fn grow(c: &mut Chain, blocks: u64, start: u64, miner: u8, now: u64) {
    for _ in 0..blocks {
        let t = start + (c.height() + 1) * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([miner; 32]), SchemeId::LamportOts, &[], t, TRIES)
            .expect("mined");
        c.submit(&b, now).expect("accepted");
    }
}

#[test]
fn a_chain_without_the_anchored_block_cannot_pass_it() {
    let now = GENESIS_TIME + 10_000_000;
    // The real chain, three blocks.
    let mut real = Chain::new(NET, genesis_block(NET));
    grow(&mut real, 3, GENESIS_TIME, 1, now);
    let anchored = real.block_at(2).expect("block 2").header.block_id();
    validate::audit_set_anchors(NET, vec![(2, anchored)]);
    assert_eq!(validate::last_anchor_height(NET), 2);
    assert!(validate::check_anchor(NET, 2, &anchored).is_ok());
    assert!(
        validate::check_anchor(NET, 3, &Hash256([9; 32])).is_ok(),
        "not an anchored height"
    );

    // A chain of its own, from the genesis: its block 2 is not the anchor.
    let mut other = Chain::new(NET, genesis_block(NET));
    grow(&mut other, 1, GENESIS_TIME + 7, 2, now);
    let b2 = other
        .mine_block(
            Hash256([2; 32]),
            SchemeId::LamportOts,
            &[],
            GENESIS_TIME + 7 + 2 * TARGET_BLOCK_SECS,
            TRIES,
        )
        .expect("mined");
    assert_eq!(b2.header.height, 2);
    assert_ne!(b2.header.block_id(), anchored);
    match other.submit(&b2, now) {
        Err(ChainError::Validation(ValidationError::NotTheAnchor { height: 2 })) => {}
        r => panic!("a block other than the anchor at its height: {r:?}"),
    }
    match other.check_header(&b2.header, now) {
        Err(ChainError::Validation(ValidationError::NotTheAnchor { height: 2 })) => {}
        r => panic!("its header alone: {r:?}"),
    }

    // The same branch offered to the real chain, as a fork: refused at the
    // anchored height too.
    let fork1 = other.block_at(1).expect("block 1 of the other chain");
    let _ = real.submit(&fork1, now);
    match real.submit(&b2, now) {
        Err(ChainError::Validation(ValidationError::NotTheAnchor { height: 2 })) => {}
        r => panic!("the fork at the anchored height: {r:?}"),
    }
    assert_eq!(real.height(), 3, "the real chain stays where it was");

    // Finality never binds below the last anchor, even with no hold at all.
    let mut young = Chain::new(NET, genesis_block(NET));
    young.set_finality_hold(None);
    assert!(!young.finality_binds(), "at the genesis, below the anchor");
    grow(&mut young, 1, GENESIS_TIME, 1, now);
    assert!(!young.finality_binds(), "at block 1, below the anchor");
    grow(&mut young, 1, GENESIS_TIME, 1, now);
    assert_eq!(
        young.block_at(2).map(|b| b.header.block_id()),
        Some(anchored),
        "the same chain, the same blocks"
    );
    assert!(young.finality_binds(), "at the anchor");
}

#[test]
fn the_testnet_anchors_are_well_formed() {
    let anchors = validate::anchors(Network::Testnet);
    // Lowest first, below the strict time activation, and each a block id.
    assert!(anchors.windows(2).all(|w| w[0].0 < w[1].0));
    for (h, id) in &anchors {
        assert!(*h > 0 && *h < q21_core::consensus::STRICT_TIME_ACTIVATION_TESTNET);
        assert_ne!(*id, Hash256::ZERO);
    }
    assert!(validate::anchors(Network::Mainnet).is_empty());
}

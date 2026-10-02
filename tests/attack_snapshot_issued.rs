//! ATTACK (red team 8b, 2nd campaign, item 6c) — a snapshot with a rewritten
//! total issued, under the right commitment.
//!
//! The commitment one copies to adopt a snapshot used to be the MuHash of the
//! UTXO set, and nothing else. But the total issued does not follow from it: a
//! peer could serve the authentic snapshot with a rewritten total issued —
//! within the range the invariants tolerate —, and it passed the comparison
//! with the trusted value. The displayed money supply was wrong, and the cap
//! bound was computed on a wrong total.
//!
//! Fix: the state commitment binds the MuHash and the total issued. The MuHash
//! does not change, nor does the snapshot format; only the value being compared
//! derives from it.

use q21_core::chain::{genesis_block, AdoptionError, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::state::state_commitment;
use q21_core::Network;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn mined_chain(n: u64) -> Chain {
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=n {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }
    c
}

#[test]
fn a_rewritten_total_issued_no_longer_passes_under_the_trusted_commitment() {
    let chain = mined_chain(20);
    let honest = chain.snapshot_at_depth(5).expect("snapshot");
    let headers = chain.headers();

    // What a trusted source displays for this height: the state commitment of
    // a full node at this same tip.
    let trusted = honest.commitment();

    // The attack: the same set, the same MuHash, a rewritten total issued.
    let mut forged = honest.clone();
    forged.issued += 1;
    assert_eq!(
        forged.muhash, honest.muhash,
        "the MuHash alone does not see the total issued: that was the flaw"
    );
    assert_ne!(
        forged.commitment(),
        trusted,
        "the state commitment, for its part, changes with the total issued"
    );

    let r = Chain::adopt_snapshot(NETWORK, forged, &headers, honest.tip, trusted);
    assert_eq!(
        r.err(),
        Some(AdoptionError::UnexpectedCommitment),
        "a snapshot with a rewritten total issued must be refused under the trusted commitment"
    );

    // The control: the honest snapshot still gets adopted under the same value.
    let r = Chain::adopt_snapshot(NETWORK, honest.clone(), &headers, honest.tip, trusted);
    assert!(
        r.is_ok(),
        "the honest snapshot must get adopted: {:?}",
        r.err()
    );

    // And what a full node displays at this height is indeed this value, by
    // construction: the chain brought back to the snapshot height carries the
    // same state commitment as the snapshot.
    let mut control = chain;
    while control.height() > honest.height {
        assert!(control.disconnect());
    }
    assert_eq!(control.state_commitment(), trusted);
    assert_eq!(
        control.state_commitment(),
        state_commitment(control.utxo_commitment(), control.total_issued().units())
    );
}

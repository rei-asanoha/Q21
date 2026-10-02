//! ATTACK (red team 8b, 2nd campaign) — remote crash of a node doing fast sync
//! through an outsized snapshot height.
//!
//! A node that adopts a snapshot (`--assume-commitment`) receives from its peer
//! a decoded `Snapshot`, whose `height` field is only valid inside the
//! authentication loop. Previously, the capacity of the path vector was
//! reserved BEFORE that loop, at `snapshot.height as usize + 1`. An adversarial
//! height of `u64::MAX` made the addition overflow — and thus, under
//! `overflow-checks` and `panic = "abort"`, ABORT the process: a reliable crash
//! of every new node syncing from that peer.
//!
//! Fix: the capacity is bounded by the number of headers actually supplied. An
//! outsized height now only causes a clean refusal.

use q21_core::address::Network;
use q21_core::chain::{AdoptionError, Chain};
use q21_core::hash::Hash256;
use q21_core::state::Snapshot;
use q21_core::utxo::UtxoSet;

#[test]
fn an_outsized_snapshot_height_is_refused_without_crashing() {
    let tip = Hash256([0x11; 32]);

    // A snapshot whose height is maximal — what an adversarial peer sets. We
    // align `tip` and the commitment with the trusted values to get past the
    // first two checks and reach the formerly vulnerable line.
    let snapshot = Snapshot {
        network: Network::Testnet,
        height: u64::MAX,
        tip,
        issued: 0,
        utxo: UtxoSet::new(),
        muhash: Hash256([0x22; 32]),
    };
    let commitment = snapshot.commitment();

    // No header supplied: the authentication loop fails anyway, but the
    // capacity of the vector is computed BEFORE it. Without the fix,
    // `u64::MAX as usize + 1` overflows and the process aborts right here.
    let r = Chain::adopt_snapshot(Network::Testnet, snapshot, &[], tip, commitment);

    assert_eq!(
        r.err(),
        Some(AdoptionError::InauthenticHeaders),
        "an outsized height must mean a clean refusal, never an abort"
    );
}

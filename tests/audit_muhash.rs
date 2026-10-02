//! Audit — the MuHash commitment to the UTXO set.
//!
//! These tests lock in the primitive and its wiring end to end: that the
//! commitment depends only on the state of the currency and not on the path by
//! which it is reached, that a snapshot carries it faithfully, and above all
//! that a node that **adopts** a snapshot reaches exactly the same committed
//! state as a node that revalidated everything. It is this last equality that
//! allows fast sync: without it, adopting a snapshot would be a gamble.

use q21_core::block::Block;
use q21_core::chain::{genesis_block, AdoptionError, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::state::{Snapshot, StateStore};
use q21_core::store::{BlockArchive, BlockStore};
use q21_core::Network;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn timestamp(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn test_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-audit-muhash-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Mines `n` blocks, writes them to an on-disk archive — as the binary does —
/// and returns the chain, the archive (body source for a resumed node) and the
/// sequence of blocks, from the genesis to the last one.
fn mined_chain(dir: &Path, n: u64) -> (Chain, Arc<BlockArchive>, Vec<Block>) {
    let path = dir.join("blocks.dat");
    let g = genesis_block(NETWORK);
    let store = BlockStore::new(&path);
    store.append(&g).unwrap();
    let (archive, _, _) = BlockArchive::open(&path, NETWORK).unwrap();
    let archive = Arc::new(archive);

    let mut c = Chain::new(NETWORK, g.clone());
    c.set_body_source(archive.clone());
    let mut blocks = vec![g];
    for i in 1..=n {
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
        archive.append(&b).unwrap();
        blocks.push(b);
    }
    (c, archive, blocks)
}

/// The commitment of the regtest genesis is a frozen vector.
///
/// This test does not check a property, it **engraves a number**. The whole
/// computation chain goes through it: the format of the serialized coin, the
/// expansion to 3072 bits, the modular reduction, the final hash. If one of
/// these links changes — a byte order in the coin, a domain tag — this number
/// changes, and two versions of the software stop agreeing on the state.
/// Freezing it forbids that silent drift.
#[test]
fn the_regtest_genesis_commitment_is_frozen() {
    let c = Chain::new(NETWORK, genesis_block(NETWORK));
    // Frozen at 0.4.0, which renamed the label and changed the genesis
    // message (hence the genesis coinbase, hence its outpoint).
    assert_eq!(
        c.utxo_commitment().to_hex(),
        "4b8e84b4b0851dae63ed1cb5591e8bc302158c99a4479e0c9daae4e5e7ea0e9f",
        "the genesis commitment changed: the coin format or the MuHash \
         moved, and two versions will no longer agree on the state"
    );
}

/// The commitment depends only on the sequence of blocks, not on the way it is
/// replayed. A node that rebuilds its chain block by block finds exactly the
/// commitment of a node that mined it.
#[test]
fn the_commitment_depends_only_on_the_state() {
    let (a, _ar, blocks) = mined_chain(&test_dir("state"), 12);

    let mut b = Chain::new(NETWORK, blocks[0].clone());
    for (i, block) in blocks.iter().enumerate().skip(1) {
        b.connect(block, timestamp(i as u64) + 1).expect("replay");
    }

    assert_eq!(a.height(), b.height());
    assert_eq!(
        a.utxo_commitment(),
        b.utxo_commitment(),
        "two chains in the same state must carry the same commitment"
    );
}

/// The snapshot taken below the tip carries a commitment faithful to its own
/// UTXO set: it is recomputed and matches.
#[test]
fn the_snapshot_carries_a_faithful_commitment() {
    let (c, _ar, _) = mined_chain(&test_dir("faithful"), 16);
    let s = c.snapshot().expect("snapshot");
    assert_eq!(
        s.muhash,
        s.utxo.commitment(),
        "the recorded commitment must match the set it accompanies"
    );
}

/// The heart of fast sync: a node that **adopts** a snapshot, then replays the
/// short window separating it from the tip, reaches exactly the same committed
/// state as a node that revalidated everything from the genesis.
///
/// Without this equality, adopting a snapshot would amount to starting again
/// from a state one could no longer prove to be the right one. With it, the
/// commitment of the resumed node can be checked against the one any synced
/// peer announces: if they agree, the shortcut cost the truth nothing.
#[test]
fn a_node_that_adopts_the_snapshot_reaches_the_same_state() {
    let (full, archive, blocks) = mined_chain(&test_dir("adopted"), 20);
    let s = full.snapshot().expect("snapshot");
    let snapshot_height = s.height;
    assert!(snapshot_height < full.height(), "taken below the tip");

    let resumption = Chain::from_snapshot(NETWORK, s, &full.headers())
        .unwrap_or_else(|e| panic!("resume refused: {e:?}"));
    let mut resumed = resumption.chain;
    resumed.set_body_source(archive.clone());
    // Replays the remaining window, block by block, as a node would at
    // startup.
    for id in &resumption.to_replay {
        let block = blocks
            .iter()
            .find(|b| b.header.block_id() == *id)
            .expect("the block to replay is known");
        resumed
            .connect(block, timestamp(block.header.height) + 1)
            .expect("replay of the window");
    }

    assert_eq!(resumed.height(), full.height(), "same tip reached");
    assert_eq!(
        resumed.utxo_commitment(),
        full.utxo_commitment(),
        "the resumed node and the full node must carry the SAME commitment"
    );
}

/// Anchored adoption: with the right trusted tip and commitment, a node adopts
/// the snapshot, replays the window, and reaches the same state as a full node.
/// It is pass B2 laid on top of B1: Q21's assumeutxo.
#[test]
fn adopting_with_the_right_values_reaches_the_same_state() {
    let (full, archive, blocks) = mined_chain(&test_dir("adopt-ok"), 20);
    let s = full.snapshot().expect("snapshot");
    let tip = s.tip;
    let commitment = s.commitment();

    let resumption = Chain::adopt_snapshot(NETWORK, s, &full.headers(), tip, commitment)
        .unwrap_or_else(|e| panic!("adoption refused: {e:?}"));
    let mut resumed = resumption.chain;
    resumed.set_body_source(archive.clone());
    for id in &resumption.to_replay {
        let block = blocks
            .iter()
            .find(|b| b.header.block_id() == *id)
            .expect("block to replay known");
        resumed
            .connect(block, timestamp(block.header.height) + 1)
            .expect("replay");
    }

    assert_eq!(resumed.height(), full.height());
    assert_eq!(resumed.utxo_commitment(), full.utxo_commitment());
}

/// A trusted commitment that does not match gets the adoption refused — even if
/// the file is, in itself, perfectly consistent.
#[test]
fn adopting_with_a_wrong_commitment_is_refused() {
    let (full, _ar, _) = mined_chain(&test_dir("adopt-commitment"), 12);
    let s = full.snapshot().expect("snapshot");
    let tip = s.tip;
    let wrong = Hash256([0x99; 32]);
    assert!(matches!(
        Chain::adopt_snapshot(NETWORK, s, &full.headers(), tip, wrong),
        Err(AdoptionError::UnexpectedCommitment)
    ));
}

/// A trusted tip that does not match gets the adoption refused.
#[test]
fn adopting_with_a_wrong_tip_is_refused() {
    let (full, _ar, _) = mined_chain(&test_dir("adopt-tip"), 12);
    let s = full.snapshot().expect("snapshot");
    let commitment = s.commitment();
    let wrong = Hash256([0x77; 32]);
    assert!(matches!(
        Chain::adopt_snapshot(NETWORK, s, &full.headers(), wrong, commitment),
        Err(AdoptionError::UnexpectedTip)
    ));
}

/// Headers that do not lead to the trusted tip — here, no header at all — get
/// the adoption refused: the tip is not authenticated.
#[test]
fn adopting_without_authenticating_headers_is_refused() {
    let (full, _ar, _) = mined_chain(&test_dir("adopt-hdr"), 12);
    let s = full.snapshot().expect("snapshot");
    let tip = s.tip;
    let commitment = s.commitment();
    assert!(matches!(
        Chain::adopt_snapshot(NETWORK, s, &[], tip, commitment),
        Err(AdoptionError::InauthenticHeaders)
    ));
}

/// A snapshot saved then read back keeps its commitment, and the set read back
/// reproduces it. It is the check a peer will make on a downloaded file.
#[test]
fn a_reread_snapshot_stays_verifiable() {
    let (c, _ar, _) = mined_chain(&test_dir("reread"), 10);
    let s = c.snapshot().expect("snapshot");

    let mut path = std::env::temp_dir();
    path.push(format!("q21-audit-muhash-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let store = StateStore::new(&path);
    store.save(&s).expect("write");

    let read_back: Snapshot = store.load(NETWORK).expect("reread");
    assert_eq!(
        read_back.muhash, s.muhash,
        "the commitment survives the disk"
    );
    assert_eq!(
        read_back.utxo.commitment(),
        read_back.muhash,
        "the set read back reproduces its commitment"
    );
    let _ = std::fs::remove_file(&path);
}

/// A snapshot in which the ownership of an output was moved — same amount,
/// another beneficiary — carries a commitment different from that of the
/// honest chain. A peer comparing against a trusted value therefore sees it,
/// where the emission check alone let it through.
#[test]
fn moving_an_output_pulls_the_commitment_away_from_the_honest_value() {
    let (c, _ar, _) = mined_chain(&test_dir("moved"), 14);
    let honest = c.utxo_commitment();

    let mut s = c.snapshot().expect("snapshot");
    let honest_at_this_height = s.utxo.commitment();

    // The forger redirects an output to themself.
    let target = *s.utxo.iter().next().unwrap().0;
    let mut stolen = *s.utxo.get(&target).unwrap();
    stolen.output.pubkey_hash = Hash256([0x99; 32]);
    s.utxo.remove(&target);
    s.utxo.insert(target, stolen);

    let forged = s.utxo.commitment();
    assert_ne!(
        forged, honest_at_this_height,
        "moving ownership must change the commitment"
    );
    // And it cannot fall by chance on the commitment of the tip either.
    assert_ne!(forged, honest);
}

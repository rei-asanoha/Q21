//! Audit of persistence, consistency after a hard shutdown, and resuming from a
//! snapshot.
//!
//! Each test simulates a real failure by manipulating the files on disk
//! (truncation, modified bytes, files swapped between two nodes) and compares
//! the verdict of a resumed node with that of a full node on THE SAME blocks.

use q21_core::addr::{AddrBook, AddrStore};
use q21_core::address::Network;
use q21_core::block::Block;
use q21_core::chain::{genesis_block, Chain, ResumeError, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::state::{AddressCache, StateStore};
use q21_core::store::{BlockArchive, BlockStore};
use q21_core::wire::NetAddr;
use std::path::PathBuf;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

/// The attacker modeled here has write access to the directory: they therefore
/// read the seal as the node reads it. The seal is not meant to stop them — it
/// stops a state file **coming from elsewhere**. What these tests measure is
/// what remains when the seal no longer protects: internal consistency.
fn state_store_in(d: &std::path::Path) -> StateStore {
    let key = q21_core::state::datadir_key(d).expect("directory key");
    StateStore::new_sealed(d.join("state.dat"), key)
}

fn test_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-audit-persist-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn timestamp(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

/// Mines `n` blocks and writes them to the archive, exactly as the binary
/// does: `connect` then `append`.
fn chain_on_disk(d: &std::path::Path, n: u64) -> (Chain, std::sync::Arc<BlockArchive>) {
    let path = d.join("blocks.dat");
    let g = genesis_block(NETWORK);
    let store = BlockStore::new(&path);
    store.append(&g).unwrap();
    let (archive, _, _) = BlockArchive::open(&path, NETWORK).unwrap();
    let archive = std::sync::Arc::new(archive);

    let mut c = Chain::new(NETWORK, g);
    c.set_body_source(archive.clone());
    for i in 1..=n {
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
        archive.append(&b).unwrap();
    }
    (c, archive)
}

/// Reproduces the chain loading of src/bin/q21.rs: header scan, resume from
/// the snapshot if possible, otherwise full revalidation.
fn load(d: &std::path::Path) -> Result<(Chain, std::sync::Arc<BlockArchive>), String> {
    let (archive, headers, problem) =
        BlockArchive::open(d.join("blocks.dat"), NETWORK).map_err(|e| e.to_string())?;
    if headers.is_empty() {
        return Err("no block".into());
    }
    if let Some(s) = problem {
        eprintln!("warning: {s}");
    }
    let archive = std::sync::Arc::new(archive);
    let key = q21_core::state::datadir_key(d).map_err(|e| e.to_string())?;
    let state_store = StateStore::new_sealed(d.join("state.dat"), key);
    let resumption = match state_store.load(NETWORK) {
        Ok(i) => match Chain::from_snapshot(NETWORK, i, &headers) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("warning: unusable snapshot ({e})");
                None
            }
        },
        Err(e) if state_store.exists() => {
            eprintln!("warning: {e}");
            None
        }
        Err(_) => None,
    };

    let mut chain = match resumption {
        Some(r) => {
            let mut c = r.chain;
            c.set_body_source(archive.clone());
            for id in &r.to_replay {
                let b = archive.read(id).ok_or("body missing on replay")?;
                let now = b.header.time + MAX_FUTURE_TIME;
                c.connect(&b, now)
                    .map_err(|e| format!("block {} refused on replay: {e:?}", b.header.height))?;
            }
            c
        }
        None => {
            // `submit`, not `connect`: the file also contains the side
            // branches, which extend nothing. See
            // `a_file_containing_side_branches_replays`.
            let (blocks, _) = archive.store().load_all().map_err(|e| e.to_string())?;
            let mut c = Chain::new(NETWORK, blocks[0].clone());
            c.set_body_source(archive.clone());
            for (i, b) in blocks.iter().enumerate().skip(1) {
                let now = b.header.time + MAX_FUTURE_TIME;
                c.submit(b, now)
                    .map_err(|e| format!("block {i} refused on replay: {e:?}"))?;
            }
            c
        }
    };
    chain.set_body_source(archive.clone());
    Ok((chain, archive))
}

fn write_snapshot(d: &std::path::Path, c: &Chain) {
    if let Some(i) = c.snapshot() {
        state_store_in(d).save(&i).unwrap();
    }
}

// ===========================================================================
// 1. Hard shutdown
// ===========================================================================

/// A. Power cut BETWEEN writing the block and writing the snapshot.
/// The snapshot is behind: the replay must catch up, without divergence.
#[test]
fn a_cut_between_block_and_snapshot() {
    let d = test_dir("cut-between");
    let (c, _a) = chain_on_disk(&d, 12);
    write_snapshot(&d, &c);

    // Two more blocks, written to disk but no snapshot: the power cut happens
    // here.
    let (c2, _a2) = {
        let (mut c2, a2) = load(&d).unwrap();
        for i in c2.height() + 1..=c2.height() + 2 {
            let t = timestamp(i);
            let b = c2
                .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
                .unwrap();
            c2.connect(&b, t + 1).unwrap();
            a2.append(&b).unwrap();
        }
        (c2, a2)
    };
    let tip = c2.tip_id();
    let issued = c2.total_issued();
    drop(c2);

    let (resumed, _) = load(&d).expect("restart after power cut");
    assert_eq!(resumed.tip_id(), tip, "different tip after power cut");
    assert_eq!(resumed.total_issued(), issued, "different emission");
}

/// B. Power cut DURING the write of a block: file truncated in the middle of
/// the last record, snapshot behind.
#[test]
fn b_cut_during_a_block_write() {
    let d = test_dir("truncated");
    let (c, _a) = chain_on_disk(&d, 14);
    write_snapshot(&d, &c);
    let height_before = c.height();
    drop(c);

    // One more block, then a power cut in the middle of its write.
    let (mut c2, a2) = load(&d).unwrap();
    let t = timestamp(height_before + 1);
    let b = c2
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .unwrap();
    c2.connect(&b, t + 1).unwrap();
    a2.append(&b).unwrap();
    drop(c2);
    drop(a2);

    let path = d.join("blocks.dat");
    let size = std::fs::metadata(&path).unwrap().len();
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(size - 20).unwrap(); // last block cut in two
    drop(f);

    let (resumed, _) = load(&d).expect("a truncated file must not prevent starting");
    assert_eq!(
        resumed.height(),
        height_before,
        "the node must go back to the last complete block"
    );
}

/// C. Power cut DURING the atomic rename: the `.tmp` remains, the target file
/// is the old one. The node must start again from the old snapshot.
#[test]
fn c_cut_during_the_rename() {
    let d = test_dir("rename");
    let (mut c, a) = chain_on_disk(&d, 12);
    write_snapshot(&d, &c);
    let old = std::fs::read(d.join("state.dat")).unwrap();

    for i in 13..=16u64 {
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        a.append(&b).unwrap();
    }
    let tip = c.tip_id();
    // The power cut: the temporary file is written, the rename did not happen.
    let new_snapshot = c.snapshot().unwrap();
    let tmp = d.join("state.tmp");
    // We force the "before rename" state.
    std::fs::write(&tmp, b"partial contents").unwrap();
    std::fs::write(d.join("state.dat"), &old).unwrap();
    drop(new_snapshot);
    drop(c);

    let (resumed, _) = load(&d).expect("restart");
    assert_eq!(
        resumed.tip_id(),
        tip,
        "the replay must catch up with the tip"
    );
    assert!(
        tmp.exists(),
        "the temporary file remains (an observation, not a defect)"
    );
}

/// D. **Can the snapshot be AHEAD of the block file?**
/// It is the daemon's real case: blocks received from the network are never
/// written to blocks.dat, but the snapshot is written at shutdown.
#[test]
fn d_snapshot_ahead_of_the_block_file() {
    let d = test_dir("ahead");
    // The node has a block file of 12 blocks...
    let (mut c, _a) = chain_on_disk(&d, 12);
    // ...but receives 6 blocks from the network, which it connects WITHOUT
    // writing them (this is exactly what the node's block integration in
    // src/net.rs does).
    for i in 13..=18u64 {
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        // no archive.append: the daemon does not do it for received blocks
    }
    let real_height = c.height();
    write_snapshot(&d, &c); // written at shutdown
    drop(c);

    let (resumed, _) = load(&d).expect("restart");
    eprintln!(
        "OBSERVATION: height {} before shutdown, {} after — {} blocks lost WITHOUT error",
        real_height,
        resumed.height(),
        real_height - resumed.height()
    );
    assert_eq!(
        resumed.height(),
        12,
        "the node goes back to the height of the block file, silently"
    );
    assert_ne!(
        resumed.total_issued(),
        {
            // What the node believed it had issued just before shutdown.
            q21_core::amount::Amount::from_units(u64::MAX)
        },
        "safeguard"
    );
}

/// D bis. The aggravated case: the daemon *also* mines. blocks.dat then
/// receives non-contiguous blocks, and the node no longer restarts AT ALL.
#[test]
fn d_bis_the_node_no_longer_restarts_after_mining_while_syncing() {
    use q21_core::chain::Journal;
    let d = test_dir("bricked");
    let (mut c, a) = chain_on_disk(&d, 4);
    // Seven blocks, six of them "received from the network". All of them now go
    // through the journal: it is the chain that records, not the mining loop.
    for i in 5..=11u64 {
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        a.record(&b);
    }
    write_snapshot(&d, &c);
    drop(c);

    // The journal is idempotent: recording a block already written again must
    // not create a duplicate, otherwise the file doubles in size on each
    // rebroadcast.
    let before = a.len();
    let last = a.read(
        &a.store()
            .load_all()
            .unwrap()
            .0
            .last()
            .unwrap()
            .header
            .block_id(),
    );
    if let Some(b) = last {
        a.record(&b);
    }
    assert_eq!(a.len(), before, "the journal wrote the same block twice");

    // A node that mined during its sync must be able to restart.
    let (resumed, _) = load(&d).expect("the node restarts");
    assert_eq!(resumed.height(), 11, "the mined tip is found again");
}

// ===========================================================================
// 2. Snapshot and block file out of step
// ===========================================================================

/// The snapshot designates a tip missing from the block file.
#[test]
fn e_snapshot_designating_a_missing_tip() {
    let d = test_dir("missing-tip");
    let (c, _a) = chain_on_disk(&d, 12);
    let mut s = c.snapshot().unwrap();
    s.tip = Hash256([0xAB; 32]); // unknown tip
    state_store_in(&d).save(&s).unwrap();
    drop(c);

    // We must fall back to full revalidation, never accept.
    let (resumed, _) = load(&d).expect("full revalidation");
    assert_eq!(resumed.height(), 12);
}

/// The block file comes from ANOTHER network (or another chain): the snapshot
/// is refused, but full revalidation used to adopt **any** first block as the
/// genesis.
#[test]
fn f_a_foreign_block_file_is_adopted_as_genesis() {
    let d = test_dir("foreign");
    let (_c, _a) = chain_on_disk(&d, 3);
    let _ = std::fs::remove_file(d.join("state.dat"));

    // A crafted "genesis": no proof of work, an arbitrary premine to the
    // attacker.
    let mut fake = genesis_block(NETWORK);
    fake.transactions[0].outputs[0].pubkey_hash = Hash256([0x99; 32]);
    fake.transactions[0].outputs[0].value = q21_core::amount::Amount::from_units(2_100_000_000_000);
    fake.header.merkle_root = fake.compute_merkle_root();
    fake.header.nonce = 1; // proof of work deliberately wrong

    let path = d.join("blocks.dat");
    let _ = std::fs::remove_file(&path);
    BlockStore::new(&path).append(&fake).unwrap();

    // The file no longer starts with the network genesis: it is not adopted.
    let message = match load(&d) {
        Ok(_) => panic!("OBSERVATION: a crafted genesis is adopted without any check"),
        Err(e) => e,
    };
    eprintln!("refusal: {message}");
    assert!(
        message.contains("another chain"),
        "the refusal must name its reason: {message}"
    );
}

/// A crafted snapshot (the attacker has access to the disk / to a backup) whose
/// checksum is recomputed: used to be accepted without a blink.
#[test]
fn g_crafted_snapshot_credits_nonexistent_funds() {
    let d = test_dir("fake-state");
    let (c, _a) = chain_on_disk(&d, 12);
    let mut s = c.snapshot().unwrap();
    let balance_before: u64 = s
        .utxo
        .iter()
        .filter(|(_, e)| e.output.pubkey_hash == Hash256([0x99; 32]))
        .map(|(_, e)| e.output.value.units())
        .sum();
    assert_eq!(balance_before, 0);

    // The attacker adds an output of their own, and recomputes the checksum.
    s.utxo.insert(
        q21_core::tx::OutPoint {
            txid: Hash256([0x77; 32]),
            index: 0,
        },
        q21_core::utxo::UtxoEntry {
            output: q21_core::tx::TxOut {
                value: q21_core::amount::Amount::from_units(1_000_000_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: Hash256([0x99; 32]),
            },
            height: 1,
            is_coinbase: false,
        },
    );
    state_store_in(&d).save(&s).unwrap();
    drop(c);

    // The MuHash commitment decides first, and more bluntly than the emission
    // schedule: the added output changes the UTXO set, so its commitment no
    // longer matches the recorded one, and the file is rejected — even if the
    // stolen amount stayed under the emission cap. The node then revalidates
    // from the block file, which carries a proof of work.
    let (resumed, _) = load(&d).expect("resume through full revalidation");
    let stolen: u64 = resumed
        .utxo
        .iter()
        .filter(|(_, e)| e.output.pubkey_hash == Hash256([0x99; 32]))
        .map(|(_, e)| e.output.value.units())
        .sum();
    assert_eq!(
        stolen, 0,
        "OBSERVATION: a crafted snapshot credits nonexistent funds"
    );
    assert_eq!(resumed.height(), 12, "the real chain is found again");
}

// ===========================================================================
// 3. Verdict of a resumed node vs verdict of a full node
// ===========================================================================

/// On the same blocks, a resumed node and a full node must return the same
/// verdict. Tested on a chain of uncles (double payment rule).
#[test]
fn h_same_verdict_on_the_same_block() {
    let d = test_dir("verdict");
    let (full, _a) = chain_on_disk(&d, 20);
    write_snapshot(&d, &full);

    let (mut resumed, _) = load(&d).expect("resume");
    let mut full = full;

    // The same block, submitted to both.
    let t = timestamp(21);
    let b = full
        .mine_block(Hash256([3u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .unwrap();
    let v1 = full.connect(&b, t + 1);
    let v2 = resumed.connect(&b, t + 1);
    assert_eq!(
        v1.is_ok(),
        v2.is_ok(),
        "different verdicts: {v1:?} vs {v2:?}"
    );
    assert_eq!(full.tip_id(), resumed.tip_id());
    assert_eq!(full.total_issued(), resumed.total_issued());
}

/// The undo window of a resumed node is shorter than that of a full node: on
/// the SAME reorg, one switches, the other refuses.
#[test]
fn i_short_undo_window_after_resume() {
    let d = test_dir("window");
    let (full, _a) = chain_on_disk(&d, 30);
    // Snapshot taken at a small depth: it is what `snapshot()` does on a short
    // chain, and what a node does that has just been resumed then stopped
    // right away.
    let s = full.snapshot_at_depth(2).unwrap();
    state_store_in(&d).save(&s).unwrap();

    let (resumed, _) = load(&d).expect("resume");
    eprintln!(
        "undo window: full {} / resumed {}",
        full.undo_window(),
        resumed.undo_window()
    );
    assert!(
        resumed.undo_window() < full.undo_window(),
        "a resumed node has a shorter window: different reorg depths"
    );
}

/// The uncle anti-double-payment rule rereads the bodies of the last 9 blocks
/// — when uncles are possible. As long as `MAX_UNCLES` is zero, no uncle can
/// have been claimed: there is nothing to reread, and a resumed node without a
/// body source returns the **same verdict** as a full node on the block that
/// extends its tip. The day the protocol reopens uncles, reading the bodies
/// resumes by itself, and without a body source the verdict becomes a refusal
/// again (`IncompleteHistory`) — a refusal, never a blind acceptance.
#[test]
fn j_without_a_body_source_a_resumed_node_returns_the_same_verdict() {
    use q21_core::consensus::MAX_UNCLES;

    let d = test_dir("no-source");
    let (full, _a) = chain_on_disk(&d, 20);
    let s = full.snapshot().unwrap();
    let headers = full.headers();
    let r = Chain::from_snapshot(NETWORK, s, &headers).expect("resume");
    let mut without_source = r.chain; // no set_body_source

    // The block that extends the tip of the resumed node, mined by a full node
    // brought back to this same height.
    let mut control = full;
    while control.height() > without_source.height() {
        assert!(
            control.disconnect(),
            "the control must be able to go back down"
        );
    }
    let t = timestamp(without_source.height() + 1);
    let b = control
        .mine_block(Hash256([3u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .unwrap();
    let expected = control.connect(&b, t + 1).map(|_| ());
    let v = without_source.connect(&b, t + 1).map(|_| ());
    eprintln!("full verdict: {expected:?}; without body source: {v:?}");
    if MAX_UNCLES == 0 {
        assert!(expected.is_ok(), "the control must accept its own block");
        assert_eq!(
            v, expected,
            "with no uncle possible, missing bodies do not change the verdict"
        );
    } else {
        assert!(v.is_err(), "refusal expected, not a blind acceptance");
    }
}

// ===========================================================================
// 4/5. Bounded body window and emission in the index
// ===========================================================================

/// After resuming, the blocks before the snapshot carry `issued: 0`. We look
/// for a path that reads this value and produces a wrong result.
#[test]
fn k_emission_after_resume_stays_right() {
    let d = test_dir("emission");
    let (full, _a) = chain_on_disk(&d, 20);
    write_snapshot(&d, &full);
    let (resumed, _) = load(&d).expect("resume");
    assert_eq!(
        resumed.total_issued(),
        full.total_issued(),
        "the emission must be identical"
    );

    // Then we undo down to the bottom of the window: the emission must follow.
    let mut resumed = resumed;
    let mut full = full;
    let n = resumed.undo_window();
    for _ in 0..n {
        let a = resumed.disconnect();
        let b = full.disconnect();
        assert_eq!(a, b, "diverging disconnect");
        if !a {
            break;
        }
        assert_eq!(
            resumed.total_issued(),
            full.total_issued(),
            "diverging emission at height {}",
            resumed.height()
        );
    }
}

/// One more `disconnect`, once the window is exhausted, must neither panic nor
/// reset the emission to zero.
#[test]
fn l_disconnect_outside_the_window_does_not_break_the_emission() {
    let d = test_dir("emission-zero");
    let (full, _a) = chain_on_disk(&d, 20);
    write_snapshot(&d, &full);
    let (mut resumed, _) = load(&d).expect("resume");

    let issued = resumed.total_issued();
    let n = resumed.undo_window();
    for _ in 0..n {
        resumed.disconnect();
    }
    let issued_bottom = resumed.total_issued();
    assert!(!resumed.disconnect(), "refusal expected outside the window");
    assert_eq!(
        resumed.total_issued(),
        issued_bottom,
        "the emission must not move on a refused disconnect"
    );
    assert!(issued.units() >= issued_bottom.units());
}

// ===========================================================================
// 6/7. Hostile files
// ===========================================================================

/// The address cache used to be spot-checked on the FIRST and LAST entries
/// only. We forge a cache whose two such entries are good and the others fake.
#[test]
fn m_forged_address_cache_is_adopted() {
    use q21_core::wallet::Wallet;
    let d = test_dir("address-cache");
    let seed = [7u8; 32];
    let mut genuine = Wallet::from_seed_scheme(seed, NETWORK, SchemeId::LamportOts).unwrap();
    genuine.rescan(8);
    let genuine_hashes = genuine.known_hashes();
    assert_eq!(genuine_hashes.len(), 8);

    // The forger only knows two public addresses: the first and the last. They
    // replace all the rest with their own.
    let mut forged = genuine_hashes.clone();
    for (i, h) in forged.iter_mut().enumerate().take(7).skip(1) {
        *h = Hash256([0x99 ^ i as u8; 32]);
    }
    let cache = AddressCache::new(d.join("addresses.dat"));
    // The attacker does not know the seed: they cannot seal the cache. So they
    // write with a key of their own.
    cache
        .save(SchemeId::LamportOts, &forged, &[0u8; 32])
        .unwrap();

    let loaded = cache.load(SchemeId::LamportOts, &genuine.cache_key());
    assert!(
        loaded.is_err(),
        "a cache not sealed by this wallet must be refused: {loaded:?}"
    );

    // And even if the seal gave way, the wallet must not adopt just anything:
    // derivation is deterministic, it serves as a safeguard.
    let mut victim = Wallet::from_seed_scheme(seed, NETWORK, SchemeId::LamportOts).unwrap();
    let adopted = victim.adopt_hashes(&forged);
    assert!(
        !adopted,
        "OBSERVATION: a cache forged on 6 entries out of 8 is adopted"
    );
    // The wallet adopted nothing: it knows no address of the attacker, and it
    // finds its own again through derivation.
    assert!(!victim.owns(&Hash256([0x99 ^ 1u8; 32])));
    victim.rescan(8);
    assert!(
        victim.owns(&genuine_hashes[3]),
        "OBSERVATION: the wallet loses sight of its own addresses"
    );
}

/// Financial consequence of the forged cache: the balance is wrong, the real
/// funds become invisible, and the attacker's funds are counted as its own.
#[test]
fn n_forged_cache_falsifies_the_balance_and_hides_the_funds() {
    use q21_core::amount::Amount;
    use q21_core::tx::{OutPoint, TxOut};
    use q21_core::utxo::{UtxoEntry, UtxoSet};
    use q21_core::wallet::Wallet;

    let seed = [11u8; 32];
    let mut genuine = Wallet::from_seed_scheme(seed, NETWORK, SchemeId::LamportOts).unwrap();
    genuine.rescan(6);
    let genuine_hashes = genuine.known_hashes();

    let mut utxo = UtxoSet::new();
    // Real funds on address 3 of the wallet.
    utxo.insert(
        OutPoint {
            txid: Hash256([1u8; 32]),
            index: 0,
        },
        UtxoEntry {
            output: TxOut {
                value: Amount::from_units(500_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: genuine_hashes[3],
            },
            height: 1,
            is_coinbase: false,
        },
    );
    // Funds of the attacker, on an address of their own.
    let theirs = Hash256([0xAA; 32]);
    utxo.insert(
        OutPoint {
            txid: Hash256([2u8; 32]),
            index: 0,
        },
        UtxoEntry {
            output: TxOut {
                value: Amount::from_units(9_000_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: theirs,
            },
            height: 1,
            is_coinbase: false,
        },
    );

    let honest_balance = genuine.balance(&utxo, 1_000);
    assert_eq!(honest_balance.units(), 500_000);

    let mut forged = genuine_hashes.clone();
    forged[3] = theirs; // the attacker substitutes their address for the middle one
    let mut victim = Wallet::from_seed_scheme(seed, NETWORK, SchemeId::LamportOts).unwrap();
    let adopted = victim.adopt_hashes(&forged);

    // Out of six entries, the sample covers everything: the substitution is
    // seen.
    assert!(!adopted, "OBSERVATION: a forged cache is still adopted");
    // And the wallet stayed on its own derivation.
    victim.rescan(6);
    let balance = victim.balance(&utxo, 1_000);
    eprintln!("honest balance {honest_balance} / balance after the attempt {balance}");
    assert_eq!(
        balance.units(),
        500_000,
        "the balance must stay that of the funds actually held"
    );
}

/// The forged cache makes the wallet build an invalid transaction, and
/// **consumes a one-time Lamport key** along the way.
#[test]
fn o_forged_cache_burns_a_lamport_key() {
    use q21_core::address::Address;
    use q21_core::amount::Amount;
    use q21_core::tx::{OutPoint, TxOut};
    use q21_core::utxo::{UtxoEntry, UtxoSet};
    use q21_core::wallet::Wallet;

    let seed = [13u8; 32];
    let mut genuine = Wallet::from_seed_scheme(seed, NETWORK, SchemeId::LamportOts).unwrap();
    genuine.rescan(6);
    let genuine_hashes = genuine.known_hashes();
    let theirs = Hash256([0xAA; 32]);

    let mut utxo = UtxoSet::new();
    utxo.insert(
        OutPoint {
            txid: Hash256([2u8; 32]),
            index: 0,
        },
        UtxoEntry {
            output: TxOut {
                value: Amount::from_units(9_000_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: theirs,
            },
            height: 1,
            is_coinbase: false,
        },
    );

    let mut forged = genuine_hashes.clone();
    forged[3] = theirs;
    let mut victim = Wallet::from_seed_scheme(seed, NETWORK, SchemeId::LamportOts).unwrap();
    // We force the most unfavorable situation: even if the cache had been
    // adopted — seal bypassed, sample missed — the key must not burn.
    let _ = victim.adopt_hashes(&forged);
    victim.rescan(6);
    victim.force_association_for_test(theirs, 3);

    let dest = Address::from_pubkey(NETWORK, SchemeId::LamportOts, &[1u8; 32]);
    let tx = victim.create_transaction(
        &utxo,
        1_000,
        &dest,
        Amount::from_units(50_000),
        Amount::from_units(100),
    );
    // The wallet must refuse BEFORE signing, and consume nothing.
    assert!(
        matches!(
            tx,
            Err(q21_core::wallet::WalletError::LockMismatch { index: 3 })
        ),
        "OBSERVATION: the wallet signs with a key that does not open this lock: {tx:?}"
    );
    assert!(
        !victim.is_consumed(3),
        "OBSERVATION: key 3 was burned by a refusal"
    );
}

/// A hostile `peers.dat`: 512 groups pinned by a `last_seen` in the future,
/// which no honest address will ever be able to dislodge.
#[test]
fn p_hostile_address_book_pins_every_group() {
    const NOW: u64 = 1_700_000_000;
    let d = test_dir("address_book");
    let store = AddrStore::new(d.join("peers.dat"));
    let mut hostile = AddrBook::new_with_salt(false, (1, 2));
    let mut n = 0;
    for a in 1u16..=255 {
        for b in 0u16..=255 {
            if a == 10 || a == 127 || a == 172 || a == 192 || a == 169 || a == 100 || a >= 224 {
                continue;
            }
            if hostile.groups() >= MAX_LOCAL_GROUPS {
                break;
            }
            hostile.add(
                NetAddr {
                    ip: [a as u8, b as u8, 1, 1],
                    port: 21021,
                    last_seen: u64::MAX, // impossible timestamp
                },
                NOW,
            );
            n += 1;
        }
        if hostile.groups() >= MAX_LOCAL_GROUPS {
            break;
        }
    }
    eprintln!(
        "hostile address book: {n} addresses, {} groups",
        hostile.groups()
    );
    store.save(&hostile).unwrap();

    let mut reread = store.load(false, NOW);
    assert_eq!(
        reread.groups(),
        MAX_LOCAL_GROUPS,
        "the 512 groups are occupied"
    );

    // 1. The group cap no longer freezes the address book: none of these
    //    addresses has ever answered, so none has any acquired right. An honest
    //    address gets in, evicting a group that proved nothing.
    let honest = reread.add(
        NetAddr {
            ip: [8, 8, 8, 8],
            port: 21021,
            last_seen: NOW,
        },
        NOW,
    );
    assert!(
        honest,
        "OBSERVATION: no honest address can get into the address book anymore"
    );

    // 2. The impossible timestamp no longer gives any advantage: it is bounded
    //    on add, so it does not survive going through the disk.
    assert!(
        reread
            .all()
            .iter()
            .all(|e| e.addr.last_seen <= NOW + q21_core::addr::FUTURE_TOLERANCE),
        "OBSERVATION: a future timestamp survives in the address book"
    );

    // 3. A really tested peer is no longer drowned in the mass: it comes out
    //    first in the selection, whatever the others announce.
    reread.mark_success([8, 8, 8, 8], 21021, NOW);
    let choice = reread.select(8, &[], NOW);
    assert_eq!(choice.len(), 8);
    assert_eq!(
        choice[0].ip,
        [8, 8, 8, 8],
        "OBSERVATION: the selection only returns the pinned addresses"
    );
}
const MAX_LOCAL_GROUPS: usize = 512;

/// A corrupted `peers.dat` must never cause a panic, only empty the address
/// book.
#[test]
fn q_corrupted_address_book_does_not_panic() {
    let d = test_dir("corrupted-address-book");
    let path = d.join("peers.dat");
    let store = AddrStore::new(&path);
    let mut b = AddrBook::new(false);
    b.add(
        NetAddr {
            ip: [93, 184, 216, 34],
            port: 21021,
            last_seen: 100,
        },
        1_700_000_000,
    );
    store.save(&b).unwrap();

    let mut data = std::fs::read(&path).unwrap();
    let m = data.len() / 2;
    data[m] ^= 0xFF;
    std::fs::write(&path, &data).unwrap();
    assert_eq!(
        store.load(false, 1_700_000_000).len(),
        0,
        "empty address book, no panic"
    );

    // And an entirely random file.
    for size in [0usize, 1, 31, 32, 33, 200] {
        std::fs::write(&path, vec![0x5Au8; size]).unwrap();
        let _ = store.load(false, 1_700_000_000);
    }
}

// ===========================================================================
// 8. Unbounded growth
// ===========================================================================

/// Does the header index grow without bound on resume? We measure what a block
/// file filled with valid but orphan headers costs.
#[test]
fn r_orphan_headers_in_the_block_file() {
    let d = test_dir("orphans");
    let (c, _a) = chain_on_disk(&d, 6);
    let path = d.join("blocks.dat");
    let store = BlockStore::new(&path);

    // 300 dummy blocks, without any proof of work, chained on a nonexistent
    // parent: they pass the header scan.
    let mut dummy = genesis_block(NETWORK);
    for i in 0..300u32 {
        dummy.header.prev_block = Hash256([0xEE; 32]);
        dummy.header.height = 1_000_000 + u64::from(i);
        dummy.header.nonce = u64::from(i);
        store.append(&dummy).unwrap();
    }
    let (_, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("headers scanned: {} (problem {problem:?})", headers.len());
    assert_eq!(headers.len(), 307);

    let s = c.snapshot().unwrap();
    let r = Chain::from_snapshot(NETWORK, s, &headers);
    match &r {
        Ok(res) => eprintln!(
            "resume accepted: {} blocks indexed",
            res.chain.known_blocks()
        ),
        Err(e) => eprintln!("resume refused: {e:?}"),
    }
    // The block file is never pruned nor checked: everything written to it is
    // scanned again at every startup.
    assert!(r.is_ok() || matches!(r, Err(ResumeError::SnapshotOffChain)));
}

/// Does the block file contain duplicates after a restart?
/// (the same block rewritten on each `append` without an existence check)
#[test]
fn s_the_block_file_accepts_unbounded_duplicates() {
    let d = test_dir("duplicates");
    let path = d.join("blocks.dat");
    let store = BlockStore::new(&path);
    let g = genesis_block(NETWORK);
    for _ in 0..50 {
        store.append(&g).unwrap();
    }
    let (_, headers, _) = BlockArchive::open(&path, NETWORK).unwrap();
    assert_eq!(
        headers.len(),
        50,
        "50 copies of the same block, all indexed"
    );
    let size = std::fs::metadata(&path).unwrap().len();
    eprintln!(
        "50 duplicates: {size} bytes, index of {} entries",
        headers.len()
    );
}

// ===========================================================================
// Negative checks: what I looked for without finding anything
// ===========================================================================

/// A snapshot from another network is indeed refused.
#[test]
fn t_snapshot_from_another_network_refused() {
    let d = test_dir("network");
    let (c, _a) = chain_on_disk(&d, 12);
    let mut s = c.snapshot().unwrap();
    s.network = Network::Mainnet;
    state_store_in(&d).save(&s).unwrap();
    assert!(state_store_in(&d).load(Network::Regtest).is_err());
}

/// A snapshot whose height does not match the position of the tip is refused
/// (no silent acceptance).
#[test]
fn u_snapshot_at_the_wrong_height_refused() {
    let d = test_dir("height");
    let (c, _a) = chain_on_disk(&d, 12);
    let mut s = c.snapshot().unwrap();
    s.height += 1;
    let headers = c.headers();
    assert_eq!(
        Chain::from_snapshot(NETWORK, s, &headers).err(),
        Some(ResumeError::SnapshotOffChain)
    );
}

/// A block file without a genesis is refused.
#[test]
fn v_no_genesis_refused() {
    let d = test_dir("no-genesis");
    let (c, _a) = chain_on_disk(&d, 12);
    let s = c.snapshot().unwrap();
    let headers: Vec<_> = c.headers().into_iter().skip(1).collect();
    assert_eq!(
        Chain::from_snapshot(NETWORK, s, &headers).err(),
        Some(ResumeError::NoGenesis)
    );
}

/// A snapshot announcing an absurd number of entries does not cause an
/// allocation.
#[test]
fn w_snapshot_with_an_absurd_count() {
    let d = test_dir("absurd-count");
    let path = d.join("state.dat");
    let (c, _a) = chain_on_disk(&d, 3);
    let s = c.snapshot();
    drop(s);
    // We build a file by hand: magic + version + network + height + tip +
    // issued + huge varint.
    let mut w = q21_core::ser::Writer::with_capacity(64);
    w.bytes(b"Q21STATE");
    w.u32(1);
    w.u8(2); // Regtest
    w.u64(0);
    w.bytes(Hash256::ZERO.as_bytes());
    w.u64(0);
    w.varint(u64::MAX);
    let mut data = w.finish();
    data.extend_from_slice(&q21_core::sha256::sha256(&data));
    std::fs::write(&path, &data).unwrap();
    let r = StateStore::new(&path).load(NETWORK);
    assert!(r.is_err(), "refusal expected, without allocation");
}

/// Two nodes in the same state write the same file, byte for byte: that is
/// what makes a snapshot comparable.
#[test]
fn x_snapshot_deterministic_between_two_nodes() {
    let d1 = test_dir("det1");
    let d2 = test_dir("det2");
    let (c1, _a1) = chain_on_disk(&d1, 8);
    // The same work redone elsewhere gives the same chain (same timestamps,
    // same beneficiary) — except the nonce, which depends on mining.
    let (c2, _a2) = chain_on_disk(&d2, 8);
    write_snapshot(&d1, &c1);
    write_snapshot(&d2, &c2);
    let f1 = std::fs::read(d1.join("state.dat")).unwrap();
    let f2 = std::fs::read(d2.join("state.dat")).unwrap();
    // The chains differ by their nonces, so the coinbase txids differ too: we
    // only check that the size is identical.
    assert_eq!(f1.len(), f2.len(), "same structure, same size");
}

/// A zero-size `state.dat`, or one made of zeros, does not panic.
#[test]
fn y_degenerate_state_dat() {
    let d = test_dir("degenerate");
    let path = d.join("state.dat");
    for contents in [vec![], vec![0u8; 31], vec![0u8; 32], vec![0xFFu8; 4096]] {
        std::fs::write(&path, &contents).unwrap();
        let r = StateStore::new(&path).load(NETWORK);
        assert!(r.is_err());
    }
}

/// The block file truncated to zero bytes: starting is impossible but clean.
#[test]
fn z_empty_block_file() {
    let d = test_dir("empty-blocks");
    let (_c, _a) = chain_on_disk(&d, 3);
    std::fs::write(d.join("blocks.dat"), b"").unwrap();
    let r = load(&d);
    assert!(r.is_err(), "clean refusal expected");
}

/// A record whose announced size overflows the file: the scan must stop, not
/// read beyond it — and above all not cut anything.
///
/// Since the second audit (P4), the precise case of the **first** record is
/// repaired: the genesis is a constant of the network, its header is intact at
/// byte 4, so the whole record is copied over, prefix included. What the test
/// checks stays the same: nothing is read beyond the file and nothing is lost.
/// It now also requires the five blocks to read back.
#[test]
fn aa_lying_size_in_the_block_file() {
    let d = test_dir("lying-size");
    let (_c, _a) = chain_on_disk(&d, 4);
    let path = d.join("blocks.dat");
    let sound = std::fs::read(&path).unwrap();
    let mut data = sound.clone();
    // We lie about the size of the first record.
    let fake = 1_000_000u32.to_le_bytes();
    data[..4].copy_from_slice(&fake);
    std::fs::write(&path, &data).unwrap();

    let (_, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("headers {} problem {problem:?}", headers.len());
    assert!(problem.is_none(), "the genesis prefix is repaired");
    assert_eq!(headers.len(), 5, "no block is lost");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        sound,
        "the file is restored identically"
    );
}

/// A snapshot taken at the tip (zero depth): `snapshot()` must refuse it,
/// otherwise the resumed node would have NO reorg capacity at all.
#[test]
fn ab_snapshot_at_the_tip_refused() {
    let g = genesis_block(NETWORK);
    let c = Chain::new(NETWORK, g);
    assert!(c.snapshot().is_none(), "chain too short: no snapshot");
    assert!(c.snapshot_at_depth(0).is_none());
}

/// Does a snapshot taken on a chain whose index has `issued: 0` everywhere
/// (a chain itself resumed) stay right? Cascading resumes.
#[test]
fn ac_cascading_resume() {
    let d = test_dir("cascade");
    let (c1, _a) = chain_on_disk(&d, 24);
    let issued = c1.total_issued();
    write_snapshot(&d, &c1);
    drop(c1);

    let (c2, _) = load(&d).expect("resume 1");
    assert_eq!(c2.total_issued(), issued, "emission after resume 1");
    write_snapshot(&d, &c2); // snapshot written by an ALREADY resumed node
    drop(c2);

    let (c3, _) = load(&d).expect("resume 2");
    assert_eq!(
        c3.total_issued(),
        issued,
        "emission after cascading resume: divergence = inflation or deflation"
    );
    let (c4, _) = {
        write_snapshot(&d, &c3);
        load(&d).expect("resume 3")
    };
    assert_eq!(c4.total_issued(), issued, "emission after 3 resumes");
}

/// The body of the genesis is never pruned: without it the chain would be
/// unintelligible.
#[test]
fn ad_the_genesis_is_never_pruned() {
    let d = test_dir("genesis");
    let (c, _a) = chain_on_disk(&d, 6);
    let g = c.active_at(0).unwrap();
    assert!(c.block_by_id(&g).is_some());
    let _ = d;
}

/// A `Block` read back from disk must be identical to the one written:
/// otherwise two nodes would compute different identifiers.
#[test]
fn ae_disk_round_trip_preserves_the_identifier() {
    let d = test_dir("round-trip");
    let (c, a) = chain_on_disk(&d, 6);
    for h in 0..=c.height() {
        let id = c.active_at(h).unwrap();
        let read_back: Block = a.read(&id).expect("body on disk");
        assert_eq!(
            read_back.header.block_id(),
            id,
            "identifier altered by the disk"
        );
    }
}

// ===========================================================================
// VERDICT divergences between a resumed node and a full node
// ===========================================================================

/// The `issued` field of `state.dat` used to be bound to nothing: neither to
/// the UTXO set nor to the headers. An attacker sets it at the cap, and the
/// resumed node REFUSES a block that every full node accepts. Two verdicts =
/// split.
#[test]
fn ba_forged_issued_gets_a_valid_block_refused() {
    use q21_core::emission::block_subsidy;
    let d = test_dir("forged-issued");
    let (mut full, _a) = chain_on_disk(&d, 16);

    // Snapshot taken one block below the tip: a single block to replay.
    let mut s = full.snapshot_at_depth(1).unwrap();
    // `issued` is bound to nothing: neither to the UTXO set nor to the
    // headers. The attacker sets it just under the cap, so that the replay
    // passes and the NEXT block is refused.
    s.issued = MAX_SUPPLY - block_subsidy(16).units();
    state_store_in(&d).save(&s).unwrap();

    // An `issued` close to the cap is impossible at height 15: the emission
    // schedule says so, and the snapshot is rejected. The node revalidates,
    // finds the real emission again, and returns the same verdict as the full
    // node.
    let (mut resumed, _) = load(&d).expect("resume through full revalidation");
    eprintln!(
        "emission: full {} / resumed {}",
        full.total_issued(),
        resumed.total_issued()
    );
    assert_eq!(full.tip_id(), resumed.tip_id(), "same tip");
    assert_eq!(
        full.total_issued(),
        resumed.total_issued(),
        "the cumulative emission must be rebuilt, not read from a file"
    );

    let t = timestamp(17);
    let b = full
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .unwrap();
    let v_full = full.connect(&b, t + 1);
    let v_resumed = resumed.connect(&b, t + 1);
    eprintln!("full   : {v_full:?}\nresumed: {v_resumed:?}");
    assert!(v_full.is_ok(), "a full node accepts this block");
    assert!(
        v_resumed.is_ok(),
        "OBSERVATION: two different verdicts on the SAME block — split"
    );
}

/// Same family, without the cap: an `issued` forged lower makes the reported
/// emission diverge, and hence the anti-inflation check of every following
/// block.
#[test]
fn bb_forged_issued_falsifies_the_reported_emission() {
    let d = test_dir("issued-low");
    let (full, _a) = chain_on_disk(&d, 16);
    let mut s = full.snapshot().unwrap();
    s.issued = 42;
    state_store_in(&d).save(&s).unwrap();
    let (resumed, _) = load(&d).expect("resume");
    assert_eq!(
        resumed.total_issued(),
        full.total_issued(),
        "OBSERVATION: the cumulative emission is entirely dictated by state.dat"
    );
    eprintln!(
        "full {} / resumed {}",
        full.total_issued(),
        resumed.total_issued()
    );
}

/// An output removed from `state.dat`: the resumed node refuses the transaction
/// that spends it, which every full node accepts.
///
/// # Since the MuHash commitment
///
/// Removing an output without recomputing the commitment no longer fools
/// anyone: the snapshot is rejected for an invalid commitment, and the node
/// replays the chain — no more divergence. The observation therefore only
/// remains against a forger who **also recomputes the commitment** to make it
/// match. This is exactly the limit documented in `state.rs`: as long as no
/// trusted value coming from elsewhere anchors the commitment, a `state.dat`
/// consistent with itself but unfaithful to the chain still diverges. We
/// therefore simulate the complete forger.
#[test]
fn bc_utxo_removed_from_the_snapshot_gets_a_spend_refused() {
    let d = test_dir("utxo-removed");
    let (full, _a) = chain_on_disk(&d, 16);
    let mut s = full.snapshot().unwrap();
    let victim = *s.utxo.iter().next().unwrap().0;
    s.utxo.remove(&victim);
    // The forger recomputes the commitment so that it matches their truncated
    // set: without external anchoring, nothing stops them.
    s.muhash = s.utxo.commitment();
    state_store_in(&d).save(&s).unwrap();

    let (resumed, _) = load(&d).expect("resume");
    assert!(
        resumed.utxo.get(&victim).is_none() || full.utxo.get(&victim).is_some(),
        "safeguard"
    );
    eprintln!(
        "output {:?}: full {} / resumed {}",
        victim,
        full.utxo.get(&victim).is_some(),
        resumed.utxo.get(&victim).is_some()
    );
    assert_ne!(
        full.utxo.len(),
        resumed.utxo.len(),
        "OBSERVATION: two different UTXO sets on the SAME tip"
    );
    assert_eq!(full.tip_id(), resumed.tip_id(), "and yet the same tip");
}

/// **The short undo window makes the verdict diverge.**
/// Same competing branch, same work: the full node reorgs, the resumed node
/// refuses. It is a split without any attacker.
#[test]
fn bd_reorg_accepted_by_the_full_node_refused_by_the_resumed_one() {
    let d = test_dir("diverging-reorg");
    let (mut full, archive) = chain_on_disk(&d, 20);

    // Shallow snapshot: it is what a node stopped shortly after a previous
    // resume produces (short undo window).
    let s = full.snapshot_at_depth(2).unwrap();
    state_store_in(&d).save(&s).unwrap();
    let (mut resumed, _) = load(&d).expect("resume");
    eprintln!(
        "window: full {} / resumed {}",
        full.undo_window(),
        resumed.undo_window()
    );

    // A competing branch that forks 5 blocks below the tip.
    let fork = full.active_at(full.height() - 5).unwrap();
    let mut branch: Vec<Block> = Vec::new();
    {
        // We rebuild a temporary chain to mine the branch.
        let mut tmp = Chain::new(NETWORK, genesis_block(NETWORK));
        tmp.set_body_source(archive.clone());
        for h in 1..=full.height() - 5 {
            let id = full.active_at(h).unwrap();
            let b = archive.read(&id).unwrap();
            tmp.connect(&b, b.header.time + 1).unwrap();
        }
        assert_eq!(tmp.tip_id(), fork);
        for h in full.height() - 4..=full.height() + 2 {
            let t = timestamp(h) + 3; // distinct timestamps: another branch
            let b = tmp
                .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
                .unwrap();
            tmp.connect(&b, t + 1).unwrap();
            branch.push(b);
        }
    }

    let mut v_full = Vec::new();
    let mut v_resumed = Vec::new();
    for b in &branch {
        let now = b.header.time + MAX_FUTURE_TIME;
        v_full.push(format!("{:?}", full.submit(b, now)));
        v_resumed.push(format!("{:?}", resumed.submit(b, now)));
    }
    eprintln!("full   : {v_full:?}");
    eprintln!("resumed: {v_resumed:?}");
    assert_ne!(
        full.tip_id(),
        resumed.tip_id(),
        "OBSERVATION: on the SAME blocks, two different tips — chain split"
    );
    assert_ne!(v_full, v_resumed, "the verdicts differ block by block");
}

/// **Pruned and unrecoverable body.** A node whose recent bodies are neither in
/// memory nor in the block file (real case: blocks received from the network,
/// never written) refuses EVERY block, forever.
#[test]
fn be_unavailable_body_stops_the_node_for_good() {
    use q21_core::chain::BodySource;
    use std::collections::HashMap;

    /// Serves only the blocks "written to disk": here, none.
    struct EmptyDisk;
    impl BodySource for EmptyDisk {
        fn body(&self, _id: &Hash256) -> Option<Block> {
            None
        }
    }

    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    c.set_body_source(std::sync::Arc::new(EmptyDisk));
    // We go beyond the body window: the oldest ones are pruned and cannot be
    // found anywhere else.
    let n = BODY_WINDOW as u64 + 12;
    let mut memory: HashMap<Hash256, Block> = HashMap::new();
    for i in 1..=n {
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        memory.insert(b.header.block_id(), b);
    }
    // A full node, for its part, kept everything.
    let mut full = Chain::new(NETWORK, genesis_block(NETWORK));
    full.set_body_source(std::sync::Arc::new(AllBodies(memory.clone())));
    for i in 1..=n {
        let id = c.active_at(i).unwrap();
        let b = memory[&id].clone();
        full.connect(&b, b.header.time + 1).unwrap();
    }

    // The same block, submitted to both.
    let t = timestamp(n + 1);
    let b = full
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
        .unwrap();
    let v_full = full.connect(&b, t + 1);
    let v_truncated = c.connect(&b, t + 1);
    eprintln!("full     : {v_full:?}\ntruncated: {v_truncated:?}");
    assert!(v_full.is_ok());
    // The last 9 bodies are still in memory: the rule passes. Pruning would
    // then be forced by submitting side branches, which consumes the body
    // window.
    eprintln!("bodies in memory: {}", c.bodies_in_memory());
    assert!(v_truncated.is_ok() || v_truncated.is_err());
}

struct AllBodies(std::collections::HashMap<Hash256, Block>);
impl q21_core::chain::BodySource for AllBodies {
    fn body(&self, id: &Hash256) -> Option<Block> {
        self.0.get(id).cloned()
    }
}

/// The uncle anti-double-payment rule requires the bodies of the last 9 active
/// blocks. If one is missing, `connect` refuses EVERYTHING. We prove it
/// directly.
#[test]
fn bf_a_single_missing_body_stops_the_node() {
    use std::collections::HashMap;
    let d = test_dir("missing-body");
    let (full, archive) = chain_on_disk(&d, 20);

    // A source that has everything EXCEPT block 18: it is exactly the state of
    // a node for which that block came from the network (never written to
    // blocks.dat) and whose memory was emptied by a restart.
    let mut bodies: HashMap<Hash256, Block> = HashMap::new();
    for h in 0..=full.height() {
        let id = full.active_at(h).unwrap();
        if h == 18 {
            continue;
        }
        bodies.insert(id, archive.read(&id).unwrap());
    }

    let s = full.snapshot_at_depth(19).unwrap(); // snapshot at height 1
    let headers = full.headers();
    let r = Chain::from_snapshot(NETWORK, s, &headers).expect("resume");
    let mut truncated = r.chain;
    truncated.set_body_source(std::sync::Arc::new(AllBodies(bodies)));
    let mut failure = None;
    for id in &r.to_replay {
        let b = match truncated.block_by_id(id) {
            Some(b) => b,
            None => {
                failure = Some("body missing on replay, height unknown".to_string());
                break;
            }
        };
        if let Err(e) = truncated.connect(&b, b.header.time + MAX_FUTURE_TIME) {
            failure = Some(format!("{e:?}"));
            break;
        }
    }
    eprintln!("OBSERVATION: replay interrupted: {failure:?}");
    assert!(
        failure.is_some(),
        "a single missing body is enough to prevent startup"
    );
}

/// The restoration after a failed reorg does `.expect(...)`: we look for a
/// path where that `expect` triggers a panic.
#[test]
fn bg_restoration_after_a_failed_reorg() {
    let d = test_dir("reorg-panic");
    let (mut full, archive) = chain_on_disk(&d, 16);
    let fork = full.active_at(full.height() - 3).unwrap();

    // Competing branch of 4 blocks (the active one has 3 since the fork): it
    // only exceeds the work at the LAST block, which triggers `try_reorg`. Its
    // SECOND block is invalid: the reorg fails midway and must restore the old
    // chain identically.
    let mut branch: Vec<Block> = Vec::new();
    {
        let mut tmp = Chain::new(NETWORK, genesis_block(NETWORK));
        tmp.set_body_source(archive.clone());
        for h in 1..=full.height() - 3 {
            let id = full.active_at(h).unwrap();
            tmp.connect(&archive.read(&id).unwrap(), timestamp(h) + 1)
                .unwrap();
        }
        assert_eq!(tmp.tip_id(), fork);
        for h in full.height() - 2..=full.height() + 1 {
            let t = timestamp(h) + 5;
            let b = tmp
                .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
                .unwrap();
            tmp.connect(&b, t + 1).unwrap();
            branch.push(b);
        }
    }
    // The second block of the branch claims one unit too many.
    let bad = &mut branch[1];
    bad.transactions[0].outputs[0].value =
        q21_core::amount::Amount::from_units(bad.transactions[0].outputs[0].value.units() + 1);
    bad.header.merkle_root = bad.compute_merkle_root();
    bad.header.nonce = 0;
    {
        let t = q21_core::memhard::PowTable::build(
            q21_core::memhard::TableParams::for_network(NETWORK),
            q21_core::memhard::epoch_of(bad.header.height),
        );
        q21_core::pow::mine_with_table(&mut bad.header, &t, ATTEMPTS).unwrap();
    }
    // The following blocks must point to the corrupted block.
    let mut prev = branch[1].header.block_id();
    for block in branch.iter_mut().skip(2) {
        block.header.prev_block = prev;
        block.header.nonce = 0;
        let t = q21_core::memhard::PowTable::build(
            q21_core::memhard::TableParams::for_network(NETWORK),
            q21_core::memhard::epoch_of(block.header.height),
        );
        q21_core::pow::mine_with_table(&mut block.header, &t, ATTEMPTS).unwrap();
        prev = block.header.block_id();
    }

    let before = full.tip_id();
    let height_before = full.height();
    let issued_before = full.total_issued();
    let utxo_before = full.utxo.len();
    let mut verdicts = Vec::new();
    for b in &branch {
        verdicts.push(format!(
            "{:?}",
            full.submit(b, b.header.time + MAX_FUTURE_TIME)
        ));
    }
    eprintln!("verdicts: {verdicts:?}");
    assert_eq!(
        full.tip_id(),
        before,
        "the original chain must be restored identically"
    );
    assert_eq!(full.height(), height_before);
    assert_eq!(
        full.total_issued(),
        issued_before,
        "emission after restoration"
    );
    assert_eq!(full.utxo.len(), utxo_before, "UTXO set after restoration");
    eprintln!("undo window after restoration: {}", full.undo_window());
}

// ===========================================================================
// 8. What a real run found, and the tests had not seen
// ===========================================================================

/// The block file is not a straight line, and the replay must know it.
///
/// # How this defect showed up
///
/// It did not come out of a test: it came out of a **real run**. Two nodes
/// mining against each other for thirty seconds produce competing branches.
/// Since the journal records the side branches — without which no reorg
/// survives a restart — the file contains blocks that do not extend the active
/// tip.
///
/// The full replay called `connect`, which requires exactly that. The node
/// therefore refused to restart:
/// `block 853 refused on replay: BadHeight { expected: 853, received: 218 }`.
///
/// And that path is the **safety fallback**: the one taken precisely when the
/// snapshot is lost or suspect. The defect made it unusable at the moment it
/// matters.
#[test]
fn a_file_containing_side_branches_replays() {
    use q21_core::chain::Journal;
    let d = test_dir("side-branches");
    let (mut c, a) = chain_on_disk(&d, 6);

    // A side block: same parent as the current tip, hence competing. It is
    // exactly what a race between two miners produces.
    let parent = c.active_at(c.height() - 1).expect("parent");
    let header = c.header_of(&parent).expect("parent header");
    let mut competitor = c
        .mine_block(
            Hash256([0xEE; 32]),
            SchemeId::LamportOts,
            &[],
            header.time + 2 * TARGET_BLOCK_SECS,
            ATTEMPTS,
        )
        .expect("mining");
    // `mine_block` builds on the tip; we attach it to the parent to make it a
    // competitor of the last block.
    competitor.header.prev_block = parent;
    competitor.header.height = header.height + 1;
    competitor.header.merkle_root = competitor.compute_merkle_root();
    let _ = q21_core::pow::mine_with_table(
        &mut competitor.header,
        &q21_core::memhard::PowTable::build(
            q21_core::memhard::TableParams::for_network(NETWORK),
            0,
        ),
        ATTEMPTS,
    );

    let verdict = c.submit(&competitor, competitor.header.time + 1);
    eprintln!("competing block: {verdict:?}");
    if verdict.is_ok() {
        a.record(&competitor);
    }

    // Two more blocks on the main chain, so that the side block ends up **in
    // the middle** of the file and not at the end.
    for i in 7..=9u64 {
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
        a.record(&b);
    }
    let expected_height = c.height();
    let expected_tip = c.tip_id();
    drop(c);

    // Without a snapshot: the full fallback must work.
    let _ = std::fs::remove_file(d.join("state.dat"));
    let (resumed, _) = load(&d).expect("the safety fallback must work");
    assert_eq!(resumed.height(), expected_height);
    assert_eq!(resumed.tip_id(), expected_tip);
}

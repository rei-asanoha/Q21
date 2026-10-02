//! ATTACK (red team 8b, 2nd campaign, item 5) — a forged body on disk.
//!
//! The block file was only read back by decoding it: bytes that form a block
//! were returned as **the** requested block, without the body having been
//! checked against its header. Two paths led there:
//!
//! - adopting a snapshot **from a folder** copied `bodies.dat` as is, whereas
//!   the network path checked each body before writing a single byte;
//! - reading back through the archive (`BlockArchive::read`) returned any
//!   decodable body, wrong Merkle root or made-up uncle list included.
//!
//! A folder supplied by a third party could therefore freeze a node on a fake
//! branch until it was erased. Now: a body read back must carry the requested
//! identifier AND a correct shape, otherwise it counts as "missing"; and the
//! folder path checks the bodies as the network path does.

use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::fast_sync::SyncSnapshot;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::store::{BlockArchive, BlockStore, HeaderStore};
use q21_core::Network;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn q21() -> &'static str {
    env!("CARGO_BIN_EXE_q21")
}

fn test_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-attack-body-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn mined_chain(dir: &Path, n: u64) -> (Chain, Arc<BlockArchive>) {
    let path = dir.join("blocks.dat");
    let g = genesis_block(NETWORK);
    BlockStore::new(&path).append(&g).unwrap();
    let (archive, _, _) = BlockArchive::open(&path, NETWORK).unwrap();
    let archive = Arc::new(archive);

    let mut c = Chain::new(NETWORK, g);
    c.set_body_source(archive.clone());
    for i in 1..=n {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
        archive.append(&b).unwrap();
    }
    (c, archive)
}

/// A made-up uncle: an arbitrary header, never mined.
fn made_up_uncle(parent: &BlockHeader) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: parent.prev_block,
        merkle_root: Hash256([0x42; 32]),
        uncles_root: Hash256::ZERO,
        miner: Hash256([0x66; 32]),
        time: parent.time,
        bits: parent.bits,
        height: parent.height,
        nonce: 0xdead_beef,
    }
}

/// The archive no longer returns a body whose shape does not match its header:
/// it counts as "missing", and will be requested again from the network.
#[test]
fn the_archive_refuses_a_body_whose_shape_does_not_match_the_header() {
    let dir = test_dir("archive");
    let (chain, _archive) = mined_chain(&dir, 5);

    // The attacker's file: the same blocks, except the 3rd, whose body carries
    // an uncle that the (unchanged) header does not commit to.
    let path = dir.join("forged.dat");
    let bs = BlockStore::new(&path);
    let mut forged_id = None;
    for h in 0..=5u64 {
        let mut b = chain.block_at(h).expect("body");
        if h == 3 {
            b.uncles.push(made_up_uncle(&b.header));
            forged_id = Some(b.header.block_id());
            assert!(
                b.check_shape().is_err(),
                "the forged body must contradict its header"
            );
        }
        bs.append(&b).unwrap();
    }
    let forged_id = forged_id.unwrap();

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).expect("open");
    assert!(
        problem.is_none(),
        "the forged file scans without incident: {problem:?}"
    );
    assert_eq!(headers.len(), 6, "the six headers are indexed");

    // The honest bodies read back; the forged body counts as "missing".
    for h in [0u64, 1, 2, 4, 5] {
        let id = chain.block_at(h).unwrap().header.block_id();
        assert!(
            archive.read(&id).is_some(),
            "honest body {h} must read back"
        );
    }
    assert!(
        archive.read(&forged_id).is_none(),
        "a body whose shape contradicts its header must never be returned"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Writes a sync snapshot folder as `q21 snapshot export-sync` would, with a
/// `bodies.dat` left to the caller's choice.
fn sync_snapshot_folder(
    dir: &Path,
    sync_snapshot: &SyncSnapshot,
    bodies: &[q21_core::block::Block],
) -> PathBuf {
    let d = dir.join("sync-snapshot");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("snapshot.q21snap"), &sync_snapshot.snapshot).unwrap();
    let hs = HeaderStore::new(d.join("headers.q21hdr"));
    hs.append(&sync_snapshot.headers).unwrap();
    let bs = BlockStore::new(d.join("bodies.dat"));
    for b in bodies {
        bs.append(b).unwrap();
    }
    d
}

fn adopt(datadir: &Path, folder: &Path, tip: Hash256, commitment: Hash256) -> std::process::Output {
    Command::new(q21())
        .arg("--datadir")
        .arg(datadir)
        .args(["snapshot", "adopt"])
        .arg(folder)
        .args(["--tip", &tip.to_hex(), "--commitment", &commitment.to_hex()])
        .stdin(Stdio::null())
        .output()
        .expect("starting q21")
}

/// Adoption from a folder checks the bodies as the network path does: a folder
/// with forged bodies is refused before writing a byte, and an honest folder
/// still gets adopted.
#[test]
fn adoption_from_a_folder_refuses_forged_bodies() {
    let dir = test_dir("adopt");
    let (chain, _archive) = mined_chain(&dir, 20);
    // The sync snapshot as `q21 snapshot export-sync` composes it: the snapshot
    // below the tip, all the headers up to it, the genesis then the window of
    // bodies around it.
    let snapshot = chain.snapshot_at_depth(5).expect("snapshot");
    let height = snapshot.height;
    assert!(height >= 10, "the snapshot must be far from the genesis");
    let headers = chain.headers()[..=height as usize].to_vec();
    let mut bodies = vec![chain.block_at(0).unwrap()];
    for hh in (height - 9)..=height {
        bodies.push(chain.block_at(hh).unwrap());
    }
    let sync_snapshot = SyncSnapshot {
        snapshot: snapshot.to_portable_bytes(),
        headers,
        bodies,
    };
    let commitment = sync_snapshot.announced_commitment().expect("commitment");
    let tip = sync_snapshot.headers.last().unwrap().block_id();

    // --- The attack: the real headers, the real snapshot, a forged body.
    let mut forged = sync_snapshot.bodies.clone();
    let target = forged
        .iter_mut()
        .find(|b| b.header.height == height)
        .expect("the body of the tip is in the window");
    target.uncles.push(made_up_uncle(&target.header));
    let folder = sync_snapshot_folder(&dir.join("hostile"), &sync_snapshot, &forged);
    let datadir = dir.join("hostile-node");
    let out = adopt(&datadir, &folder, tip, commitment);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    eprintln!("hostile: status {:?}\n{stdout}{stderr}", out.status.code());
    assert!(
        !out.status.success(),
        "a folder with forged bodies must be refused"
    );
    assert!(
        format!("{stdout}{stderr}").contains("adoption refused"),
        "the refusal must be stated as such"
    );
    assert!(
        !datadir.join("blocks.dat").exists(),
        "nothing must have been written in the node's directory"
    );

    // --- The control: the same folder, with intact bodies, gets adopted.
    let folder = sync_snapshot_folder(&dir.join("honest"), &sync_snapshot, &sync_snapshot.bodies);
    let datadir = dir.join("honest-node");
    let out = adopt(&datadir, &folder, tip, commitment);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    eprintln!("honest: status {:?}\n{stdout}{stderr}", out.status.code());
    assert!(
        out.status.success(),
        "an honest folder must always get adopted"
    );
    assert!(
        datadir.join("blocks.dat").exists(),
        "the honest bodies must have been laid down"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

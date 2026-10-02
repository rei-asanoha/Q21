//! Regressions from the second persistence audit: a flipped bit in a length
//! prefix of the block file no longer costs a valid block, a snapshot, or a
//! revalidation (P1, P4, P6); a pruned or adopted node restarts whatever
//! happens to its headers, and syncs again (P2); a snapshot whose write failed
//! authorizes no pruning (P3).
//!
//! Each test handles `blocks.dat`, `headers.dat` or `state.dat` as a worn-out
//! SD card, a full disk or a hard shutdown would, then replays the startup of
//! the binary — `BlockArchive::open`, then `q21_core::pruning::resume_chain`,
//! the very path of the binary.

use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::net::Node;
use q21_core::sig::SchemeId;
use q21_core::state::StateStore;
use q21_core::store::{BlockArchive, BlockStore, HeaderStore};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn test_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-regr-audit2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn timestamp(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn state_store_in(d: &Path) -> StateStore {
    let key = q21_core::state::datadir_key(d).unwrap();
    StateStore::new_sealed(d.join("state.dat"), key)
}

/// Mines `n` blocks and writes them as the binary does: `connect` then
/// `append`.
fn chain_on_disk(d: &Path, n: u64) -> (Chain, Arc<BlockArchive>) {
    let path = d.join("blocks.dat");
    let g = genesis_block(NETWORK);
    BlockStore::new(&path).append(&g).unwrap();
    let (archive, _, _) = BlockArchive::open(&path, NETWORK).unwrap();
    let archive = Arc::new(archive);
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

/// Positions (start of the length prefix) and lengths of each record, read by
/// following the prefixes as they are.
fn prefixes(path: &Path) -> Vec<(u64, u32)> {
    let raw = std::fs::read(path).unwrap();
    let mut v = Vec::new();
    let mut p = 0usize;
    while p + 4 <= raw.len() {
        let t = u32::from_le_bytes(raw[p..p + 4].try_into().unwrap());
        v.push((p as u64, t));
        p += 4 + t as usize;
    }
    v
}

fn flip_bit(path: &Path, position: u64, mask: u8) {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    f.seek(SeekFrom::Start(position)).unwrap();
    let mut o = [0u8; 1];
    f.read_exact(&mut o).unwrap();
    f.seek(SeekFrom::Start(position)).unwrap();
    f.write_all(&[o[0] ^ mask]).unwrap();
}

/// Every block of the chain reads back from the archive.
fn everything_reads_back(c: &Chain, archive: &BlockArchive, up_to: u64) {
    for h in 0..=up_to {
        let id = c.active_at(h).unwrap();
        assert!(
            archive.read(&id).is_some(),
            "block {h} no longer reads back"
        );
    }
}

// ===========================================================================
// P1 — a bit in a length prefix near the end.
// ===========================================================================

/// The defect: the tail repair cut up to `MAX_BLOCK_SIZE + 4` bytes after the
/// last complete record — eleven valid blocks here, thousands on a real chain —
/// and the snapshot, taken below the tip, no longer designated anything.
/// Expected now: the prefix is rewritten, the 61 headers are there, nothing is
/// cut, the snapshot holds.
#[test]
fn a_bit_in_a_prefix_near_the_end_cuts_no_block() {
    let d = test_dir("p1-prefix-end");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 60);
    let snap = c.snapshot_at_depth(5).unwrap();
    assert_eq!(snap.height, 55);
    state_store_in(&d).save(&snap).unwrap();
    drop(archive);
    let sound_size = std::fs::metadata(&path).unwrap().len();

    let records = prefixes(&path);
    assert_eq!(records.len(), 61);
    // Bit 20 (+1 MiB) in the prefix of block 50: the length points beyond the
    // end of the file, like an interrupted write.
    let (pos50, _) = records[50];
    flip_bit(&path, pos50 + 2, 0x10);

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("headers: {}, problem: {:?}", headers.len(), problem);
    assert_eq!(headers.len(), 61, "no valid block must be lost");
    assert!(
        problem.is_none(),
        "the prefix repaired, nothing left to report"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        sound_size,
        "nothing was cut"
    );
    assert!(
        !d.join("blocks.dat.cut").exists(),
        "nothing was thrown away, so no copy"
    );
    assert_eq!(prefixes(&path), records, "the prefix got its value back");
    everything_reads_back(&c, &archive, 60);

    // The snapshot (height 55) is still on the visible chain.
    let r = Chain::from_snapshot(NETWORK, snap, &headers).expect("resume from snapshot");
    assert_eq!(r.to_replay.len(), 5, "only 56..=60 remain to replay");
    drop(archive);

    // A second opening finds nothing left to repair.
    let (_a, headers2, problem2) = BlockArchive::open(&path, NETWORK).unwrap();
    assert_eq!(headers2.len(), 61);
    assert!(problem2.is_none());
    let _ = std::fs::remove_dir_all(&d);
}

/// A prefix that is too **short** on the last record: the scan accepts the
/// block with a wrong length, then reads anything. Same remedy: the actual
/// length is found by decoding the block.
#[test]
fn a_too_short_prefix_on_the_last_block_is_rewritten() {
    let d = test_dir("p1-prefix-short");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 30);
    drop(archive);
    let records = prefixes(&path);
    let (pos30, _) = records[30];
    // Bit 3 (-8): the announced length is shorter than the block.
    flip_bit(&path, pos30, 0x08);

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("headers: {}, problem: {:?}", headers.len(), problem);
    assert_eq!(headers.len(), 31);
    assert!(problem.is_none());
    assert_eq!(prefixes(&path), records);
    everything_reads_back(&c, &archive, 30);
    let _ = std::fs::remove_dir_all(&d);
}

/// A truly interrupted write — the file stops in the middle of the last block —
/// is still repaired as before: the fragment is cut, a copy kept, the complete
/// blocks remain.
#[test]
fn a_truly_interrupted_write_is_still_cut() {
    let d = test_dir("p1-interrupted");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 60);
    drop(archive);
    let records = prefixes(&path);
    let (pos60, len60) = records[60];
    let end_59 = pos60;
    // The file stops halfway through block 60.
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(pos60 + 4 + u64::from(len60) / 2).unwrap();
    drop(f);

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("headers: {}, problem: {:?}", headers.len(), problem);
    assert_eq!(headers.len(), 60, "0..=59 remain");
    assert!(problem.is_none(), "the tail cut, nothing left to report");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), end_59);
    assert!(
        d.join("blocks.dat.cut").exists(),
        "the fragment is kept alongside"
    );
    everything_reads_back(&c, &archive, 59);
    let _ = std::fs::remove_dir_all(&d);
}

/// Both at once: a damaged prefix at block 50 **and** an interrupted write at
/// block 60. The prefix is rewritten, only the final fragment is cut.
#[test]
fn a_damaged_prefix_then_an_interrupted_write_are_both_repaired() {
    let d = test_dir("p1-both");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 60);
    drop(archive);
    let records = prefixes(&path);
    let (pos60, len60) = records[60];
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(pos60 + 4 + u64::from(len60) / 2).unwrap();
    drop(f);
    let (pos50, _) = records[50];
    flip_bit(&path, pos50 + 2, 0x10);

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("headers: {}, problem: {:?}", headers.len(), problem);
    assert_eq!(headers.len(), 60);
    assert!(problem.is_none());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), pos60);
    everything_reads_back(&c, &archive, 59);
    let _ = std::fs::remove_dir_all(&d);
}

/// On a pruned file, the first block of the window no longer has its parent in
/// the file. Its damaged prefix must still be repaired: it is the successor
/// that vouches for it.
#[test]
fn a_damaged_prefix_on_the_first_block_of_a_pruned_window_is_rewritten() {
    let d = test_dir("p1-pruned");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 40);
    let summary = archive.prune(|h| h.height == 0 || h.height >= 30).unwrap();
    assert_eq!(summary.kept, 12);
    drop(archive);
    let records = prefixes(&path);
    assert_eq!(records.len(), 12);
    // Record 1 is block 30, whose parent (29) was removed.
    let (pos1, _) = records[1];
    flip_bit(&path, pos1 + 2, 0x10);

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("headers: {}, problem: {:?}", headers.len(), problem);
    assert_eq!(headers.len(), 12);
    assert!(problem.is_none());
    for h in 30..=40 {
        assert!(archive.read(&c.active_at(h).unwrap()).is_some());
    }
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P6 — a bit in a prefix IN THE MIDDLE of the file, below the snapshot.
// ===========================================================================

/// Before: the scan stopped at the damaged block, the snapshot was no longer on
/// the visible chain (full revalidation), then the unreadable body got the file
/// cut at 0..=19 and everything downloaded again. Now: the prefix is rewritten
/// on opening, the snapshot holds, nothing needs redoing.
#[test]
fn a_bit_in_a_prefix_in_the_middle_costs_neither_revalidation_nor_cut() {
    let d = test_dir("p6-middle");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 40);
    let snap = c.snapshot_at_depth(5).unwrap();
    assert_eq!(snap.height, 35);
    state_store_in(&d).save(&snap).unwrap();
    drop(archive);
    let sound_size = std::fs::metadata(&path).unwrap().len();
    let records = prefixes(&path);
    let (pos20, _) = records[20];
    flip_bit(&path, pos20, 0x08);

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("headers: {}, problem: {:?}", headers.len(), problem);
    assert_eq!(headers.len(), 41);
    assert!(problem.is_none());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), sound_size);
    everything_reads_back(&c, &archive, 40);
    let r = Chain::from_snapshot(NETWORK, snap, &headers).expect("resume from snapshot");
    assert_eq!(r.to_replay.len(), 5);
    let _ = std::fs::remove_dir_all(&d);
}

/// A bit in the **body** of a block in the middle of the file (not in the
/// prefix, not in the header): nothing can repair it without the network. The
/// scan sees nothing, reading the body fails, the binary cuts the archive at
/// that height and the network supplies it again; what is written afterwards
/// reads back. A cost — revalidation and downloading again — never a loss. The
/// archive tells the operator, once, naming the cause.
#[test]
fn a_bit_in_a_body_in_the_middle_costs_a_cut_but_nothing_is_lost() {
    let d = test_dir("p6-body");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 40);
    drop(archive);
    let records = prefixes(&path);
    let (pos20, len20) = records[20];
    // A bit in the length of the coinbase of block 20 (right after the
    // transaction count): the body no longer decodes. A bit in a value field
    // would decode and only fail at validation (Merkle root) — same outcome in
    // the binary, through another path.
    flip_bit(&path, pos20 + 4 + BlockHeader::SIZE as u64 + 1, 0x40);
    assert!(len20 > BlockHeader::SIZE as u32 + 2);

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    assert_eq!(headers.len(), 41, "the headers are intact");
    assert!(problem.is_none(), "the scan sees nothing: that is expected");
    let id20 = c.active_at(20).unwrap();
    assert!(archive.read(&id20).is_none(), "body 20 does not read back");
    assert!(
        archive.read(&id20).is_none(),
        "second read: same answer, without a second message"
    );
    // The binary's path: cut from 20 on, then the network supplies it again.
    let summary = archive.prune(|h| h.height < 20).unwrap();
    assert_eq!(summary.kept, 20);
    for h in 20..=40 {
        archive.append(&c.block_at(h).unwrap()).unwrap();
    }
    drop(archive);
    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    assert_eq!(headers.len(), 41);
    assert!(problem.is_none());
    everything_reads_back(&c, &archive, 40);
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P4 — a bit in the length prefix of the GENESIS.
// ===========================================================================

/// Before: "headers 1, BlockTooLarge" (reduced length) or "headers 0,
/// TruncatedFile" (enlarged length), and the node died advising `q21 init`.
/// Expected: the genesis is copied over, prefix included, and the 30 blocks
/// that follow are read back.
#[test]
fn a_bit_in_the_genesis_prefix_is_repaired() {
    let d = test_dir("p4-genesis-prefix");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 30);
    let snap = c.snapshot_at_depth(5).unwrap();
    state_store_in(&d).save(&snap).unwrap();
    drop(archive);
    let sound = std::fs::read(&path).unwrap();

    for (mask, offset, name) in [
        (0x08u8, 0u64, "bit 3, length -8"),
        (0x10, 2, "bit 20, length +1 MiB"),
        (0x01, 0, "bit 0, length +1"),
        (0xff, 3, "most significant byte flipped"),
    ] {
        std::fs::write(&path, &sound).unwrap();
        flip_bit(&path, offset, mask);
        let (archive, headers, problem) =
            BlockArchive::open(&path, NETWORK).unwrap_or_else(|e| panic!("{name}: {e}"));
        eprintln!("{name}: headers {}, problem {:?}", headers.len(), problem);
        assert_eq!(headers.len(), 31, "{name}");
        assert!(problem.is_none(), "{name}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            sound,
            "{name}: file restored identically"
        );
        everything_reads_back(&c, &archive, 30);
        let r = Chain::from_snapshot(NETWORK, snap.clone(), &headers);
        assert!(r.is_ok(), "{name}: the snapshot must hold");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Prefix **and** header of the genesis damaged: the rest of the file is enough
/// to recognize it.
#[test]
fn genesis_prefix_and_header_damaged_together_are_repaired() {
    let d = test_dir("p4-prefix-and-header");
    let path = d.join("blocks.dat");
    let (c, archive) = chain_on_disk(&d, 10);
    drop(archive);
    let sound = std::fs::read(&path).unwrap();
    flip_bit(&path, 1, 0x04);
    flip_bit(&path, 4 + BlockHeader::SIZE as u64 - 1, 0x01);

    let (archive, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    assert_eq!(headers.len(), 11);
    assert!(problem.is_none());
    assert_eq!(std::fs::read(&path).unwrap(), sound);
    everything_reads_back(&c, &archive, 10);
    let _ = std::fs::remove_dir_all(&d);
}

/// A file that is not ours — foreign first record, no continuation linking to
/// our genesis — is not "repaired": it is refused, as before.
#[test]
fn a_foreign_genesis_is_not_overwritten_by_the_repair() {
    let d = test_dir("p4-foreign");
    let path = d.join("blocks.dat");
    // A chain from another network, written into the file.
    let g = genesis_block(Network::Testnet);
    let s = BlockStore::new(&path);
    s.append(&g).unwrap();
    let mut b = g.clone();
    b.header.height = 1;
    b.header.prev_block = g.header.block_id();
    s.append(&b).unwrap();
    let before = std::fs::read(&path).unwrap();

    let r = BlockArchive::open(&path, NETWORK);
    assert!(
        matches!(r, Err(q21_core::store::StoreError::ForeignGenesis { .. })),
        "expected ForeignGenesis"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing was written");
    let _ = std::fs::remove_dir_all(&d);
}

/// A tail of zeros — what a file system leaves after a power cut — decodes as
/// a "block" (zero header, zero transactions) but is attached to nothing: it is
/// cut, not adopted.
#[test]
fn a_tail_of_zeros_is_not_taken_for_a_block() {
    let d = test_dir("p1-zeros");
    let path = d.join("blocks.dat");
    let (_c, archive) = chain_on_disk(&d, 5);
    drop(archive);
    let sound = std::fs::metadata(&path).unwrap().len();
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        // A plausible prefix (300 bytes), then 1000 zeros: more than the prefix
        // announces, less than a block.
        f.write_all(&300u32.to_le_bytes()).unwrap();
        f.write_all(&vec![0u8; 1000]).unwrap();
    }
    // The prefix says 300, there are 1000 bytes: this is not a truncation. The
    // scan sees a record of 300 zeros then a zero prefix; the first 162 zeros
    // form a decodable "block", but one attached to nothing: the prefix must
    // not be rewritten to 162.
    let before = std::fs::read(&path).unwrap();
    let (_a, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!("zeros: headers {}, problem {:?}", headers.len(), problem);
    assert!(problem.is_some(), "the incident stays reported");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "nothing was rewritten"
    );
    // And a real truncated tail of zeros (a prefix that overflows) is cut.
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(sound).unwrap();
    drop(f);
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&2000u32.to_le_bytes()).unwrap();
        f.write_all(&vec![0u8; 1000]).unwrap();
    }
    let (_a, headers, problem) = BlockArchive::open(&path, NETWORK).unwrap();
    eprintln!(
        "truncated zeros: headers {}, problem {:?}",
        headers.len(),
        problem
    );
    assert_eq!(headers.len(), 6);
    assert!(problem.is_none(), "the tail of zeros was cut");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), sound);
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P2 — a pruned or adopted node had no fallback path.
// ===========================================================================

/// The startup of the binary, after `BlockArchive::open`: the same call.
fn restart(d: &Path) -> Result<(Arc<BlockArchive>, Chain), String> {
    let (archive, headers, problem) =
        BlockArchive::open(d.join("blocks.dat"), NETWORK).map_err(|e| e.to_string())?;
    if let Some(s) = problem {
        eprintln!("warning: {s}");
    }
    let archive = Arc::new(archive);
    let header_store = HeaderStore::new(d.join("headers.dat"));
    let chain = q21_core::pruning::resume_chain(
        NETWORK,
        &archive,
        headers,
        &header_store,
        &state_store_in(d),
    )?;
    Ok((archive, chain))
}

/// A pruned directory: the store covers `0..=store_up_to`, the bodies below
/// `first_body` are removed, the snapshot is at `snapshot_height`.
fn pruned_dir(
    d: &Path,
    n: u64,
    store_up_to: u64,
    first_body: u64,
    snapshot_height: u64,
) -> (Chain, Arc<BlockArchive>) {
    let (c, archive) = chain_on_disk(d, n);
    HeaderStore::new(d.join("headers.dat"))
        .append(&c.headers()[..=store_up_to as usize])
        .unwrap();
    let snap = c.snapshot_at_depth((n - snapshot_height) as usize).unwrap();
    assert_eq!(snap.height, snapshot_height);
    state_store_in(d).save(&snap).unwrap();
    archive
        .prune(|h| h.height == 0 || h.height >= first_body)
        .unwrap();
    (c, archive)
}

/// Waits for a condition to become true, without blocking forever.
fn wait_for(mut cond: impl FnMut() -> bool, seconds: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(seconds) {
        if cond() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    cond()
}

/// The repaired node, plugged into its archive, catches up with a full peer.
///
/// A full node serves chain `c`; the resumed node `chain` logs into `archive`.
/// On return, the resumed node is at the tip of `c`.
fn resyncs_from_a_peer(c: Chain, chain: Chain, archive: Arc<BlockArchive>) {
    let target = c.height();
    let tip = c.tip_id();
    let value = c.utxo.total_value();
    let full = Node::new(NETWORK, c);
    let resumed = Node::new(NETWORK, chain);
    resumed.set_journal(archive);
    let addr = full.listen("127.0.0.1:0").expect("listen");
    resumed.connect(addr).expect("connect");
    assert!(
        wait_for(|| resumed.height() == target, 60),
        "the resumed node stayed at height {} out of {target}",
        resumed.height()
    );
    assert_eq!(resumed.tip_id(), tip, "the tips must match");
    assert_eq!(
        resumed.with_chain(|ch| ch.utxo.total_value()),
        value,
        "the UTXO sets must match"
    );
    full.shutdown();
    resumed.shutdown();
}

/// Test D. Before: a bit in the `time` field of header 15 of `headers.dat` made
/// the store unreadable (`HeadersBrokenLink`), the binary refused to start and
/// advised starting again "in an empty directory" — the one that contains the
/// wallet. Expected: the store is truncated at the last sound position, the
/// node starts at a height at most equal to the sound height, and a full peer
/// brings it back to the tip.
#[test]
fn d_a_bit_in_headers_dat_no_longer_dooms_a_pruned_directory() {
    let d = test_dir("p2-d-headers");
    let (c, archive) = pruned_dir(&d, 60, 40, 41, 50);
    drop(archive);
    let headers_path = d.join("headers.dat");
    let size = std::fs::metadata(&headers_path).unwrap().len();
    // A bit in the `time` field of header 15: link 16 no longer links.
    let position = 12 + 15 * BlockHeader::SIZE as u64 + 4 + 32 * 4;
    assert!(position < size);
    flip_bit(&headers_path, position, 0x01);

    let (archive, chain) = restart(&d).expect("the node starts");
    eprintln!("D: height at restart {}", chain.height());
    assert!(chain.height() <= 50, "at most the sound height");
    // The store was truncated at the first broken link: 0..=15 remain, header
    // 15 itself being the one in which a bit changed (it still links to 14; it
    // is 16 that no longer links to it).
    let header_store = HeaderStore::new(&headers_path);
    let read_back = header_store.load(NETWORK).unwrap();
    assert_eq!(read_back.len(), 16);
    assert_eq!(
        std::fs::metadata(&headers_path).unwrap().len(),
        12 + 16 * BlockHeader::SIZE as u64
    );
    assert!(
        archive.read(&c.active_at(0).unwrap()).is_some(),
        "the genesis reads back"
    );

    let tip = c.tip_id();
    resyncs_from_a_peer(c, chain, archive.clone());
    // What was synced again reads back at the next restart.
    drop(archive);
    let (_, chain2) = restart(&d).expect("second startup");
    assert_eq!(chain2.height(), 60);
    assert_eq!(chain2.tip_id(), tip);
    // And the store is completed from the chain — the damaged header 15, which
    // the chain contradicts, is removed and rewritten: the node will prune
    // again.
    let added = q21_core::pruning::complete_header_store(&chain2, &header_store, 50).unwrap();
    assert_eq!(added, 36, "15..=50 rewritten");
    let read_back = header_store.load(NETWORK).unwrap();
    assert_eq!(read_back.len(), 51);
    assert!(read_back
        .iter()
        .all(|h| chain2.active_at(h.height) == Some(h.block_id())));
    let _ = std::fs::remove_dir_all(&d);
}

/// Test H. Before: store `0..=20`, snapshot at 50, a bit in the nonce of the
/// header of block 35 in `blocks.dat` — between the store and the snapshot,
/// the vital window of a pruned node. The scan saw nothing, `from_snapshot`
/// returned `SnapshotOffChain`, the binary refused to start. Expected: the node
/// starts (height at most 50), and the full peer brings it back to 60.
#[test]
fn h_a_bit_in_a_header_below_the_snapshot_no_longer_dooms_a_pruned_node() {
    let d = test_dir("p2-h-header");
    let path = d.join("blocks.dat");
    let (c, archive) = pruned_dir(&d, 60, 20, 21, 50);
    drop(archive);
    // Block 35 is the 15th record of the pruned file (genesis, then 21..). A
    // bit in its nonce: the header decodes, but is no longer itself.
    let records = prefixes(&path);
    let (pos35, _) = records[1 + (35 - 21)];
    flip_bit(&path, pos35 + 4 + BlockHeader::SIZE as u64 - 1, 0x01);

    let (archive, chain) = restart(&d).expect("the node starts");
    eprintln!("H: height at restart {}", chain.height());
    assert!(chain.height() <= 50, "at most the sound height");
    assert!(
        archive.read(&c.active_at(0).unwrap()).is_some(),
        "the genesis reads back"
    );

    resyncs_from_a_peer(c, chain, archive.clone());
    drop(archive);
    let (_, chain2) = restart(&d).expect("second startup");
    assert_eq!(chain2.height(), 60);
    let _ = std::fs::remove_dir_all(&d);
}

/// The window ABOVE the snapshot: a bit in the Merkle root of header 55 of a
/// pruned directory (store `0..=40`, snapshot at 50). The replay stops at the
/// last sound block, the archive is cut there, and the peer supplies 55..=60
/// again — the full node's path, reused as is.
#[test]
fn a_damaged_header_above_the_snapshot_costs_a_cut_and_the_network_resupplies() {
    let d = test_dir("p2-upper-window");
    let path = d.join("blocks.dat");
    let (c, archive) = pruned_dir(&d, 60, 40, 41, 50);
    drop(archive);
    let records = prefixes(&path);
    let (pos55, _) = records[1 + (55 - 41)];
    // Byte 4 (prefix) + 4 (version) + 32 (parent): the Merkle root.
    flip_bit(&path, pos55 + 4 + 4 + 32, 0x01);

    let (archive, chain) = restart(&d).expect("the node starts");
    eprintln!("upper window: height at restart {}", chain.height());
    assert_eq!(
        chain.height(),
        54,
        "the replay stops at the last sound block"
    );
    assert_eq!(chain.tip_id(), c.active_at(54).unwrap());

    let tip = c.tip_id();
    resyncs_from_a_peer(c, chain, archive.clone());
    drop(archive);
    let (_, chain2) = restart(&d).expect("second startup");
    assert_eq!(chain2.height(), 60);
    assert_eq!(chain2.tip_id(), tip);
    let _ = std::fs::remove_dir_all(&d);
}

/// A store that is not one (wrong magic): it is set aside as
/// `headers.dat.damaged`, the node starts on what the block file allows, and
/// the network supplies the rest again.
#[test]
fn an_unusable_header_store_is_set_aside_and_the_node_starts() {
    let d = test_dir("p2-store-magic");
    let (c, archive) = pruned_dir(&d, 60, 40, 41, 50);
    drop(archive);
    flip_bit(&d.join("headers.dat"), 0, 0xff);

    let (archive, chain) = restart(&d).expect("the node starts");
    assert!(chain.height() <= 50);
    assert!(
        d.join("headers.dat.damaged").exists(),
        "the store is set aside"
    );
    assert!(!d.join("headers.dat").exists());
    resyncs_from_a_peer(c, chain, archive.clone());
    drop(archive);
    let (_, chain2) = restart(&d).expect("second startup");
    assert_eq!(chain2.height(), 60);
    let _ = std::fs::remove_dir_all(&d);
}

/// The store is completed at every snapshot, not only at pruning: the vital
/// window (last pruning, snapshot] no longer exists. Here, a pruned directory
/// whose store stops at 20; the snapshot at 50 has just been written; the
/// store is completed up to 50 without rereading the file, and a bit in header
/// 35 of `blocks.dat` no longer costs anything.
#[test]
fn completing_the_store_at_every_snapshot_removes_the_vital_window() {
    let d = test_dir("p2-completion");
    let path = d.join("blocks.dat");
    let (c, archive) = pruned_dir(&d, 60, 20, 21, 50);
    let header_store = HeaderStore::new(d.join("headers.dat"));
    assert_eq!(header_store.count(), Some(21));
    let added = q21_core::pruning::complete_header_store(&c, &header_store, 50).unwrap();
    assert_eq!(added, 30);
    assert_eq!(header_store.count(), Some(51));
    assert_eq!(header_store.last().map(|h| h.height), Some(50));
    // Nothing to do a second time.
    assert_eq!(
        q21_core::pruning::complete_header_store(&c, &header_store, 50).unwrap(),
        0
    );
    drop(archive);

    let records = prefixes(&path);
    let (pos35, _) = records[1 + (35 - 21)];
    flip_bit(&path, pos35 + 4 + BlockHeader::SIZE as u64 - 1, 0x01);
    let (_, chain) = restart(&d).expect("the node starts");
    assert_eq!(
        chain.height(),
        60,
        "the snapshot holds, the replay goes up to the tip"
    );
    assert_eq!(chain.tip_id(), c.tip_id());
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P3 — pruning on the strength of a snapshot that was not written.
// ===========================================================================

/// Test C. Before: snapshot on disk at 100, the write of the one at 115 failing
/// (`state.tmp` is a directory: the rename fails, like a full disk or a file
/// held by an antivirus); pruning received 115 from the caller and removed 109
/// bodies; on restart, 9 bodies to replay were missing and the archive was
/// brought back to the genesis. Expected: pruning reads the height from disk
/// (100), finds it older than the window, refuses and says so, the file is
/// intact; once the write succeeds, it prunes normally and the restart finds
/// the tip again.
#[test]
fn c_an_unwritten_snapshot_authorizes_no_pruning() {
    use q21_core::pruning::{prune, Policy};
    let d = test_dir("p3-c-snapshot");
    let (c, archive) = chain_on_disk(&d, 120);
    let header_store = HeaderStore::new(d.join("headers.dat"));
    let state_store = state_store_in(&d);
    let old = c.snapshot_at_depth(20).unwrap();
    assert_eq!(old.height, 100);
    state_store.save(&old).unwrap();

    std::fs::create_dir_all(d.join("state.tmp")).unwrap();
    let new = c.snapshot_at_depth(5).unwrap();
    assert_eq!(new.height, 115);
    assert!(state_store.save(&new).is_err(), "the snapshot write fails");

    // Fifteen bodies kept: more than what the uncle rule rereads
    // (`MAX_UNCLE_AGE`), less than what separates the old snapshot from the
    // tip.
    let policy = Policy {
        kept_bodies: 15,
        step: 1,
    };
    let mut last_pruned = 0;
    let before = archive.len();
    let r = prune(
        &c,
        &archive,
        &header_store,
        &state_store,
        NETWORK,
        policy,
        &mut last_pruned,
    );
    let message = r.as_ref().err().cloned().unwrap_or_default();
    eprintln!("C, write failing: {message}");
    assert!(
        message.contains("height 100") && message.contains("older than the kept window"),
        "pruning must be refused naming the cause, got {r:?}"
    );
    assert_eq!(archive.len(), before, "no body removed");
    assert!(!header_store.exists(), "nothing was written in the store");
    assert_eq!(last_pruned, 0, "a refusal does not count as a pruning");

    // The write succeeds: pruning resumes its normal course.
    std::fs::remove_dir_all(d.join("state.tmp")).unwrap();
    state_store.save(&new).unwrap();
    let summary = prune(
        &c,
        &archive,
        &header_store,
        &state_store,
        NETWORK,
        policy,
        &mut last_pruned,
    )
    .expect("pruning")
    .expect("there was something to prune");
    eprintln!(
        "C, write succeeded: {} removed, {} kept",
        summary.removed, summary.kept
    );
    assert_eq!(summary.kept, 1 + 16); // genesis + 105..=120
    assert_eq!(
        header_store.load(NETWORK).unwrap().last().map(|h| h.height),
        Some(115)
    );
    drop(archive);

    // Restart: nothing is missing, the tip is found again.
    let (_, chain) = restart(&d).expect("the node restarts");
    assert_eq!(chain.height(), 120, "no regression");
    assert_eq!(chain.tip_id(), c.tip_id());
    let _ = std::fs::remove_dir_all(&d);
}

/// Variant: `state.dat` itself has become a directory — no readable snapshot
/// left on disk. Pruning refuses as well.
#[test]
fn an_unreadable_snapshot_on_disk_authorizes_no_pruning() {
    use q21_core::pruning::{prune, Policy};
    let d = test_dir("p3-unreadable");
    let (c, archive) = chain_on_disk(&d, 120);
    let header_store = HeaderStore::new(d.join("headers.dat"));
    let state_store = state_store_in(&d);
    std::fs::create_dir_all(d.join("state.dat")).unwrap();
    assert!(state_store.save(&c.snapshot_at_depth(5).unwrap()).is_err());
    let policy = Policy {
        kept_bodies: 10,
        step: 1,
    };
    let mut last_pruned = 0;
    let before = archive.len();
    let r = prune(
        &c,
        &archive,
        &header_store,
        &state_store,
        NETWORK,
        policy,
        &mut last_pruned,
    );
    let message = r.as_ref().err().cloned().unwrap_or_default();
    eprintln!("unreadable state.dat: {message}");
    assert!(message.contains("unreadable"), "got {r:?}");
    assert_eq!(archive.len(), before, "no body removed");
    assert!(!header_store.exists());
    let _ = std::fs::remove_dir_all(&d);
}

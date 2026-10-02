//! Pruning of the block file, and restarting a node on what it has.
//!
//! # Why
//!
//! The block file only ever grew. A node that validates for itself — a wallet,
//! a miner on a Raspberry Pi — yet only needs what it can still undo (the reorg
//! window) and what its history displays: everything before that is summed up
//! in the snapshot. An SD card does not hold ten years of bodies; it holds ten
//! years of snapshots.
//!
//! # What makes pruning safe: the order of writes
//!
//! A pruned node is, on restart, in the exact situation of a node that adopted
//! a snapshot: it starts again from the recorded state, rereads its headers
//! from the header store, and replays the bodies after the snapshot. Three
//! things must therefore be true **before** removing a single body:
//!
//! 1. the snapshot is **on disk** — not "has just been written" according to
//!    the caller, but read back from the file by [`prune`] itself;
//! 2. the header store covers the genesis up to the snapshot height — it is
//!    completed here, and if that fails nothing is pruned;
//! 3. the bodies after the snapshot remain — the kept window goes well beyond
//!    the depth of the snapshot, and this is checked here.
//!
//! Rewriting the file does not hold the chain lock any longer than reading the
//! headers; the archive serializes its own reads and writes.
//!
//! # The restart, for every node
//!
//! [`resume_chain`] is the single path through which the binary rebuilds its
//! chain at startup — full, pruned or adopted node. It lives here, in the
//! library, for a simple reason: it is the path that must work on the day the
//! disk lied, and it can only be tested if it can be called from a test. Its
//! rule: **a local corruption costs network traffic, never a refusal to
//! start**, as long as the genesis is readable. What does not read back is
//! removed, what is missing will be requested again.
//!
//! # What a pruned node can no longer do
//!
//! Serve as an explorer (the address index points to bodies it no longer has),
//! and revalidate its history without being supplied the bodies of a full
//! node. It still checks everything it receives; it simply does not keep what
//! it will never read again.

use crate::address::Network;
use crate::block::BlockHeader;
use crate::chain::Chain;
use crate::consensus::{BODY_WINDOW, MAX_FUTURE_TIME};
use crate::state::StateStore;
use crate::store::{BlockArchive, HeaderStore, PruneSummary};
use std::sync::Arc;

/// What a pruned node keeps, and how often it prunes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Bodies kept below the tip.
    pub kept_bodies: u64,
    /// Blocks between two prunings.
    pub step: u64,
}

/// The default policy: the wallet history window plus the reorg window —
/// everything a node may still have to read again or display —, and a rewrite
/// every two thousand blocks (less than three days), enough to keep the file
/// at its cruising size without rewriting it every five minutes.
pub const DEFAULT_POLICY: Policy = Policy {
    kept_bodies: crate::rpc::HISTORY_WINDOW + BODY_WINDOW as u64,
    step: 2_016,
};

/// Completes the header store, from what it already holds up to height
/// `up_to` inclusive, with the headers of the active chain.
///
/// # The defect this closes
///
/// The store was only completed at pruning time, every 2,016 blocks. Between
/// two prunings, the header chain of a pruned node was therefore the store
/// (genesis -> last pruning) **extended by the headers read from the block
/// file**. In that window — up to three thousand blocks — the first 164 bytes
/// of each record were vital: one flipped bit in one of them, and the snapshot
/// was no longer on the chain, with no body to rebuild the state. Called after
/// every snapshot written, this function makes the window disappear: a few
/// 160-byte headers every five minutes, and the store always covers the
/// genesis up to the snapshot.
///
/// It does not reread the file: its size tells how many headers it carries,
/// and its tail is checked against the chain before writing after it (see
/// [`reattach_header_store`]).
///
/// Returns the number of headers added.
pub fn complete_header_store(
    chain: &Chain,
    header_store: &HeaderStore,
    up_to: u64,
) -> Result<usize, String> {
    let already = reattach_header_store(chain, header_store)?;
    append_from_chain(chain, header_store, already, up_to)
}

/// Brings the tail of the store back to what the active chain confirms, and
/// returns the next height to write.
///
/// The store does not check the proof of work on reread: a damaged header that
/// still links to its parent — a bit in its nonce — stays in it, in last
/// position, since the one that followed it no longer links to it and was cut.
/// The in-memory chain, on the other hand, knows which header is the real one
/// at that height. We walk back from the end to the first header the chain
/// confirms, cut what follows, and the caller rewrites the rest from the
/// chain. Without this, a store whose tail was wrong was never completed again,
/// and the node no longer pruned.
///
/// A damaged header is rare: the walk back almost always stops at the first
/// one — a single 160-byte read.
pub fn reattach_header_store(chain: &Chain, header_store: &HeaderStore) -> Result<u64, String> {
    let count = header_store.count().unwrap_or(0);
    let mut n = count;
    while n > 0 {
        let confirmed = header_store
            .header_at(n - 1)
            .is_some_and(|h| h.height + 1 == n && chain.active_at(h.height) == Some(h.block_id()));
        if confirmed {
            break;
        }
        n -= 1;
    }
    if n < count {
        header_store
            .truncate(n)
            .map_err(|e| format!("header store not truncated: {e}"))?;
        eprintln!(
            "  header store repaired: {} header(s) at the tail contradicted by the chain, \
             removed from height {n}; they will be rewritten from the chain",
            count - n
        );
    }
    Ok(n)
}

/// Writes the headers `already..=up_to` of the active chain after the store.
/// The caller has checked that `already` is indeed the next height.
fn append_from_chain(
    chain: &Chain,
    header_store: &HeaderStore,
    already: u64,
    up_to: u64,
) -> Result<usize, String> {
    if already > up_to {
        return Ok(0);
    }
    let mut new_headers: Vec<BlockHeader> = Vec::with_capacity((up_to - already + 1) as usize);
    for h in already..=up_to {
        let id = chain
            .active_at(h)
            .ok_or_else(|| format!("the active chain does not reach height {h}"))?;
        let header = chain
            .header_of(&id)
            .ok_or_else(|| format!("header at height {h} missing from the index"))?;
        new_headers.push(header);
    }
    header_store
        .append(&new_headers)
        .map_err(|e| format!("headers not written: {e}"))?;
    Ok(new_headers.len())
}

/// Prunes if enough blocks have piled up since the last pruning.
///
/// `snapshot` is the snapshot file of the directory: its height is read back
/// **from disk** here, before removing anything. `last_pruned` is the tip
/// height at the last pruning, updated here.
///
/// # The defect this closes
///
/// The snapshot height used to be a parameter, supplied by the caller from the
/// snapshot it had just **tried** to write. When the write failed — full disk,
/// rename refused — the height passed was fictitious, the safeguard compared
/// it with the kept window, and let it through: the bodies between the
/// snapshot actually on disk and the window were removed. On restart, the
/// first body to replay was missing, and the node fell back to the old
/// snapshot. Here, the only height that counts is the one the file announces,
/// seal checked; if it is older than the window, nothing is pruned and we say
/// so.
///
/// Returns `Ok(None)` when there was nothing to do, `Ok(Some(summary))` after a
/// rewrite, and an error — the file then intact — if the snapshot on disk is
/// unreadable, too old or off the chain, or if the header store could not be
/// completed.
pub fn prune(
    chain: &Chain,
    archive: &BlockArchive,
    header_store: &HeaderStore,
    snapshot: &StateStore,
    network: Network,
    policy: Policy,
    last_pruned: &mut u64,
) -> Result<Option<PruneSummary>, String> {
    let tip = chain.height();
    if tip < *last_pruned + policy.step || tip <= policy.kept_bodies {
        return Ok(None);
    }

    // Safeguard 1: the snapshot, as the disk carries it.
    let (snapshot_height, snapshot_tip) = snapshot
        .header_on_disk(network)
        .map_err(|e| format!("the snapshot on disk is unreadable ({e}): not pruning"))?;
    if chain.active_at(snapshot_height) != Some(snapshot_tip) {
        return Err(format!(
            "the snapshot on disk (height {snapshot_height}) does not designate the \
             active chain: not pruning"
        ));
    }
    // Safeguard 3: what follows the snapshot must remain. The default policy
    // guarantees it by far; a test policy, or a snapshot whose write has been
    // failing for hours, could miss it.
    let keep_from = tip.saturating_sub(policy.kept_bodies);
    if snapshot_height < keep_from {
        return Err(format!(
            "the snapshot on disk (height {snapshot_height}) is older than \
             the kept window (from {keep_from}): pruning would lose bodies to \
             replay, not pruning"
        ));
    }
    // Safeguard 2: the header store, from the genesis to the snapshot. Read in
    // full here — it is rare — so that a damaged header is cut and rewritten
    // from the chain, which has them all in memory, rather than discovered at
    // the next startup.
    header_store
        .load(network)
        .map_err(|e| format!("unreadable header store: {e}"))?;
    let already = reattach_header_store(chain, header_store)?;
    append_from_chain(chain, header_store, already, snapshot_height)?;

    // The bodies: the genesis, and everything less than `kept_bodies` from the
    // tip. Anything older is summed up in the snapshot.
    let summary = archive
        .prune(|h| h.height == 0 || h.height >= keep_from)
        .map_err(|e| format!("rewriting the block file: {e}"))?;

    // The "last pruned" height is only advanced HERE, after pruning succeeded.
    // Placed higher, a failure of `load`, `reattach_header_store`,
    // `append_from_chain` or `prune` would have advanced it without any body
    // being removed, delaying the next pruning by a whole step.
    *last_pruned = tip;
    Ok(Some(summary))
}

/// A body that is unreadable or refused on replay: we stop at the last sound
/// block.
///
/// # The defect this closes
///
/// A corruption of a body that was not at the tail of the file — a flipped bit
/// on an SD card — made every startup impossible, with a message that did not
/// say what to do. Nothing was wrong in that refusal: better not to start than
/// to adopt a wrong state. But a node knows exactly what to do with this case:
/// keep what comes before, remove what follows, and request the rest again
/// from the network. That is what is done here — the rewrite goes through the
/// same path as pruning, which is safe, and what is removed was unusable
/// anyway.
/// A block that **this binary** cannot verify is not a wrong block: nothing is
/// cut, we stop and say so.
///
/// Without this guard, a binary built without ML-DSA that reopened a directory
/// carrying an ML-DSA transaction removed every body from that block on —
/// measured: 72,342 bytes brought down to 56,625, "block 208 refused during
/// reconstruction: SchemeUnavailable" — and the node started again truncated,
/// on a chain it could not have followed anyway.
fn refuse_to_cut_if_unable(
    e: &crate::validate::ValidationError,
    height: u64,
) -> Result<(), String> {
    if let Some(scheme) = e.locally_unverifiable_scheme() {
        return Err(format!(
            "block {height} carries {} signatures that this binary cannot verify \
             (built without ML-DSA). Nothing is cut: the block file is intact.\n\n\
             Rebuild it:   cargo build --release   (ML-DSA is included by default)",
            scheme.name()
        ));
    }
    Ok(())
}

pub fn truncate_archive_at(
    archive: &BlockArchive,
    height: u64,
    reason: &str,
) -> Result<(), String> {
    eprintln!(
        "  block file: {reason}.\n               The bodies from height {height} on are removed; the network \n               will supply the rest."
    );
    archive
        .prune(|h| h.height < height)
        .map(|_| ())
        .map_err(|e| format!("cannot cut the block file: {e}"))
}

/// Name under which an unusable header store is set aside.
fn damaged_path(header_store: &HeaderStore) -> std::path::PathBuf {
    let mut name = header_store
        .path()
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".damaged");
    header_store.path().with_file_name(name)
}

/// Rebuilds the chain of a directory from what its disk allows.
///
/// `bare_headers` are the headers that [`BlockArchive::open`] scanned;
/// `header_store` and `state_store` are the header store and the snapshot of
/// the directory, present or not.
///
/// # The three paths, and what ties them together
///
/// 1. **Adopted or pruned directory** (the store exists): the header chain is
///    the store — genesis up to wherever it goes — extended by the headers of
///    the block file beyond it. The store repairs itself on reread (truncation
///    at the first damaged header); if it is unusable, it is set aside as
///    `headers.dat.damaged` and we carry on with the block file alone.
/// 2. **Snapshot**: if it reads back and designates a block of the active
///    chain, we start again from it and replay the bodies that follow. An
///    unreadable or refused body stops the replay at the last sound block, and
///    the file is cut there: the network will supply the rest.
/// 3. **No usable snapshot**: revalidation from the genesis, in height order,
///    as far as the bodies allow. On a directory that does not have the bodies
///    from before the snapshot, this stops at the genesis — this is the
///    **minimal state**: the node starts, and syncs again.
///
/// # The defect this closes
///
/// Path 3 was forbidden to adopted or pruned directories: "nothing to replay,
/// sync again into an empty directory". A single flipped bit — in the store,
/// or in a header of the block file between the last pruning and the snapshot
/// — therefore made the directory permanently unable to start, and the advice
/// given led to erasing a directory that contains the wallet. Now a directory
/// refuses to start only if its genesis is unreadable; everything else costs
/// network traffic, not data.
pub fn resume_chain(
    network: Network,
    archive: &Arc<BlockArchive>,
    mut bare_headers: Vec<BlockHeader>,
    header_store: &HeaderStore,
    state_store: &StateStore,
) -> Result<Chain, String> {
    // --- 1. Adopted directory: the header chain comes from the store, not
    // from the bodies. A node that started from a snapshot does not have the
    // bodies from before it, so their headers cannot be read from the block
    // file.
    let adopted = header_store.exists();
    if adopted {
        let base = match header_store.load(network) {
            Ok(b) if !b.is_empty() => Some(b),
            Ok(_) => {
                eprintln!("warning: empty header store, ignored");
                None
            }
            Err(e) => {
                let aside = damaged_path(header_store);
                let moved = std::fs::rename(header_store.path(), &aside).is_ok();
                eprintln!(
                    "warning: unusable header store ({e}).\n               {} \
                     The chain starts again from what the block file allows; the network \n               \
                     will supply the missing headers again. The wallet is not touched.",
                    if moved {
                        format!("It is set aside in {}.", aside.display())
                    } else {
                        String::new()
                    }
                );
                None
            }
        };
        if let Some(mut base) = base {
            // The headers of the block file are **all** added, not only those
            // beyond the store: the block tree merges duplicates by
            // identifier, and the chain with the most work wins. Taking only
            // the later ones let the last link of the store, if it was damaged
            // but still linked, override the real header that the block file
            // carried at the same height — and the reconstruction cut the
            // archive at that height, after a resync that was nonetheless
            // complete.
            base.extend(bare_headers.iter().copied());
            bare_headers = base;
        }
    }

    // --- 2. Resume from the snapshot, if we have one and it is consistent.
    let resumed = match state_store.load(network) {
        Ok(i) => match Chain::from_snapshot(network, i, &bare_headers) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("warning: unusable snapshot ({e}) — full revalidation");
                None
            }
        },
        Err(e) if state_store.exists() => {
            eprintln!("warning: {e}");
            None
        }
        Err(_) => None,
    };

    if let Some(r) = resumed {
        let mut c = r.chain;
        // The body source is plugged in BEFORE the replay: the uncle double
        // payment rule rereads the bodies from before the snapshot, and
        // validating without them would be validating blind.
        c.set_body_source(archive.clone());
        // Only the window that follows the snapshot is revalidated — this is
        // what rebuilds the undo records, hence the ability to reorg.
        for id in &r.to_replay {
            let Some(b) = archive.read(id) else {
                truncate_archive_at(archive, c.height() + 1, "body missing on replay")?;
                break;
            };
            let now = b.header.time + MAX_FUTURE_TIME;
            if let Err(e) = c.connect(&b, now) {
                refuse_to_cut_if_unable(&e, b.header.height)?;
                truncate_archive_at(
                    archive,
                    b.header.height,
                    &format!("block {} refused on replay: {e:?}", b.header.height),
                )?;
                break;
            }
        }
        return Ok(c);
    }

    // --- 3. Without a usable snapshot, we rebuild from the genesis.
    //
    // This is the fallback path, the one that must work on the day everything
    // else has failed — an unplugging, a flat battery, a forced shutdown, a
    // flipped bit.
    //
    // On an adopted or pruned directory, there are no bodies from before the
    // snapshot: the reconstruction stops at the genesis, or at the last body
    // present, and the network supplies the rest again. It is a cost — a
    // resync — and not a refusal: the directory, and the wallet it contains,
    // stay in place.
    if adopted {
        eprintln!(
            "warning: this directory does not have the whole history (adopted from a \
             snapshot, or pruned) and its snapshot is not usable.\n               \
             Starting again from what the block file allows to rebuild; the network \n               \
             will supply the rest. The wallet is not touched."
        );
    }
    //
    // --- What was wrong, and cost an incident
    //
    // This path replayed the file **in its write order**, calling `submit`
    // for each record. But the file is not a straight line: it also records
    // the side branches, without which no reorg would survive a restart.
    // Replaying that order therefore amounted to asking the chain to accept
    // dozens of successive reorgs — and to running into the **anti-reorg
    // defenses**, which are made to push back an attacker, not to reread
    // one's own history that was already validated.
    //
    // Measured on two nodes mining against each other: after two thousand
    // blocks, the node flatly refused to restart, with a message that could
    // lead nowhere — `BeyondFinality { depth: 18446744073709551615 }`. A node
    // unable to reread its own file is one power outage away from total loss.
    //
    // --- What we do instead
    //
    // We first ask the **headers** which chain is active — it is a
    // computation, not an opinion: the heaviest tip, then the walk back to the
    // genesis. Then we validate that sequence **in height order**, from the
    // genesis to the tip, with `connect`.
    //
    // There is then not a single reorg left to accept: each block extends the
    // previous one, by construction. The side branches stay in the file and in
    // the index — a later reorg will find their bodies.
    let tree =
        Chain::block_tree(&bare_headers).map_err(|e| format!("unreadable block index: {e:?}"))?;
    let genesis_id = tree.active[0];
    let genesis_body = archive.read(&genesis_id).ok_or(
        "the body of the genesis block cannot be read back from the block file: it is the only \
         loss that prevents starting. First put the wallet in a safe place (wallet.dat, \
         wallet.seq, addresses.dat). Then either move blocks.dat, state.dat and \
         headers.dat out of the directory — the genesis will be rewritten and the network will \
         supply the chain again —, or sync again into an empty directory",
    )?;
    let mut c = Chain::new(network, genesis_body);
    c.set_body_source(archive.clone());
    for id in tree.active.iter().skip(1) {
        let Some(b) = archive.read(id) else {
            truncate_archive_at(
                archive,
                c.height() + 1,
                &format!("body of block {id} missing from the file"),
            )?;
            break;
        };
        let now = b.header.time + MAX_FUTURE_TIME;
        if let Err(e) = c.connect(&b, now) {
            refuse_to_cut_if_unable(&e, b.header.height)?;
            truncate_archive_at(
                archive,
                b.header.height,
                &format!(
                    "block {} refused during reconstruction: {e:?}",
                    b.header.height
                ),
            )?;
            break;
        }
    }
    // The side branches are fed back afterwards, once the active chain is in
    // place. Each one is then a mere competing branch with less work: none
    // triggers a reorg, and their presence in the index is what will allow
    // adopting one later if it takes the lead.
    let active: std::collections::HashSet<_> = tree.active.iter().copied().collect();
    let mut side_blocks = 0usize;
    for (id, header) in &tree.by_id {
        if active.contains(id) || !tree.work.contains_key(id) {
            continue;
        }
        let Some(b) = archive.read(id) else { continue };
        let now = header.time + MAX_FUTURE_TIME;
        if c.submit(&b, now).is_ok() {
            side_blocks += 1;
        }
    }
    if side_blocks > 0 {
        println!("  {side_blocks} side branch block(s) reinstated");
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis_block, BodySource};
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::hash::Hash256;
    use crate::sig::SchemeId;
    use crate::state::Snapshot;
    use std::path::{Path, PathBuf};

    fn state_store_in(d: &Path) -> StateStore {
        StateStore::new_sealed(d.join("state.dat"), [3u8; 32])
    }

    const NETWORK: Network = Network::Regtest;

    fn test_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-pruning-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mine(c: &mut Chain, archive: &BlockArchive, n: usize) {
        for _ in 0..n {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            let b = c
                .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
            archive.append(&b).unwrap();
        }
    }

    /// A pruned node restarts exactly where it was.
    ///
    /// We mine a chain, log it, prune it with a short policy; then we "restart"
    /// it as the binary does: snapshot, store headers completed by those of the
    /// remaining bodies, replay of the bodies after the snapshot from the
    /// pruned archive. The tip, the UTXO set and the emission must be those of
    /// the original chain — and the restarted chain must be able to continue.
    #[test]
    fn a_pruned_node_restarts_where_it_was() {
        let d = test_dir("restart");
        let (archive, _, _) = BlockArchive::open(d.join("blocks.dat"), NETWORK).unwrap();
        let archive = Arc::new(archive);
        let header_store = HeaderStore::new(d.join("headers.dat"));

        let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
        archive.append(&genesis_block(NETWORK)).unwrap();
        mine(&mut c, &archive, 120);
        let tip = c.height();
        let snapshot: Snapshot = c.snapshot_at_depth(20).expect("snapshot");
        assert_eq!(snapshot.height, tip - 20);
        let state_store = state_store_in(&d);
        state_store.save(&snapshot).expect("snapshot written");

        let policy = Policy {
            kept_bodies: 40,
            step: 10,
        };
        let mut last_pruned = 0;
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
        // Genesis + the bodies at heights 80..=120.
        assert_eq!(summary.kept, 1 + 41);
        assert_eq!(summary.removed, 120 - 41);
        assert_eq!(last_pruned, tip);

        // Too early to do it again.
        assert_eq!(
            prune(
                &c,
                &archive,
                &header_store,
                &state_store,
                NETWORK,
                policy,
                &mut last_pruned
            )
            .unwrap(),
            None
        );

        // The store covers the genesis up to the snapshot.
        let base = header_store.load(NETWORK).expect("readable store");
        assert_eq!(base.first().map(|h| h.height), Some(0));
        assert_eq!(base.last().map(|h| h.height), Some(snapshot.height));

        // --- The restart, as the binary does it.
        let (archive2, remaining, problem) =
            BlockArchive::open(d.join("blocks.dat"), NETWORK).unwrap();
        assert!(problem.is_none());
        let snapshot_h = base.last().unwrap().height;
        let mut headers = base.clone();
        let mut later: Vec<BlockHeader> = remaining
            .iter()
            .copied()
            .filter(|h| h.height > snapshot_h)
            .collect();
        later.sort_by_key(|h| h.height);
        headers.extend(later);

        let r = Chain::from_snapshot(NETWORK, snapshot, &headers).expect("resume");
        let archive2 = Arc::new(archive2);
        let mut rc = r.chain;
        rc.set_body_source(archive2.clone());
        for id in &r.to_replay {
            let b = archive2.body(id).expect("body after the snapshot");
            rc.connect(&b, b.header.time + 1).expect("replay");
        }
        assert_eq!(rc.height(), c.height());
        assert_eq!(rc.tip_id(), c.tip_id());
        assert_eq!(rc.utxo, c.utxo);
        assert_eq!(rc.total_issued(), c.total_issued());

        // And it continues.
        mine(&mut rc, &archive2, 1);
        assert_eq!(rc.height(), tip + 1);

        // A second pruning, later, completes the store without rewriting it.
        mine(&mut rc, &archive2, 30);
        let snapshot2 = rc.snapshot_at_depth(5).expect("snapshot");
        state_store.save(&snapshot2).expect("snapshot written");
        let summary2 = prune(
            &rc,
            &archive2,
            &header_store,
            &state_store,
            NETWORK,
            policy,
            &mut last_pruned,
        )
        .expect("second pruning")
        .expect("there was something to prune");
        assert!(summary2.removed > 0);
        let base2 = header_store.load(NETWORK).expect("readable store");
        assert_eq!(base2.last().map(|h| h.height), Some(snapshot2.height));
        assert!(base2.windows(2).all(|w| w[1].height == w[0].height + 1));

        let _ = std::fs::remove_dir_all(&d);
    }

    /// A snapshot older than the kept window is refused: a body that would have
    /// to be replayed is never thrown away.
    #[test]
    fn a_snapshot_that_is_too_old_prevents_pruning() {
        let d = test_dir("too-old");
        let (archive, _, _) = BlockArchive::open(d.join("blocks.dat"), NETWORK).unwrap();
        let header_store = HeaderStore::new(d.join("headers.dat"));
        let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
        archive.append(&genesis_block(NETWORK)).unwrap();
        mine(&mut c, &archive, 60);
        let policy = Policy {
            kept_bodies: 10,
            step: 1,
        };
        let mut last_pruned = 0;
        let before = archive.len();
        let state_store = state_store_in(&d);
        state_store
            .save(&c.snapshot_at_depth(40).expect("snapshot at 20"))
            .expect("snapshot written");
        let r = prune(
            &c,
            &archive,
            &header_store,
            &state_store,
            NETWORK,
            policy,
            &mut last_pruned,
        );
        assert!(
            r.is_err(),
            "a snapshot at height 20 does not cover bodies 21..50"
        );
        assert_eq!(last_pruned, 0, "a refusal does not count as a pruning");
        assert_eq!(archive.len(), before, "the file is intact");
        assert!(!header_store.exists(), "nothing was written");
        let _ = std::fs::remove_dir_all(&d);
    }
}

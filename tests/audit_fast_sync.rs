//! Audit — fast sync from a sync snapshot, peer to peer.
//!
//! We start a real node that listens, and a client that downloads its sync
//! snapshot over the network, exactly as a newcomer would. We check that the
//! package arrives faithful, that the commitment is the only judge of trust,
//! and that a peer that does not announce the expected commitment is set aside
//! without adopting anything.

use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::fast_sync;
use q21_core::hash::Hash256;
use q21_core::net::{magic_for, Node};
use q21_core::sig::SchemeId;
use q21_core::store::{BlockArchive, BlockStore};
use q21_core::Network;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn timestamp(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn test_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-audit-fast-sync-{name}-{}", std::process::id()));
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
        let t = timestamp(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
        archive.append(&b).unwrap();
    }
    (c, archive)
}

/// A peer serves a sync snapshot, and the client receives it faithfully: byte
/// for byte, and with the announced commitment matching that of the package.
#[test]
fn a_peer_serves_a_faithful_sync_snapshot() {
    let dir = test_dir("faithful");
    let (chain, _archive) = mined_chain(&dir, 20);

    // What the server can serve, computed directly for comparison.
    let expected = chain.build_sync_snapshot().expect("sync snapshot");
    let commitment = expected.announced_commitment().unwrap();

    let node = Node::new(NETWORK, chain);
    let addr = node.listen("127.0.0.1:0").expect("listen");

    let received = fast_sync::download_sync_snapshot(
        addr,
        magic_for(NETWORK),
        0,
        commitment,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .expect("download");

    assert_eq!(
        received, expected,
        "the received sync snapshot must be identical to the one served"
    );
    assert_eq!(received.announced_commitment(), Some(commitment));
    assert!(!received.headers.is_empty());
    assert!(!received.bodies.is_empty());
}

/// The commitment is the only judge: a trusted value that does not match gets
/// the peer set aside, without adopting anything.
#[test]
fn a_wrong_commitment_gets_the_peer_set_aside() {
    let dir = test_dir("wrong");
    let (chain, _archive) = mined_chain(&dir, 16);
    let node = Node::new(NETWORK, chain);
    let addr = node.listen("127.0.0.1:0").expect("listen");

    let wrong = Hash256([0x99; 32]);
    let r = fast_sync::download_sync_snapshot(
        addr,
        magic_for(NETWORK),
        0,
        wrong,
        Duration::from_secs(5),
        Duration::from_secs(30),
    );
    assert!(r.is_err(), "a wrong commitment must make the download fail");
    let msg = r.err().unwrap();
    assert!(
        msg.contains("commitment") || msg.contains("trusted"),
        "the refusal must name its reason: {msg}"
    );
}

/// A **crafted** header chain, without the slightest work, must not be adopted
/// — even if all the anchors "match".
///
/// # The attack, as it was possible
///
/// Adoption checked three things: the commitment equals the trusted value, the
/// tip equals the trusted tip, and the headers lead structurally from that tip
/// to the real genesis. The reasoning was that a linking up to the tip
/// authenticates the whole chain.
///
/// It proves that the ancestors are authentic *given that the tip is*. But the
/// tip only comes from a hexadecimal string copied by the operator. Whoever
/// controls it — spoofed explorer, interception, malicious mirror, typo —
/// crafts a consistent header chain **without any computation**, ending on
/// their own tip, and supplies their own trusted values. The three checks
/// passed. The node adopted a made-up state, for an attack cost of zero.
///
/// Proof of work is the only thing that can be checked without trusting
/// anyone. So it is checked again, and the attack stops being free.
#[test]
fn a_crafted_header_chain_is_not_adopted() {
    use q21_core::block::BlockHeader;
    use q21_core::chain::AdoptionError;

    let dir = test_dir("crafted");
    let (chain, _archive) = mined_chain(&dir, 30);
    // A depth of a single block: the snapshot is high, so the chain the
    // attacker has to craft is long. With a fully "set back" snapshot it would
    // only be one header, and a single unmined header passes the very
    // permissive regtest target once in 256 — the test would then prove
    // nothing.
    let honest_snapshot = chain.snapshot_at_depth(1).expect("snapshot");
    assert!(
        honest_snapshot.height >= 25,
        "the crafted chain must be long enough for the check to bite"
    );

    // The attacker starts from the real genesis — otherwise the genesis check
    // unmasks it right away — then stacks headers without mining.
    let genesis = genesis_block(NETWORK);
    let mut headers: Vec<BlockHeader> = vec![genesis.header];
    let mut prev = genesis.header.block_id();
    for h in 1..=honest_snapshot.height {
        let e = BlockHeader {
            version: 1,
            prev_block: prev,
            merkle_root: Hash256([0x11; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([0x66; 32]),
            time: timestamp(h),
            bits: genesis.header.bits,
            height: h,
            // No mining: that is the whole point of the attack.
            nonce: 0,
        };
        prev = e.block_id();
        headers.push(e);
    }
    let crafted_tip = prev;

    // The attacker supplies their own anchors, perfectly consistent with one
    // another: exactly what a spoofed explorer would display.
    let mut snapshot = honest_snapshot;
    snapshot.tip = crafted_tip;
    let commitment = snapshot.commitment();

    let r = Chain::adopt_snapshot(NETWORK, snapshot, &headers, crafted_tip, commitment);

    assert!(
        matches!(
            r,
            Err(AdoptionError::InvalidWork { .. }) | Err(AdoptionError::InvalidDifficulty { .. })
        ),
        "a header chain without work was adopted: the monetary state \
         of a new node can then be crafted for free"
    );
}

/// The package received over the network gets adopted: a new node derives from
/// it the same committed state as a full node. The whole loop, from the wire to
/// adoption.
#[test]
fn the_sync_snapshot_received_over_the_network_gets_adopted() {
    use q21_core::chain::AdoptionError;

    let dir = test_dir("adopted");
    let (chain, _archive) = mined_chain(&dir, 20);
    let expected = chain.build_sync_snapshot().expect("sync snapshot");
    let commitment = expected.announced_commitment().unwrap();
    let tip = expected.announced_tip().unwrap();

    let node = Node::new(NETWORK, chain);
    let addr = node.listen("127.0.0.1:0").expect("listen");

    let received = fast_sync::download_sync_snapshot(
        addr,
        magic_for(NETWORK),
        0,
        commitment,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .expect("download");

    // We adopt the received package, anchored to the trusted commitment and
    // tip.
    let snapshot = q21_core::state::Snapshot::from_portable_bytes(&received.snapshot, NETWORK)
        .expect("snapshot");
    let r: Result<_, AdoptionError> =
        Chain::adopt_snapshot(NETWORK, snapshot, &received.headers, tip, commitment);
    assert!(
        r.is_ok(),
        "the received sync snapshot must get adopted: {:?}",
        r.err()
    );
}

/// An anchor written into the binary takes precedence over what the operator
/// copies.
///
/// It is the last barrier of the trust model. Rechecking the work already makes
/// the attack costly, but an adversary with a lot of power could pay for it. A
/// compiled anchor confronts it with a value that comes from no network: it
/// comes from the software the user already runs, reviewed by anyone who reads
/// the repository.
#[test]
fn a_compiled_anchor_takes_precedence_over_the_operator_value() {
    use q21_core::chain::AdoptionError;
    use q21_core::fast_sync::Anchor;

    let dir = test_dir("anchor");
    let (chain, _archive) = mined_chain(&dir, 30);
    let snapshot = chain.snapshot_at_depth(1).expect("snapshot");

    // The honest path, as adoption rebuilds it.
    let path: Vec<q21_core::block::BlockHeader> = (0..=snapshot.height)
        .map(|h| {
            let id = chain.active_at(h).expect("active height");
            chain.header_of(&id).expect("header")
        })
        .collect();

    // 1. A matching anchor lets it through.
    let real = Anchor {
        height: 10,
        tip: chain.active_at(10).expect("block 10"),
        commitment: Hash256::ZERO, // ignored: height != that of the snapshot
    };
    assert!(
        Chain::check_anchors(&path, &snapshot, &[real]).is_ok(),
        "a chain matching the anchor must be accepted"
    );

    // 2. An anchor that designates another block at that height refuses
    //    everything, even if the chain carries perfectly valid work.
    let poisoned = Anchor {
        height: 10,
        tip: Hash256([0xab; 32]),
        commitment: Hash256::ZERO,
    };
    assert!(
        matches!(
            Chain::check_anchors(&path, &snapshot, &[poisoned]),
            Err(AdoptionError::AnchorContradicted { height: 10 })
        ),
        "a chain that contradicts an anchor must be refused"
    );

    // 3. At the exact height of the snapshot, the commitment must match: the
    //    operator cannot get another monetary state adopted where the binary
    //    knows the commitment.
    let wrong_commitment = Anchor {
        height: snapshot.height,
        tip: snapshot.tip,
        commitment: Hash256([0xcd; 32]),
    };
    assert!(
        matches!(
            Chain::check_anchors(&path, &snapshot, &[wrong_commitment]),
            Err(AdoptionError::AnchorContradicted { .. })
        ),
        "a commitment contradicting the anchor must be refused"
    );

    // 4. An anchor beyond what is being adopted says nothing.
    let beyond = Anchor {
        height: snapshot.height + 1_000,
        tip: Hash256([0xef; 32]),
        commitment: Hash256([0xef; 32]),
    };
    assert!(
        Chain::check_anchors(&path, &snapshot, &[beyond]).is_ok(),
        "an anchor higher than the snapshot must forbid nothing"
    );
}

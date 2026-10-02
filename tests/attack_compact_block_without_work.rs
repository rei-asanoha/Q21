//! ATTACK (red-team 8b, 2nd campaign, item 4): making a node search its
//! mempool with compact blocks that carry no work.
//!
//! A compact block only brings the header and short identifiers; the body is
//! rebuilt by the node, by searching its mempool, under the global lock. That
//! reconstruction happened BEFORE anyone had checked whether the header
//! carried real work. A peer that had completed the handshake, on a known
//! parent, within its announcement budget, could therefore make the node
//! search its mempool for headers fabricated without mining.
//!
//! Fix: the header is checked on its own (height, finality, difficulty,
//! timestamp, work) before a single identifier is compared (BIP 152). A false
//! header no longer costs anything beyond reading it, and earns the peer the
//! penalty for an invalid block. A true header goes through exactly as before.

use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::compact::CompactBlock;
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::net::{magic_for, Node, BAN_THRESHOLD, MISCONDUCT_BAD_BLOCK};
use q21_core::pow::{PowEngine, Q21Pow};
use q21_core::sig::SchemeId;
use q21_core::wire::{Message, PROTOCOL_VERSION};
use q21_core::Network;

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::Duration;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn handshake(s: &mut TcpStream, magic: [u8; 4], nonce: u64) {
    s.write_all(
        &Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 0,
            nonce,
            user_agent: "test".into(),
            start_height: 0,
        }
        .frame(magic),
    )
    .expect("version");
    s.write_all(&Message::VerAck.frame(magic)).expect("verack");
    std::thread::sleep(Duration::from_millis(300));
}

/// Waits for a counter to reach `target`, two seconds at most.
fn wait_for(read: impl Fn() -> u64, target: u64) -> u64 {
    let start = std::time::Instant::now();
    loop {
        let v = read();
        if v >= target || start.elapsed() > Duration::from_secs(2) {
            return v;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_compact_block_without_work_is_never_reconstructed() {
    let node = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
    let addr = node.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);

    // A real, mined block: everything in it is correct (parent, height,
    // difficulty, timestamp, work).
    let t = GENESIS_TIME + TARGET_BLOCK_SECS;
    let real = node
        .with_chain(|c| c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ATTEMPTS))
        .expect("mining");
    let pow = Q21Pow::new(NETWORK);
    assert!(
        pow.check(&real.header).is_ok(),
        "the mined block must carry its work"
    );

    // The same header, with the nonce changed until the work is FALSE:
    // everything else (parent, height, difficulty, timestamp) stays correct,
    // so that only the work can get it refused.
    let mut forged = real.header;
    forged.nonce = forged.nonce.wrapping_add(1);
    while pow.check(&forged).is_ok() {
        forged.nonce = forged.nonce.wrapping_add(1);
    }
    let compact_forged = CompactBlock {
        header: forged,
        ..CompactBlock::from_block(&real, 7)
    };

    let mut s = TcpStream::connect(addr).expect("connection");
    handshake(&mut s, magic, 0xc0ff_ee04);

    // --- The attack: a header without work, within the announcement budget.
    s.write_all(&Message::CmpctBlock(Box::new(compact_forged)).frame(magic))
        .expect("forged cmpctblock");
    let rejected = wait_for(
        || node.stats.compacts_header_rejected.load(Ordering::Relaxed),
        1,
    );
    let reconstructed = node.stats.compacts_reconstructed.load(Ordering::Relaxed);
    let invalid = node.stats.invalid_blocks.load(Ordering::Relaxed);
    eprintln!(
        "forged: {rejected} header(s) rejected before reconstruction, \
         {reconstructed} reconstruction(s) started, {invalid} invalid block(s)"
    );
    assert_eq!(
        rejected, 1,
        "the header without work must be rejected before any reconstruction"
    );
    assert_eq!(
        reconstructed, 0,
        "no reconstruction must be started for a false header"
    );
    assert_eq!(invalid, 1, "a false header counts as an invalid block");
    assert_eq!(node.height(), 0, "nothing must have been connected");
    // A single offense does not disconnect yet: the penalty is that of an
    // invalid block, and the threshold requires more than one offense.
    const _: () = assert!(MISCONDUCT_BAD_BLOCK < BAN_THRESHOLD);
    assert_eq!(
        node.peer_count(),
        1,
        "a single offense does not disconnect yet"
    );

    // --- The real block, from the same peer: nothing has changed for it.
    let compact_real = CompactBlock::from_block(&real, 7);
    s.write_all(&Message::CmpctBlock(Box::new(compact_real)).frame(magic))
        .expect("real cmpctblock");
    let reconstructed = wait_for(
        || node.stats.compacts_reconstructed.load(Ordering::Relaxed),
        1,
    );
    let height = wait_for(|| node.height(), 1);
    eprintln!("real: {reconstructed} reconstruction(s), height {height}");
    assert_eq!(
        reconstructed, 1,
        "a header with correct work must be reconstructed"
    );
    assert_eq!(height, 1, "the real block must be connected");
    assert_eq!(
        node.stats.compacts_header_rejected.load(Ordering::Relaxed),
        1,
        "the real block must not be counted as rejected"
    );

    // --- Persisting gets the peer disconnected: a second offense crosses the
    //     threshold.
    let mut forged2 = forged;
    forged2.nonce = forged2.nonce.wrapping_add(1);
    forged2.time = t + 1;
    while pow.check(&forged2).is_ok() {
        forged2.nonce = forged2.nonce.wrapping_add(1);
    }
    // On the genesis again: the tip has moved forward, but the genesis is
    // still a known parent within finality range.
    let compact_forged2 = CompactBlock {
        header: forged2,
        ..CompactBlock::from_block(&real, 7)
    };
    s.write_all(&Message::CmpctBlock(Box::new(compact_forged2)).frame(magic))
        .expect("forged cmpctblock 2");
    let mut remaining = node.peer_count();
    for _ in 0..40 {
        if remaining == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        remaining = node.peer_count();
    }
    assert_eq!(remaining, 0, "two false headers must disconnect the peer");
    assert_eq!(
        node.stats.compacts_reconstructed.load(Ordering::Relaxed),
        1,
        "still a single reconstruction: the one for the real block"
    );
    node.shutdown();
}

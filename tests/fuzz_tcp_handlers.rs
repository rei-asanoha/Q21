//! Handler fuzzing through real sockets.
//!
//! The in-memory fuzzing (`tests_handler_fuzz` in `src/net.rs`) calls `handle`
//! directly. This one goes through the real entry door: a TCP connection, the
//! read loop, the buffer, the framing. It only uses the public interface.
//!
//! Three families of aggressions:
//!
//! - mutated valid frames: flipped bits, truncations, lying length field,
//!   bad checksum, foreign magic, and dozens of frames glued end to end. Some
//!   of the mutations recompute the checksum, so that the mutated payload gets
//!   past the gate and reaches the decoder and then the handler;
//! - the same, after a real handshake, to reach the handlers reserved for
//!   established peers;
//! - partial frames trickled byte by byte ("slow-loris"), while an honest peer
//!   synchronizes.
//!
//! At the end, the node must still serve an honest peer: handshake,
//! synchronization of its blocks, and adoption of a new block.
//!
//! `Q21_FUZZ_ITERATIONS` sets the number of aggressive connections, and
//! `Q21_FUZZ_SEED` the seed.

use q21_core::address::Network;
use q21_core::chain::{genesis_block, Chain};
use q21_core::hash::Hash256;
use q21_core::net::{magic_for, Node};
use q21_core::sha256::sha256;
use q21_core::sig::SchemeId;
use q21_core::wire::{InvItem, InvKind, Message, NetAddr, MAX_PAYLOAD, PROTOCOL_VERSION};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;
const HEADER_LEN: usize = 24;

/// splitmix64: reproducible and dependency-free.
struct Prng(u64);

impl Prng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
}

fn env_u64(name: &str) -> Option<u64> {
    let v = std::env::var(name).ok()?;
    let v = v.trim();
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

fn wait_until(mut cond: impl FnMut() -> bool, seconds: u64) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}

fn mine(n: &Node, count: usize, beneficiary: u8) {
    for _ in 0..count {
        let b = n
            .with_chain(|c| {
                c.mine_block(
                    Hash256([beneficiary; 32]),
                    SchemeId::LamportOts,
                    &[],
                    c.tip().time + 1,
                    5_000_000,
                )
            })
            .expect("regtest mining");
        n.with_chain(|c| c.connect(&b, b.header.time + 1).expect("connection"));
    }
}

fn handshake() -> Vec<Message> {
    vec![
        Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 1_800_000_000,
            nonce: 0xf022,
            user_agent: "fuzz".into(),
            start_height: 0,
        },
        Message::VerAck,
    ]
}

/// Corpus seeds: one valid instance of each common shape.
fn corpus(n: &Node) -> Vec<Message> {
    let block = n.with_chain(|c| c.block_at(1)).expect("block 1");
    let headers = n.with_chain(|c| c.headers_from(&[], Hash256::ZERO, 3));
    let tip = n.tip_id();
    let mut v = handshake();
    v.extend([
        Message::Ping(7),
        Message::Pong(7),
        Message::GetHeaders {
            locator: vec![tip, Hash256([9; 32])],
            stop: Hash256::ZERO,
        },
        Message::Headers(headers),
        Message::Inv(vec![InvItem {
            kind: InvKind::CompactBlock,
            hash: Hash256([5; 32]),
        }]),
        Message::GetData(vec![
            InvItem {
                kind: InvKind::Block,
                hash: tip,
            },
            InvItem {
                kind: InvKind::CompactBlock,
                hash: tip,
            },
        ]),
        Message::Tx(Box::new(block.transactions[0].clone())),
        Message::Block(Box::new(block.clone())),
        Message::CmpctBlock(Box::new(q21_core::compact::CompactBlock::from_block(
            &block, 3,
        ))),
        Message::GetBlockTxn {
            block: tip,
            indices: vec![0, 1, 70_000],
        },
        Message::BlockTxn {
            block: tip,
            txs: vec![block.transactions[0].clone()],
        },
        Message::GetAddr,
        Message::Addr(vec![NetAddr {
            ip: [198, 51, 100, 7],
            port: 21021,
            last_seen: 1_800_000_000,
        }]),
        Message::Reject {
            command: "tx".into(),
            reason: "x".into(),
        },
        Message::GetSnapshot,
        Message::GetSnapshotChunk { index: 0 },
    ]);
    v
}

/// Recomputes the checksum of a frame whose length is correct.
fn reseal(t: &mut [u8]) {
    if t.len() >= HEADER_LEN {
        let s = sha256(&t[HEADER_LEN..]);
        t[20..24].copy_from_slice(&s[..4]);
    }
}

/// A mutation of a valid frame.
fn mutate(a: &mut Prng, mut t: Vec<u8>, magic: [u8; 4]) -> Vec<u8> {
    match a.below(9) {
        // Bits flipped in the payload, checksum recomputed: the decoder and the
        // handler see the mutation.
        0 | 1 => {
            for _ in 0..1 + a.below(8) {
                if t.len() > HEADER_LEN {
                    let i = HEADER_LEN + a.below((t.len() - HEADER_LEN) as u64) as usize;
                    t[i] ^= 1 << a.below(8);
                }
            }
            reseal(&mut t);
        }
        // Bits flipped anywhere, checksum left as is.
        2 => {
            let i = a.below(t.len() as u64) as usize;
            t[i] ^= 1 << a.below(8);
        }
        // Truncation.
        3 => {
            let l = a.below(t.len() as u64) as usize;
            t.truncate(l);
        }
        // Lying length field.
        4 => {
            let real = (t.len() - HEADER_LEN) as u32;
            let fake: u32 = match a.below(6) {
                0 => 0,
                1 => real.wrapping_sub(1),
                2 => real + 1,
                3 => MAX_PAYLOAD as u32,
                4 => MAX_PAYLOAD as u32 + 1,
                _ => u32::MAX,
            };
            t[16..20].copy_from_slice(&fake.to_le_bytes());
        }
        // Bad checksum.
        5 => t[20] ^= 0xff,
        // Foreign magic.
        6 => {
            let other = if magic == magic_for(Network::Mainnet) {
                magic_for(Network::Testnet)
            } else {
                magic_for(Network::Mainnet)
            };
            t[..4].copy_from_slice(&other);
        }
        // Truncated but resealed payload: consistent length and checksum, the
        // decoder receives a short payload.
        7 => {
            if t.len() > HEADER_LEN {
                let l = HEADER_LEN + a.below((t.len() - HEADER_LEN) as u64) as usize;
                t.truncate(l);
                let len = (l - HEADER_LEN) as u32;
                t[16..20].copy_from_slice(&len.to_le_bytes());
                reseal(&mut t);
            }
        }
        // Bytes overwritten at random in the payload, resealed.
        _ => {
            if t.len() > HEADER_LEN {
                let i = HEADER_LEN + a.below((t.len() - HEADER_LEN) as u64) as usize;
                let k = (1 + a.below(16) as usize).min(t.len() - i);
                for o in &mut t[i..i + k] {
                    *o = a.next_u64() as u8;
                }
                reseal(&mut t);
            }
        }
    }
    t
}

fn send(addr: SocketAddr, bytes: &[u8]) {
    if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
        let _ = s.set_read_timeout(Some(Duration::from_millis(30)));
        let _ = s.write_all(bytes);
        // Read a little: the node replies, and a full socket must not block
        // its writer.
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b);
    }
}

#[test]
fn the_node_survives_mutated_frames_and_still_serves_an_honest_peer() {
    let seed = env_u64("Q21_FUZZ_SEED").unwrap_or(0x7c9_2100);
    let iterations = env_u64("Q21_FUZZ_ITERATIONS").unwrap_or(300);
    let mut a = Prng(seed);
    let magic = magic_for(NETWORK);

    let target = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
    mine(&target, 3, 2);
    let addr = target.listen("127.0.0.1:0").expect("listen");
    let seeds: Vec<Vec<u8>> = corpus(&target).iter().map(|m| m.frame(magic)).collect();
    let introduction: Vec<u8> = handshake().iter().flat_map(|m| m.frame(magic)).collect();

    let start = Instant::now();
    let mut frames = 0u64;
    for _ in 0..iterations {
        let mut stream = Vec::new();
        // Half of the connections introduce themselves first: the handlers
        // reserved for established peers are reached too.
        if a.below(2) == 0 {
            stream.extend_from_slice(&introduction);
        }
        // One or more frames, valid or mutated, glued end to end.
        let count = if a.below(8) == 0 {
            20 + a.below(40)
        } else {
            1 + a.below(3)
        };
        for _ in 0..count {
            let t = seeds[a.below(seeds.len() as u64) as usize].clone();
            let t = if a.below(4) == 0 {
                t
            } else {
                mutate(&mut a, t, magic)
            };
            stream.extend_from_slice(&t);
            frames += 1;
        }
        send(addr, &stream);
    }
    assert!(
        wait_until(|| target.peer_count() == 0, 30),
        "closed connections are still counted: {}",
        target.peer_count()
    );
    let mutation_duration = start.elapsed();

    // --- Slow-loris: partial frames trickled byte by byte, one of which
    // announces the largest admitted payload and sends none of it, while an
    // honest peer introduces itself and synchronizes.
    let mut slow: Vec<TcpStream> = Vec::new();
    for i in 0..8 {
        let mut s = TcpStream::connect(addr).expect("slow connection");
        let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
        if i % 2 == 0 {
            let _ = s.write_all(&introduction);
        }
        slow.push(s);
    }
    let mut announcement = Message::Ping(1).frame(magic);
    announcement.truncate(HEADER_LEN);
    announcement[4..16].copy_from_slice(b"block\0\0\0\0\0\0\0");
    announcement[16..20].copy_from_slice(&(MAX_PAYLOAD as u32).to_le_bytes());
    let trickle = std::thread::spawn({
        let mut slow = slow;
        let mut partials: Vec<Vec<u8>> = seeds.clone();
        partials.push(announcement);
        move || {
            for round in 0..200 {
                for (i, s) in slow.iter_mut().enumerate() {
                    let t = &partials[i % partials.len()];
                    // In order, and never the last byte: the frame stays
                    // incomplete and the connection open.
                    if round + 1 < t.len() {
                        let _ = s.write_all(&t[round..round + 1]);
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            slow
        }
    });

    // --- The honest peer: real handshake, synchronization of the target's
    // three blocks, then a new block that it announces and the target adopts.
    let honest = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
    let sync_start = Instant::now();
    honest.connect(addr).expect("honest connection");
    assert!(
        wait_until(|| honest.peer_count_established() == 1, 15),
        "the target no longer completes an honest peer's handshake"
    );
    assert!(
        wait_until(|| honest.height() == target.height(), 30),
        "the target no longer serves its blocks: honest at {}, target at {}",
        honest.height(),
        target.height()
    );
    assert_eq!(honest.tip_id(), target.tip_id());
    let sync_duration = sync_start.elapsed();

    let height = target.height();
    let b = honest
        .with_chain(|c| {
            c.mine_block(
                Hash256([4; 32]),
                SchemeId::LamportOts,
                &[],
                c.tip().time + 1,
                5_000_000,
            )
        })
        .expect("regtest mining");
    honest.with_chain(|c| c.connect(&b, b.header.time + 1).expect("connection"));
    honest.announce_block(&b);
    assert!(
        wait_until(|| target.height() == height + 1, 30),
        "the target no longer adopts a block announced by an honest peer"
    );
    assert_eq!(target.tip_id(), b.header.block_id());

    let slow = trickle.join().expect("slow thread");
    drop(slow);
    eprintln!(
        "tcp fuzz: seed {seed:#x}, {iterations} connections, {frames} frames in \
         {mutation_duration:?}; honest sync under slow-loris in {sync_duration:?}"
    );
    target.shutdown();
    honest.shutdown();
}

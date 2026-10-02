//! Network regression tests, from the phase 8 adversarial audit.
//!
//! These tests connect to the node as a hostile peer would. Each one was first
//! a working exploit; it now checks that the attack fails.

use q21_core::block::Block;
use q21_core::chain::{genesis_block, Chain};
use q21_core::net::{magic_for, Node};
use q21_core::wire::{InvItem, InvKind, Message, MAX_BLOCK_TXN, MAX_INV, PROTOCOL_VERSION};
use q21_core::Network;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const NETWORK: Network = Network::Regtest;

fn node() -> Node {
    let g = genesis_block(NETWORK);
    Node::new(NETWORK, Chain::new(NETWORK, g))
}

/// Reads from the stream for at most `secs`, returns everything that arrived.
fn drain(mut s: TcpStream, secs: u64) -> Vec<u8> {
    // Setting a timeout on a socket whose other end has just closed returns
    // EINVAL on macOS. This is not a test error: it is the normal case when
    // the node has disconnected the peer, and the read that follows will
    // simply return zero bytes.
    let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
    let start = std::time::Instant::now();
    let mut all = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    while start.elapsed() < Duration::from_secs(secs) {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => {
                if !all.is_empty() {
                    break;
                }
            }
        }
    }
    all
}

/// `getblocktxn` with repeated indices: no more amplification.
///
/// The exploit asked for the same index a hundred thousand times. The node
/// cloned the transaction as many times and assembled a 15.5 MiB frame —
/// which even exceeded its own `MAX_PAYLOAD`, hence unreadable by an honest
/// peer. Producing a reply nobody can read is the definition of a
/// denial-of-service vector.
///
/// Three rules close the door: handshake required, deduplicated indices,
/// outgoing byte budget.
#[test]
fn getblocktxn_with_repeated_indices_no_longer_amplifies() {
    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);

    // The genesis block always exists; its coinbase is at index 0.
    let genesis_id = a.tip_id();

    let indices = vec![0u32; MAX_BLOCK_TXN]; // the same index 100_000 times
    let request = Message::GetBlockTxn {
        block: genesis_id,
        indices,
    };
    let frame = request.frame(magic);
    let request_size = frame.len();

    let mut s = TcpStream::connect(addr).expect("connection");
    s.write_all(&frame).expect("send");

    let received = drain(s.try_clone().unwrap(), 8);

    eprintln!(
        "request = {} bytes, reply = {} bytes",
        request_size,
        received.len()
    );
    assert!(
        received.len() <= request_size,
        "the reply ({} bytes) still amplifies the request ({} bytes)",
        received.len(),
        request_size
    );
    assert!(
        received.len() < q21_core::wire::MAX_PAYLOAD,
        "the node still emits more than its own MAX_PAYLOAD"
    );
    a.shutdown();
}

/// `getdata` with repeated hashes: no more amplification.
///
/// The exploit asked for the same block twenty thousand times: the node sent
/// back twenty thousand copies, each in its own frame, and for a compact
/// block recomputed all the short identifiers each time. The audit's
/// measurement: a 660 KiB request for a 6.8 MiB reply — on real 4 MiB
/// blocks, 80 GiB.
#[test]
fn getdata_with_repeated_hashes_no_longer_amplifies() {
    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);
    let genesis_id = a.tip_id();

    const K: usize = 20_000;
    let items = vec![
        InvItem {
            kind: InvKind::Block,
            hash: genesis_id,
        };
        K
    ];
    const _: () = assert!(K <= MAX_INV);
    let frame = Message::GetData(items).frame(magic);
    let request_size = frame.len();

    let mut s = TcpStream::connect(addr).expect("connection");
    s.write_all(&frame).expect("send");

    let received = drain(s.try_clone().unwrap(), 10);

    // Counts the `block` frames sent back.
    let mut rest = &received[..];
    let mut blocks = 0usize;
    while let Ok((m, n)) = Message::parse(rest, magic) {
        if matches!(m, Message::Block(_)) {
            blocks += 1;
        }
        rest = &rest[n..];
        if rest.is_empty() {
            break;
        }
    }

    eprintln!(
        "request = {} bytes, reply = {} bytes, block frames = {}",
        request_size,
        received.len(),
        blocks
    );
    assert!(
        blocks <= 1,
        "a hash requested twenty thousand times must be served at most once \
         (received {blocks} copies)"
    );
    assert!(
        received.len() <= request_size,
        "the reply still amplifies the request"
    );
    a.shutdown();
}

/// Nothing expensive is served before the handshake.
///
/// The two attacks above worked over a mere TCP connection, without `version`
/// or `verack`: their cost to the attacker came down to one `connect()`.
#[test]
fn nothing_is_served_before_the_handshake() {
    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);
    let genesis_id = a.tip_id();

    // A getdata right away, with no prior version.
    let frame = Message::GetData(vec![InvItem {
        kind: InvKind::Block,
        hash: genesis_id,
    }])
    .frame(magic);

    let mut s = TcpStream::connect(addr).expect("connection");
    s.write_all(&frame).expect("send");
    let received = drain(s.try_clone().unwrap(), 5);

    // Nothing must come back, and the connection must drop.
    let served = Message::parse(&received, magic)
        .map(|(m, _)| matches!(m, Message::Block(_)))
        .unwrap_or(false);
    assert!(
        !served,
        "a block was served without a prior handshake ({} bytes received)",
        received.len()
    );
    let _ = Block::decode; // silences the warning if unused
    a.shutdown();
}

/// A compact block whose parent is unknown costs nothing.
///
/// The faulty version cloned **the whole mempool** — up to 64 MiB — under the
/// global lock, for every compact announcement. A 170-byte message was enough
/// to serialize the entire node; repeated, it froze it.
///
/// We check two things: the node starts no reconstruction (no `getblocktxn`
/// in reply), and it remains perfectly responsive afterwards.
#[test]
fn an_orphan_compact_block_triggers_no_work() {
    use q21_core::block::BlockHeader;
    use q21_core::compact::CompactBlock;
    use q21_core::hash::Hash256;

    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);

    let mut s = TcpStream::connect(addr).expect("connection");

    // Complete handshake: we put ourselves in the case most favorable to the
    // attacker, that of a legitimate peer.
    s.write_all(
        &Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 0,
            nonce: 0xdead_beef,
            user_agent: "test".into(),
            start_height: 0,
        }
        .frame(magic),
    )
    .expect("send version");
    s.write_all(&Message::VerAck.frame(magic)).expect("verack");
    std::thread::sleep(Duration::from_millis(300));

    // Two hundred compact announcements whose parent does not exist.
    for k in 0..200u8 {
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block: Hash256([k; 32]), // unknown parent
            merkle_root: Hash256([1u8; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([2u8; 32]),
            time: 1_800_000_000,
            bits: 0x2000_ffff,
            height: 1,
            nonce: 0,
        };
        let c = CompactBlock {
            header,
            nonce: 7,
            short_ids: vec![1, 2, 3],
            prefilled: Vec::new(),
            uncles: Vec::new(),
        };
        let _ = s.write_all(&Message::CmpctBlock(Box::new(c)).frame(magic));
    }

    // The node must stay responsive: we ask it for a pong.
    s.write_all(&Message::Ping(0x1234).frame(magic))
        .expect("ping");
    let received = drain(s.try_clone().unwrap(), 5);

    let mut rest = &received[..];
    let mut pong = false;
    let mut requests = 0usize;
    while let Ok((m, n)) = Message::parse(rest, magic) {
        match m {
            Message::Pong(0x1234) => pong = true,
            Message::GetBlockTxn { .. } | Message::GetData(_) => requests += 1,
            _ => {}
        }
        rest = &rest[n..];
        if rest.is_empty() {
            break;
        }
    }

    assert_eq!(
        requests, 0,
        "the node started a reconstruction for a block whose parent it does not know"
    );
    assert!(
        pong,
        "the node no longer answers after 200 orphan compact announcements"
    );
    a.shutdown();
}

/// A block or a transaction pushed before the handshake is not read.
///
/// Every serving message required the handshake; the two pushed messages —
/// `Tx` and `Block` — did not. A transaction with a bad signature spending
/// its own output forced a complete post-quantum verification under the
/// global lock, over a mere anonymous connection, with neither penalty nor
/// budget: about sixty per second were enough to freeze the node.
#[test]
fn nothing_is_read_before_the_handshake_even_when_pushed() {
    use std::sync::atomic::Ordering;
    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);
    let genesis = genesis_block(NETWORK);

    let mut s = TcpStream::connect(addr).expect("connection");
    // A block (the genesis, already known) and a transaction (the genesis
    // coinbase), pushed without any `Version`.
    s.write_all(&Message::Block(Box::new(genesis.clone())).frame(magic))
        .expect("send block");
    s.write_all(&Message::Tx(Box::new(genesis.transactions[0].clone())).frame(magic))
        .expect("send tx");
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(
        a.stats.blocks_received.load(Ordering::Relaxed),
        0,
        "a block pushed without a handshake was read"
    );
    assert_eq!(
        a.stats.txs_received.load(Ordering::Relaxed),
        0,
        "a transaction pushed without a handshake was read"
    );
    a.shutdown();
}

/// The per-peer budget of new transactions bites, and insisting gets the peer
/// disconnected.
///
/// After the handshake, a peer has a reserve of `TX_BUCKET_MAX` new
/// transactions, then `TX_RATE_PER_SEC` per second. Beyond that, the message
/// is not read, and the peer loses points with every send.
#[test]
fn the_per_peer_transaction_budget_ends_up_disconnecting() {
    use q21_core::amount::Amount;
    use q21_core::hash::Hash256;
    use q21_core::net::TX_BUCKET_MAX;
    use q21_core::sig::SchemeId;
    use q21_core::tx::OutPoint;
    use q21_core::tx::{Transaction, TxIn, TxOut, Witness};

    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);

    let mut s = TcpStream::connect(addr).expect("connection");
    s.write_all(
        &Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 0,
            nonce: 0xbeef_cafe,
            user_agent: "test".into(),
            start_height: 0,
        }
        .frame(magic),
    )
    .expect("version");
    s.write_all(&Message::VerAck.frame(magic)).expect("verack");
    std::thread::sleep(Duration::from_millis(300));

    // New transactions, all invalid (unknown input) — each one distinct by its
    // output. Far more than the reserve.
    let n = TX_BUCKET_MAX as u32 + 200;
    for k in 0..n {
        let t = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([7u8; 32]),
                    index: k,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::from_units(10_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: Hash256([(k % 251) as u8; 32]),
            }],
            lock_time: 0,
        };
        if s.write_all(&Message::Tx(Box::new(t)).frame(magic)).is_err() {
            break;
        }
    }
    // The peer must have been disconnected. We ask the **node**, not the
    // socket: depending on the machine's speed, the socket is already dead
    // when we query it, and the test would then measure the operating system
    // rather than the rule.
    let mut remaining = a.peer_count();
    for _ in 0..80 {
        if remaining == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        remaining = a.peer_count();
    }
    assert_eq!(
        remaining, 0,
        "a peer that insists beyond its budget must be disconnected"
    );
    a.shutdown();
}

/// Listening keeps slots for our own outbound dials, and bounds each group.
///
/// Thirty-two connections from a single address took the thirty-two slots;
/// the anti-eclipse address book was then never consulted again.
#[test]
fn listening_reserves_slots_for_outbound() {
    use q21_core::net::{MAX_PEERS, RESERVED_OUTBOUND_SLOTS};
    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let mut kept = Vec::new();
    for _ in 0..(MAX_PEERS + 4) {
        if let Ok(s) = TcpStream::connect(addr) {
            kept.push(s);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    let n = a.peer_count();
    assert!(
        n <= MAX_PEERS - RESERVED_OUTBOUND_SLOTS,
        "{n} inbound connections admitted: the outbound slots are not reserved"
    );
    drop(kept);
    a.shutdown();
}

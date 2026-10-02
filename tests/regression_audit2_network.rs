//! Network regression tests, from the second adversarial audit.
//!
//! Like those of `regression_network.rs`, these tests connect to the node as a
//! hostile peer would. Each one was first a working exploit; it now checks
//! that the attack fails.

use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, Chain};
use q21_core::hash::Hash256;
use q21_core::net::{inbound_group, magic_for, NetGroup, Node};
use q21_core::net::{CMPCT_BUCKET_MAX, INBOUND_PER_GROUP, MAX_BODIES_IN_FLIGHT};
use q21_core::wire::{Message, MAX_HEADERS, PROTOCOL_VERSION};
use q21_core::Network;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::time::Duration;

const NETWORK: Network = Network::Regtest;

fn node() -> Node {
    let g = genesis_block(NETWORK);
    Node::new(NETWORK, Chain::new(NETWORK, g))
}

/// Reads from the stream for at most `secs`, returns everything that arrived.
fn drain(mut s: TcpStream, secs: u64) -> Vec<u8> {
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

/// Complete handshake: we put ourselves in the case most favorable to the
/// attacker, that of an established peer.
fn introduce(s: &mut TcpStream, magic: [u8; 4], nonce: u64) {
    introduce_at_height(s, magic, nonce, 0);
}

/// Introduces itself announcing `height`: above its own, the node then
/// requests headers, and the reply we push to it is expected.
fn introduce_at_height(s: &mut TcpStream, magic: [u8; 4], nonce: u64, height: u64) {
    s.write_all(
        &Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 0,
            nonce,
            user_agent: "test".into(),
            start_height: height,
        }
        .frame(magic),
    )
    .expect("version");
    s.write_all(&Message::VerAck.frame(magic)).expect("verack");
    std::thread::sleep(Duration::from_millis(300));
}

/// A sequence of `n` headers perfectly chained onto `prev`, without a single
/// mined nonce: `seed` changes their content, hence the identifiers.
fn chained_headers(prev: Hash256, n: usize, seed: u8) -> Vec<BlockHeader> {
    let mut v = Vec::with_capacity(n);
    let mut prev = prev;
    for i in 0..n {
        let h = BlockHeader {
            version: 1,
            prev_block: prev,
            merkle_root: Hash256([seed; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([2u8; 32]),
            time: 1_800_000_000 + i as u64,
            bits: 0x2000_ffff,
            height: 1 + i as u64,
            nonce: 0,
        };
        prev = h.block_id();
        v.push(h);
    }
    v
}

/// What the node requested: number of `getdata` items, and distinct hashes.
fn requests(received: &[u8], magic: [u8; 4]) -> (usize, usize) {
    let mut rest = received;
    let mut total = 0usize;
    let mut distinct: HashSet<Hash256> = HashSet::new();
    while let Ok((m, n)) = Message::parse(rest, magic) {
        if let Message::GetData(items) = m {
            total += items.len();
            distinct.extend(items.iter().map(|i| i.hash));
        }
        rest = &rest[n..];
        if rest.is_empty() {
            break;
        }
    }
    (total, distinct.len())
}

/// Headers pushed without a handshake make the node request nothing.
///
/// `getheaders` required the handshake; `headers` did not. The pushed message
/// — the one that makes the node hash two thousand headers and request two
/// thousand bodies — went through the door that the requested message kept
/// shut. A mere TCP connection, without `version`, made the node ask for ten
/// thousand block bodies in five frames.
#[test]
fn anonymous_headers_trigger_no_requests() {
    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);
    let genesis = a.tip_id();

    let mut s = TcpStream::connect(addr).expect("connection");
    // Same anonymous connection: first `getheaders`, which must stay silent.
    s.write_all(
        &Message::GetHeaders {
            locator: vec![genesis],
            stop: Hash256::ZERO,
        }
        .frame(magic),
    )
    .expect("getheaders");
    // Then `headers`, with neither `Version` nor `VerAck`.
    for batch in 0..5u8 {
        let headers = chained_headers(genesis, MAX_HEADERS, batch + 1);
        s.write_all(&Message::Headers(headers).frame(magic))
            .expect("headers");
    }
    let received = drain(s.try_clone().unwrap(), 4);

    let mut rest = &received[..];
    let mut headers_served = 0usize;
    while let Ok((m, n)) = Message::parse(rest, magic) {
        if let Message::Headers(v) = m {
            headers_served += v.len();
        }
        rest = &rest[n..];
        if rest.is_empty() {
            break;
        }
    }
    let (total, distinct) = requests(&received, magic);
    eprintln!(
        "anonymous: getheaders -> {headers_served} header(s) served; \
         headers -> {total} getdata item(s), {distinct} distinct"
    );
    assert_eq!(headers_served, 0, "anonymous getheaders was served");
    assert_eq!(
        total, 0,
        "anonymous headers made the node request {total} block bodies"
    );
    a.shutdown();
}

/// The bodies in flight per peer are capped, whatever the peer announces.
///
/// Headers are only checked for chaining, not for work: a sequence chained
/// onto the tip can be fabricated offline, for free. Each batch of two
/// thousand caused two thousand tokens to be recorded in a table with no cap,
/// whose only purge was time-based. Five batches: ten thousand bodies
/// requested, ten thousand entries, and the peer never disconnected.
///
/// Now, whatever the number of batches, the node never requests more than
/// `MAX_BODIES_IN_FLIGHT` distinct bodies from a peer that delivers nothing.
///
/// Since 0.3.2, a batch of headers is only read if it answers a request. The
/// peer therefore announces a higher height, so that the node requests headers
/// from it: the first batch is expected and read, the next four no longer are.
/// The cap must hold in both cases.
#[test]
fn bodies_in_flight_are_capped_per_peer() {
    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);
    let genesis = a.tip_id();

    let mut s = TcpStream::connect(addr).expect("connection");
    introduce_at_height(&mut s, magic, 0xc0ff_ee01, 1_000_000);

    for batch in 0..5u8 {
        let headers = chained_headers(genesis, MAX_HEADERS, batch + 1);
        s.write_all(&Message::Headers(headers).frame(magic))
            .expect("headers");
    }
    let received = drain(s.try_clone().unwrap(), 6);
    let (total, distinct) = requests(&received, magic);
    eprintln!(
        "established: 5 batches of {MAX_HEADERS} forged headers -> {total} getdata \
         item(s), {distinct} distinct body(ies) requested, cap {MAX_BODIES_IN_FLIGHT}"
    );
    assert!(
        distinct <= MAX_BODIES_IN_FLIGHT,
        "{distinct} distinct bodies requested from a peer that delivers nothing: \
         the cap of {MAX_BODIES_IN_FLIGHT} is not enforced"
    );
    assert!(
        distinct > 0,
        "an established peer with chained headers must be asked for bodies"
    );
    a.shutdown();
}

/// Compact announcements are metered, and insisting gets the peer
/// disconnected.
///
/// After the handshake, a compact announcement whose parent is the tip
/// triggered, without restraint, a scan of the mempool and an allocation of
/// the announced size, under the global lock — with neither bucket nor
/// penalty, whereas `tx` and the snapshot had them. Two hundred announcements
/// of twenty thousand identifiers: two hundred reconstructions, peer still
/// connected.
///
/// Now the reserve is `CMPCT_BUCKET_MAX` unsolicited announcements; beyond
/// it, nothing is reconstructed and the peer loses points until it is
/// disconnected.
///
/// The announced header is **genuine** — mined, at the right difficulty, on
/// time — because since the 2nd campaign of phase 8b a false header is
/// rejected even before the bucket (see `attack_compact_block_without_work`):
/// it really is the bucket being measured here, not the header check. Only the
/// SipHash key changes from one announcement to the next; the short
/// identifiers match nothing, so each announcement starts a reconstruction
/// without ever completing it.
#[test]
fn compact_announcements_are_metered_and_insisting_disconnects() {
    use q21_core::chain::GENESIS_TIME;
    use q21_core::compact::CompactBlock;
    use q21_core::consensus::TARGET_BLOCK_SECS;
    use q21_core::sig::SchemeId;

    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);

    let t = GENESIS_TIME + TARGET_BLOCK_SECS;
    let genuine = a
        .with_chain(|c| c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 50_000_000))
        .expect("mining");
    let header: BlockHeader = genuine.header;

    let mut s = TcpStream::connect(addr).expect("connection");
    introduce(&mut s, magic, 0xc0ff_ee02);

    const ANNOUNCEMENTS: u64 = 200;
    let mut sent = 0u64;
    for k in 0..ANNOUNCEMENTS {
        let c = CompactBlock {
            header,
            nonce: k, // a different SipHash key for each announcement
            short_ids: (0..20_000u64)
                .map(|i| i.wrapping_mul(0x9e37_79b9))
                .collect(),
            prefilled: Vec::new(),
            uncles: Vec::new(),
        };
        if s.write_all(&Message::CmpctBlock(Box::new(c)).frame(magic))
            .is_err()
        {
            break;
        }
        sent += 1;
    }

    // We ask the node, not the socket.
    let mut remaining = a.peer_count();
    for _ in 0..80 {
        if remaining == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        remaining = a.peer_count();
    }
    let received = a.stats.compacts_received.load(Ordering::Relaxed);
    let reconstructed = a.stats.compacts_reconstructed.load(Ordering::Relaxed);
    let rejected = a.stats.compacts_rejected.load(Ordering::Relaxed);
    eprintln!(
        "{sent} announcements sent, {received} received, {reconstructed} \
         reconstruction(s) started, {rejected} rejected by the bucket; \
         remaining peers = {remaining}"
    );
    assert_eq!(
        remaining, 0,
        "a peer that insists beyond its announcement budget must be disconnected"
    );
    // The reserve, plus what the rate could give back during the send: on a
    // slow machine, a few seconds.
    let margin = 4;
    assert!(
        reconstructed <= CMPCT_BUCKET_MAX + margin,
        "{reconstructed} reconstructions started for a reserve of \
         {CMPCT_BUCKET_MAX}: the bucket does not bound the expense"
    );
    assert!(rejected > 0, "no announcement rejected by the bucket");
    a.shutdown();
}

/// The handshake concludes in one exchange, not in a loop.
///
/// Found while testing the cap on bodies in flight: the synchronization went
/// on even without resumption, because every `Version` received made the node
/// send back a `Version` — including to the one replying to ours. Two nodes
/// exchanged `Version`/`VerAck`/`GetAddr`/`Addr` endlessly: forty-eight
/// thousand `Version` in two seconds over loopback, and a header request at
/// each round.
///
/// A peer that behaves like a node — it replies `VerAck` + `Version` to every
/// `Version` — must receive only one `Version`, and the handshake must
/// nevertheless conclude (the node then asks for its address book).
#[test]
fn the_handshake_does_not_loop() {
    let a = node();
    let addr = a.listen("127.0.0.1:0").expect("listen");
    let magic = magic_for(NETWORK);

    let mut s = TcpStream::connect(addr).expect("connection");
    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
    let ours = Message::Version {
        version: PROTOCOL_VERSION,
        timestamp: 0,
        nonce: 0xc0ff_ee03,
        user_agent: "test".into(),
        start_height: 0,
    };
    s.write_all(&ours.frame(magic)).expect("version");

    let start = std::time::Instant::now();
    let mut buffer = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    let (mut versions, mut veracks, mut getaddr) = (0usize, 0usize, 0usize);
    while start.elapsed() < Duration::from_secs(2) {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
        while let Ok((m, n)) = Message::parse(&buffer, magic) {
            buffer.drain(..n);
            match m {
                Message::Version { .. } => {
                    versions += 1;
                    // Like a node: we acknowledge, and introduce ourselves in
                    // turn.
                    s.write_all(&Message::VerAck.frame(magic)).expect("verack");
                    s.write_all(&ours.frame(magic)).expect("version");
                }
                Message::VerAck => veracks += 1,
                Message::GetAddr => getaddr += 1,
                _ => {}
            }
        }
    }
    eprintln!("versions received = {versions}, veracks = {veracks}, getaddr = {getaddr}");
    assert_eq!(
        versions, 1,
        "the node must introduce itself only once, not at every Version received"
    );
    assert_eq!(veracks, 1, "a single acknowledgment");
    assert!(getaddr >= 1, "the handshake did not conclude: no GetAddr");
    a.shutdown();
}

/// Group diversity also applies to IPv6 inbound connections.
///
/// The `INBOUND_PER_GROUP` cap was only computed for IPv4: every IPv6
/// connection fell into "no group". A single `/64` — the allocation of any
/// rented server — could occupy every inbound slot of a node listening on
/// `[::]`.
///
/// The test machine has no IPv6: we cannot open `INBOUND_PER_GROUP + 1`
/// connections from `::1`. So we test the group function itself, the one the
/// admission applies — the admission test on peers with a chosen address is
/// in `net.rs` (`admission_also_bounds_ipv6_inbound`).
#[test]
fn group_diversity_also_applies_to_ipv6() {
    // INBOUND_PER_GROUP + 1 addresses from the same /64: a single group.
    let groups: HashSet<Option<NetGroup>> = (1..=INBOUND_PER_GROUP as u16 + 1)
        .map(|k| {
            let a: SocketAddr = format!("[2001:db8:1:2::{k:x}]:21021").parse().unwrap();
            inbound_group(a)
        })
        .collect();
    assert_eq!(groups.len(), 1, "a /64 must form a single group");
    let only = groups.into_iter().next().unwrap();
    assert!(
        only.is_some(),
        "a public IPv6 address must have a group: without it, the cap of \
         {INBOUND_PER_GROUP} per group does not apply"
    );
    assert_eq!(
        only,
        Some(NetGroup::V6([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2])),
        "the IPv6 group is the /64: the first eight bytes"
    );

    // Another /64 of the same /48: another group.
    let neighbor: SocketAddr = "[2001:db8:1:3::1]:21021".parse().unwrap();
    assert_ne!(inbound_group(neighbor), only);

    // An IPv4 address presented as IPv6 (listening on `[::]`) remains an IPv4
    // address of its /16: otherwise the whole v4 Internet would fall into a
    // single /64.
    let mapped: SocketAddr = "[::ffff:203.0.113.7]:21021".parse().unwrap();
    let v4: SocketAddr = "203.0.113.200:21021".parse().unwrap();
    assert_eq!(inbound_group(mapped), inbound_group(v4));
    assert_eq!(inbound_group(v4), Some(NetGroup::V4([203, 0])));

    // Loopback is a group in neither family.
    assert_eq!(inbound_group("[::1]:21021".parse().unwrap()), None);
    assert_eq!(inbound_group("127.0.0.1:21021".parse().unwrap()), None);
    assert_eq!(
        inbound_group("[::ffff:127.0.0.1]:21021".parse().unwrap()),
        None
    );
}

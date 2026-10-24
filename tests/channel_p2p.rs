//! Channel transport over the real network: capability gating and the promise
//! that a node which does not speak the protocol never receives a channel
//! message and is never banned for lacking it.

use q21_core::address::Network;
use q21_core::chain::{genesis_block, Chain};
use q21_core::net::{ChannelOutcome, ChannelSink, Node};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const NET: Network = Network::Regtest;

/// A sink that records how many frames it received.
struct Recorder {
    count: AtomicU64,
    last: std::sync::Mutex<Vec<u8>>,
}

impl ChannelSink for Recorder {
    fn deliver(&self, _peer: u64, _peer_identity: &str, bytes: &[u8]) -> ChannelOutcome {
        self.count.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = bytes.to_vec();
        ChannelOutcome::default()
    }
}

fn node() -> Node {
    Node::new(NET, Chain::new(NET, genesis_block(NET)))
}

fn wait_established(a: &Node, b: &Node) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10)
        && !(a.peer_count_established() == 1 && b.peer_count_established() == 1)
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(a.peer_count_established(), 1, "a did not establish");
    assert_eq!(b.peer_count_established(), 1, "b did not establish");
}

#[test]
fn a_peer_without_the_capability_is_never_sent_a_channel_message_nor_banned() {
    // `a` speaks the channel protocol; `b` is a plain node (as a v0.4.9 peer
    // would be) and installs no sink.
    let a = node();
    let b = node();
    a.set_channel_sink(Arc::new(Recorder {
        count: AtomicU64::new(0),
        last: Default::default(),
    }));
    assert!(a.channels_enabled());
    assert!(!b.channels_enabled());

    let addr = a.listen("127.0.0.1:0").expect("listen");
    b.connect(addr).expect("connect");
    wait_established(&a, &b);

    // `b` never advertised the capability, so from `a`'s side it is not a
    // channel peer: `a` has nobody to send a channel message to.
    assert!(
        a.channel_peers().is_empty(),
        "a must not treat a non-advertising peer as channel-capable"
    );
    // The handshake completed and stayed up: `b` did not ban `a` for carrying
    // the capability token, and `a` did not ban `b` for lacking it.
    assert_eq!(a.peer_count_established(), 1);
    assert_eq!(b.peer_count_established(), 1);
}

#[test]
fn two_capable_nodes_exchange_a_channel_frame() {
    let a = node();
    let b = node();
    a.set_channel_sink(Arc::new(Recorder {
        count: AtomicU64::new(0),
        last: Default::default(),
    }));
    let b_sink = Arc::new(Recorder {
        count: AtomicU64::new(0),
        last: Default::default(),
    });
    b.set_channel_sink(b_sink.clone());

    let addr = a.listen("127.0.0.1:0").expect("listen");
    b.connect(addr).expect("connect");
    wait_established(&a, &b);

    // Each sees the other as channel-capable.
    let peers = a.channel_peers();
    assert_eq!(peers.len(), 1, "a should see b as channel-capable");
    let b_from_a = peers[0];

    // `a` sends `b` a channel frame; `b`'s sink receives exactly those bytes.
    let payload = vec![0xa5u8; 64];
    assert!(a.send_channel(b_from_a, payload.clone()));
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) && b_sink.count.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        b_sink.count.load(Ordering::SeqCst),
        1,
        "b received the frame"
    );
    assert_eq!(*b_sink.last.lock().unwrap(), payload, "bytes match");
}

#[test]
fn getpeers_lists_a_channel_capable_peer_with_a_usable_id() {
    let a = node();
    let b = node();
    a.set_channel_sink(Arc::new(Recorder {
        count: AtomicU64::new(0),
        last: Default::default(),
    }));
    b.set_channel_sink(Arc::new(Recorder {
        count: AtomicU64::new(0),
        last: Default::default(),
    }));

    let addr = a.listen("127.0.0.1:0").expect("listen");
    b.connect(addr).expect("connect");
    wait_established(&a, &b);

    // `a`'s peer view names `b` with a stable id, the handshake done, the
    // channel capability advertised, and a height.
    let listed = a.peer_list();
    assert_eq!(listed.len(), 1, "exactly one peer listed");
    let b_entry = &listed[0];
    assert!(b_entry.handshake_complete, "handshake reported complete");
    assert!(b_entry.supports_channels, "channel capability reported");

    // The id getpeers reports is exactly the one send_channel (and thus
    // channelopen) takes, and it reaches the capable peer.
    assert!(
        a.send_channel(b_entry.id, vec![0x11u8; 8]),
        "the listed id is the one channelopen would use"
    );
    // It matches what channel_peers reports, too.
    assert_eq!(a.channel_peers(), vec![b_entry.id]);
}

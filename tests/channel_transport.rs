//! The channel transport as a node runs it ([`ChannelTransport`]): sessions
//! over P2P connections, what reaches the channel manager through them, the
//! bounds on the handshake work a stranger can cause, recovery from a record
//! lost or tampered with, and a relay between two nodes.
//!
//! The P2P connection is simulated: each transport's sender pushes into a
//! queue that a pump delivers in order, as TCP would, through a filter that
//! plays the network (or the party between the nodes).

#![cfg(feature = "mldsa")]

use q21_core::address::Network;
use q21_core::channel::keys::NodeIdentity;
use q21_core::channel::link::{ChannelTransport, DosLimits, HANDSHAKE_BURST};
use q21_core::channel::manager::{ChannelManager, Hooks};
use q21_core::channel::transport::{self, Context, Initiator, Limits};
use q21_core::hash::Hash256;
use q21_core::net::ChannelLink;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NET: Network = Network::Regtest;

fn hooks() -> Hooks {
    Hooks {
        fund: Box::new(|_, _| Err("no funds here".into())),
        broadcast: Box::new(|_| Ok(())),
        sweep_address: Box::new(|| Hash256([1; 32])),
        payout_address: Box::new(|| Hash256([2; 32])),
        reserve: Box::new(|_, _| {}),
    }
}

fn manager(seed: u8, tag: &str) -> Arc<ChannelManager> {
    let dir = std::env::temp_dir().join(format!(
        "q21chan-transport-{}-{tag}-{seed}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Arc::new(ChannelManager::new(
        NET,
        10,
        [seed; 32],
        dir,
        12,
        2,
        hooks(),
    ))
}

/// What travels: (destination end, payload).
type Wire = Arc<Mutex<VecDeque<(usize, Vec<u8>)>>>;

/// One node's end of a connection.
struct End {
    t: Arc<ChannelTransport>,
    /// The connection id this end knows the link by.
    conn: u64,
    link: ChannelLink,
}

/// Two ends of one connection; end 0 dialed.
fn link(seed_a: u8, seed_b: u8, tag: &str) -> (Vec<End>, Wire) {
    let wire: Wire = Arc::new(Mutex::new(VecDeque::new()));
    let ends: Vec<End> = [(seed_a, true, 0u64), (seed_b, false, 1u64)]
        .into_iter()
        .map(|(seed, outbound, i)| {
            let t = ChannelTransport::new(manager(seed, tag));
            let w = wire.clone();
            t.set_sender(Box::new(move |_peer, bytes| {
                w.lock().unwrap().push_back((1 - i as usize, bytes));
                true
            }));
            End {
                t,
                conn: 10 + i,
                link: ChannelLink {
                    outbound,
                    local_nonce: 0xa000 + i,
                    remote_nonce: 0xa000 + (1 - i),
                },
            }
        })
        .collect();
    (ends, wire)
}

/// Delivers everything queued, in order, through `filter` (which may drop
/// or rewrite a payload), until quiet. Returns the misconduct charged.
fn pump(
    ends: &[End],
    wire: &Wire,
    mut filter: impl FnMut(usize, Vec<u8>) -> Option<Vec<u8>>,
) -> u32 {
    let mut penalties = 0;
    for _ in 0..10_000 {
        let next = wire.lock().unwrap().pop_front();
        let Some((to, bytes)) = next else {
            return penalties;
        };
        if let Some(bytes) = filter(to, bytes) {
            let e = &ends[to];
            penalties += e.t.deliver(e.conn, &e.link, &bytes).penalize;
        }
    }
    panic!("the link did not fall quiet");
}

/// Lets every handshake frame through, and records only towards the
/// acceptor (end 1): an open goes as far as its Hello, which is all these
/// tests look at.
fn to_acceptor_only(to: usize, b: Vec<u8>) -> Option<Vec<u8>> {
    (to == 1 || transport::frame_type(&b) != Some(transport::T_RECORD)).then_some(b)
}

fn connect(ends: &[End], wire: &Wire) -> u32 {
    for e in ends {
        e.t.connect(e.conn, &e.link);
    }
    pump(ends, wire, |_, b| Some(b))
}

fn node_id(e: &End) -> String {
    e.t.manager().node_id()
}

/// What end `i`'s manager believes its session peer is.
fn seen(ends: &[End], i: usize) -> Option<String> {
    ends[i].t.manager().peer_node_id(ends[i].conn)
}

/// A Hello as the manager frames it: what an open sends first.
fn hello_from(ends: &[End]) -> Vec<u8> {
    ends[0]
        .t
        .manager()
        .open(ends[0].conn, 4_000_000, None, None)
        .unwrap()
}

#[test]
fn a_session_comes_up_on_connect_and_authenticates_both_nodes() {
    let (ends, wire) = link(1, 2, "up");
    assert_eq!(connect(&ends, &wire), 0);
    assert!(ends[0].t.has_session(ends[0].conn));
    assert!(ends[1].t.has_session(ends[1].conn));
    assert_eq!(seen(&ends, 0), Some(node_id(&ends[1])));
    assert_eq!(seen(&ends, 1), Some(node_id(&ends[0])));
}

/// An engine frame reaches the manager only from inside a session: in clear
/// it is not a transport frame at all, and before a session there is none to
/// open it in. Sealed in the session, the same frame is taken.
#[test]
fn channel_frames_reach_the_manager_only_through_a_session() {
    let (ends, wire) = link(3, 4, "only");
    // A session on another connection lends the funder something to open.
    let (other, other_wire) = link(3, 4, "only-other");
    connect(&other, &other_wire);
    let hello = hello_from(&other);
    // In clear, before any session: misconduct, nothing pending.
    let r = ends[1].t.deliver(ends[1].conn, &ends[1].link, &hello);
    assert!(r.penalize > 0);
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 0));
    // A record before any session opens nothing; the responder asks for one.
    let mut s = {
        let a = NodeIdentity::derive(&[9; 32]);
        let b = NodeIdentity::derive(&[8; 32]);
        let ctx = Context {
            network: NET,
            initiator_nonce: 1,
            responder_nonce: 2,
        };
        let (i, init) = Initiator::start(&a, ctx).unwrap();
        let (r, resp) = transport::Responder::accept(&b, ctx, &init).unwrap();
        let (s, _, fin) = i.finish(&a, &resp).unwrap();
        r.finish(&fin).unwrap();
        s
    };
    let record = s.seal(&hello).unwrap();
    let r = ends[1].t.deliver(ends[1].conn, &ends[1].link, &record);
    assert_eq!(r.penalize, 0);
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 0));
    assert_eq!(
        wire.lock().unwrap().pop_front().map(|(_, b)| b),
        Some(vec![transport::VERSION, transport::T_RESET])
    );
    // With the session up: in clear, still refused.
    connect(&ends, &wire);
    let r = ends[1].t.deliver(ends[1].conn, &ends[1].link, &hello);
    assert!(r.penalize > 0);
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 0));
    // Sealed in it, taken.
    let hello = hello_from(&ends);
    assert!(ends[0].t.send(ends[0].conn, hello));
    assert_eq!(pump(&ends, &wire, to_acceptor_only), 0);
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 1));
}

/// A record tampered with on the way ends the session at the end that sees
/// it, which asks for a new one; the next session carries traffic again.
#[test]
fn a_tampered_record_ends_the_session_and_a_new_one_takes_over() {
    let (ends, wire) = link(5, 6, "tamper");
    connect(&ends, &wire);
    let first = seen(&ends, 1);
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    let mut tampered = false;
    let penalties = pump(&ends, &wire, |to, mut b| {
        if to == 1 && transport::frame_type(&b) == Some(transport::T_RECORD) && !tampered {
            tampered = true;
            let at = b.len() / 2;
            b[at] ^= 1;
        }
        Some(b)
    });
    assert!(tampered);
    assert!(penalties > 0, "a forged record is misconduct");
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 0), "acted on");
    // Recovered: a new session, the same peers.
    assert!(ends[0].t.has_session(ends[0].conn));
    assert!(ends[1].t.has_session(ends[1].conn));
    assert_eq!(seen(&ends, 1), first);
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    assert_eq!(pump(&ends, &wire, to_acceptor_only), 0);
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 1));
}

/// A record lost on the way (dropped by a rate limit, say) leaves a gap: the
/// next record ends the session, without blame, and a new one takes over.
#[test]
fn a_lost_record_is_recovered_by_a_new_session() {
    let (ends, wire) = link(7, 8, "gap");
    connect(&ends, &wire);
    // Two frames from the dialer; the first is lost.
    assert!(ends[0].t.send(ends[0].conn, vec![0u8; 40]));
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    let mut dropped = false;
    let penalties = pump(&ends, &wire, |_, b| {
        if !dropped && transport::frame_type(&b) == Some(transport::T_RECORD) {
            dropped = true;
            return None;
        }
        Some(b)
    });
    assert_eq!(penalties, 0, "a lost record is nobody's misconduct");
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 0));
    assert!(ends[0].t.has_session(ends[0].conn));
    assert!(ends[1].t.has_session(ends[1].conn));
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    assert_eq!(pump(&ends, &wire, to_acceptor_only), 0);
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 1));
}

/// A replayed record is refused, and ends the session.
#[test]
fn a_replayed_record_is_refused() {
    let (ends, wire) = link(9, 10, "replay");
    connect(&ends, &wire);
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    let mut copy = None;
    pump(&ends, &wire, |to, b| {
        if transport::frame_type(&b) == Some(transport::T_RECORD) && copy.is_none() {
            copy = Some(b.clone());
        }
        to_acceptor_only(to, b)
    });
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 1));
    let r = ends[1]
        .t
        .deliver(ends[1].conn, &ends[1].link, &copy.unwrap());
    assert!(r.penalize > 0);
    assert!(!ends[1].t.has_session(ends[1].conn), "the session ended");
}

/// Sessions agree on when to rekey, and keep carrying traffic across it.
#[test]
fn sessions_rekey_and_keep_working() {
    let (ends, wire) = link(11, 12, "rekey");
    for e in &ends {
        e.t.set_rekey_limits(Limits {
            records: 2,
            bytes: 1 << 20,
        });
    }
    connect(&ends, &wire);
    for _ in 0..7 {
        assert!(ends[0].t.send(ends[0].conn, vec![0u8; 40]));
        assert!(ends[1].t.send(ends[1].conn, vec![0u8; 40]));
    }
    // The 40-byte frames are not channel frames: each is refused by the
    // manager, without ending the session.
    pump(&ends, &wire, |_, b| Some(b));
    assert!(ends[0].t.has_session(ends[0].conn));
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    assert_eq!(pump(&ends, &wire, to_acceptor_only), 0);
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 1));
}

/// Init frames for the responder, from an initiator identity of our own.
fn inits(n: usize, ctx: Context) -> Vec<Vec<u8>> {
    let me = NodeIdentity::derive(&[0x77; 32]);
    (0..n)
        .map(|_| Initiator::start(&me, ctx).unwrap().1)
        .collect()
}

fn resps(wire: &Wire) -> usize {
    wire.lock()
        .unwrap()
        .drain(..)
        .filter(|(_, b)| transport::frame_type(b) == Some(transport::T_RESP))
        .count()
}

/// One connection gets a few answered handshakes, then one per refill: a
/// stranger cannot make the responder sign at will.
#[test]
fn handshakes_are_bounded_per_connection() {
    let (ends, wire) = link(13, 14, "per-conn");
    let b = &ends[1];
    let ctx = Context {
        network: NET,
        initiator_nonce: b.link.remote_nonce,
        responder_nonce: b.link.local_nonce,
    };
    for init in inits(3 * HANDSHAKE_BURST as usize, ctx) {
        assert_eq!(b.t.deliver(b.conn, &b.link, &init).penalize, 0);
    }
    assert_eq!(resps(&wire), HANDSHAKE_BURST as usize);
}

/// All connections together get a bounded number of answered handshakes.
#[test]
fn handshakes_are_bounded_across_connections() {
    let (ends, wire) = link(15, 16, "global");
    let b = &ends[1];
    b.t.set_dos_limits(DosLimits {
        global_burst: 5,
        global_refill: Duration::from_secs(3600),
        ..DosLimits::default()
    });
    let mut answered = 0;
    for conn in 0..12u64 {
        let link = ChannelLink {
            remote_nonce: 0xb000 + conn,
            ..b.link
        };
        let ctx = Context {
            network: NET,
            initiator_nonce: link.remote_nonce,
            responder_nonce: link.local_nonce,
        };
        let init = inits(1, ctx).remove(0);
        b.t.deliver(100 + conn, &link, &init);
        answered += resps(&wire);
    }
    assert_eq!(answered, 5);
}

/// Responders waiting for a Fin are bounded, and one that waited too long is
/// forgotten.
#[test]
fn pending_handshakes_are_bounded() {
    let (ends, wire) = link(17, 18, "pending");
    let b = &ends[1];
    b.t.set_dos_limits(DosLimits {
        max_pending: 3,
        timeout: Duration::from_millis(300),
        ..DosLimits::default()
    });
    let send_from = |conn: u64| {
        let link = ChannelLink {
            remote_nonce: 0xc000 + conn,
            ..b.link
        };
        let ctx = Context {
            network: NET,
            initiator_nonce: link.remote_nonce,
            responder_nonce: link.local_nonce,
        };
        b.t.deliver(200 + conn, &link, &inits(1, ctx).remove(0));
        resps(&wire)
    };
    let answered: usize = (0..6).map(send_from).sum();
    assert_eq!(answered, 3);
    // Once the pending ones time out, room again.
    std::thread::sleep(Duration::from_millis(350));
    b.t.tick();
    assert_eq!(send_from(10), 1);
}

/// A party between two nodes — dialed by one, dialing the other — passing
/// frames along. Whatever it does, it gets no session in which a channel of
/// theirs could be heard, and reads nothing.
#[test]
fn a_relay_between_two_nodes_gets_no_session_of_theirs() {
    // A (seed 21) dials the relay; the relay dials B (seed 22). A sees the
    // relay's connection nonce, B sees the relay's other one.
    let relay_nonces = (0xd001u64, 0xd002u64);
    let make = |copy_nonces: bool, tag: &str| {
        let (mut ends, wire) = link(21, 22, tag);
        let (to_a, to_b) = if copy_nonces {
            (ends[1].link.local_nonce, ends[0].link.local_nonce)
        } else {
            relay_nonces
        };
        ends[0].link.remote_nonce = to_a;
        ends[1].link.remote_nonce = to_b;
        (ends, wire)
    };

    // 1. Passing every frame on, over connections of its own: the two
    //    transcripts differ in their nonces, and neither end gets a session.
    let (ends, wire) = make(false, "relay-own");
    connect(&ends, &wire);
    assert!(!ends[0].t.has_session(ends[0].conn));
    assert!(!ends[1].t.has_session(ends[1].conn));
    assert_eq!(seen(&ends, 0), None);

    // 2. Substituting its own ephemeral key for A's, to read what B
    //    encapsulates: B signs over the relay's key, A refuses.
    let (ends, wire) = make(true, "relay-kem");
    let mine = NodeIdentity::derive(&[0x55; 32]);
    let ctx = Context {
        network: NET,
        initiator_nonce: 0,
        responder_nonce: 0,
    };
    let (_, own_init) = Initiator::start(&mine, ctx).unwrap();
    let ek = transport::EK_LEN;
    connect_with(&ends, &wire, |_, mut b| {
        if transport::frame_type(&b) == Some(transport::T_INIT) {
            b[2..2 + ek].copy_from_slice(&own_init[2..2 + ek]);
        }
        Some(b)
    });
    assert!(!ends[0].t.has_session(ends[0].conn));
    assert!(!ends[1].t.has_session(ends[1].conn));

    // 3. Substituting the responder's ephemeral key and ciphertext.
    let (ends, wire) = make(true, "relay-kem-resp");
    connect_with(&ends, &wire, |_, mut b| {
        if transport::frame_type(&b) == Some(transport::T_RESP) {
            b[2..2 + ek].copy_from_slice(&own_init[2..2 + ek]);
        }
        Some(b)
    });
    assert!(!ends[0].t.has_session(ends[0].conn));

    // 4. Passing frames on unchanged with the nonces copied: the session is
    //    the two nodes' own, end to end. The relay is a pipe holding no key:
    //    nothing it alters is taken.
    let (ends, wire) = make(true, "relay-pipe");
    connect(&ends, &wire);
    assert_eq!(seen(&ends, 0), Some(node_id(&ends[1])));
    let hello = hello_from(&ends);
    assert!(ends[0].t.send(ends[0].conn, hello.clone()));
    let mut seen_bytes = Vec::new();
    pump(&ends, &wire, |to, b| {
        seen_bytes.extend_from_slice(&b);
        to_acceptor_only(to, b)
    });
    assert!(
        !seen_bytes.windows(64).any(|w| w == &hello[40..104]),
        "the relay read the Hello"
    );
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 1));
    //    A record it alters ends the session; nothing of it is taken.
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    let penalties = pump(&ends, &wire, |to, mut b| {
        if to == 1 && transport::frame_type(&b) == Some(transport::T_RECORD) {
            let last = b.len() - 1;
            b[last] ^= 0x80;
        }
        to_acceptor_only(to, b)
    });
    assert!(penalties > 0);
    // The session it broke is gone, and the open in progress on it.
    assert_eq!(ends[1].t.manager().pending_opens(), (0, 0));
    assert!(ends[1].t.has_session(ends[1].conn), "a new one took over");

    // 5. Running a handshake with each side as itself: each side's session
    //    authenticates the relay, never its real counterparty.
    let (a_to_r, w1) = link(21, 0x99, "relay-self-a");
    let (r_to_b, w2) = link(0x99, 22, "relay-self-b");
    connect(&a_to_r, &w1);
    connect(&r_to_b, &w2);
    let relay = node_id(&a_to_r[1]);
    assert_eq!(seen(&a_to_r, 0), Some(relay.clone()));
    assert_eq!(seen(&r_to_b, 1), Some(relay));
    assert_ne!(seen(&a_to_r, 0), Some(node_id(&r_to_b[1])));
}

fn connect_with(
    ends: &[End],
    wire: &Wire,
    filter: impl FnMut(usize, Vec<u8>) -> Option<Vec<u8>>,
) -> u32 {
    for e in ends {
        e.t.connect(e.conn, &e.link);
    }
    pump(ends, wire, filter)
}

/// A frame of the earlier, clear protocol from a peer advertising version 3
/// is misconduct; the transport carries only its own frames.
#[test]
fn a_frame_of_another_version_is_refused() {
    let (ends, wire) = link(23, 24, "version");
    connect(&ends, &wire);
    let mut v2 = vec![0u8; 33];
    v2.extend_from_slice(&[2, 6]);
    assert!(ends[1].t.deliver(ends[1].conn, &ends[1].link, &v2).penalize > 0);
    let mut init = inits(
        1,
        Context {
            network: NET,
            initiator_nonce: 0,
            responder_nonce: 0,
        },
    )
    .remove(0);
    init[0] = 2;
    assert!(
        ends[1]
            .t
            .deliver(ends[1].conn, &ends[1].link, &init)
            .penalize
            > 0
    );
    assert!(ends[1].t.has_session(ends[1].conn), "nothing ended");
}

/// An `Init` from `who` on a new connection `conn` of `b`: how many answers.
fn init_on(b: &End, wire: &Wire, conn: u64, who: &NodeIdentity) -> usize {
    let link = ChannelLink {
        remote_nonce: 0xe000 + conn,
        ..b.link
    };
    let ctx = Context {
        network: NET,
        initiator_nonce: link.remote_nonce,
        responder_nonce: link.local_nonce,
    };
    let (_, init) = Initiator::start(who, ctx).unwrap();
    b.t.deliver(conn, &link, &init);
    resps(wire)
}

/// Strangers that empty the shared handshake budget do not keep out a peer
/// we hold a channel with: its key draws on a pool of its own, within a
/// share per key, so a stranger claiming that key takes only that share.
#[test]
fn a_channel_peer_is_answered_while_strangers_hold_the_shared_budget() {
    let (ends, wire) = link(31, 32, "known");
    connect(&ends, &wire);
    // The acceptor holds a channel with the dialer (its funding fails here,
    // which leaves the acceptor's channel waiting for it).
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    pump(&ends, &wire, |_, b| Some(b));
    let b = &ends[1];
    assert_eq!(b.t.manager().list().len(), 1);
    b.t.set_dos_limits(DosLimits {
        global_burst: 3,
        global_refill: Duration::from_secs(3600),
        ..DosLimits::default()
    });
    let answered: usize = (0..6u64)
        .map(|k| {
            init_on(
                b,
                &wire,
                300 + k,
                &NodeIdentity::derive(&[0x70 + k as u8; 32]),
            )
        })
        .sum();
    assert_eq!(answered, 3, "the strangers' pool");
    let peer = NodeIdentity::derive(&[31; 32]);
    assert_eq!(peer.id().0, {
        let id = ends[0].t.manager().identity().id();
        id.0
    });
    assert_eq!(init_on(b, &wire, 400, &peer), 1, "the channel peer, first");
    assert_eq!(
        init_on(b, &wire, 401, &peer),
        1,
        "and on another connection"
    );
}

/// A connection can close while its handshake completes, before the link
/// layer hears of it: what was kept for it is pruned at the next tick, and a
/// frame from a connection that is gone makes no entry.
#[test]
fn what_a_connection_gone_unannounced_left_is_pruned() {
    let (ends, wire) = link(33, 34, "prune");
    let b = &ends[1];
    let live = Arc::new(Mutex::new(vec![b.conn]));
    let l = live.clone();
    b.t.set_alive(Box::new(move |p| l.lock().unwrap().contains(&p)));
    connect(&ends, &wire);
    assert!(b.t.has_session(b.conn));
    assert_eq!(b.t.manager().sessions().len(), 1);
    // Gone, and nobody said so.
    live.lock().unwrap().clear();
    b.t.tick();
    assert!(!b.t.has_session(b.conn));
    assert!(b.t.manager().sessions().is_empty());
    // An Init on a connection that is gone is not answered.
    let who = NodeIdentity::derive(&[0x71; 32]);
    assert_eq!(init_on(b, &wire, 500, &who), 0);
}

/// `b` holding a channel with the dialer of a fresh link: the dialer's
/// identity, and the acceptor's end.
fn acceptor_with_a_channel(tag: &str) -> (Vec<End>, Wire, NodeIdentity) {
    let (ends, wire) = link(41, 42, tag);
    connect(&ends, &wire);
    assert!(ends[0].t.send(ends[0].conn, hello_from(&ends)));
    pump(&ends, &wire, |_, b| Some(b));
    assert_eq!(ends[1].t.manager().list().len(), 1);
    (ends, wire, NodeIdentity::derive(&[41; 32]))
}

fn link_for(b: &End, conn: u64) -> (ChannelLink, Context) {
    let link = ChannelLink {
        remote_nonce: 0xf000 + conn,
        ..b.link
    };
    let ctx = Context {
        network: NET,
        initiator_nonce: link.remote_nonce,
        responder_nonce: link.local_nonce,
    };
    (link, ctx)
}

/// A full handshake by `who` on a new connection `conn` of `b`: whether `b`
/// answered it and holds the session.
fn handshake_on(b: &End, wire: &Wire, conn: u64, who: &NodeIdentity) -> bool {
    let (link, ctx) = link_for(b, conn);
    let (ini, init) = Initiator::start(who, ctx).unwrap();
    b.t.deliver(conn, &link, &init);
    let resp = wire
        .lock()
        .unwrap()
        .drain(..)
        .map(|(_, f)| f)
        .find(|f| transport::frame_type(f) == Some(transport::T_RESP));
    let Some(resp) = resp else {
        return false;
    };
    let (_, _, fin) = ini.finish(who, &resp).unwrap();
    assert_eq!(b.t.deliver(conn, &link, &fin).penalize, 0);
    wire.lock().unwrap().clear();
    b.t.has_session(conn)
}

/// An `Init` claiming `whose` key, from a party that does not hold it, on
/// connection `conn` of `b`; then, if `fin`, a `Fin` it cannot sign.
/// Whether `b` answered, and the misconduct charged.
fn claim_on(b: &End, wire: &Wire, conn: u64, whose: &NodeIdentity, fin: bool) -> (bool, u32) {
    let (link, ctx) = link_for(b, conn);
    let me = NodeIdentity::derive(&[0x66; 32]);
    let (ini, mut init) = Initiator::start(&me, ctx).unwrap();
    let at = 2 + transport::EK_LEN;
    init[at..at + transport::PK_LEN].copy_from_slice(whose.pubkey());
    b.t.deliver(conn, &link, &init);
    let resp = wire
        .lock()
        .unwrap()
        .drain(..)
        .map(|(_, f)| f)
        .find(|f| transport::frame_type(f) == Some(transport::T_RESP));
    let Some(resp) = resp else {
        return (false, 0);
    };
    let _ = (ini, resp);
    let mut penalty = 0;
    if fin {
        // A Fin of the right length, whose signature proves nothing.
        let mut forged = vec![0u8; transport::FIN_LEN];
        forged[0] = transport::VERSION;
        forged[1] = transport::T_FIN;
        penalty = b.t.deliver(conn, &link, &forged).penalize;
    }
    wire.lock().unwrap().clear();
    (true, penalty)
}

/// A channel peer's reserved share refills over time: its handshakes are
/// not limited to the first few of the process.
#[test]
fn a_channel_peers_share_refills_over_time() {
    let (ends, wire, peer) = acceptor_with_a_channel("share-refill");
    let b = &ends[1];
    b.t.set_dos_limits(DosLimits {
        burst: 100,
        refill: Duration::from_millis(300),
        global_burst: 0,
        global_refill: Duration::from_secs(3600),
        known_burst: 100,
        known_refill: Duration::from_millis(1),
        ..DosLimits::default()
    });
    assert!(handshake_on(b, &wire, 400, &peer));
    assert!(handshake_on(b, &wire, 400, &peer));
    assert!(!handshake_on(b, &wire, 400, &peer), "its share is spent");
    std::thread::sleep(Duration::from_millis(350));
    assert!(handshake_on(b, &wire, 400, &peer), "and refilled");
}

/// A party claiming a channel peer's key — public, it travels in every
/// handshake — cannot lock that peer out: each of its connections is
/// demoted once its claim goes unproven, a `Fin` that does not prove it is
/// misconduct, and the real peer on its own connection keeps its share.
#[test]
fn a_party_claiming_a_peers_key_cannot_lock_the_peer_out() {
    let (ends, wire, peer) = acceptor_with_a_channel("claimed-key");
    let b = &ends[1];
    b.t.set_dos_limits(DosLimits {
        burst: 100,
        refill: Duration::from_millis(1),
        global_burst: 0,
        global_refill: Duration::from_secs(3600),
        known_burst: 4,
        known_refill: Duration::from_millis(100),
        timeout: Duration::from_millis(150),
        ..DosLimits::default()
    });
    // A claim followed by a Fin that cannot prove it: misconduct.
    let (answered, penalty) = claim_on(b, &wire, 299, &peer, true);
    assert!(answered);
    assert!(penalty > 0, "an unproven claim is misconduct");
    // Three more connections claim the key: the reserved pool is spent, and
    // the real peer finds none left for now.
    for conn in 300..303u64 {
        assert!(claim_on(b, &wire, conn, &peer, false).0);
    }
    assert!(!handshake_on(b, &wire, 400, &peer));
    // Their claims go unproven; the pool refills.
    std::thread::sleep(Duration::from_millis(500));
    b.t.tick();
    for conn in 299..303u64 {
        assert!(
            !claim_on(b, &wire, conn, &peer, false).0,
            "a connection that never proved its claim draws on the pool again"
        );
    }
    assert!(
        handshake_on(b, &wire, 400, &peer),
        "the real peer is locked out"
    );
}

/// A dialer whose Inits go unanswered — a peer that follows the activation
/// but runs no channels — backs off instead of asking every few seconds
/// forever; a frame of the transport from the peer ends the backoff.
#[test]
fn unanswered_inits_back_off() {
    let (ends, wire) = link(43, 44, "backoff");
    let a = &ends[0];
    a.t.set_dos_limits(DosLimits {
        burst: 1000,
        refill: Duration::from_millis(1),
        timeout: Duration::from_millis(30),
        ..DosLimits::default()
    });
    a.t.connect(a.conn, &a.link);
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(1200) {
        std::thread::sleep(Duration::from_millis(5));
        a.t.tick();
    }
    wire.lock().unwrap().clear();
    let attempts = a.t.handshake_attempts();
    // Without the backoff: one every 30 ms, some forty.
    assert!((4..=10).contains(&attempts), "{attempts} attempts");
    // The peer speaks the transport after all: asked again at once.
    let reset = vec![transport::VERSION, transport::T_RESET];
    a.t.deliver(a.conn, &a.link, &reset);
    assert_eq!(a.t.handshake_attempts(), attempts + 1);
}

/// Both ends reach the activation at once: the responder's `Reset` crosses
/// the dialer's `Init`, the dialer starts again, and the answer to its first
/// `Init` arrives before the one to the second. The handshake under way is
/// not lost to it: the session is up without waiting for a retry.
#[test]
fn a_resp_to_a_crossed_init_does_not_cost_the_handshake() {
    let (ends, wire) = link(45, 46, "crossed");
    let (a, b) = (&ends[0], &ends[1]);
    a.t.connect(a.conn, &a.link);
    let init1 = wire.lock().unwrap().pop_front().unwrap().1;
    b.t.deliver(b.conn, &b.link, &init1);
    let resp1 = wire.lock().unwrap().pop_front().unwrap().1;
    // The responder's Reset, sent as it opened, reaches the dialer now.
    let reset = vec![transport::VERSION, transport::T_RESET];
    a.t.deliver(a.conn, &a.link, &reset);
    let init2 = wire.lock().unwrap().pop_front().unwrap().1;
    assert_eq!(transport::frame_type(&init2), Some(transport::T_INIT));
    // The answer to the first Init, then the second exchange.
    assert_eq!(a.t.deliver(a.conn, &a.link, &resp1).penalize, 0);
    b.t.deliver(b.conn, &b.link, &init2);
    assert_eq!(pump(&ends, &wire, |_, f| Some(f)), 0);
    assert!(a.t.has_session(a.conn) && b.t.has_session(b.conn));
}

//! Peer-to-peer layer.
//!
//! Plain TCP, `std::net`, one thread per peer. No networking library: in code
//! that receives bytes from strangers, every dependency is an attack surface
//! nobody has reviewed.
//!
//! # The threading model, and why it cannot deadlock
//!
//! One thread accepts incoming connections, one thread reads each peer. The
//! shared state — chain, mempool, peer table — lives behind a single lock.
//!
//! The rule that prevents deadlock fits in one sentence: **we never hold the
//! lock during a network write.** Each handler computes, under the lock, the
//! list of replies to send, releases it, then sends. A slow peer therefore
//! cannot freeze the whole node by ceasing to read.
//!
//! # What compact relay does here
//!
//! When a block is accepted, we do not send five megabytes to every peer: we
//! announce the compact block, a few kilobytes, and the peer only asks again
//! for what it is missing. This is what reduces propagation latency, hence the
//! orphan rate, hence the superlinear advantage of large miners.

use crate::addr::AddrBook;
use crate::address::Network;
use crate::block::Block;
use crate::chain::{Accept, Chain};
use crate::compact::{CompactBlock, Reconstruction};
use crate::consensus::{NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_TESTNET};
use crate::hash::Hash256;
use crate::mempool::Mempool;
use crate::tx::Transaction;
use crate::wire::{
    InvItem, InvKind, Message, WireError, HEADER_LEN, MAX_PAYLOAD, MIN_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Ban score beyond which we disconnect.
pub const BAN_THRESHOLD: u32 = 100;

/// Cost of an unreadable frame: a peer that sends ten is disconnected.
pub const MISCONDUCT_MALFORMED: u32 = 10;
/// Cost of an invalid block: far more serious, it is wasted work.
pub const MISCONDUCT_BAD_BLOCK: u32 = 50;

/// Maximum number of simultaneous peers.
pub const MAX_PEERS: usize = 32;

/// Slots that listening always leaves free for our outbound connections.
///
/// Without this reserve, a flood of inbound connections filled the
/// `MAX_PEERS` slots and the node could no longer dial anyone from its
/// address book — the anti-eclipse address book was then never consulted.
pub const RESERVED_OUTBOUND_SLOTS: usize = 8;

/// Compact block reconstructions that a peer can leave pending.
///
/// Without a bound, a peer announced incomplete compact blocks one after
/// another and never answered the request for the missing transactions: each
/// announcement stayed in memory, with no limit and no deadline. One
/// reconstruction in flight per peer is what the protocol calls for; four
/// leave room for two blocks found back to back.
pub const MAX_PENDING_RECONSTRUCTIONS: usize = 4;

/// Time granted to a peer to deliver a block body we asked it for.
///
/// # The defect this closes
///
/// Missing bodies were requested from the peer that had announced the
/// headers, and nothing watched for the reply: a peer that answered pings but
/// withheld the bodies froze the synchronization forever. Past this timeout,
/// the request is made again to another peer and the withholder loses points;
/// a node bootstrapped from a single malicious address at least ends up
/// disconnecting it.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(60);

/// Cost of a body requested and never delivered. Two are enough to disconnect.
pub const MISCONDUCT_BODY_WITHHELD: u32 = 50;

/// Block bodies we accept having requested from one peer without having
/// received them yet.
///
/// # The defect this closes
///
/// The table of requested bodies had no cap: its only purge was time-based,
/// at [`BODY_TIMEOUT`]. Yet the headers that cause a body to be requested are
/// checked only for **chaining**, not for work — checking the work of two
/// thousand headers would cost more than what it protects, since Q21's proof
/// is memory-hard. Fabricating offline a sequence of headers perfectly chained
/// onto our tip therefore costs nothing, and each batch of two thousand caused
/// two thousand more tokens to be recorded, without bound, for the minute the
/// delivery timeout lasts.
///
/// The safety bound of header-based synchronization is therefore this cap,
/// not a work check: whatever a peer announces, it never makes us request
/// more than sixteen bodies at a time. The rest waits in a queue, itself
/// bounded ([`MAX_PENDING_BODIES`]), and is only requested as bodies arrive.
/// Sixteen are enough to keep a link busy: a requested body never waits for
/// the next one to go out.
pub const MAX_BODIES_IN_FLIGHT: usize = 16;

/// Block bodies a peer can leave us to request, while waiting for an
/// in-flight slot to free up.
///
/// A batch of headers contains at most [`crate::wire::MAX_HEADERS`]; a peer's
/// queue is replaced at each batch, and therefore never exceeds one batch.
/// These are identifiers, not headers: sixty-four kibibytes at most per peer.
pub const MAX_PENDING_BODIES: usize = crate::wire::MAX_HEADERS;

/// Unsolicited compact block announcements a peer can push right away.
///
/// An honest peer only announces what it has just accepted: a few blocks per
/// minute at most, and the bodies that **we** requested from it are not
/// counted here. Eight let through two blocks found back to back and a small
/// reorg.
pub const CMPCT_BUCKET_MAX: u64 = 8;

/// Sustained rate of unsolicited compact announcements granted to a peer, per
/// second.
///
/// # The defect this closes
///
/// A compact announcement whose parent is known triggered, **under the global
/// lock**, a scan of the mempool with one SipHash per transaction and an
/// allocation of the announced size — up to sixty-five thousand slots —
/// before the slightest check rejected it. `tx` and the snapshot had a
/// bucket; compact announcements did not, and nothing penalized a peer that
/// pushed two hundred in a row. One block per second at a sustained rate is
/// still sixty times the network's cadence.
pub const CMPCT_RATE_PER_SEC: u64 = 1;

/// Cost of a rejected compact announcement: beyond the bucket, or rejected by
/// the reconstruction itself (missing coinbase, index outside the block,
/// absurd number of transactions — shapes only the sender could have
/// produced). Ten are enough to disconnect, as for unreadable frames.
pub const MISCONDUCT_CMPCT_REJECTED: u32 = 10;

/// Inbound connections admitted from the same network group (/16 in IPv4,
/// /64 in IPv6 — see [`inbound_group`]).
///
/// A single address could occupy all thirty-two slots; four per group let a
/// machine or a small network come in several times, without a single range
/// being able to shut the door on the others.
pub const INBOUND_PER_GROUP: usize = 4;

/// Network group of an inbound connection, for slot diversity.
///
/// Two families, two granularities: in IPv4 the address book's `/16`, in IPv6
/// the `/64` — that is the prefix a hosting provider gives to a single
/// machine, hence the unit below which distinct addresses cost nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetGroup {
    V4([u8; 2]),
    V6([u8; 8]),
}

/// Group of an inbound address, or `None` if it has none.
///
/// # The defect this closes
///
/// Group diversity was computed only for IPv4 addresses: every IPv6
/// connection fell into the "no group" case and escaped
/// [`INBOUND_PER_GROUP`]. A single `/64` — the allocation of any rented
/// server — could then occupy every inbound slot, as long as the node
/// listened on IPv6. The `/64` is the answer: it is the accepted equivalent
/// of the v4 `/16`.
///
/// An IPv4 address presented in its IPv6 form (`::ffff:a.b.c.d`, which is
/// what listening on `[::]` yields) is grouped with the IPv4 ones: treating
/// it as a `/64` would put the entire v4 Internet in a single group.
///
/// Loopback is not a group: several nodes on the same machine (regtest,
/// tests) do not eclipse one another.
pub fn inbound_group(address: SocketAddr) -> Option<NetGroup> {
    match address {
        SocketAddr::V4(a) if !a.ip().is_loopback() => {
            Some(NetGroup::V4(crate::addr::group(a.ip().octets())))
        }
        SocketAddr::V4(_) => None,
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) if v4.is_loopback() => None,
            Some(v4) => Some(NetGroup::V4(crate::addr::group(v4.octets()))),
            None if a.ip().is_loopback() => None,
            None => {
                let o = a.ip().octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&o[..8]);
                Some(NetGroup::V6(prefix))
            }
        },
    }
}

/// Header requests a peer can send us right away.
///
/// # The defect this closes
///
/// A header request of a few dozen bytes — a locator we do not know is
/// enough — made us serve two thousand headers from genesis: more than three
/// hundred kibibytes, prepared under the global lock. Nothing bounded the
/// rate: it was the only service without a bucket, and an amplification by a
/// factor of one hundred fifty within reach of any established peer.
///
/// An honest peer only asks for headers again once the bodies of the previous
/// batch have arrived, that is at most once per batch of two thousand blocks.
/// Eight requests right away, then one per second, cover a synchronization at
/// two thousand blocks per second — far beyond what a link delivers.
pub const HEADERS_BUCKET_MAX: u64 = 8;

/// Sustained rate of header requests granted to a peer, per second.
pub const HEADERS_RATE_PER_SEC: u64 = 1;

/// Header replies we expect at most from one peer.
///
/// # The defect this closes
///
/// A batch of headers pushed without having been requested was treated as a
/// reply: two thousand hashes under the lock, and the queue of bodies to
/// request replaced. The code said so — "we only receive headers in reply to
/// our own request" — without checking it. Now each request sent opens a
/// slot, each batch received consumes one, and a batch that arrives without a
/// slot is not read.
pub const MAX_EXPECTED_HEADERS: u8 = 4;

/// Addresses a peer can make us record right away: a full reply to our
/// `getaddr`, which we send to every new peer.
pub const ADDR_BUCKET_MAX: u64 = crate::wire::MAX_ADDR as u64;

/// Sustained rate of addresses granted to a peer, per second.
///
/// # The defect this closes
///
/// With the address book full, each address from an unknown group makes us
/// scan the five hundred twelve groups to evict one, under the global lock: an
/// `addr` frame of a thousand addresses held it for nearly eight milliseconds,
/// and nothing bounded the rate — handler fuzzing campaign. An honest peer
/// announces its address once per lease renewal, and relays what it learns
/// once in a while: ten per second leave plenty of margin. Beyond that, the
/// addresses are ignored, without penalty.
pub const ADDR_RATE_PER_SEC: u64 = 10;

/// Cost of a batch of headers nobody requested. No honest node sends one: only
/// the reply to a request produces one.
pub const MISCONDUCT_UNREQUESTED_HEADERS: u32 = 10;

/// Read timeout. A silent peer is eventually released.
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Silence after which we ask the peer to show signs of life.
///
/// Short enough for a laptop waking up to find the network again in under a
/// minute, long enough not to chatter on a slow link.
pub const PING_AFTER: Duration = Duration::from_secs(45);

/// Silence after which we consider the peer dead and free its slot.
///
/// Counted from the last frame received, not from the `Ping` sent: a peer
/// that answers something else stays alive.
pub const MAX_SILENCE: Duration = Duration::from_secs(100);

/// Maximum time to complete the handshake.
///
/// An inbound connection that has not introduced itself — `Version` **then**
/// `VerAck` — within this time is closed.
///
/// # The defect this timeout closes
///
/// The only liveness check was the silence since the last frame, and **any**
/// frame refreshes that marker, including a `Ping` received before the
/// handshake (to which we reply with a `Pong` without requiring the
/// introduction). An attacker could therefore open inbound connections, send
/// a `Ping` every forty seconds, and never introduce itself: the connection
/// stayed "alive" forever, `handshaked` false. A few /16 groups were enough
/// to occupy the twenty-four inbound slots and shut the door on honest
/// newcomers — a denial of service on the reachability of a bootstrap node,
/// found by the phase 8b red team. A handshake deadline removes these
/// unfinished connections, whatever their surface activity.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Sustained rate granted to a peer for the snapshot service, in bytes per
/// second.
pub const SNAPSHOT_RATE_PER_SEC: u64 = 2 * 1024 * 1024;

/// Reserve granted right away, in bytes. It lets an honest newcomer start
/// without waiting, while bounding what a peer can extract in one go.
pub const SNAPSHOT_BUCKET_MAX: u64 = 8 * 1024 * 1024;

/// Cost of a transaction that is invalid in itself — bad signature, key that
/// does not match the lock, incorrect form, value not conserved. Five are
/// enough to disconnect: a transaction made this way can only come from a
/// peer that fabricates it, never from an honest relay.
pub const MISCONDUCT_BAD_TX: u32 = 20;

/// See [`crate::validate::ValidationError::locally_unverifiable_scheme`].
pub fn locally_unverifiable_scheme(
    e: &crate::validate::ValidationError,
) -> Option<crate::sig::SchemeId> {
    e.locally_unverifiable_scheme()
}

/// Says it once per run, not at every block.
fn report_unverifiable_scheme(scheme: crate::sig::SchemeId) {
    static ALREADY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !ALREADY.swap(true, Ordering::Relaxed) {
        eprintln!(
            "warning: a block carries {} signatures that this binary cannot verify \
             (built without ML-DSA). The peer is not penalized and the block is not \
             adopted. Rebuild: cargo build --release",
            scheme.name()
        );
    }
}

/// Writes an inbound rejection to the log, at most once per minute.
///
/// A rejection used to be silent: the bootstrap node dropped the connection
/// without a word. But a rejection is also something an attacker can trigger
/// at will, by knocking in a loop; one line per rejection would give it a way
/// to flood the log. So we write the first one, then silently count the
/// following ones, and the next line says how many there were.
fn report_rejection(address: Option<SocketAddr>, reason: &str) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) < 60
        || LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let suppressed = SUPPRESSED.swap(0, Ordering::Relaxed);
    let who = address
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "?".into());
    let more = if suppressed > 0 {
        format!(" (and {suppressed} other rejection(s) since the previous message)")
    } else {
        String::new()
    };
    eprintln!("  inbound connection from {who} rejected: {reason}{more}");
}

/// Verification budget a peer can consume right away, in signatures.
///
/// The bucket is now denominated in **signature verifications**, not in
/// transactions: verification is what costs, and a transaction carries as
/// many of them as it has inputs. The cap covers the largest possible valid
/// transaction — bounded by weight, on the order of a few hundred inputs — so
/// that no honest transaction is ever rejected for lack of budget: it drains
/// the bucket, then the bucket refills. See the rate below.
pub const TX_BUCKET_MAX: u64 = 512;

/// Below this number of inputs, a transaction rejected for lack of budget is
/// treated as a message flood (penalizable); above it, as a single large
/// request that may be honest (deferred without penalty). See the
/// `Message::Tx` arm.
pub const FLOOD_INPUT_THRESHOLD: u64 = 16;

/// Sustained rate of signature verifications granted to a peer, per second.
///
/// # The defect this closes, and its real size
///
/// A pushed transaction costs the receiver one post-quantum signature
/// verification **per input**, under the global lock. The previous note
/// claimed "sixteen milliseconds" per ML-DSA-87 verification; the actual
/// measurement (`sig` benchmark, on the test machine) is on the order of
/// **0.33 ms** — the note was fifty times too pessimistic. The danger does
/// not disappear for all that: nothing bounded the number of inputs of a
/// transaction (only weight bounds it, ~271 inputs for ML-DSA-87), and the
/// budget was counted in transactions, not in verifications. A transaction
/// with many inputs, or a flood of such transactions, therefore held the lock
/// far longer than one token per transaction suggested — red team 8b, second
/// campaign.
///
/// Now the bucket is debited in proportion to the inputs. At this rate, the
/// verification work a peer can impose is bounded to ~0.33 ms per unit, that
/// is a negligible fraction of a core, while an ordinary transaction (one or
/// two inputs) is still served unhindered.
pub const TX_RATE_PER_SEC: u64 = 8;

/// Token bucket bounding how much snapshot data a peer can get served.
///
/// # The defect this closes
///
/// The other serving arms count their bytes; the snapshot arm counted
/// nothing. A peer that had passed the handshake could therefore request
/// **the same chunk** in a loop: each nine-byte request caused up to one
/// mebibyte to be copied, **under the global lock** — the one that is also
/// used to validate blocks. The ratio between the cost of the request and the
/// cost of the reply is what defines a denial-of-service vector.
///
/// A sustained rate of two mebibytes per second lets an honest newcomer
/// download its snapshot without trouble — it is an operation it only does
/// once — while reducing abuse to a trickle.
///
/// # Why the instant is a parameter
///
/// A hidden clock makes a rate rule impossible to test other than by
/// sleeping, hence poorly tested. Here the caller supplies the instant: the
/// tests control time, and the rule is checked exactly.
#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    tokens: u64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: SNAPSHOT_BUCKET_MAX,
            last: now,
        }
    }

    /// Allows `bytes` if the bucket contains them, and removes them. The
    /// bucket first refills in proportion to the elapsed time, without ever
    /// exceeding its capacity.
    pub fn allow(&mut self, bytes: u64, now: Instant) -> bool {
        self.allow_with(bytes, now, SNAPSHOT_BUCKET_MAX, SNAPSHOT_RATE_PER_SEC)
    }

    /// A transaction bucket: same rule, in units rather than bytes.
    pub fn for_transactions(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: TX_BUCKET_MAX,
            last: now,
        }
    }

    /// A compact announcement bucket: same rule, in unsolicited announcements.
    pub fn for_compact_announcements(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: CMPCT_BUCKET_MAX,
            last: now,
        }
    }

    /// Would the bucket grant `cost` units now? Removes nothing.
    ///
    /// Used to decide on preliminary work done outside the lock — the proof
    /// of work of a compact announcement — without debiting the same
    /// announcement twice: the real debit remains the handler's, under the
    /// lock.
    pub fn available(&self, cost: u64, now: Instant, max: u64, rate: u64) -> bool {
        let mut copy = *self;
        copy.allow_with(cost, now, max, rate)
    }

    /// A bucket of received addresses: same rule, in addresses.
    pub fn for_addresses(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: ADDR_BUCKET_MAX,
            last: now,
        }
    }

    /// A header request bucket: same rule, in requests.
    pub fn for_header_requests(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: HEADERS_BUCKET_MAX,
            last: now,
        }
    }

    /// Allows `cost` units against a bucket of capacity `max` and a rate of
    /// `rate` per second.
    pub fn allow_with(&mut self, cost: u64, now: Instant, max: u64, rate: u64) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_millis() as u64;
        // The refill is computed in milliseconds: below a millisecond, we
        // credit nothing and do not move the marker, otherwise a burst of very
        // closely spaced requests would never credit anything.
        let gain = elapsed.saturating_mul(rate) / 1000;
        if gain > 0 {
            self.tokens = self.tokens.saturating_add(gain).min(max);
            self.last = now;
        }
        let units = cost;
        if self.tokens >= units {
            self.tokens -= units;
            true
        } else {
            false
        }
    }
}

/// Maximum time for a write to a peer.
///
/// Shorter than the read: a peer may legitimately stay silent for two
/// minutes, it cannot legitimately refuse to take in its bytes for thirty
/// seconds. Beyond that, the connection drops and propagation continues
/// without it.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn magic_for(network: Network) -> [u8; 4] {
    match network {
        Network::Mainnet => NETWORK_MAGIC_MAINNET,
        _ => NETWORK_MAGIC_TESTNET,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Connected peer.
struct Peer {
    addr: SocketAddr,
    writer: Arc<Mutex<TcpStream>>,
    /// True if **we** initiated this connection (outbound). An inbound
    /// connection is chosen by the other end; only outbound ones are chosen
    /// by us, from the address book, with its group diversity. Counting
    /// inbound ones toward the peer target would let an attacker fill our
    /// slots from a single IP and **suppress every outbound dial**: the
    /// anti-eclipse address book would then never be consulted. We keep them
    /// apart.
    outbound: bool,
    /// True as soon as a valid `Version` message has been received from this
    /// peer. The handshake is only complete (`handshaked`) after `Version`
    /// **then** `VerAck`: a `VerAck` alone, without `Version`, must not open
    /// access to expensive messages nor skip the anti-loop nonce check.
    version_received: bool,
    /// True as soon as **we** have sent our `Version` to this peer — on
    /// connection for an outbound one, in reply to theirs for an inbound one.
    /// We only introduce ourselves once: see the `Version` arm.
    version_sent: bool,
    handshaked: bool,
    ban_score: u32,
    /// Height announced by the peer at the handshake.
    start_height: u64,
    /// Compact block reconstructions waiting for transactions.
    pending: HashMap<Hash256, (CompactBlock, Vec<u32>)>,
    /// How much snapshot data this peer can still get served. See
    /// [`TokenBucket`].
    snapshot_bucket: TokenBucket,
    /// The new transactions this peer can still push. See
    /// [`TX_RATE_PER_SEC`].
    tx_bucket: TokenBucket,
    /// The unsolicited compact announcements this peer can still push.
    /// See [`CMPCT_RATE_PER_SEC`].
    cmpct_bucket: TokenBucket,
    /// The header requests this peer can still send us. See
    /// [`HEADERS_RATE_PER_SEC`].
    headers_bucket: TokenBucket,
    /// The addresses this peer can still make us record. See
    /// [`ADDR_RATE_PER_SEC`].
    addr_bucket: TokenBucket,
    /// Header replies we expect from this peer. See
    /// [`MAX_EXPECTED_HEADERS`].
    expected_headers: u8,
    /// Block bodies requested from this peer, and when. See [`BODY_TIMEOUT`].
    /// Never more than [`MAX_BODIES_IN_FLIGHT`] entries: see
    /// [`Peer::note_body_requested`].
    requested_bodies: HashMap<Hash256, Instant>,
    /// Bodies this peer made known to us and that we have not requested yet,
    /// for lack of an in-flight slot. Served in chain order.
    /// See [`MAX_PENDING_BODIES`].
    bodies_to_request: VecDeque<Hash256>,
    /// This peer's last batch of headers was full: it has more, to be
    /// requested again once the queue and the bodies in flight are drained.
    more_expected: bool,
    /// Instant of the last frame received from this peer.
    ///
    /// # The defect this field fixes
    ///
    /// The read loop sets a 120-second timeout on the socket, and handled its
    /// expiry like this:
    ///
    /// ```text
    ///     Err(e) if e.kind() == WouldBlock => continue,
    /// ```
    ///
    /// That is: it started waiting again, indefinitely. A peer that stops
    /// sending was therefore **never** removed. The peer count stayed at one,
    /// and the maintenance loop — which only reconnects if peers are missing
    /// — had nothing to do.
    ///
    /// A laptop whose lid is closed produces exactly that: the connection dies
    /// without any FIN or RST arriving, and the node keeps a ghost peer
    /// forever. Found by closing a MacBook — the chain stopped at height 442
    /// and never moved again.
    ///
    /// On a public network, it is also an eclipse path: opening connections
    /// and then going quiet is enough to occupy every slot.
    last_received: Instant,
    /// Instant of the last `Ping` sent that has gone unanswered.
    pending_ping: Option<Instant>,
    /// Instant the connection was opened, fixed at creation. Used for the
    /// handshake deadline: see [`HANDSHAKE_TIMEOUT`]. Unlike `last_received`,
    /// no frame pushes it back — a connection that does not introduce itself
    /// therefore cannot extend its stay by fidgeting.
    connected_at: Instant,
    /// Number of headers received that connect to nothing known.
    ///
    /// Counts the signs that this peer is on another chain. Without this
    /// counter, two nodes with different geneses exchange blocks indefinitely
    /// that neither can connect — a defect observed by actually running two
    /// nodes, invisible in unit tests because both shared the same genesis
    /// there.
    consecutive_orphans: u32,
}

impl Peer {
    /// Notes a body requested from this peer, if the in-flight room allows it.
    ///
    /// This is the only entry point into `requested_bodies`: whatever path an
    /// identifier arrives by — headers, `inv`, re-request after withholding —
    /// the table never exceeds [`MAX_BODIES_IN_FLIGHT`]. Returns true if the
    /// body is in flight (newly noted, or already).
    fn note_body_requested(&mut self, h: Hash256, now: Instant) -> bool {
        if self.requested_bodies.contains_key(&h) {
            return true;
        }
        if self.requested_bodies.len() >= MAX_BODIES_IN_FLIGHT {
            return false;
        }
        self.requested_bodies.insert(h, now);
        true
    }

    /// What a message we send to this peer commits us to expect.
    ///
    /// A requested body takes an in-flight slot; a header request opens a
    /// reply slot. This is the only place where these two counts go up, and
    /// every send to a peer goes through it: see [`Node::handle`] and
    /// [`Node::send_to`].
    fn note_sent(&mut self, m: &Message, now: Instant) {
        match m {
            Message::GetData(items) => {
                for i in items.iter().filter(|i| i.kind == InvKind::CompactBlock) {
                    self.note_body_requested(i.hash, now);
                }
            }
            Message::GetHeaders { .. } => {
                self.expected_headers = self
                    .expected_headers
                    .saturating_add(1)
                    .min(MAX_EXPECTED_HEADERS);
            }
            _ => {}
        }
    }

    /// Stores a body to request later, if the queue has room.
    fn queue_body(&mut self, h: Hash256) {
        if self.bodies_to_request.len() < MAX_PENDING_BODIES {
            self.bodies_to_request.push_back(h);
        }
    }

    /// Moves the synchronization with this peer forward.
    ///
    /// Frees the slots of the bodies that arrived, fills the remaining ones
    /// from the queue, and — when there is nothing left either in flight or
    /// pending — asks for headers again if the peer announced more.
    ///
    /// # Why the header re-request waits for this moment
    ///
    /// It used to go out as soon as a full batch was received, with a locator
    /// that did not yet contain any of the batch's blocks: the peer replied
    /// with the same batch a second time. Here it goes out once the bodies
    /// have arrived, with an up-to-date locator, and asks for what follows.
    ///
    /// `after_progress` says whether a block from this peer has just been
    /// accepted. Only then does the height announced at the handshake
    /// authorize a re-request: on a mere batch of headers that are all known,
    /// it would make two nodes loop forever when one regards the other as a
    /// side branch. A full batch, on the other hand, always authorizes the
    /// continuation — the continuation is something other than this batch,
    /// since the locator now contains it.
    fn continue_sync(
        &mut self,
        id: u64,
        chain: &Chain,
        outgoing: &mut Vec<Outgoing>,
        now: Instant,
        after_progress: bool,
    ) {
        if !self.handshaked {
            return;
        }
        self.requested_bodies.retain(|h, _| !chain.has_block(h));
        let mut items = Vec::new();
        while self.requested_bodies.len() < MAX_BODIES_IN_FLIGHT {
            let Some(h) = self.bodies_to_request.pop_front() else {
                break;
            };
            if chain.has_block(&h) || self.requested_bodies.contains_key(&h) {
                continue;
            }
            if self.note_body_requested(h, now) {
                items.push(InvItem {
                    kind: InvKind::CompactBlock,
                    hash: h,
                });
            }
        }
        if !items.is_empty() {
            outgoing.push(Outgoing {
                peer: id,
                message: Message::GetData(items),
            });
            return;
        }
        let drained = self.bodies_to_request.is_empty() && self.requested_bodies.is_empty();
        let has_more = self.more_expected || (after_progress && self.start_height > chain.height());
        if drained && has_more {
            self.more_expected = false;
            outgoing.push(Outgoing {
                peer: id,
                message: Message::GetHeaders {
                    locator: chain.locator(),
                    stop: Hash256::ZERO,
                },
            });
        }
    }
}

/// Shared state of the node.
struct Shared {
    chain: Chain,
    mempool: Mempool,
    /// Address book, organized by network group.
    ///
    /// Lives under the same lock as the rest: a peer that announces addresses
    /// does so in the same message as the rest of its traffic, and splitting
    /// the locks would save time that does not exist at the cost of a deadlock
    /// risk that does.
    book: AddrBook,
    peers: HashMap<u64, Peer>,
    network: Network,
    /// The node's nonce: used to detect a connection to oneself.
    nonce: u64,
    /// Where to record accepted blocks. Absent in pure memory (tests).
    journal: Option<Arc<dyn crate::chain::Journal>>,
    /// The already-serialized fast-sync snapshot, kept as long as the tip
    /// does not move. Rebuilding it is expensive (state snapshot +
    /// commitment): we only do it on request, and only once per tip.
    snapshot_cache: Option<SnapshotCache>,
}

/// The served snapshot, frozen for a given tip.
struct SnapshotCache {
    tip: Hash256,
    bytes: Vec<u8>,
    height: u64,
    announced_tip: Hash256,
    commitment: Hash256,
}

/// Rebuilds the served snapshot if the tip has moved since last time.
///
/// A client downloading while the tip advances will receive chunks of a
/// snapshot different from the announced one; its commitment check detects
/// it and it starts over. Consistency is therefore never broken silently.
fn refresh_snapshot(g: &mut Shared) {
    let tip = g.chain.tip_id();
    if g.snapshot_cache.as_ref().map(|c| c.tip) == Some(tip) {
        return;
    }
    g.snapshot_cache = g.chain.build_sync_snapshot().map(|a| {
        let bytes = a.encode();
        SnapshotCache {
            tip,
            height: a.announced_height().unwrap_or(0),
            announced_tip: a.announced_tip().unwrap_or(Hash256::ZERO),
            commitment: a.announced_commitment().unwrap_or(Hash256::ZERO),
            bytes,
        }
    });
}

/// Maximum items served in reply to a single message.
///
/// An honest peer never asks for that many at once; a hostile peer will get
/// nothing more.
const MAX_SERVED_ITEMS: usize = 512;

/// Outgoing byte budget for the reply to a single message.
///
/// This is the bound that turns an amplification into a plain request. Set
/// below the protocol's `MAX_PAYLOAD`: a reply the peer could not read would
/// be nothing but one-way waste.
const REPLY_BYTE_BUDGET: usize = 4 * 1024 * 1024;

/// Reply to send after the lock is released.
struct Outgoing {
    peer: u64,
    message: Message,
}

#[derive(Clone)]
pub struct Node {
    shared: Arc<Mutex<Shared>>,
    magic: [u8; 4],
    next_id: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    /// Observation counters, useful for tests and operations.
    pub stats: Arc<Stats>,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub blocks_received: AtomicU64,
    pub blocks_accepted: AtomicU64,
    pub txs_received: AtomicU64,
    pub compacts_received: AtomicU64,
    /// Compact blocks reconstructed without any round trip.
    pub compacts_without_round_trip: AtomicU64,
    /// Compact announcements for which a reconstruction was started — mempool
    /// scan and allocation, under the lock. This is the expense the bucket
    /// bounds; see [`CMPCT_RATE_PER_SEC`].
    pub compacts_reconstructed: AtomicU64,
    /// Compact announcements rejected by the bucket, without reconstruction.
    pub compacts_rejected: AtomicU64,
    /// Compact announcements whose header was rejected **before** any
    /// reconstruction: wrong height, difficulty, timestamp or work. Nothing
    /// was searched or allocated for them; see [`Chain::check_header`].
    pub compacts_header_rejected: AtomicU64,
    pub peers_banned: AtomicU64,
    /// Blocks whose parent was unknown at the time they arrived.
    ///
    /// Must stay close to zero: strict header-based synchronization only
    /// requests a body after it connects. A counter that runs away signals a
    /// resynchronization loop — exactly the defect that only shows up when
    /// running real processes.
    pub orphan_blocks: AtomicU64,
    /// Blocks rejected by validation.
    pub invalid_blocks: AtomicU64,
    /// `addr` frames part of which was ignored, for lack of the peer's budget.
    pub addresses_ignored: AtomicU64,
    /// Header requests rejected by the peer's bucket, without serving anything.
    pub headers_rejected: AtomicU64,
    /// Batches of headers received without having been requested, and
    /// therefore ignored.
    pub unrequested_headers: AtomicU64,
    /// Proofs of work verified **outside** the global lock, before the block
    /// or announcement is processed. See [`Node::check_work_outside_lock`].
    pub work_outside_lock: AtomicU64,
}

impl Node {
    pub fn new(network: Network, chain: Chain) -> Node {
        let nonce = {
            // Entropy source without dependencies: the fine-grained clock is
            // enough to tell apart two nodes on the same machine.
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
                .unwrap_or(1);
            t.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1)
        };
        Node {
            shared: Arc::new(Mutex::new(Shared {
                chain,
                mempool: Mempool::new(),
                // Loopback only makes sense on test networks, where everything
                // runs on a single machine.
                book: AddrBook::new(!matches!(network, Network::Mainnet)),
                peers: HashMap::new(),
                network,
                nonce,
                journal: None,
                snapshot_cache: None,
            })),
            magic: magic_for(network),
            next_id: Arc::new(AtomicU64::new(1)),
            stop: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Stats::default()),
        }
    }

    /// Plugs in the journal where accepted blocks are recorded.
    ///
    /// To be called **before** letting in the slightest block: a block
    /// accepted without a journal is a block lost at the next shutdown.
    pub fn set_journal(&self, j: Arc<dyn crate::chain::Journal>) {
        self.shared.lock().unwrap().journal = Some(j);
    }

    pub fn height(&self) -> u64 {
        self.shared.lock().unwrap().chain.height()
    }

    // -----------------------------------------------------------------------
    // Address book
    // -----------------------------------------------------------------------

    /// Pours addresses into the address book — bootstrap or reload from disk.
    pub fn seed_addresses(&self, v: &[crate::wire::NetAddr]) -> usize {
        let mut g = self.shared.lock().unwrap();
        let n = unix_now();
        v.iter().filter(|a| g.book.add(**a, n)).count()
    }

    /// Addresses to try, all from distinct network groups and distinct from
    /// those of the peers already connected.
    pub fn addresses_to_try(&self, count: usize) -> Vec<crate::wire::NetAddr> {
        let g = self.shared.lock().unwrap();
        let already: Vec<[u8; 4]> = g
            .peers
            .values()
            .filter_map(|p| match p.addr {
                SocketAddr::V4(a) => Some(a.ip().octets()),
                _ => None,
            })
            .collect();
        g.book.select(count, &already, unix_now())
    }

    /// Distinct network groups among the connected peers.
    ///
    /// This is the measure that matters for eclipse: ten peers in a single
    /// group are worth a single peer.
    pub fn peer_groups(&self) -> usize {
        let g = self.shared.lock().unwrap();
        let s: std::collections::HashSet<[u8; 2]> = g
            .peers
            .values()
            .filter_map(|p| match p.addr {
                SocketAddr::V4(a) => Some(crate::addr::group(a.ip().octets())),
                _ => None,
            })
            .collect();
        s.len()
    }

    pub fn address_count(&self) -> usize {
        self.shared.lock().unwrap().book.len()
    }

    /// Copy of the address book, to write it to disk.
    pub fn address_entries(&self) -> Vec<crate::addr::AddrEntry> {
        self.shared.lock().unwrap().book.all()
    }

    pub fn note_connect_success(&self, ip: [u8; 4], port: u16) {
        let mut g = self.shared.lock().unwrap();
        g.book.add(
            crate::wire::NetAddr {
                ip,
                port,
                last_seen: unix_now(),
            },
            unix_now(),
        );
        g.book.mark_success(ip, port, unix_now());
    }

    pub fn note_connect_failure(&self, ip: [u8; 4], port: u16) {
        self.shared.lock().unwrap().book.mark_failure(ip, port);
    }

    pub fn tip_id(&self) -> Hash256 {
        self.shared.lock().unwrap().chain.tip_id()
    }

    /// Highest height announced by a peer whose handshake is done.
    ///
    /// This is the only measure a node has to know whether it is behind. It is
    /// worth what the peers are worth: an eclipsed node will see the height its
    /// adversary shows it. The address book is what makes this situation
    /// expensive to produce.
    pub fn max_announced_height(&self) -> u64 {
        let g = self.shared.lock().unwrap();
        g.peers
            .values()
            .filter(|p| p.handshaked)
            .map(|p| p.start_height)
            .max()
            .unwrap_or(0)
    }

    /// Number of open connections, **whether the handshake is done or not**.
    ///
    /// A peer counts here as soon as it is registered, before `Version` and
    /// `VerAck`. The sends that require the introduction — `announce_block`,
    /// `announce_tx` — will only see it once `handshaked`. Waiting for
    /// `peer_count() == 1` therefore does not guarantee that an announcement
    /// will be received.
    pub fn peer_count(&self) -> usize {
        self.shared.lock().unwrap().peers.len()
    }

    /// Number of peers whose handshake is **complete**.
    ///
    /// This is the only count that says "we are really talking". A TCP
    /// connection accepted and then closed by the peer — because it is full,
    /// or because our geneses differ — counts in `peer_count` for the space of
    /// a breath and never here. A diagnostic that only looked at `peer_count`
    /// would therefore announce a link where there is none.
    pub fn peer_count_established(&self) -> usize {
        self.shared
            .lock()
            .unwrap()
            .peers
            .values()
            .filter(|p| p.handshaked)
            .count()
    }

    /// Number of **outbound** connections — the ones we initiated from the
    /// address book. It is this count, not the total, that the maintenance
    /// loop must bring back to the target: otherwise a flood of inbound
    /// connections from a single IP is enough to prevent us from going out to
    /// find diversified peers, and the anti-eclipse defense falls.
    /// Does an inbound connection have its place?
    ///
    /// Three bounds: the total, the outbound reserve, and the share of a
    /// single network group — IPv4 and IPv6 alike, see [`inbound_group`].
    /// See [`RESERVED_OUTBOUND_SLOTS`] and [`INBOUND_PER_GROUP`].
    ///
    /// Takes the address rather than the stream: this way the rule can be
    /// tested on addresses that a machine without IPv6 could not open.
    /// Listening goes through [`Self::inbound_rejection`], which also gives
    /// the reason to the log.
    #[cfg(test)]
    fn admit_inbound(&self, address: Option<SocketAddr>) -> bool {
        self.inbound_rejection(address).is_none()
    }

    /// Why an inbound connection has no place, or `None` if it has one.
    ///
    /// Same rule as [`Self::admit_inbound`], which uses it; the reason goes to
    /// the log. A rejection without explanation cost hours: a household whose
    /// devices occupied the four slots of its group saw its fifth device
    /// "waiting" endlessly, and nothing, neither on the server side nor on the
    /// wallet side, said why.
    fn inbound_rejection(&self, address: Option<SocketAddr>) -> Option<&'static str> {
        let g = self.shared.lock().unwrap();
        let total = g.peers.len();
        if total >= MAX_PEERS {
            return Some("all slots are taken");
        }
        let inbound = g.peers.values().filter(|p| !p.outbound).count();
        if inbound + RESERVED_OUTBOUND_SLOTS >= MAX_PEERS {
            return Some("all inbound slots are taken");
        }
        if let Some(gr) = address.and_then(inbound_group) {
            let same = g
                .peers
                .values()
                .filter(|p| !p.outbound)
                .filter(|p| inbound_group(p.addr) == Some(gr))
                .count();
            if same >= INBOUND_PER_GROUP {
                return Some("its address group already has all its slots");
            }
        }
        None
    }

    pub fn peer_count_outbound(&self) -> usize {
        self.shared
            .lock()
            .unwrap()
            .peers
            .values()
            .filter(|p| p.outbound)
            .count()
    }

    /// Drops every connection, and returns how many there were.
    ///
    /// Used when a machine wakes up from sleep: after a few minutes of
    /// suspension, all TCP links are dead anyway — the router has forgotten
    /// its translation table, the peer on the other end has given up. Waiting
    /// for the silence timeout would cost two more minutes to someone who has
    /// simply reopened their laptop.
    ///
    /// Being wrong only costs a reconnection.
    pub fn disconnect_all_peers(&self) -> usize {
        let ids: Vec<u64> = self.shared.lock().unwrap().peers.keys().copied().collect();
        let n = ids.len();
        for id in ids {
            self.disconnect(id);
        }
        n
    }

    /// Are we already connected to this address?
    ///
    /// Used to avoid opening a second connection to a bootstrap address that
    /// we retry periodically: two links to the same peer waste a slot and
    /// double the traffic without bringing anything.
    pub fn is_connected_to(&self, addr: SocketAddr) -> bool {
        self.shared
            .lock()
            .unwrap()
            .peers
            .values()
            .any(|p| p.addr == addr)
    }

    /// Queries silent peers, and frees the slot of those that are dead.
    ///
    /// # Why it is not the socket that says so
    ///
    /// A TCP connection can outlive the machine on the other end. A laptop
    /// whose lid is closed, an unplugged cable, a router that forgets its
    /// table: in these cases, no FIN or RST ever arrives. The socket stays
    /// open, the read waits, and the node believes it has a peer.
    ///
    /// The only reliable sign of life is **a received frame**. So we ask the
    /// peer to show signs of life after a silence, and free its slot if it
    /// does not. This is what Bitcoin does, for the same reason.
    ///
    /// Returns the number of peers disconnected.
    pub fn maintain_peers(&self) -> usize {
        let now = Instant::now();
        let mut to_ping: Vec<(u64, Arc<Mutex<TcpStream>>)> = Vec::new();
        let mut dead: Vec<u64> = Vec::new();
        let magic = self.magic;
        let mut to_rerequest: Vec<Outgoing> = Vec::new();
        let nonce = {
            let mut g = self.shared.lock().unwrap();
            let Shared {
                ref chain,
                ref mut peers,
                ..
            } = *g;
            // --- The requested bodies: delivered, pending, or withheld?
            let mut withheld: Vec<Hash256> = Vec::new();
            let mut withholders: Vec<u64> = Vec::new();
            for (id, p) in peers.iter_mut() {
                let mut overdue = 0u32;
                p.requested_bodies.retain(|h, since| {
                    if chain.has_block(h) {
                        return false;
                    }
                    if now.duration_since(*since) >= BODY_TIMEOUT {
                        overdue += 1;
                        withheld.push(*h);
                        return false;
                    }
                    true
                });
                if overdue > 0 {
                    withholders.push(*id);
                    p.ban_score = p.ban_score.saturating_add(MISCONDUCT_BODY_WITHHELD);
                    if p.ban_score >= BAN_THRESHOLD {
                        self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                        dead.push(*id);
                    }
                }
            }
            if !withheld.is_empty() {
                // To another peer — established, and not the one withholding.
                let other = peers
                    .iter()
                    .filter(|(id, p)| {
                        p.handshaked && !dead.contains(id) && !withholders.contains(id)
                    })
                    .map(|(id, _)| *id)
                    .next();
                if let Some(id) = other {
                    // As a full block, and without noting it in flight: this
                    // peer announced none of these bodies, it must not be
                    // punished for not having them. Noted in flight, the
                    // re-request cost it fifty points at the next deadline —
                    // and an identifier invented by an anonymous connection
                    // thus disconnected an honest peer in two rounds. The
                    // number stays bounded: at most `MAX_BODIES_IN_FLIGHT` per
                    // withholder.
                    to_rerequest.push(Outgoing {
                        peer: id,
                        message: Message::GetData(
                            withheld
                                .iter()
                                .map(|h| InvItem {
                                    kind: InvKind::Block,
                                    hash: *h,
                                })
                                .collect(),
                        ),
                    });
                    if let Some(p) = peers.get_mut(&id) {
                        p.continue_sync(id, chain, &mut to_rerequest, now, false);
                    }
                }
            }
            for (id, p) in peers.iter_mut() {
                if dead.contains(id) {
                    continue;
                }
                let silence = now.duration_since(p.last_received);
                if silence >= MAX_SILENCE {
                    dead.push(*id);
                } else if !p.handshaked && now.duration_since(p.connected_at) >= HANDSHAKE_TIMEOUT {
                    // Handshake never completed within the time limit: the
                    // inbound slot must not stay squatted by a connection that
                    // only fidgets. See HANDSHAKE_TIMEOUT.
                    dead.push(*id);
                } else if silence >= PING_AFTER && p.pending_ping.is_none() {
                    p.pending_ping = Some(now);
                    to_ping.push((*id, p.writer.clone()));
                }
            }
            g.nonce
        };
        for e in to_rerequest {
            self.send_to(e.peer, &e.message);
        }
        // The write happens outside the lock: a clogged socket would otherwise
        // block the whole node for the duration of the write timeout.
        for (_, writer) in to_ping {
            let _ = write_message(&writer, &Message::Ping(nonce), magic);
        }
        let dropped = dead.len();
        for id in dead {
            // `disconnect` closes the socket in both directions: the read
            // loop, which was waiting, exits with an error and its thread dies.
            self.disconnect(id);
        }
        dropped
    }

    pub fn mempool_len(&self) -> usize {
        self.shared.lock().unwrap().mempool.len()
    }

    /// Runs `f` with exclusive access to the chain.
    pub fn with_chain<R>(&self, f: impl FnOnce(&mut Chain) -> R) -> R {
        let mut g = self.shared.lock().unwrap();
        f(&mut g.chain)
    }

    pub fn with_mempool<R>(&self, f: impl FnOnce(&mut Mempool) -> R) -> R {
        let mut g = self.shared.lock().unwrap();
        f(&mut g.mempool)
    }

    /// Runs `f` with exclusive access to the chain **and** the mempool.
    ///
    /// Both live under the same lock. Calling `with_chain` inside
    /// `with_mempool` — or the reverse — would take it twice and freeze the
    /// node on the spot. Any operation that needs both goes through here.
    pub fn with_chain_and_mempool<R>(&self, f: impl FnOnce(&mut Chain, &mut Mempool) -> R) -> R {
        let mut g = self.shared.lock().unwrap();
        let Shared {
            ref mut chain,
            ref mut mempool,
            ..
        } = *g;
        f(chain, mempool)
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Opens a listening port and accepts connections in the background.
    pub fn listen(&self, addr: &str) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        let node = self.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if node.is_stopped() {
                    break;
                }
                match stream {
                    Ok(s) => {
                        let address = s.peer_addr().ok();
                        if let Some(reason) = node.inbound_rejection(address) {
                            report_rejection(address, reason);
                            continue;
                        }
                        node.start_peer(s, false);
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(local)
    }

    /// Connects to a peer and starts the handshake.
    pub fn connect(&self, addr: SocketAddr) -> std::io::Result<u64> {
        // Four seconds: enough for a slow link, not enough for a batch of
        // silent addresses to hold the maintenance loop for a minute.
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(4))?;
        Ok(self.start_peer(stream, true))
    }

    fn start_peer(&self, stream: TcpStream, outbound: bool) -> u64 {
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        // Without a write timeout, a peer that never takes in its bytes blocks
        // the thread writing to it indefinitely — while holding the mutex of
        // its stream. Since broadcasts write to every peer, a single silent
        // peer ended up blocking the entire propagation.
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
        let _ = stream.set_nodelay(true);
        let addr = stream
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let reader = match stream.try_clone() {
            Ok(f) => f,
            Err(_) => return 0,
        };

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let writer = Arc::new(Mutex::new(stream));

        {
            let mut g = self.shared.lock().unwrap();
            g.peers.insert(
                id,
                Peer {
                    addr,
                    writer: writer.clone(),
                    outbound,
                    snapshot_bucket: TokenBucket::new(Instant::now()),
                    tx_bucket: TokenBucket::for_transactions(Instant::now()),
                    cmpct_bucket: TokenBucket::for_compact_announcements(Instant::now()),
                    headers_bucket: TokenBucket::for_header_requests(Instant::now()),
                    addr_bucket: TokenBucket::for_addresses(Instant::now()),
                    expected_headers: 0,
                    requested_bodies: HashMap::new(),
                    bodies_to_request: VecDeque::new(),
                    more_expected: false,
                    version_received: false,
                    version_sent: outbound,
                    handshaked: false,
                    ban_score: 0,
                    start_height: 0,
                    pending: HashMap::new(),
                    consecutive_orphans: 0,
                    last_received: Instant::now(),
                    pending_ping: None,
                    connected_at: Instant::now(),
                },
            );
        }

        // The connecting side speaks first.
        if outbound {
            let (nonce, height) = {
                let g = self.shared.lock().unwrap();
                (g.nonce, g.chain.height())
            };
            let v = Message::Version {
                version: PROTOCOL_VERSION,
                timestamp: unix_now(),
                nonce,
                user_agent: "q21:0.4".into(),
                start_height: height,
            };
            let _ = write_message(&writer, &v, self.magic);
        }

        let node = self.clone();
        std::thread::spawn(move || {
            node.read_loop(id, reader);
            node.disconnect(id);
        });
        id
    }

    fn disconnect(&self, id: u64) {
        let mut g = self.shared.lock().unwrap();
        if let Some(p) = g.peers.remove(&id) {
            let _ = p.writer.lock().unwrap().shutdown(std::net::Shutdown::Both);
        }
    }

    /// A peer's read loop.
    ///
    /// The buffer never grows beyond the maximum size of a frame: this is what
    /// prevents a peer from exhausting memory by announcing a gigantic payload
    /// and then sending nothing.
    fn read_loop(&self, id: u64, mut stream: TcpStream) {
        let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut chunk = [0u8; 32 * 1024];

        loop {
            if self.is_stopped() {
                return;
            }
            let n = match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => return,
            };
            buffer.extend_from_slice(&chunk[..n]);

            if buffer.len() > MAX_PAYLOAD + HEADER_LEN {
                self.penalize(id, MISCONDUCT_MALFORMED * 10);
                return;
            }

            loop {
                match Message::parse(&buffer, self.magic) {
                    Ok((msg, consumed)) => {
                        buffer.drain(..consumed);
                        if !self.handle(id, msg) {
                            return;
                        }
                    }
                    Err(WireError::Incomplete) => break,
                    Err(_) => {
                        self.penalize(id, MISCONDUCT_MALFORMED);
                        // Lost framing cannot be recovered: we disconnect.
                        return;
                    }
                }
            }
        }
    }

    /// A transaction that only its author could have made invalid.
    fn tx_invalid_in_itself(e: &crate::mempool::MempoolError) -> bool {
        use crate::mempool::MempoolError as M;
        use crate::validate::ValidationError as V;
        match e {
            // "I cannot verify" is not "you are lying": see
            // `locally_unverifiable_scheme`.
            M::Validation(v) if locally_unverifiable_scheme(v).is_some() => false,
            M::Validation(
                V::Signature(_)
                | V::KeyDoesNotMatchLock
                | V::Transaction(_)
                | V::ValueNotConserved { .. }
                | V::SchemeForbiddenOnNetwork(_)
                | V::DustOutput { .. },
            ) => true,
            _ => false,
        }
    }

    fn penalize(&self, id: u64, points: u32) -> bool {
        let mut g = self.shared.lock().unwrap();
        if let Some(p) = g.peers.get_mut(&id) {
            p.ban_score = p.ban_score.saturating_add(points);
            if p.ban_score >= BAN_THRESHOLD {
                self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        true
    }

    /// Verifies the proof of work of a received header **without** holding the
    /// global lock, and keeps the verdict for the chain.
    ///
    /// # The defect this closes
    ///
    /// A received block or compact announcement made us compute its
    /// memory-hard hash under the global lock — and, at the first block of an
    /// epoch, build that epoch's entire cache, several seconds on mainnet.
    /// During that time, no other peer was served and the wallet no longer
    /// responded. A peer only had to send headers with the correct context and
    /// wrong work to occupy the lock at will, within the limit of its score.
    ///
    /// The lock is now only taken for the cheap checks — handshake,
    /// announcement budget, connection to the chain, difficulty, timestamp:
    /// see [`Chain::header_to_prove`]. The hash is computed afterwards, with
    /// the lock released, and its verdict recorded in the chain's registry.
    /// The handler then takes its usual path, where the chain reads the
    /// verdict back instead of recomputing it. No rule changes: the checks are
    /// all redone under the lock, in the same order.
    ///
    /// A compact announcement that the peer's budget would reject is not
    /// computed: the budget comes before the work, here as under the lock.
    fn check_work_outside_lock(
        &self,
        id: u64,
        header: &crate::block::BlockHeader,
        announcement: bool,
    ) {
        let to_prove = {
            let g = self.shared.lock().unwrap();
            let Some(p) = g.peers.get(&id) else {
                return;
            };
            if !p.handshaked {
                return;
            }
            if announcement
                && !p.requested_bodies.contains_key(&header.block_id())
                && !p.cmpct_bucket.available(
                    1,
                    Instant::now(),
                    CMPCT_BUCKET_MAX,
                    CMPCT_RATE_PER_SEC,
                )
            {
                return;
            }
            g.chain.header_to_prove(header, unix_now())
        }; // --- lock released: the computation that follows blocks nobody ---
        if let Some((engine, memo)) = to_prove {
            use crate::pow::PowEngine;
            memo.record(header.block_id(), engine.check(header));
            self.stats.work_outside_lock.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Handles a message. Returns `false` if the connection must be dropped.
    fn handle(&self, id: u64, msg: Message) -> bool {
        let mut outgoing: Vec<Outgoing> = Vec::new();
        let mut drop_peer = false;

        // The work of a block or of an announcement is checked before the lock.
        match &msg {
            Message::Block(b) => self.check_work_outside_lock(id, &b.header, false),
            Message::CmpctBlock(c) => self.check_work_outside_lock(id, &c.header, true),
            _ => {}
        }

        {
            let mut g = self.shared.lock().unwrap();
            // A received frame, whatever it is, proves that the peer is alive.
            // It is the only proof that counts: an open socket is not one, it
            // can outlive the machine on the other end.
            if let Some(p) = g.peers.get_mut(&id) {
                p.last_received = Instant::now();
                p.pending_ping = None;
            }
            let network = g.network;
            let local_nonce = g.nonce;
            // The handshake gates access to expensive messages. Serving a
            // `getdata` to a mere anonymous TCP connection reduces the cost of
            // an amplification to one `connect()`.
            let handshaked = g.peers.get(&id).map(|p| p.handshaked).unwrap_or(false);

            match msg {
                Message::Version {
                    version,
                    nonce,
                    start_height,
                    ..
                } => {
                    // Connection to oneself: we disconnect without ceremony. A
                    // peer from another era of the protocol too: it would not
                    // validate the same rules, and each would punish the other
                    // for blocks the other considers valid.
                    if nonce == local_nonce || version < MIN_PROTOCOL_VERSION {
                        drop_peer = true;
                    } else {
                        let height = g.chain.height();
                        if let Some(p) = g.peers.get_mut(&id) {
                            // --- One `Version` per peer, and only one in return.
                            //
                            // Every `Version` received made us send back a
                            // `Version`, including to the one who had sent it
                            // in reply to ours: two nodes therefore exchanged
                            // `Version`/`VerAck`/`GetAddr`/`Addr` endlessly,
                            // tens of thousands of frames per second, and each
                            // round restarted a header request. The responder
                            // introduces itself once, before its `VerAck` so
                            // that the other end has our `Version` when the
                            // acknowledgment reaches it; a duplicate is ignored.
                            if !p.version_received {
                                p.version_received = true;
                                p.start_height = start_height;
                                if !p.version_sent {
                                    p.version_sent = true;
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::Version {
                                            version: PROTOCOL_VERSION,
                                            timestamp: unix_now(),
                                            nonce: local_nonce,
                                            user_agent: "q21:0.4".into(),
                                            start_height: height,
                                        },
                                    });
                                }
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::VerAck,
                                });
                            }
                        }
                    }
                }

                Message::VerAck => {
                    let (behind, locator) = {
                        let height = g.chain.height();
                        let p = g.peers.get_mut(&id);
                        match p {
                            // A `VerAck` only completes the handshake if a
                            // `Version` preceded it. Otherwise we ignore it: no
                            // access to expensive messages, and the nonce check
                            // (connection to oneself) is not bypassed.
                            Some(p) if p.version_received => {
                                p.handshaked = true;
                                (p.start_height > height, g.chain.locator())
                            }
                            _ => (false, Vec::new()),
                        }
                    };
                    if behind {
                        outgoing.push(Outgoing {
                            peer: id,
                            message: Message::GetHeaders {
                                locator,
                                stop: Hash256::ZERO,
                            },
                        });
                    }
                    // We ask every new peer for its address book. It is the
                    // only discovery mechanism: without it, a node only ever
                    // knows the addresses it was given by hand.
                    outgoing.push(Outgoing {
                        peer: id,
                        message: Message::GetAddr,
                    });
                }

                Message::Ping(n) => outgoing.push(Outgoing {
                    peer: id,
                    message: Message::Pong(n),
                }),
                Message::Pong(_) => {}

                Message::GetHeaders { locator, stop } => {
                    // Like any service, the reply to headers requires the
                    // handshake: synchronization never asks for headers before
                    // it (see the VerAck arm), so nothing honest is lost, and an
                    // anonymous connection can no longer trigger serving work.
                    //
                    // And, like any service, it goes through a bucket: see
                    // [`HEADERS_RATE_PER_SEC`]. Beyond it, we serve nothing and
                    // do not disconnect — an honest client waits.
                    let allowed = handshaked
                        && g.peers
                            .get_mut(&id)
                            .map(|p| {
                                p.headers_bucket.allow_with(
                                    1,
                                    Instant::now(),
                                    HEADERS_BUCKET_MAX,
                                    HEADERS_RATE_PER_SEC,
                                )
                            })
                            .unwrap_or(false);
                    if handshaked && !allowed {
                        self.stats.headers_rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    if allowed {
                        let h = g
                            .chain
                            .headers_from(&locator, stop, crate::wire::MAX_HEADERS);
                        if !h.is_empty() {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::Headers(h),
                            });
                        }
                    }
                }

                Message::Headers(v) if v.is_empty() => {}

                Message::Headers(v) if !handshaked => {
                    // Same rule as `getheaders`: synchronization only receives
                    // headers in reply to its own request, which goes out after
                    // the handshake (VerAck arm). Nothing honest is lost, and an
                    // anonymous connection no longer makes us hash two thousand
                    // headers nor request a single body. The "pushed" message
                    // went through the door that the "requested" message kept
                    // shut.
                    let _ = v;
                }

                Message::Headers(v) if g.peers.get(&id).map(|p| p.expected_headers) == Some(0) => {
                    // Nobody asked for this batch: see [`MAX_EXPECTED_HEADERS`].
                    // It is not read — no hash, no body queue — and the peer,
                    // the only one who could have produced it, loses points.
                    let _ = v;
                    self.stats
                        .unrequested_headers
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(p) = g.peers.get_mut(&id) {
                        p.ban_score = p.ban_score.saturating_add(MISCONDUCT_UNREQUESTED_HEADERS);
                        if p.ban_score >= BAN_THRESHOLD {
                            self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                            drop_peer = true;
                        }
                    }
                }

                Message::Headers(v) => {
                    if let Some(p) = g.peers.get_mut(&id) {
                        p.expected_headers = p.expected_headers.saturating_sub(1);
                    }
                    // --- Header-based synchronization, strict on chaining.
                    //
                    // We **never** request a block body before having checked
                    // that the sequence of headers connects to the chain we
                    // already know. Without this check, a peer on an
                    // incompatible chain makes us download orphan blocks
                    // indefinitely: that is the defect observed when running
                    // two nodes with different geneses, 29,850 blocks received
                    // for a height that stayed at zero.
                    //
                    // Strict on chaining, not on work: the proof of work is not
                    // checked here — it is memory-hard, and checking it on two
                    // thousand headers would cost more than what it would
                    // protect. A sequence chained onto our tip can therefore be
                    // fabricated offline, for free. What bounds what it can make
                    // us do is the per-peer cap on bodies in flight
                    // (`MAX_BODIES_IN_FLIGHT`): the work is only checked when the
                    // body arrives, sixteen at a time.
                    let connects = g.chain.has_block(&v[0].prev_block);

                    let mut contiguous = connects;
                    if contiguous {
                        for f in v.windows(2) {
                            if f[1].prev_block != f[0].block_id() {
                                contiguous = false;
                                break;
                            }
                        }
                    }

                    if !contiguous {
                        let incompatible = {
                            let p = g.peers.get_mut(&id);
                            match p {
                                Some(p) => {
                                    p.consecutive_orphans += 1;
                                    p.consecutive_orphans >= 3
                                }
                                None => true,
                            }
                        };
                        if incompatible {
                            // This peer is not on our chain. Insisting would
                            // cost everyone and lead nowhere.
                            drop_peer = true;
                        }
                    } else {
                        let Shared {
                            ref chain,
                            ref mut peers,
                            ..
                        } = *g;
                        if let Some(p) = peers.get_mut(&id) {
                            p.consecutive_orphans = 0;
                            // The batch replaces the queue: a peer only replies
                            // with headers to our request, and we only ask for
                            // the continuation once the queue is drained. This
                            // is what bounds the queue to one batch, whatever
                            // the peer pushes.
                            p.bodies_to_request.clear();
                            p.bodies_to_request.extend(
                                v.iter()
                                    .map(|h| h.block_id())
                                    .filter(|bid| !chain.has_block(bid))
                                    .take(MAX_PENDING_BODIES),
                            );
                            p.more_expected = v.len() >= crate::wire::MAX_HEADERS;
                            p.continue_sync(id, chain, &mut outgoing, Instant::now(), false);
                        }
                    }
                }

                Message::Inv(v) if !handshaked => {
                    // Same rule as `getdata` and `addr`: nothing is read before
                    // the handshake. A read `inv` made us request bodies and
                    // record them in flight on behalf of an anonymous
                    // connection — the starting point of the defect fixed in
                    // `maintain_peers`. No honest node announces before having
                    // introduced itself: see `announce_block` and `announce_tx`.
                    let _ = v;
                }

                Message::Inv(v) => {
                    let mut wanted = Vec::new();
                    let mut blocks = Vec::new();
                    for i in v {
                        match i.kind {
                            InvKind::Block | InvKind::CompactBlock => {
                                if !g.chain.has_block(&i.hash) {
                                    blocks.push(i.hash);
                                }
                            }
                            InvKind::Tx => {
                                if !g.mempool.contains(&i.hash) {
                                    wanted.push(i);
                                }
                            }
                        }
                    }
                    // Blocks go through the same cap as headers: what has no
                    // in-flight slot waits in the queue, and an `inv` of fifty
                    // thousand identifiers records nothing more than a batch of
                    // headers.
                    if let Some(p) = g.peers.get_mut(&id) {
                        let now = Instant::now();
                        for h in blocks {
                            if p.requested_bodies.contains_key(&h) {
                                continue;
                            }
                            if p.note_body_requested(h, now) {
                                wanted.push(InvItem {
                                    kind: InvKind::CompactBlock,
                                    hash: h,
                                });
                            } else {
                                p.queue_body(h);
                            }
                        }
                    }
                    if !wanted.is_empty() {
                        outgoing.push(Outgoing {
                            peer: id,
                            message: Message::GetData(wanted),
                        });
                    }
                }

                Message::GetData(v) => {
                    // --- Defense: amplification.
                    //
                    // The original handler served each item as is, without
                    // deduplicating or capping. A peer sent the same hash
                    // 20,000 times — a 660 KiB request — and the node produced
                    // 20,000 copies of the block. The audit's measurement:
                    // 6.8 MiB out, and for compact blocks a complete
                    // recomputation of the short identifiers for each copy. On
                    // 4 MiB blocks, 80 GiB for a 660 KiB request.
                    //
                    // Three rules, and none is negotiable: the handshake first,
                    // an item served at most once, and an outgoing byte budget.
                    // We serve nothing, but we do not disconnect: disconnecting
                    // would punish a benign race. A legitimate peer may request
                    // an announced block before its `verack` has reached us, and
                    // breaking the connection for that amounts to inflicting a
                    // network partition on oneself. That is what happened on the
                    // first real trial: two honest nodes disconnected each other
                    // immediately, height stuck at zero.
                    let mut seen: HashSet<Hash256> = HashSet::new();
                    let mut budget = if handshaked { REPLY_BYTE_BUDGET } else { 0 };
                    for i in v.into_iter().take(MAX_SERVED_ITEMS) {
                        if !seen.insert(i.hash) || budget == 0 {
                            continue;
                        }
                        match i.kind {
                            InvKind::Block => {
                                if let Some(b) = g.chain.block_by_id(&i.hash) {
                                    budget = budget.saturating_sub(b.encode().len());
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::Block(Box::new(b)),
                                    });
                                }
                            }
                            InvKind::CompactBlock => {
                                if let Some(b) = g.chain.block_by_id(&i.hash) {
                                    let c = CompactBlock::from_block(&b, unix_now());
                                    budget = budget.saturating_sub(c.encode().len());
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::CmpctBlock(Box::new(c)),
                                    });
                                }
                            }
                            InvKind::Tx => {
                                if let Some(t) = g.mempool.get(&i.hash) {
                                    budget = budget.saturating_sub(t.encode().len());
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::Tx(Box::new(t.clone())),
                                    });
                                }
                            }
                        }
                    }
                }

                Message::Block(b) => {
                    // --- Defense: a block pushed by a stranger.
                    //
                    // Every serving message requires the handshake; a pushed
                    // block did not, and got hashed, checked and connected over
                    // a mere anonymous TCP connection. Same rule for all.
                    if handshaked {
                        self.stats.blocks_received.fetch_add(1, Ordering::Relaxed);
                        drop_peer = !Self::integrate(&mut g, &b, &self.stats, &mut outgoing, id);
                    }
                }

                Message::CmpctBlock(c) => {
                    self.stats.compacts_received.fetch_add(1, Ordering::Relaxed);
                    let bid = c.header.block_id();
                    if g.chain.has_block(&bid) {
                        // Already known: nothing to reconstruct. But if it was a
                        // body requested from this peer, its in-flight slot is
                        // freed.
                        let Shared {
                            ref chain,
                            ref mut peers,
                            ..
                        } = *g;
                        if let Some(p) = peers.get_mut(&id) {
                            if p.requested_bodies.contains_key(&bid) {
                                p.continue_sync(id, chain, &mut outgoing, Instant::now(), true);
                            }
                        }
                    } else if !handshaked || !g.chain.has_block(&c.header.prev_block) {
                        // --- Defense: work imposed by a stranger.
                        //
                        // A minimal compact block is about 170 bytes, and was
                        // enough to trigger a full clone of the mempool — up to
                        // 64 MiB — **under the global lock**, hence to serialize
                        // the whole node. Repeated, it froze it.
                        //
                        // We now refuse before any expense: no handshake, or a
                        // parent we do not know, and the message costs only a
                        // comparison. A block whose parent is unknown could not
                        // be connected anyway.
                    } else {
                        // --- Defense: the peer's announcement budget.
                        //
                        // A body we requested from this peer is not an
                        // announcement: it arrives because we wanted it, and the
                        // cap on bodies in flight already bounds what we want.
                        // Everything else is a spontaneous announcement, and an
                        // honest peer only makes a few per minute. Beyond that,
                        // we do not reconstruct — no scan, no allocation — and
                        // insisting costs points.
                        let solicited = g
                            .peers
                            .get(&id)
                            .map(|p| p.requested_bodies.contains_key(&bid))
                            .unwrap_or(false);
                        let allowed = solicited
                            || g.peers
                                .get_mut(&id)
                                .map(|p| {
                                    p.cmpct_bucket.allow_with(
                                        1,
                                        Instant::now(),
                                        CMPCT_BUCKET_MAX,
                                        CMPCT_RATE_PER_SEC,
                                    )
                                })
                                .unwrap_or(false);
                        if !allowed {
                            self.stats.compacts_rejected.fetch_add(1, Ordering::Relaxed);
                            if let Some(p) = g.peers.get_mut(&id) {
                                p.ban_score = p.ban_score.saturating_add(MISCONDUCT_CMPCT_REJECTED);
                                if p.ban_score >= BAN_THRESHOLD {
                                    self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                    drop_peer = true;
                                }
                            }
                        } else if let Err(e) = g.chain.check_header(&c.header, unix_now()) {
                            // --- Defense: the header before the body (BIP 152).
                            //
                            // The bucket bounds the NUMBER of announcements; it
                            // says nothing about their value. An announcement
                            // whose header did not carry the work its position
                            // requires still made us search the mempool and
                            // allocate the reconstruction, under the lock.
                            // Now: height, finality, difficulty, timestamp and
                            // work are checked on the 160 bytes of the header,
                            // and nothing else is touched if one of them fails.
                            // These are the same checks that submitting the full
                            // block would apply; we only move them earlier.
                            //
                            // A false header can only come from whoever
                            // fabricated it: same penalty as an invalid block,
                            // and we request nothing again — its body is worth
                            // no more.
                            //
                            // Exception: what this binary cannot read is not
                            // the peer's fault.
                            self.stats
                                .compacts_header_rejected
                                .fetch_add(1, Ordering::Relaxed);
                            match e {
                                crate::chain::ChainError::Validation(v)
                                    if locally_unverifiable_scheme(&v).is_some() =>
                                {
                                    report_unverifiable_scheme(
                                        locally_unverifiable_scheme(&v).expect("guarded"),
                                    );
                                }
                                _ => {
                                    self.stats.invalid_blocks.fetch_add(1, Ordering::Relaxed);
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        p.ban_score =
                                            p.ban_score.saturating_add(MISCONDUCT_BAD_BLOCK);
                                        if p.ban_score >= BAN_THRESHOLD {
                                            self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                            drop_peer = true;
                                        }
                                    }
                                }
                            }
                        } else {
                            self.stats
                                .compacts_reconstructed
                                .fetch_add(1, Ordering::Relaxed);
                            let available = Self::useful_mempool_txs(&g.mempool, &c);
                            match Reconstruction::from_compact(&c, &available) {
                                Ok(r) if r.is_complete() => {
                                    self.stats
                                        .compacts_without_round_trip
                                        .fetch_add(1, Ordering::Relaxed);
                                    match r.finish() {
                                        Ok(b) => {
                                            drop_peer = !Self::integrate(
                                                &mut g,
                                                &b,
                                                &self.stats,
                                                &mut outgoing,
                                                id,
                                            );
                                        }
                                        Err(_) => {
                                            // Plausible but wrong reconstruction:
                                            // we request the full block again.
                                            outgoing.push(Outgoing {
                                                peer: id,
                                                message: Message::GetData(vec![InvItem {
                                                    kind: InvKind::Block,
                                                    hash: bid,
                                                }]),
                                            });
                                        }
                                    }
                                }
                                Ok(r) => {
                                    let indices = r.missing().to_vec();
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        // Beyond the bound, the oldest gives way:
                                        // we never keep more than what the peer
                                        // can honestly have in flight.
                                        if p.pending.len() >= MAX_PENDING_RECONSTRUCTIONS {
                                            let oldest = p
                                                .pending
                                                .iter()
                                                .min_by_key(|(_, (cb, _))| cb.header.height)
                                                .map(|(k, _)| *k);
                                            if let Some(k) = oldest {
                                                p.pending.remove(&k);
                                            }
                                        }
                                        p.pending.insert(bid, (*c.clone(), indices.clone()));
                                    }
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::GetBlockTxn {
                                            block: bid,
                                            indices,
                                        },
                                    });
                                }
                                Err(_) => {
                                    // Rejected before even looking for the
                                    // transactions: missing coinbase, index
                                    // outside the block, absurd count. An
                                    // announcement made this way can only come
                                    // from the peer that fabricated it — unlike
                                    // a wrong Merkle root, which can arise from a
                                    // collision of short identifiers. We request
                                    // the full block again, and the peer loses
                                    // points.
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        p.ban_score =
                                            p.ban_score.saturating_add(MISCONDUCT_CMPCT_REJECTED);
                                        if p.ban_score >= BAN_THRESHOLD {
                                            self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                            drop_peer = true;
                                        }
                                    }
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::GetData(vec![InvItem {
                                            kind: InvKind::Block,
                                            hash: bid,
                                        }]),
                                    });
                                }
                            }
                        }
                    }
                }

                Message::GetBlockTxn { block, indices } => {
                    // --- Defense: amplification.
                    //
                    // Without deduplication or cap, `indices: [0; 100_000]`
                    // made us clone the same transaction a hundred thousand
                    // times in a single frame. The audit's measurement: a
                    // 100 KiB request for a 15.5 MiB reply — a frame that even
                    // exceeded the protocol's MAX_PAYLOAD, hence unreadable by
                    // an honest peer. Producing a reply nobody can read is the
                    // definition of a denial-of-service vector.
                    // Same rule as above: we serve nothing, we do not disconnect.
                    let mut seen: HashSet<u32> = HashSet::new();
                    let unique: Vec<u32> = indices
                        .into_iter()
                        .take(MAX_SERVED_ITEMS)
                        .filter(|i| seen.insert(*i))
                        .collect();

                    // Loading the block (opening a file, reading, cloning)
                    // came before the handshake: an anonymous peer made the
                    // node do a disk read under the global lock for zero bytes
                    // served. We require it first.
                    if handshaked {
                        if let Some(b) = g.chain.block_by_id(&block) {
                            let mut txs = Vec::new();
                            let mut budget = if handshaked { REPLY_BYTE_BUDGET } else { 0 };
                            let mut valid = true;
                            for i in &unique {
                                match b.transactions.get(*i as usize) {
                                    Some(t) => {
                                        let size = t.encode().len();
                                        if size > budget {
                                            break;
                                        }
                                        budget -= size;
                                        txs.push(t.clone());
                                    }
                                    None => {
                                        valid = false;
                                        break;
                                    }
                                }
                            }
                            if valid && !txs.is_empty() {
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::BlockTxn { block, txs },
                                });
                            }
                        }
                    }
                }

                Message::BlockTxn { block, txs } => {
                    let waiting = g.peers.get_mut(&id).and_then(|p| p.pending.remove(&block));
                    if let Some((c, _)) = waiting {
                        let available = Self::useful_mempool_txs(&g.mempool, &c);
                        match Reconstruction::from_compact(&c, &available)
                            .and_then(|r| r.complete(txs))
                        {
                            Ok(b) => {
                                drop_peer =
                                    !Self::integrate(&mut g, &b, &self.stats, &mut outgoing, id);
                            }
                            Err(_) => {
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::GetData(vec![InvItem {
                                        kind: InvKind::Block,
                                        hash: block,
                                    }]),
                                });
                            }
                        }
                    }
                }

                Message::Tx(t) if !handshaked => {
                    // A transaction pushed before the handshake costs nothing:
                    // it is not read. See `Message::Block`.
                    let _ = t;
                }

                Message::Tx(t) => {
                    self.stats.txs_received.fetch_add(1, Ordering::Relaxed);
                    // --- Defense: the peer's budget, debited BEFORE any
                    // expensive computation, and IN PROPORTION to the
                    // verification work.
                    //
                    // # The two defects this debit closes
                    //
                    // 1. Replay (red team 8b, 1st campaign). To know whether a
                    //    transaction is new, one first needs its identifier
                    //    `t.txid()`, a hash of the whole transaction. By
                    //    replaying a large, already-known transaction, a peer
                    //    forced this computation for every message. So we debit
                    //    BEFORE the hash.
                    // 2. Verification (red team 8b, 2nd campaign). A transaction
                    //    costs one post-quantum signature PER INPUT, under the
                    //    global lock. Nothing bounds the number of inputs (only
                    //    weight does, ~271), and the old budget counted one unit
                    //    PER TRANSACTION: a transaction with many inputs, or a
                    //    flood of them, held the lock far longer. So we debit in
                    //    proportion to the inputs.
                    //
                    // The cost is capped at the bucket: the largest valid
                    // transaction drains the budget but is never refused. Beyond
                    // the budget, we DEFER without banning — a consolidation with
                    // many inputs can be perfectly honest, and the old ban on
                    // overrun could exclude a legitimate relay (a peer's score
                    // never decreases). The peer will resend when its bucket
                    // refills. A really invalid transaction, on the other hand,
                    // is always penalized further down (`tx_invalid_in_itself`).
                    let cost = (t.inputs.len() as u64).clamp(1, TX_BUCKET_MAX);
                    let allowed = g
                        .peers
                        .get_mut(&id)
                        .map(|p| {
                            p.tx_bucket.allow_with(
                                cost,
                                Instant::now(),
                                TX_BUCKET_MAX,
                                TX_RATE_PER_SEC,
                            )
                        })
                        .unwrap_or(false);
                    if !allowed {
                        // Budget overrun, two distinct cases:
                        // - small transaction: the peer sends too many MESSAGES,
                        //   it is a flood. We penalize, as always.
                        // - large transaction (many inputs): a single message
                        //   asked for a lot of work at once. It may be honest
                        //   (consolidation). We DEFER without banning — the peer
                        //   will resend when its bucket refills — because a ban
                        //   score never decreases and a legitimate relay would
                        //   end up excluded.
                        // In both cases: neither hash nor verification. The work
                        // is bounded because we stop here.
                        if cost <= FLOOD_INPUT_THRESHOLD {
                            if let Some(p) = g.peers.get_mut(&id) {
                                p.ban_score = p.ban_score.saturating_add(MISCONDUCT_MALFORMED);
                                if p.ban_score >= BAN_THRESHOLD {
                                    self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                    drop_peer = true;
                                }
                            }
                        }
                    } else {
                        let txid = t.txid();
                        let is_new = !g.mempool.contains(&txid);
                        let height = g.chain.height();
                        // On a reference, never on a copy: duplicating the UTXO
                        // set for every transaction received cost hundreds of
                        // mebibytes per message on a real chain, under the
                        // global lock — a chatty peer was enough to freeze the
                        // node. The reborrow `&mut *g` splits the fields of the
                        // guard.
                        let shared = &mut *g;
                        let result = if is_new {
                            shared
                                .mempool
                                .accept(&t, &shared.chain.utxo, network, height)
                        } else {
                            // Already known: nothing to revalidate, nothing to
                            // relay.
                            Err(crate::mempool::MempoolError::AlreadyPresent)
                        };
                        match result {
                            Ok(txid) => {
                                // To established peers only, like every
                                // announcement: see `announce_tx`.
                                let others: Vec<u64> = g
                                    .peers
                                    .iter()
                                    .filter(|(p, e)| **p != id && e.handshaked)
                                    .map(|(p, _)| *p)
                                    .collect();
                                for p in others {
                                    outgoing.push(Outgoing {
                                        peer: p,
                                        message: Message::Inv(vec![InvItem {
                                            kind: InvKind::Tx,
                                            hash: txid,
                                        }]),
                                    });
                                }
                            }
                            Err(e) => {
                                // A rejected transaction is not necessarily an
                                // aggression: it may already be known, or spend
                                // an output that a block has just consumed. But a
                                // bad signature, a key that does not match the
                                // lock, an incorrect form or a value not conserved
                                // can only come from a peer that fabricated it.
                                if Self::tx_invalid_in_itself(&e) {
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        p.ban_score = p.ban_score.saturating_add(MISCONDUCT_BAD_TX);
                                        if p.ban_score >= BAN_THRESHOLD {
                                            self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                            drop_peer = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                Message::GetAddr if !handshaked => {
                    // Serving the address book before the handshake offered an
                    // anonymous scanner every known address, and an
                    // amplification of about 600x (24 bytes requested, up to
                    // 16 KB returned) built under the global lock — which the
                    // rest of the code already refuses ("nothing is read before
                    // the handshake"). GetAddr is aligned with GetHeaders. Red
                    // team 8b.
                }

                Message::GetAddr => {
                    // Even after the handshake, the reply is bounded by the
                    // bucket: its actual size is debited, so that a burst of
                    // `getaddr` does not turn into a bandwidth amplification
                    // under the lock.
                    let mut v = g.book.to_announce(crate::wire::MAX_ADDR);
                    if v.len() < crate::wire::MAX_ADDR {
                        for p in g.peers.values() {
                            // ONLY the OUTBOUND peers: their `addr` carries the
                            // real listening port, hence a reachable address.
                            // An inbound peer is known by its ephemeral source
                            // port, which is unusable: broadcasting it polluted
                            // the address books of the whole network with dead
                            // addresses.
                            if !p.outbound {
                                continue;
                            }
                            if let SocketAddr::V4(a) = p.addr {
                                let n = crate::wire::NetAddr {
                                    ip: a.ip().octets(),
                                    port: a.port(),
                                    last_seen: unix_now(),
                                };
                                if !v.iter().any(|x| x.ip == n.ip && x.port == n.port) {
                                    v.push(n);
                                }
                            }
                            if v.len() >= crate::wire::MAX_ADDR {
                                break;
                            }
                        }
                    }
                    if !v.is_empty() {
                        // ~20 bytes per address; we debit the served size from
                        // the peer's snapshot bucket. Beyond the budget, we do
                        // not reply: the peer waits, the node does not wear
                        // itself out.
                        let cost = (v.len() as u64).saturating_mul(20);
                        let allowed = g
                            .peers
                            .get_mut(&id)
                            .map(|p| p.snapshot_bucket.allow(cost, Instant::now()))
                            .unwrap_or(false);
                        if allowed {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::Addr(v),
                            });
                        }
                    }
                }

                Message::Addr(v) if !handshaked => {
                    // Same rule as `getaddr`: nothing is read before the
                    // handshake. With the address book full, each address from a
                    // new group makes us scan every group to evict one — nearly
                    // eight milliseconds of global lock per sixteen-kibibyte
                    // frame, with no bucket. No honest peer announces addresses
                    // before having introduced itself.
                    let _ = v;
                }

                Message::Addr(v) => {
                    // The addresses come from a stranger: the address book
                    // applies its own rules — routability, cap per group — and
                    // nothing else is done with this message. In particular, we
                    // never dial an address because a peer suggested it: the
                    // maintenance loop decides.
                    //
                    // Each address goes through the peer's bucket: see
                    // [`ADDR_RATE_PER_SEC`]. The bucket is consulted before the
                    // address book, hence before any scan.
                    let now = unix_now();
                    let instant = Instant::now();
                    let Shared {
                        ref mut book,
                        ref mut peers,
                        ..
                    } = *g;
                    let bucket = peers.get_mut(&id).map(|p| &mut p.addr_bucket);
                    if let Some(bucket) = bucket {
                        for a in v.into_iter().take(crate::wire::MAX_ADDR) {
                            if !bucket.allow_with(1, instant, ADDR_BUCKET_MAX, ADDR_RATE_PER_SEC) {
                                self.stats.addresses_ignored.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            // An address announced as seen in the future would
                            // be a way to get ahead of all the others.
                            let mut a = a;
                            a.last_seen = a.last_seen.min(now);
                            book.add(a, now);
                        }
                    }
                }
                Message::Reject { .. } => {}

                // --- Fast sync: serving a snapshot.
                //
                // Like any expensive message, these replies require the
                // handshake: serving an entire UTXO set to an anonymous
                // connection would bring an amplification down to the price of
                // one `connect()`.
                Message::GetSnapshot => {
                    if handshaked {
                        refresh_snapshot(&mut g);
                        if let Some(c) = &g.snapshot_cache {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::SnapshotInfo {
                                    height: c.height,
                                    tip: c.announced_tip,
                                    commitment: c.commitment,
                                    size: c.bytes.len() as u64,
                                    chunks: crate::fast_sync::chunk_count(c.bytes.len()),
                                },
                            });
                        }
                        // No snapshot (chain too short): we reply nothing. The
                        // requester will look elsewhere.
                    }
                }
                Message::GetSnapshotChunk { index } => {
                    if handshaked {
                        refresh_snapshot(&mut g);
                        // Measure first, copy afterwards: the bucket must be
                        // consulted **before** the mebibyte of copying,
                        // otherwise it would protect against nothing.
                        let size = g
                            .snapshot_cache
                            .as_ref()
                            .map(|c| crate::fast_sync::chunk(&c.bytes, index).len())
                            .unwrap_or(0);
                        let allowed = size > 0
                            && g.peers
                                .get_mut(&id)
                                .map(|p| p.snapshot_bucket.allow(size as u64, Instant::now()))
                                .unwrap_or(false);
                        if allowed {
                            if let Some(c) = &g.snapshot_cache {
                                let chunk = crate::fast_sync::chunk(&c.bytes, index);
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::SnapshotChunk {
                                        index,
                                        data: chunk.to_vec(),
                                    },
                                });
                            }
                        }
                        // Beyond the granted rate, we serve nothing and do not
                        // disconnect: an honest client slows down and resumes.
                    }
                }
                // A server does not receive snapshot replies: we ignore them.
                Message::SnapshotInfo { .. } | Message::SnapshotChunk { .. } => {}
            }
        } // --- lock released here, before any network write ---

        for e in outgoing {
            let writer = {
                let mut g = self.shared.lock().unwrap();
                // A requested body is noted, so we know whether it arrives —
                // within the limit of in-flight slots, as everywhere. A header
                // request too: only an expected reply will be read.
                g.peers.get_mut(&e.peer).map(|p| {
                    p.note_sent(&e.message, Instant::now());
                    p.writer.clone()
                })
            };
            if let Some(s) = writer {
                let _ = write_message(&s, &e.message, self.magic);
            }
        }

        !drop_peer
    }

    /// Submits a block to the chain and prepares its broadcast.
    ///
    /// Returns `false` if the peer deserves to be disconnected.
    /// Mempool transactions **actually useful** to this compact block.
    ///
    /// The previous version cloned the whole mempool for each announcement.
    /// Here we only keep the transactions whose short identifier appears in the
    /// announcement: the memory cost becomes that of a block, not that of the
    /// mempool. The scan remains linear, but a scan does not compare with
    /// sixty-four megabytes of copies.
    fn useful_mempool_txs(mempool: &Mempool, c: &CompactBlock) -> HashMap<Hash256, Transaction> {
        let (k0, k1) = crate::compact::short_id_key(&c.header, c.nonce);
        let targeted: HashSet<u64> = c.short_ids.iter().copied().collect();
        let mut m = HashMap::with_capacity(targeted.len());
        for t in mempool.txids() {
            if targeted.contains(&crate::compact::short_id(k0, k1, &t)) {
                if let Some(tx) = mempool.get(&t) {
                    m.insert(t, tx.clone());
                }
            }
        }
        m
    }

    fn integrate(
        g: &mut Shared,
        b: &Block,
        stats: &Stats,
        outgoing: &mut Vec<Outgoing>,
        source: u64,
    ) -> bool {
        let bid = b.header.block_id();
        if g.chain.has_block(&bid) {
            Self::body_arrived(g, source, outgoing);
            return true;
        }
        match g.chain.submit(b, unix_now()) {
            Ok(Accept::Extended) | Ok(Accept::Reorganized { .. }) => {
                stats.blocks_accepted.fetch_add(1, Ordering::Relaxed);
                // An accepted block is a stored block. Before, only the blocks
                // this node mined itself reached the disk.
                if let Some(j) = &g.journal {
                    j.record(b);
                }
                g.mempool.on_block_connected(b);
                let height = g.chain.height();
                // Same rule as when receiving a transaction: the mempool reads
                // the UTXO set in place, it does not copy it.
                g.mempool.revalidate(&g.chain.utxo, g.network, height);

                // Broadcast: compact announcement, not the full block.
                //
                // Only to peers whose handshake is complete. Announcing earlier
                // creates a race: the peer requests the block, and its request
                // reaches us before its `verack`.
                let others: Vec<u64> = g
                    .peers
                    .iter()
                    .filter(|(p, e)| **p != source && e.handshaked)
                    .map(|(p, _)| *p)
                    .collect();
                for p in others {
                    outgoing.push(Outgoing {
                        peer: p,
                        message: Message::Inv(vec![InvItem {
                            kind: InvKind::CompactBlock,
                            hash: bid,
                        }]),
                    });
                }
                Self::body_arrived(g, source, outgoing);
                true
            }
            Ok(Accept::SideBranch) => {
                // A side branch is valid work: if it wins later, its bodies
                // will be needed. Not writing them made any reorg impossible
                // after a restart.
                if let Some(j) = &g.journal {
                    j.record(b);
                }
                Self::body_arrived(g, source, outgoing);
                true
            }
            Ok(_) => {
                Self::body_arrived(g, source, outgoing);
                true
            }
            Err(crate::chain::ChainError::UnknownParent(_)) => {
                stats.orphan_blocks.fetch_add(1, Ordering::Relaxed);
                // A block whose parent is unknown should no longer arrive:
                // strict header-based synchronization only requests a body
                // after having checked that it connects. Asking for headers
                // again here would recreate the infinite loop we just fixed. We
                // ignore it, without punishing: it may be a benign race between
                // two announcements.
                true
            }
            Err(crate::chain::ChainError::Validation(v))
                if locally_unverifiable_scheme(&v).is_some() =>
            {
                // The block is not wrong: it is this binary that cannot read
                // it. The peer is not to blame, we do not penalize it; we tell
                // the operator once, and we do not count the block as invalid
                // — it may well not be.
                report_unverifiable_scheme(locally_unverifiable_scheme(&v).expect("guarded"));
                true
            }
            Err(_) => {
                stats.invalid_blocks.fetch_add(1, Ordering::Relaxed);
                if let Some(p) = g.peers.get_mut(&source) {
                    p.ban_score = p.ban_score.saturating_add(MISCONDUCT_BAD_BLOCK);
                    if p.ban_score >= BAN_THRESHOLD {
                        stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                }
                true
            }
        }
    }

    /// A body has arrived from a peer: its in-flight slot is freed, and the
    /// synchronization with this peer resumes where it was.
    ///
    /// This is the counterpart of the cap on bodies in flight: without this
    /// resumption, a synchronization would stop after the first sixteen bodies.
    fn body_arrived(g: &mut Shared, source: u64, outgoing: &mut Vec<Outgoing>) {
        let Shared {
            ref chain,
            ref mut peers,
            ..
        } = *g;
        if let Some(p) = peers.get_mut(&source) {
            p.continue_sync(source, chain, outgoing, Instant::now(), true);
        }
    }

    /// Announces our own external address to the peers, to get into their
    /// address books and, step by step, into those of the whole network.
    ///
    /// We send a plain `Addr`: a message that even older peers already
    /// understand. No protocol change, hence no break between versions. The
    /// announced address has been verified to be public by the caller; the
    /// peer's address book applies its own routability rules anyway before
    /// keeping it.
    pub fn announce_address(&self, n: crate::wire::NetAddr) {
        let targets: Vec<Arc<Mutex<TcpStream>>> = {
            let g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            g.peers
                .values()
                .filter(|p| p.handshaked)
                .map(|p| p.writer.clone())
                .collect()
        };
        let m = Message::Addr(vec![n]);
        for s in targets {
            let _ = write_message(&s, &m, self.magic);
        }
    }

    /// Announces a block we have just mined ourselves.
    pub fn announce_block(&self, b: &Block) {
        let bid = b.header.block_id();
        let targets: Vec<Arc<Mutex<TcpStream>>> = {
            let g = self.shared.lock().unwrap();
            // Only peers whose handshake is complete: announcing earlier would
            // trigger a request that would reach us before their `verack`, and
            // that we could not serve.
            g.peers
                .values()
                .filter(|p| p.handshaked)
                .map(|p| p.writer.clone())
                .collect()
        };
        let m = Message::Inv(vec![InvItem {
            kind: InvKind::CompactBlock,
            hash: bid,
        }]);
        for s in targets {
            let _ = write_message(&s, &m, self.magic);
        }
    }

    /// Broadcasts a local transaction.
    /// Sends a message to a peer, outside the lock, noting the requested
    /// bodies as `handle` does.
    fn send_to(&self, id: u64, m: &Message) {
        let writer = {
            let mut g = self.shared.lock().unwrap();
            g.peers.get_mut(&id).map(|p| {
                p.note_sent(m, Instant::now());
                p.writer.clone()
            })
        };
        if let Some(s) = writer {
            let _ = write_message(&s, m, self.magic);
        }
    }

    pub fn announce_tx(&self, txid: Hash256) {
        let targets: Vec<Arc<Mutex<TcpStream>>> = {
            let g = self.shared.lock().unwrap();
            g.peers
                .values()
                .filter(|p| p.handshaked)
                .map(|p| p.writer.clone())
                .collect()
        };
        let m = Message::Inv(vec![InvItem {
            kind: InvKind::Tx,
            hash: txid,
        }]);
        for s in targets {
            let _ = write_message(&s, &m, self.magic);
        }
    }
}

fn write_message(
    stream: &Arc<Mutex<TcpStream>>,
    m: &Message,
    magic: [u8; 4],
) -> std::io::Result<()> {
    let frame = m.frame(magic);
    let mut g = stream.lock().unwrap();
    g.write_all(&frame)?;
    g.flush()
}

#[cfg(test)]
mod tests {
    /// "I cannot verify" is not the peer's fault.
    ///
    /// A block or a transaction whose signature belongs to a known scheme that
    /// is absent from this build costs the peer no points. A bad signature, on
    /// the other hand, always costs points: the distinction cannot be used to
    /// flood for free.
    #[test]
    fn local_inability_is_not_the_peer_s_fault() {
        use crate::mempool::MempoolError as M;
        use crate::sig::{SchemeId, VerifyError};
        use crate::validate::ValidationError as V;
        let local = V::Signature(VerifyError::SchemeUnavailable(SchemeId::MlDsa87));
        let bad = V::Signature(VerifyError::InvalidSignature);
        assert_eq!(
            super::locally_unverifiable_scheme(&local),
            Some(SchemeId::MlDsa87)
        );
        assert_eq!(super::locally_unverifiable_scheme(&bad), None);
        let (local, bad) = (M::Validation(local), M::Validation(bad));
        assert!(!super::Node::tx_invalid_in_itself(&local));
        assert!(super::Node::tx_invalid_in_itself(&bad));
    }

    /// ML-DSA is compiled by default: a bare `cargo build` gives a node that
    /// can verify mainnet. The dependency-free core remains available through
    /// `--no-default-features`, and it then refuses to start where it cannot
    /// verify.
    #[test]
    fn ml_dsa_is_compiled_by_default() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            manifest.contains("default = [\"mldsa\"]"),
            "the mldsa feature must be among the default features"
        );
    }
    use super::*;
    use crate::chain::genesis_block;
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::sig::SchemeId;

    const NETWORK: Network = Network::Regtest;
    const MAX_TRIES: u64 = 5_000_000;

    fn node() -> Node {
        let g = genesis_block(NETWORK);
        Node::new(NETWORK, Chain::new(NETWORK, g))
    }

    /// Two nodes starting from the same genesis.
    fn node_pair() -> (Node, Node) {
        let g = genesis_block(NETWORK);
        (
            Node::new(NETWORK, Chain::new(NETWORK, g.clone())),
            Node::new(NETWORK, Chain::new(NETWORK, g)),
        )
    }

    fn mine(n: &Node, count: usize) {
        for _ in 0..count {
            let b = n.with_chain(|c| {
                let t = c.tip().time + TARGET_BLOCK_SECS;
                c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, MAX_TRIES)
            });
            if let Some(b) = b {
                n.with_chain(|c| {
                    let t = b.header.time + 1;
                    c.connect(&b, t).expect("local connection")
                });
            }
        }
    }

    /// Waits for a condition to become true, without blocking indefinitely.
    fn wait_until(mut cond: impl FnMut() -> bool, seconds: u64) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(seconds) {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        cond()
    }

    /// Peer discovery, end to end: A knows addresses, B connects to A, and B
    /// learns them without anyone having given them to it.
    #[test]
    fn a_peer_learns_its_neighbor_s_addresses() {
        let (a, b) = node_pair();
        // A has heard of three peers, in three distinct ranges.
        let known = [
            crate::wire::NetAddr {
                ip: [93, 184, 216, 34],
                port: 21021,
                last_seen: 1_000,
            },
            crate::wire::NetAddr {
                ip: [8, 8, 8, 8],
                port: 21021,
                last_seen: 1_000,
            },
            crate::wire::NetAddr {
                ip: [1, 1, 1, 1],
                port: 21021,
                last_seen: 1_000,
            },
        ];
        assert_eq!(a.seed_addresses(&known), 3);
        assert_eq!(b.address_count(), 0);

        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| b.address_count() >= 3, 10),
            "B did not learn A's addresses: {}",
            b.address_count()
        );

        // And it will never propose two addresses from the same group.
        let choice = b.addresses_to_try(10);
        let groups: std::collections::HashSet<[u8; 2]> =
            choice.iter().map(|x| crate::addr::group(x.ip)).collect();
        assert_eq!(groups.len(), choice.len());

        a.shutdown();
        b.shutdown();
    }

    /// A malicious peer that announces a thousand addresses from a single range
    /// must not be able to occupy its neighbor's address book.
    #[test]
    fn an_address_flood_does_not_fill_the_address_book() {
        let n = node();
        let mut flood = Vec::new();
        for i in 0..1_000u32 {
            flood.push(crate::wire::NetAddr {
                ip: [203, 0, (i >> 8) as u8, i as u8],
                port: 21021,
                last_seen: 1_000 + u64::from(i),
            });
        }
        n.seed_addresses(&flood);
        assert!(
            n.address_count() <= crate::addr::MAX_PER_GROUP,
            "{} addresses kept",
            n.address_count()
        );
        assert_eq!(n.addresses_to_try(50).len(), 1);
    }

    #[test]
    fn a_node_listens_and_accepts_a_connection() {
        let a = node();
        let b = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| a.peer_count() == 1 && b.peer_count() == 1, 5),
            "the two nodes should have seen each other"
        );
        a.shutdown();
        b.shutdown();
    }

    /// An inbound connection does not count as outbound. This is the invariant
    /// that protects against eclipse: the maintenance loop aims for a number of
    /// **outbound** peers (chosen from the address book, with its group
    /// diversity); if an inbound connection counted toward them, an attacker
    /// would fill our slots from a single IP and we would never go looking for
    /// a diversified peer.
    #[test]
    fn an_inbound_connection_does_not_count_as_outbound() {
        let a = node();
        let b = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| a.peer_count() == 1 && b.peer_count() == 1, 5),
            "the two nodes should have seen each other"
        );

        // b initiated: it is an outbound one for b. a accepted it: an inbound
        // one for a, which must therefore count no outbound peer.
        assert_eq!(b.peer_count_outbound(), 1, "b initiated the connection");
        assert_eq!(
            a.peer_count_outbound(),
            0,
            "a only accepted: no outbound one, otherwise the eclipse gets through"
        );
        a.shutdown();
        b.shutdown();
    }

    /// The bucket bounds what a peer extracts from the snapshot service.
    ///
    /// Time is supplied by the test, never read from a clock: a rate rule that
    /// can only be tested by sleeping is a poorly tested rule.
    #[test]
    fn the_snapshot_bucket_bounds_the_rate() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(t0);

        // The initial reserve is served in one go, and not one byte more.
        assert!(
            bucket.allow(SNAPSHOT_BUCKET_MAX, t0),
            "the initial reserve must be served"
        );
        assert!(
            !bucket.allow(1, t0),
            "beyond the reserve, nothing more is served without waiting"
        );

        // One elapsed second credits exactly the granted rate.
        let t1 = t0 + Duration::from_secs(1);
        assert!(
            bucket.allow(SNAPSHOT_RATE_PER_SEC, t1),
            "one second must credit one second's worth of rate"
        );
        assert!(!bucket.allow(1, t1), "and nothing more");

        // The bucket does not overflow: a long absence does not give unlimited
        // credit, otherwise waiting would be enough to take everything back in
        // one go.
        let t2 = t1 + Duration::from_secs(3600);
        assert!(
            bucket.allow(SNAPSHOT_BUCKET_MAX, t2),
            "the capacity is owed"
        );
        assert!(
            !bucket.allow(1, t2),
            "but never more than the capacity, however long the wait"
        );
    }

    /// An honest newcomer must not be hindered: downloading an entire snapshot
    /// is an operation it only does once.
    #[test]
    fn the_bucket_lets_an_honest_download_through() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(t0);
        let chunk = crate::fast_sync::CHUNK_SIZE as u64;

        // A 64 MiB snapshot, requested chunk by chunk at the pace the network
        // delivers them: everything gets through.
        let mut served = 0u32;
        let mut t = t0;
        for _ in 0..64 {
            if bucket.allow(chunk, t) {
                served += 1;
            }
            // Half a second between two chunks: the real rate of an ordinary
            // link, well below the granted limit.
            t += Duration::from_millis(500);
        }
        assert_eq!(served, 64, "an honest download must lose nothing");
    }

    /// Abuse, on the other hand, is brought down to the granted rate: the tight
    /// loop no longer yields anything.
    #[test]
    fn the_bucket_throttles_a_tight_loop() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(t0);
        let chunk = crate::fast_sync::CHUNK_SIZE as u64;

        // A thousand requests at the same instant, as an attacker would do.
        let mut served = 0u32;
        for _ in 0..1_000 {
            if bucket.allow(chunk, t0) {
                served += 1;
            }
        }
        let cap = (SNAPSHOT_BUCKET_MAX / chunk) as u32;
        assert_eq!(
            served, cap,
            "a tight loop must only obtain the reserve, that is {cap} chunks"
        );
        assert!(
            served < 1_000,
            "without the bucket, all thousand requests would have been served"
        );
    }

    /// A lone `VerAck`, without a prior `Version`, must not complete the
    /// handshake: otherwise a peer would skip the negotiation and the nonce
    /// check, and open access to expensive messages with a single frame.
    #[test]
    fn a_lone_verack_does_not_complete_the_handshake() {
        use std::io::Write;
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        let magic = magic_for(NETWORK);

        let mut s = std::net::TcpStream::connect(addr).expect("connection");
        s.write_all(&Message::VerAck.frame(magic)).unwrap();
        s.flush().unwrap();

        assert!(
            wait_until(|| a.peer_count() == 1, 5),
            "the TCP connection must be accepted"
        );
        // But never marked handshaked on an orphan verack.
        assert!(
            !wait_until(
                || {
                    let g = a.shared.lock().unwrap();
                    g.peers.values().any(|p| p.handshaked)
                },
                2
            ),
            "a verack without version must not complete the handshake"
        );
        a.shutdown();
    }

    /// A peer from an earlier version of the protocol is disconnected at the
    /// handshake: it does not validate the same rules, and exchanging with it
    /// would only produce mutual rejections.
    #[test]
    fn a_peer_from_an_earlier_version_is_dropped_at_the_handshake() {
        use std::io::Write;
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        let magic = magic_for(NETWORK);

        let mut s = std::net::TcpStream::connect(addr).expect("connection");
        let old = Message::Version {
            version: MIN_PROTOCOL_VERSION - 1,
            timestamp: unix_now(),
            nonce: 0x1234_5678,
            user_agent: "q21:0.1".into(),
            start_height: 0,
        };
        s.write_all(&old.frame(magic)).unwrap();
        s.flush().unwrap();

        // The peer is accepted at the TCP level then dropped: it does not stay.
        assert!(
            wait_until(|| a.peer_count() == 0, 5) && {
                std::thread::sleep(std::time::Duration::from_millis(300));
                a.peer_count() == 0
            },
            "a peer from an earlier version must be dropped"
        );
        assert!(
            !{
                let g = a.shared.lock().unwrap();
                g.peers.values().any(|p| p.handshaked)
            },
            "and never marked handshaked"
        );
        a.shutdown();
    }

    #[test]
    fn the_handshake_announces_the_height() {
        let (a, b) = node_pair();
        mine(&a, 3);
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(
                || {
                    let g = b.shared.lock().unwrap();
                    g.peers
                        .values()
                        .any(|p| p.handshaked && p.start_height == 3)
                },
                5
            ),
            "b should have learned that a is at height 3"
        );
        a.shutdown();
        b.shutdown();
    }

    /// A silent peer ends up disconnected, and its slot freed.
    ///
    /// # The defect locked down here
    ///
    /// The read loop set a 120-second timeout on the socket and handled its
    /// expiry with `continue`: it started waiting again, indefinitely. A peer
    /// that stops sending was therefore never removed.
    ///
    /// Consequence, observed on a real laptop: you close the MacBook's lid, the
    /// connection dies without any FIN or RST arriving, and the node keeps a
    /// ghost peer. The peer count stays at one, the maintenance loop — which
    /// only searches if peers are missing — has nothing to do, and the chain
    /// stops at the height it was at. It stayed there.
    ///
    /// On a public network, it is also an eclipse path: opening connections
    /// and then going quiet is enough to occupy every slot.
    ///
    /// The test cannot wait a hundred seconds: it ages the last reception by
    /// hand, which is exactly what time would have done.
    #[test]
    fn a_silent_peer_is_dropped_and_its_slot_freed() {
        let (a, b) = node_pair();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");
        assert!(wait_until(|| b.peer_count() == 1, 20), "no peer");

        // Nothing must move as long as the peer talks.
        assert_eq!(b.maintain_peers(), 0, "a live peer was dropped");
        assert_eq!(b.peer_count(), 1);

        // Time passes, and nothing arrives anymore.
        {
            let mut g = b.shared.lock().unwrap();
            let old = Instant::now()
                .checked_sub(MAX_SILENCE + Duration::from_secs(5))
                .expect("clock");
            for p in g.peers.values_mut() {
                p.last_received = old;
            }
        }
        assert_eq!(b.maintain_peers(), 1, "the silent peer was not dropped");
        assert_eq!(
            b.peer_count(),
            0,
            "the silent peer's slot was not freed: the node will always \
             believe it has a peer, and will look for no one"
        );

        // And the freed slot can be taken again: that is the whole point of the
        // operation.
        b.connect(addr).expect("reconnection");
        assert!(wait_until(|| b.peer_count() == 1, 20), "no reconnection");

        a.shutdown();
        b.shutdown();
    }

    /// A shorter silence triggers a `Ping`, without disconnecting.
    ///
    /// Disconnecting at the first silence would be as wrong as never
    /// disconnecting: a slow link, a busy peer, and we end up reopening
    /// connections nonstop. We first ask the peer to show signs of life.
    #[test]
    fn a_brief_silence_queries_the_peer_without_dropping_it() {
        let (a, b) = node_pair();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");
        assert!(wait_until(|| b.peer_count() == 1, 20), "no peer");

        {
            let mut g = b.shared.lock().unwrap();
            let old = Instant::now()
                .checked_sub(PING_AFTER + Duration::from_secs(2))
                .expect("clock");
            for p in g.peers.values_mut() {
                p.last_received = old;
            }
        }
        assert_eq!(
            b.maintain_peers(),
            0,
            "a peer that was merely silent was dropped"
        );
        assert_eq!(b.peer_count(), 1);

        // The peer answers: the reply brings it back to life, and the next
        // maintenance finds nothing more to drop.
        assert!(
            wait_until(
                || {
                    let g = b.shared.lock().unwrap();
                    g.peers
                        .values()
                        .all(|p| p.last_received.elapsed() < PING_AFTER)
                },
                20
            ),
            "the peer did not answer the Ping"
        );

        a.shutdown();
        b.shutdown();
    }

    /// The test that proves phase 4 works.
    #[test]
    fn two_nodes_synchronize_over_tcp() {
        let (a, b) = node_pair();
        mine(&a, 12);
        assert_eq!(a.height(), 12);
        assert_eq!(b.height(), 0);

        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| b.height() == 12, 30),
            "b stayed at height {}",
            b.height()
        );
        assert_eq!(b.tip_id(), a.tip_id(), "the tips must match");
        assert_eq!(
            b.with_chain(|c| c.utxo.total_value()),
            a.with_chain(|c| c.utxo.total_value()),
            "the UTXO sets must match"
        );
        // Proof that the bytes really went over the wire: without it, a test
        // that passed by accident would prove nothing.
        //
        // The counter looks at **compact** blocks: since header-based
        // synchronization requests compact announcements rather than full
        // bodies, no `block` message travels anymore during catch-up. This is
        // the intended behavior, and this assertion locks it in.
        let compacts = b.stats.compacts_received.load(Ordering::Relaxed);
        assert!(
            compacts >= 12,
            "only {compacts} compact announcements received over the wire"
        );
        assert!(
            b.stats.blocks_accepted.load(Ordering::Relaxed) >= 12,
            "blocks received but not accepted"
        );
        // A fresh node has nothing in its mempool: each block therefore
        // required a round trip. The gain of compact relay is measured in
        // steady state, not during the initial catch-up.
        assert_eq!(
            b.stats.compacts_without_round_trip.load(Ordering::Relaxed),
            12,
            "blocks without transactions are reconstructed without a round trip"
        );
        a.shutdown();
        b.shutdown();
    }

    /// The cap on bodies in flight must not stop the synchronization.
    ///
    /// With at most sixteen bodies in flight per peer, a catch-up of more than
    /// sixteen blocks only holds if each body received makes us request the
    /// next one. Three and a half caps: enough to go through several waves,
    /// and for the header re-request on a drained queue to be exercised too.
    #[test]
    fn sync_continues_beyond_the_bodies_in_flight() {
        let (a, b) = node_pair();
        let target = MAX_BODIES_IN_FLIGHT * 3 + MAX_BODIES_IN_FLIGHT / 2;
        mine(&a, target);
        assert_eq!(a.height(), target as u64);

        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| b.height() == target as u64, 30),
            "b stayed at height {} out of {target}: the synchronization \
             stopped at the cap on bodies in flight",
            b.height()
        );
        assert_eq!(b.tip_id(), a.tip_id(), "the tips must match");
        // And never more than the in-flight cap toward this peer.
        let in_flight = {
            let g = b.shared.lock().unwrap();
            g.peers
                .values()
                .map(|p| p.requested_bodies.len())
                .max()
                .unwrap_or(0)
        };
        assert!(
            in_flight <= MAX_BODIES_IN_FLIGHT,
            "{in_flight} bodies in flight"
        );
        a.shutdown();
        b.shutdown();
    }

    /// A fake peer, to test admission on addresses that a machine without
    /// IPv6 cannot open. The socket is real — a `Peer` holds one — but the
    /// address is whatever we want.
    fn fake_peer(n: &Node, id: u64, addr: SocketAddr, outbound: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let stream = TcpStream::connect(listener.local_addr().unwrap()).expect("socket");
        let mut g = n.shared.lock().unwrap();
        g.peers.insert(
            id,
            Peer {
                addr,
                writer: Arc::new(Mutex::new(stream)),
                outbound,
                snapshot_bucket: TokenBucket::new(Instant::now()),
                tx_bucket: TokenBucket::for_transactions(Instant::now()),
                cmpct_bucket: TokenBucket::for_compact_announcements(Instant::now()),
                headers_bucket: TokenBucket::for_header_requests(Instant::now()),
                addr_bucket: TokenBucket::for_addresses(Instant::now()),
                expected_headers: 0,
                requested_bodies: HashMap::new(),
                bodies_to_request: VecDeque::new(),
                more_expected: false,
                version_received: false,
                version_sent: outbound,
                handshaked: false,
                ban_score: 0,
                start_height: 0,
                pending: HashMap::new(),
                consecutive_orphans: 0,
                last_received: Instant::now(),
                pending_ping: None,
                connected_at: Instant::now(),
            },
        );
    }

    /// Group diversity also applies to IPv6 inbound connections.
    ///
    /// The per-group cap was only computed for IPv4: a single `/64` could
    /// occupy every inbound slot of a node listening on IPv6. The test machine
    /// has no IPv6 and cannot open an IPv6 socket: we test the admission rule
    /// on peers with a chosen address.
    #[test]
    fn admission_also_bounds_ipv6_inbound() {
        let a = node();
        let same_64 =
            |k: u16| -> SocketAddr { format!("[2001:db8:1:2::{k:x}]:21021").parse().unwrap() };
        for k in 0..INBOUND_PER_GROUP as u16 {
            assert!(
                a.admit_inbound(Some(same_64(k + 1))),
                "connection number {} from the /64 must get through",
                k + 1
            );
            fake_peer(&a, 100 + u64::from(k), same_64(k + 1), false);
        }
        assert!(
            !a.admit_inbound(Some(same_64(0x99))),
            "a whole /64 must be bounded to {INBOUND_PER_GROUP} inbound connections, \
             like a /16 in IPv4"
        );
        // Another /64 of the same /48 is another group.
        let other_64: SocketAddr = "[2001:db8:1:3::1]:21021".parse().unwrap();
        assert!(
            a.admit_inbound(Some(other_64)),
            "another /64 must remain admitted"
        );
        // An IPv4 address presented as IPv6 counts with the IPv4 addresses of
        // its /16, not in a /64 shared by the whole v4 Internet.
        for k in 0..INBOUND_PER_GROUP as u16 {
            let v4: SocketAddr = format!("203.0.113.{}:21021", k + 1).parse().unwrap();
            fake_peer(&a, 200 + u64::from(k), v4, false);
        }
        let mapped: SocketAddr = "[::ffff:203.0.113.77]:21021".parse().unwrap();
        assert!(
            !a.admit_inbound(Some(mapped)),
            "a mapped IPv4 address must be counted in its /16"
        );
        let mapped_elsewhere: SocketAddr = "[::ffff:198.51.100.1]:21021".parse().unwrap();
        assert!(
            a.admit_inbound(Some(mapped_elsewhere)),
            "a mapped IPv4 address from another /16 must get through"
        );
        // And loopback stays outside any group, in v6 as in v4.
        assert_eq!(inbound_group("[::1]:1".parse().unwrap()), None);
        a.shutdown();
    }

    /// A household that has filled its group's slots learns why.
    ///
    /// The real-life case: four connections from the same router address, and
    /// a fifth device rejected without a word. The log must name the real
    /// cause — the group, not a full bootstrap node —, otherwise the operator
    /// looks at the server's capacity, which has nothing to do with it.
    #[test]
    fn a_group_rejection_says_it_is_the_group() {
        let a = node();
        let household =
            |k: u16| -> SocketAddr { format!("203.0.113.45:{}", 40000 + k).parse().unwrap() };
        assert_eq!(a.inbound_rejection(Some(household(0))), None);
        for k in 0..INBOUND_PER_GROUP as u16 {
            fake_peer(&a, 300 + u64::from(k), household(k), false);
        }
        let reason = a
            .inbound_rejection(Some(household(99)))
            .expect("the household's fifth device must be rejected");
        assert!(
            reason.contains("group"),
            "the reason must name the address group: {reason}"
        );
        // Another household, on the other hand, always gets in.
        let neighbor: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        assert_eq!(a.inbound_rejection(Some(neighbor)), None);
        a.shutdown();
    }

    /// Number of peers whose handshake is **complete** — the only ones
    /// `announce_block` talks to.
    ///
    /// `peer_count` also counts connections still introducing themselves. A
    /// test that waits for `peer_count() == 1` and then announces a block
    /// therefore runs a race: measured over 150 trials, in 135 cases the peer
    /// was counted before having introduced itself. The announcement then went
    /// to nobody, silently, and the test only held so far because mining the
    /// block took longer than finishing the handshake. On a loaded machine — a
    /// continuous integration runner running six hundred tests side by side —
    /// that is no longer true, and the release fails without a single line of
    /// code having changed.
    fn established_peers(n: &Node) -> usize {
        n.shared
            .lock()
            .unwrap()
            .peers
            .values()
            .filter(|p| p.handshaked)
            .count()
    }

    #[test]
    fn a_block_mined_after_connection_propagates() {
        let (a, b) = node_pair();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");
        // The handshake, not just the connection: see `established_peers`.
        assert!(
            wait_until(
                || established_peers(&a) == 1 && established_peers(&b) == 1,
                5
            ),
            "handshake not completed"
        );

        mine(&a, 1);
        let block = a.with_chain(|c| c.block_by_id(&c.tip_id())).unwrap();
        a.announce_block(&block);

        assert!(
            wait_until(|| b.height() == 1, 20),
            "the announced block was not fetched"
        );
        assert_eq!(b.tip_id(), a.tip_id());
        // Propagation must have gone through compact relay.
        assert!(
            b.stats.compacts_received.load(Ordering::Relaxed) > 0,
            "the block should have traveled as compact"
        );
        a.shutdown();
        b.shutdown();
    }

    #[test]
    fn a_node_refuses_to_connect_to_itself() {
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        a.connect(addr).expect("connection");
        // Nonce detection must end up closing both sides.
        assert!(
            wait_until(|| a.peer_count() <= 1, 10),
            "the connection to itself was not dropped"
        );
        a.shutdown();
    }

    #[test]
    fn random_bytes_do_not_bring_the_node_down() {
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");

        for seed in 0..20u64 {
            if let Ok(mut s) = TcpStream::connect(addr) {
                let mut raw = vec![0u8; 256];
                let mut g = seed.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(3);
                for o in raw.iter_mut() {
                    g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    *o = (g >> 33) as u8;
                }
                let _ = s.write_all(&raw);
            }
        }

        // The node must stay alive and answer normally afterwards.
        let b = node();
        b.connect(addr).expect("connection after aggression");
        assert!(
            wait_until(|| b.peer_count() == 1, 10),
            "the node stopped answering after random bytes"
        );
        a.shutdown();
        b.shutdown();
    }
}

#[cfg(test)]
mod tests_incompatible_chains {
    use super::tests_util::*;
    use super::*;
    use crate::block::BlockHeader;

    /// The defect found by running two real nodes, turned into a test.
    ///
    /// Two different geneses: the peers must notice it and part ways, instead
    /// of exchanging orphan blocks until exhaustion.
    #[test]
    fn two_nodes_with_different_geneses_part_ways() {
        let a = node_with_genesis(7);
        let b = node_with_genesis(99);
        assert_ne!(a.tip_id(), b.tip_id(), "the geneses must differ");

        mine_locally(&a, 5);
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        // Node b must neither progress nor keep at it.
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(b.height(), 0, "b should not have adopted a foreign chain");
        assert!(
            b.stats.blocks_received.load(Ordering::Relaxed) < 50,
            "b downloaded {} orphan blocks: the infinite loop is back",
            b.stats.blocks_received.load(Ordering::Relaxed)
        );
        a.shutdown();
        b.shutdown();
    }

    #[test]
    fn headers_that_do_not_follow_each_other_are_rejected() {
        let a = node_with_genesis(1);
        let mut fake = BlockHeader {
            version: 1,
            prev_block: a.tip_id(),
            merkle_root: Hash256([1u8; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([2u8; 32]),
            time: 1,
            bits: crate::consensus::INITIAL_BITS,
            height: 1,
            nonce: 0,
        };
        let first = fake;
        // The second does not point to the first: the sequence is broken.
        fake.prev_block = Hash256([0xaa; 32]);
        fake.height = 2;

        let before = a.stats.blocks_received.load(Ordering::Relaxed);
        let _ = a.handle(999, Message::Headers(vec![first, fake]));
        assert_eq!(
            a.stats.blocks_received.load(Ordering::Relaxed),
            before,
            "no body must be requested on a broken sequence"
        );
        a.shutdown();
    }
}

#[cfg(test)]
mod tests_util {
    use super::*;
    use crate::chain::genesis_block;
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::sig::SchemeId;

    pub const NETWORK: Network = Network::Regtest;

    /// Node whose genesis is artificially distinct.
    ///
    /// The real genesis is deterministic per network — that is precisely the
    /// fix. To simulate two incompatible chains, we shift its timestamp.
    pub fn node_with_genesis(offset: u64) -> Node {
        let mut g = genesis_block(NETWORK);
        g.header.time += offset;
        g.header.nonce = 0;
        let table =
            crate::memhard::PowTable::build(crate::memhard::TableParams::for_network(NETWORK), 0);
        let _ = crate::pow::mine_with_table(&mut g.header, &table, 5_000_000);
        Node::new(NETWORK, Chain::new(NETWORK, g))
    }

    pub fn mine_locally(n: &Node, count: usize) {
        for _ in 0..count {
            let b = n.with_chain(|c| {
                let t = c.tip().time + TARGET_BLOCK_SECS;
                c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
            });
            if let Some(b) = b {
                n.with_chain(|c| {
                    let t = b.header.time + 1;
                    let _ = c.connect(&b, t);
                });
            }
        }
    }
}

/// Hardening 0.3.2: work outside the lock, header bucket, unrequested
/// headers.
#[cfg(test)]
mod tests_hardening {
    use super::*;
    use crate::chain::genesis_block;
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::pow::PowEngine;
    use crate::sig::SchemeId;

    const NETWORK: Network = Network::Regtest;

    fn node_pair() -> (Node, Node) {
        let g = genesis_block(NETWORK);
        (
            Node::new(NETWORK, Chain::new(NETWORK, g.clone())),
            Node::new(NETWORK, Chain::new(NETWORK, g)),
        )
    }

    /// An established peer, on a real socket whose other end nobody reads: we
    /// observe the node's state, not what it writes.
    fn established_peer(n: &Node, id: u64) -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let stream = TcpStream::connect(listener.local_addr().unwrap()).expect("socket");
        let addr = stream.peer_addr().unwrap();
        let mut g = n.shared.lock().unwrap();
        g.peers.insert(
            id,
            Peer {
                addr,
                writer: Arc::new(Mutex::new(stream)),
                outbound: true,
                snapshot_bucket: TokenBucket::new(Instant::now()),
                tx_bucket: TokenBucket::for_transactions(Instant::now()),
                cmpct_bucket: TokenBucket::for_compact_announcements(Instant::now()),
                headers_bucket: TokenBucket::for_header_requests(Instant::now()),
                addr_bucket: TokenBucket::for_addresses(Instant::now()),
                expected_headers: 0,
                requested_bodies: HashMap::new(),
                bodies_to_request: VecDeque::new(),
                more_expected: false,
                version_received: true,
                version_sent: true,
                handshaked: true,
                ban_score: 0,
                start_height: 0,
                pending: HashMap::new(),
                consecutive_orphans: 0,
                last_received: Instant::now(),
                pending_ping: None,
                connected_at: Instant::now(),
            },
        );
        listener
    }

    /// A valid block mined on `n`, without connecting it.
    fn next_block(n: &Node) -> Block {
        n.with_chain(|c| {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
        })
        .expect("regtest mining")
    }

    fn memo(n: &Node) -> std::sync::Arc<crate::pow::WorkMemo> {
        n.with_chain(|c| c.work_memo())
    }

    /// The work of a received block is checked before the lock, and the chain
    /// reads the verdict back instead of recomputing it under the lock.
    #[test]
    fn the_work_of_a_received_block_is_checked_outside_the_lock() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let block = next_block(&a);
        let m = memo(&b);
        assert!(b.handle(7, Message::Block(Box::new(block))));
        assert_eq!(b.height(), 1, "the valid block must be adopted");
        assert_eq!(b.stats.work_outside_lock.load(Ordering::Relaxed), 1);
        assert_eq!(
            m.computed.load(Ordering::Relaxed),
            0,
            "no work hash must be computed under the lock"
        );
        assert!(m.hits.load(Ordering::Relaxed) >= 1);
    }

    /// A header with wrong work, announced as compact: the rejection comes from
    /// the verdict computed outside the lock, with no reconstruction and no
    /// computation under the lock.
    #[test]
    fn an_announcement_with_wrong_work_is_rejected_without_computing_under_the_lock() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let mut block = next_block(&a);
        let engine = crate::pow::Q21Pow::new(NETWORK);
        while engine.check(&block.header).is_ok() {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        let c = CompactBlock::from_block(&block, 1);
        let m = memo(&b);
        let _ = b.handle(7, Message::CmpctBlock(Box::new(c)));
        assert_eq!(b.height(), 0);
        assert_eq!(b.stats.work_outside_lock.load(Ordering::Relaxed), 1);
        assert_eq!(b.stats.compacts_header_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(b.stats.compacts_reconstructed.load(Ordering::Relaxed), 0);
        assert_eq!(m.computed.load(Ordering::Relaxed), 0);
    }

    /// The announcement budget comes before the work, outside the lock as
    /// inside it.
    #[test]
    fn an_over_budget_announcement_computes_nothing() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        b.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .cmpct_bucket = TokenBucket {
            tokens: 0,
            last: Instant::now(),
        };
        let c = CompactBlock::from_block(&next_block(&a), 1);
        let _ = b.handle(7, Message::CmpctBlock(Box::new(c)));
        assert_eq!(b.stats.work_outside_lock.load(Ordering::Relaxed), 0);
        assert_eq!(b.stats.compacts_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(memo(&b).computed.load(Ordering::Relaxed), 0);
    }

    /// A header at a height that does not follow its parent computes nothing,
    /// even outside the lock: the height chooses the epoch, and an unknown
    /// epoch costs an entire cache.
    #[test]
    fn an_out_of_context_header_computes_nothing() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let mut block = next_block(&a);
        block.header.height = 1_000_000;
        let _ = b.handle(7, Message::Block(Box::new(block)));
        assert_eq!(b.stats.work_outside_lock.load(Ordering::Relaxed), 0);
        assert_eq!(memo(&b).computed.load(Ordering::Relaxed), 0);
        assert!(memo(&b).is_empty());
    }

    /// Header requests go through a bucket: beyond it, nothing is served.
    #[test]
    fn header_requests_are_bounded_by_a_bucket() {
        let (a, _) = node_pair();
        crate::net::tests_util::mine_locally(&a, 3);
        let _e = established_peer(&a, 7);
        let request = || Message::GetHeaders {
            locator: vec![Hash256([0x55; 32])],
            stop: Hash256::ZERO,
        };
        let burst = HEADERS_BUCKET_MAX + 5;
        for _ in 0..burst {
            assert!(a.handle(7, request()), "an overrun does not disconnect");
        }
        assert_eq!(a.stats.headers_rejected.load(Ordering::Relaxed), 5);
        // The bucket refills over time: a request gets through again.
        std::thread::sleep(Duration::from_millis(1100));
        let _ = a.handle(7, request());
        assert_eq!(a.stats.headers_rejected.load(Ordering::Relaxed), 5);
    }

    /// A batch of headers nobody requested is not read, and costs points; the
    /// same batch, requested, is read.
    #[test]
    fn an_unrequested_header_batch_is_ignored() {
        let (a, b) = node_pair();
        crate::net::tests_util::mine_locally(&a, 3);
        let headers = a.with_chain(|c| c.headers_from(&[], Hash256::ZERO, 10));
        assert_eq!(headers.len(), 3);
        let _e = established_peer(&b, 7);

        let _ = b.handle(7, Message::Headers(headers.clone()));
        {
            let g = b.shared.lock().unwrap();
            let p = &g.peers[&7];
            assert!(p.bodies_to_request.is_empty() && p.requested_bodies.is_empty());
            assert_eq!(p.ban_score, MISCONDUCT_UNREQUESTED_HEADERS);
        }
        assert_eq!(b.stats.unrequested_headers.load(Ordering::Relaxed), 1);

        // A request sent opens a slot: the reply is read.
        b.send_to(
            7,
            &Message::GetHeaders {
                locator: vec![],
                stop: Hash256::ZERO,
            },
        );
        let _ = b.handle(7, Message::Headers(headers));
        let g = b.shared.lock().unwrap();
        let p = &g.peers[&7];
        assert_eq!(p.expected_headers, 0, "the reply consumes its slot");
        assert_eq!(
            p.requested_bodies.len() + p.bodies_to_request.len(),
            3,
            "the three bodies must be requested or queued"
        );
    }

    /// Reply slots do not accumulate beyond the bound.
    #[test]
    fn reply_slots_are_bounded() {
        let (a, _) = node_pair();
        let _e = established_peer(&a, 7);
        for _ in 0..50 {
            a.send_to(
                7,
                &Message::GetHeaders {
                    locator: vec![],
                    stop: Hash256::ZERO,
                },
            );
        }
        assert_eq!(
            a.shared.lock().unwrap().peers[&7].expected_headers,
            MAX_EXPECTED_HEADERS
        );
    }

    /// An `inv` received before the handshake is not read: nothing is requested
    /// or recorded in flight on behalf of an anonymous connection.
    #[test]
    fn an_inv_before_the_handshake_is_not_read() {
        let a = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
        let _e = established_peer(&a, 7);
        a.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .handshaked = false;
        let announcement: Vec<InvItem> = (0..100u8)
            .map(|k| InvItem {
                kind: InvKind::Block,
                hash: Hash256([k; 32]),
            })
            .collect();
        let _ = a.handle(7, Message::Inv(announcement.clone()));
        {
            let g = a.shared.lock().unwrap();
            let p = &g.peers[&7];
            assert!(p.requested_bodies.is_empty() && p.bodies_to_request.is_empty());
        }
        // Once established, the same `inv` is read, within the limit of the
        // in-flight slots.
        a.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .handshaked = true;
        let _ = a.handle(7, Message::Inv(announcement));
        let g = a.shared.lock().unwrap();
        assert_eq!(g.peers[&7].requested_bodies.len(), MAX_BODIES_IN_FLIGHT);
    }

    /// Received addresses go through a bucket: a full reply gets through, a
    /// burst beyond it is ignored without disconnecting.
    #[test]
    fn received_addresses_are_bounded_by_a_bucket() {
        let a = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
        let _e = established_peer(&a, 7);
        // A thousand routable addresses from distinct groups.
        let batch = |base: u8| -> Vec<crate::wire::NetAddr> {
            (0..crate::wire::MAX_ADDR)
                .map(|k| crate::wire::NetAddr {
                    ip: [base, (k / 250) as u8 + 1, (k % 250) as u8 + 1, 7],
                    port: 21121,
                    last_seen: 1,
                })
                .collect()
        };
        assert!(a.handle(7, Message::Addr(batch(11))));
        let after_one = a.address_count();
        assert!(after_one > 0);
        assert_eq!(a.stats.addresses_ignored.load(Ordering::Relaxed), 0);
        // The bucket is empty: the next batch records nothing, and does not
        // disconnect.
        assert!(a.handle(7, Message::Addr(batch(12))));
        assert_eq!(a.stats.addresses_ignored.load(Ordering::Relaxed), 1);
        assert_eq!(a.address_count(), after_one);
    }

    /// A misbehavior score never overflows: `overflow-checks` is on in
    /// production, and an overflow there would stop the node.
    #[test]
    fn the_misbehavior_score_saturates() {
        let a = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
        let _e = established_peer(&a, 7);
        a.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .ban_score = u32::MAX - 1;
        assert!(!a.penalize(7, MISCONDUCT_BAD_BLOCK));
        assert_eq!(a.shared.lock().unwrap().peers[&7].ban_score, u32::MAX);
    }
}

/// Handler fuzzing: `handle` fed structured, hostile messages, over several
/// interleaved peers, with the module's bounds checked after every step.
///
/// The decoder fuzzing (`tests/fuzz_decoders.rs`) stops at `parse`; here we
/// start from already-decoded messages, with fields chosen to land on the
/// edges: limits off by one, huge counts that the decoder still accepts,
/// headers with real work chained onto the tip, and from time to time a real
/// valid block so that the chain advances and honest progress gets tested
/// too.
///
/// Reproducible: `Q21_FUZZ_SEED` sets the starting seed, `Q21_FUZZ_SEEDS` the
/// number of seeds, `Q21_FUZZ_ITERATIONS` the number of messages per seed. On
/// failure, the seed and the step are printed.
#[cfg(test)]
mod tests_handler_fuzz {
    use super::*;
    use crate::amount::Amount;
    use crate::block::BlockHeader;
    use crate::chain::genesis_block;
    use crate::sig::SchemeId;
    use crate::tx::{OutPoint, TxIn, TxOut, Witness};
    use crate::wire::NetAddr;
    use std::collections::BTreeMap;
    use std::net::TcpListener;

    const NETWORK: Network = Network::Regtest;

    /// Generous threshold for a single `handle`: far beyond anything an honest
    /// message requires, it only serves to bring out a lock held abnormally
    /// long.
    const HANDLE_THRESHOLD: Duration = Duration::from_secs(2);

    /// splitmix64: dependency-free, reproducible.
    struct Prng(u64);

    impl Prng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        /// Integer in `[0, n)`, `n > 0`.
        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n.max(1)
        }
        fn one_in(&mut self, n: u64) -> bool {
            self.below(n) == 0
        }
        fn hash(&mut self) -> Hash256 {
            let mut o = [0u8; 32];
            for c in o.chunks_mut(8) {
                c.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            Hash256(o)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next_u64() as u8).collect()
        }
        /// Fewer than `bound` arbitrary bytes.
        fn bytes_up_to(&mut self, bound: u64) -> Vec<u8> {
            let n = self.below(bound) as usize;
            self.bytes(n)
        }
        /// A u64 value on the edges: zero, one, maximum, neighbors, or
        /// arbitrary.
        fn edge_u64(&mut self, around: u64) -> u64 {
            match self.below(8) {
                0 => 0,
                1 => 1,
                2 => u64::MAX,
                3 => u64::MAX - 1,
                4 => around.wrapping_sub(1),
                5 => around,
                6 => around.wrapping_add(1),
                _ => self.next_u64(),
            }
        }
        fn edge_u32(&mut self, around: u32) -> u32 {
            match self.below(7) {
                0 => 0,
                1 => u32::MAX,
                2 => u32::MAX - 1,
                3 => around.wrapping_sub(1),
                4 => around,
                5 => around.wrapping_add(1),
                _ => self.next_u64() as u32,
            }
        }
        /// A list size: empty, one, the bound, the bound minus one, or
        /// arbitrary below it.
        fn count(&mut self, max: usize) -> usize {
            match self.below(6) {
                0 => 0,
                1 => 1.min(max),
                2 if self.one_in(4) => max,
                3 if self.one_in(4) => max.saturating_sub(1),
                _ => self.below((max as u64).min(64) + 1) as usize,
            }
        }
    }

    /// Plugs in a fake peer. The other end of its socket is read and discarded
    /// by a thread: the node's replies go out without ever blocking, and the
    /// thread dies with the socket when the peer is disconnected.
    fn plug_in(n: &Node, id: u64, established: bool, outbound: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let stream = TcpStream::connect(listener.local_addr().unwrap()).expect("socket");
        let (mut other, _) = listener.accept().expect("accept");
        std::thread::spawn(move || {
            let mut b = [0u8; 64 * 1024];
            while let Ok(k) = other.read(&mut b) {
                if k == 0 {
                    break;
                }
            }
        });
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let addr = stream.peer_addr().unwrap();
        let now = Instant::now();
        n.shared.lock().unwrap().peers.insert(
            id,
            Peer {
                addr,
                writer: Arc::new(Mutex::new(stream)),
                outbound,
                snapshot_bucket: TokenBucket::new(now),
                tx_bucket: TokenBucket::for_transactions(now),
                cmpct_bucket: TokenBucket::for_compact_announcements(now),
                headers_bucket: TokenBucket::for_header_requests(now),
                addr_bucket: TokenBucket::for_addresses(now),
                expected_headers: 0,
                requested_bodies: HashMap::new(),
                bodies_to_request: VecDeque::new(),
                more_expected: false,
                version_received: established,
                version_sent: established || outbound,
                handshaked: established,
                ban_score: 0,
                start_height: 0,
                pending: HashMap::new(),
                consecutive_orphans: 0,
                last_received: now,
                pending_ping: None,
                connected_at: now,
            },
        );
    }

    /// Mines a header as is: the work is real, the content is whatever the
    /// caller chose. This is what gets a hostile message past the header
    /// checks and down to the deep paths.
    struct Miner {
        table: Option<Arc<crate::memhard::PowTable>>,
    }

    impl Miner {
        fn mine(&mut self, mut h: BlockHeader) -> Option<BlockHeader> {
            let epoch = crate::memhard::epoch_of(h.height);
            if self.table.as_ref().map(|t| t.epoch()) != Some(epoch) {
                self.table = Some(Arc::new(crate::memhard::PowTable::build(
                    crate::memhard::TableParams::for_network(NETWORK),
                    epoch,
                )));
            }
            let t = self.table.as_ref().unwrap();
            crate::pow::mine_with_table(&mut h, t, 5_000_000).ok()?;
            Some(h)
        }
    }

    /// What the fuzzer knows about the node's chain, to aim right.
    struct Known {
        active: Vec<Hash256>,
        coinbases: Vec<Hash256>,
        pending: Vec<Hash256>,
        /// Last genuinely valid block built and not yet delivered.
        next_valid: Option<Block>,
    }

    fn header_on(tip: &BlockHeader, tip_id: Hash256, a: &mut Prng) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: tip_id,
            merkle_root: a.hash(),
            uncles_root: Hash256::ZERO,
            miner: a.hash(),
            time: tip.time.wrapping_add(1),
            bits: crate::consensus::INITIAL_BITS,
            height: tip.height.wrapping_add(1),
            nonce: a.next_u64(),
        }
    }

    /// A hostile transaction: many inputs, huge witnesses, bad signatures,
    /// amounts on the edges, real or invented inputs.
    fn hostile_tx(a: &mut Prng, known: &Known) -> Transaction {
        let n_in = match a.below(5) {
            0 => 0,
            1 => 1,
            2 => a.below(600) as usize,
            _ => 1 + a.below(4) as usize,
        };
        let big_witness = a.one_in(20);
        let inputs = (0..n_in)
            .map(|_| {
                let prev_out = match a.below(4) {
                    0 if !known.coinbases.is_empty() => OutPoint {
                        txid: known.coinbases[a.below(known.coinbases.len() as u64) as usize],
                        index: a.edge_u32(0),
                    },
                    1 => OutPoint::COINBASE,
                    _ => OutPoint {
                        txid: a.hash(),
                        index: a.edge_u32(0),
                    },
                };
                let size = if big_witness {
                    a.below(64 * 1024) as usize
                } else {
                    a.below(96) as usize
                };
                TxIn {
                    prev_out,
                    witness: Witness {
                        pubkey: a.bytes(size / 2),
                        signature: a.bytes(size),
                    },
                    sequence: a.edge_u32(0),
                }
            })
            .collect();
        let n_out = match a.below(4) {
            0 => 0,
            1 => a.below(300) as usize,
            _ => 1 + a.below(3) as usize,
        };
        let outputs = (0..n_out)
            .map(|_| TxOut {
                value: Amount::from_units(a.edge_u64(crate::consensus::MIN_OUTPUT_VALUE)),
                scheme: if a.one_in(2) {
                    SchemeId::LamportOts
                } else {
                    SchemeId::MlDsa65
                },
                pubkey_hash: a.hash(),
            })
            .collect();
        Transaction {
            version: a.edge_u32(1),
            inputs,
            outputs,
            lock_time: a.edge_u64(0),
        }
    }

    fn targeted_hash(a: &mut Prng, known: &Known) -> Hash256 {
        match a.below(4) {
            0 if !known.active.is_empty() => {
                known.active[a.below(known.active.len() as u64) as usize]
            }
            1 if !known.pending.is_empty() => {
                known.pending[a.below(known.pending.len() as u64) as usize]
            }
            2 => Hash256::ZERO,
            _ => a.hash(),
        }
    }

    fn inv_kind(a: &mut Prng) -> InvKind {
        match a.below(3) {
            0 => InvKind::Tx,
            1 => InvKind::Block,
            _ => InvKind::CompactBlock,
        }
    }

    /// A message of variant `v`, with fields chosen to hit the edges. Also
    /// returns `true` if the message carries a genuinely valid block that
    /// extends the tip.
    fn message(
        v: u64,
        a: &mut Prng,
        n: &Node,
        known: &mut Known,
        miner: &mut Miner,
    ) -> (Message, bool) {
        let (tip, tip_id, height, local_nonce) = {
            let g = n.shared.lock().unwrap();
            (g.chain.tip(), g.chain.tip_id(), g.chain.height(), g.nonce)
        };
        let m = match v {
            0 => Message::Version {
                version: match a.below(4) {
                    0 => MIN_PROTOCOL_VERSION - 1,
                    1 => PROTOCOL_VERSION,
                    2 => u32::MAX,
                    _ => a.next_u64() as u32,
                },
                timestamp: a.edge_u64(unix_now()),
                nonce: if a.one_in(8) {
                    local_nonce
                } else {
                    a.edge_u64(local_nonce)
                },
                user_agent: String::from_utf8_lossy(&a.bytes_up_to(65)).into_owned(),
                start_height: a.edge_u64(height),
            },
            1 => Message::VerAck,
            2 => Message::Ping(a.next_u64()),
            3 => Message::Pong(a.next_u64()),
            4 => Message::GetHeaders {
                locator: (0..a.count(crate::wire::MAX_LOCATOR))
                    .map(|_| targeted_hash(a, known))
                    .collect(),
                stop: targeted_hash(a, known),
            },
            5 => {
                // A sequence of headers chained onto the tip or elsewhere, with
                // right or wrong height, difficulty and time.
                let k = a.count(crate::wire::MAX_HEADERS);
                let mut prev = tip;
                let mut prev_id = if a.one_in(6) { a.hash() } else { tip_id };
                let mut v = Vec::with_capacity(k);
                for _ in 0..k {
                    let mut h = header_on(&prev, prev_id, a);
                    match a.below(10) {
                        0 => h.height = a.edge_u64(prev.height),
                        1 => h.bits = a.edge_u32(crate::consensus::INITIAL_BITS),
                        2 => h.time = a.edge_u64(prev.time),
                        3 => h.prev_block = a.hash(),
                        _ => {}
                    }
                    prev = h;
                    prev_id = h.block_id();
                    v.push(h);
                }
                Message::Headers(v)
            }
            6 | 7 => {
                let k = if a.one_in(40) {
                    crate::wire::MAX_INV
                } else {
                    a.count(crate::wire::MAX_INV)
                };
                let items: Vec<InvItem> = (0..k)
                    .map(|_| InvItem {
                        kind: inv_kind(a),
                        hash: targeted_hash(a, known),
                    })
                    .collect();
                if v == 6 {
                    Message::Inv(items)
                } else {
                    Message::GetData(items)
                }
            }
            8 => {
                // A block: genuinely valid, mutated, or forged with real work
                // but a wrong body.
                match a.below(4) {
                    0 => {
                        // A block set aside is only worth anything if it still
                        // extends the tip.
                        let kept = known
                            .next_valid
                            .take()
                            .filter(|b| b.header.prev_block == tip_id);
                        let b = kept.unwrap_or_else(|| {
                            n.with_chain(|c| {
                                c.mine_block(
                                    a.hash(),
                                    SchemeId::LamportOts,
                                    &[],
                                    c.tip().time + 1,
                                    5_000_000,
                                )
                            })
                            .expect("regtest mining")
                        });
                        return (Message::Block(Box::new(b)), true);
                    }
                    1 => {
                        let mut b = n
                            .with_chain(|c| {
                                c.mine_block(
                                    a.hash(),
                                    SchemeId::LamportOts,
                                    &[],
                                    c.tip().time + 1,
                                    5_000_000,
                                )
                            })
                            .expect("regtest mining");
                        known.next_valid = Some(b.clone());
                        match a.below(5) {
                            0 => b.header.height = a.edge_u64(b.header.height),
                            1 => b.header.time = a.edge_u64(b.header.time),
                            2 => b.transactions.clear(),
                            3 => b.transactions.push(hostile_tx(a, known)),
                            _ => b.transactions[0].outputs[0].value = Amount::from_units(u64::MAX),
                        }
                        Message::Block(Box::new(b))
                    }
                    2 => {
                        // Real work, body inconsistent with the rules.
                        let mut b = n.with_chain(|c| {
                            c.mining_candidate(
                                a.hash(),
                                SchemeId::LamportOts,
                                &[],
                                c.tip().time + 1,
                            )
                        });
                        b.transactions.push(hostile_tx(a, known));
                        b.header.merkle_root = b.compute_merkle_root();
                        if let Some(h) = miner.mine(b.header) {
                            b.header = h;
                        }
                        Message::Block(Box::new(b))
                    }
                    _ => Message::Block(Box::new(Block {
                        header: header_on(&tip, tip_id, a),
                        transactions: (0..a.below(3)).map(|_| hostile_tx(a, known)).collect(),
                        uncles: Vec::new(),
                    })),
                }
            }
            9 => Message::Tx(Box::new(hostile_tx(a, known))),
            10 => {
                // Compact block: header with or without real work, random
                // short identifiers, absurd counts, missing coinbase.
                let header = match a.below(4) {
                    0 | 1 => miner
                        .mine(header_on(&tip, tip_id, a))
                        .unwrap_or_else(|| header_on(&tip, tip_id, a)),
                    2 => n.with_chain(|c| c.tip()),
                    _ => header_on(&tip, tip_id, a),
                };
                if a.one_in(6) {
                    // Consistent announcement: the root covers the coinbase
                    // and an invalid transaction, the work is real. The
                    // reconstruction succeeds, validation must refuse.
                    let mut b = n.with_chain(|c| {
                        c.mining_candidate(a.hash(), SchemeId::LamportOts, &[], c.tip().time + 1)
                    });
                    let t = hostile_tx(a, known);
                    b.transactions.push(t);
                    b.header.merkle_root = b.compute_merkle_root();
                    if let Some(h) = miner.mine(b.header) {
                        b.header = h;
                    }
                    let mut c = CompactBlock::from_block(&b, a.next_u64());
                    if a.one_in(2) {
                        // We hold back the transaction: it will have to be
                        // requested again.
                        known.pending.push(b.header.block_id());
                    } else {
                        c.prefilled.push((1, b.transactions[1].clone()));
                        c.short_ids.clear();
                    }
                    return (Message::CmpctBlock(Box::new(c)), false);
                }
                let n_ids = match a.below(5) {
                    0 => crate::compact::MAX_TX_PER_BLOCK,
                    1 => crate::compact::MAX_TX_PER_BLOCK - 1,
                    _ => a.below(40) as usize,
                };
                let mut prefilled = Vec::new();
                match a.below(4) {
                    0 => {}
                    1 => prefilled.push((a.edge_u32(0), hostile_tx(a, known))),
                    _ => {
                        prefilled.push((0, hostile_tx(a, known)));
                        for _ in 0..a.below(4) {
                            prefilled.push((a.edge_u32(n_ids as u32), hostile_tx(a, known)));
                        }
                    }
                }
                let c = CompactBlock {
                    header,
                    nonce: a.next_u64(),
                    short_ids: (0..n_ids)
                        .map(|_| a.next_u64() & 0x0000_ffff_ffff_ffff)
                        .collect(),
                    prefilled,
                    uncles: (0..a.count(64))
                        .map(|_| header_on(&tip, tip_id, a))
                        .collect(),
                };
                known.pending.push(c.header.block_id());
                if known.pending.len() > 64 {
                    known.pending.remove(0);
                }
                Message::CmpctBlock(Box::new(c))
            }
            11 => Message::GetBlockTxn {
                block: targeted_hash(a, known),
                indices: (0..if a.one_in(30) {
                    crate::wire::MAX_BLOCK_TXN
                } else {
                    a.count(crate::wire::MAX_BLOCK_TXN)
                })
                    .map(|_| a.edge_u32(0))
                    .collect(),
            },
            12 => Message::BlockTxn {
                block: targeted_hash(a, known),
                txs: (0..a.below(4)).map(|_| hostile_tx(a, known)).collect(),
            },
            13 => Message::GetAddr,
            14 => {
                let k = if a.one_in(4) {
                    crate::wire::MAX_ADDR
                } else {
                    a.count(crate::wire::MAX_ADDR)
                };
                Message::Addr(
                    (0..k)
                        .map(|_| NetAddr {
                            ip: match a.below(6) {
                                0 => [127, 0, 0, 1],
                                1 => [10, a.next_u64() as u8, 0, 1],
                                2 => [192, 168, 1, a.next_u64() as u8],
                                3 => [255, 255, 255, 255],
                                _ => {
                                    let b = a.next_u64().to_le_bytes();
                                    [b[0], b[1], b[2], b[3]]
                                }
                            },
                            port: if a.one_in(8) { 0 } else { a.next_u64() as u16 },
                            last_seen: a.edge_u64(unix_now()),
                        })
                        .collect(),
                )
            }
            15 => Message::Reject {
                command: String::from_utf8_lossy(&a.bytes_up_to(65)).into_owned(),
                reason: String::from_utf8_lossy(&a.bytes_up_to(257)).into_owned(),
            },
            16 => Message::GetSnapshot,
            17 => Message::SnapshotInfo {
                height: a.edge_u64(height),
                tip: a.hash(),
                commitment: a.hash(),
                size: a.edge_u64(0),
                chunks: a.edge_u32(0),
            },
            18 => Message::GetSnapshotChunk {
                index: a.edge_u32(0),
            },
            _ => Message::SnapshotChunk {
                index: a.edge_u32(0),
                data: a.bytes_up_to(4096),
            },
        };
        (m, false)
    }

    const VARIANTS: u64 = 20;

    /// The module's bounds, checked after every step.
    fn check_invariants(n: &Node, context: &str, check_book: bool) {
        assert!(!n.shared.is_poisoned(), "{context}: lock poisoned");
        let g = n.shared.lock().unwrap();
        for (id, p) in &g.peers {
            assert!(
                p.pending.len() <= MAX_PENDING_RECONSTRUCTIONS,
                "{context}: peer {id}, {} pending reconstructions",
                p.pending.len()
            );
            assert!(
                p.requested_bodies.len() <= MAX_BODIES_IN_FLIGHT,
                "{context}: peer {id}, {} bodies in flight",
                p.requested_bodies.len()
            );
            assert!(
                p.bodies_to_request.len() <= MAX_PENDING_BODIES,
                "{context}: peer {id}, {} bodies queued",
                p.bodies_to_request.len()
            );
            assert!(
                p.expected_headers <= MAX_EXPECTED_HEADERS,
                "{context}: peer {id}, {} expected header replies",
                p.expected_headers
            );
            assert!(
                p.snapshot_bucket.tokens <= SNAPSHOT_BUCKET_MAX,
                "{context}: snapshot bucket"
            );
            assert!(
                p.tx_bucket.tokens <= TX_BUCKET_MAX,
                "{context}: transaction bucket"
            );
            assert!(
                p.cmpct_bucket.tokens <= CMPCT_BUCKET_MAX,
                "{context}: compact bucket"
            );
            assert!(
                p.headers_bucket.tokens <= HEADERS_BUCKET_MAX,
                "{context}: header bucket"
            );
            assert!(
                p.addr_bucket.tokens <= ADDR_BUCKET_MAX,
                "{context}: address bucket"
            );
            assert!(
                !p.handshaked || p.version_received,
                "{context}: peer {id} established without `Version`"
            );
        }
        assert!(
            g.mempool.bytes() <= crate::mempool::MEMPOOL_MAX_BYTES,
            "{context}: mempool beyond its cap"
        );
        assert!(
            g.book.groups() <= crate::addr::MAX_GROUPS,
            "{context}: {} groups in the address book",
            g.book.groups()
        );
        if check_book {
            let all = g.book.all();
            assert!(
                all.len() <= crate::addr::MAX_GROUPS * crate::addr::MAX_PER_GROUP,
                "{context}: {} addresses in the address book",
                all.len()
            );
            let limit = unix_now() + crate::addr::FUTURE_TOLERANCE;
            for e in all {
                assert!(e.addr.port != 0, "{context}: zero port in the address book");
                assert!(
                    crate::addr::routable(e.addr.ip, true),
                    "{context}: non-routable address in the address book"
                );
                assert!(
                    e.addr.last_seen <= limit,
                    "{context}: address seen in the future"
                );
            }
        }
    }

    /// Necessary conditions for an adopted block, checked without going
    /// through the chain: parent, recomputed work, shape, coinbase within the
    /// subsidy.
    fn independently_valid(b: &Block, parent: Hash256, context: &str) {
        use crate::pow::PowEngine;
        assert_eq!(
            b.header.prev_block, parent,
            "{context}: wrong parent adopted"
        );
        assert!(
            crate::pow::Q21Pow::new(NETWORK).check(&b.header).is_ok(),
            "{context}: block without work adopted"
        );
        assert!(
            b.check_shape().is_ok(),
            "{context}: malformed block adopted"
        );
        assert_eq!(
            b.transactions.len(),
            1,
            "{context}: invented transaction adopted"
        );
        let paid = b.transactions[0].total_output().expect("sum").units();
        assert!(
            paid <= crate::emission::block_subsidy(b.header.height).units(),
            "{context}: coinbase beyond the subsidy"
        );
    }

    /// What a seed observed, for the report.
    #[derive(Default)]
    struct Tally {
        messages: BTreeMap<&'static str, (u64, Duration)>,
        valid_blocks: u64,
        drops: u64,
        /// Generated messages larger than a frame, hence discarded.
        oversized: u64,
    }

    /// Prints the seed and the step if a step panics, whatever it is.
    struct FailureReporter {
        seed: u64,
        step: u64,
        command: &'static str,
    }

    impl Drop for FailureReporter {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!(
                    "FUZZ FAILURE: seed {:#x}, step {}, message `{}`. \
                     Replay with Q21_FUZZ_SEED={:#x} Q21_FUZZ_SEEDS=1",
                    self.seed, self.step, self.command, self.seed
                );
            }
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

    /// One seed: `iterations` messages spread over several peers, then the
    /// proof that the node still synchronizes an honest peer.
    fn campaign(seed: u64, iterations: u64, tally: &mut Tally) {
        let n = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
        let mut a = Prng(seed);
        let mut miner = Miner { table: None };
        let mut known = Known {
            active: vec![n.tip_id()],
            coinbases: Vec::new(),
            pending: Vec::new(),
            next_valid: None,
        };
        // Four established peers, two that are not, in each direction.
        let mut ids: Vec<u64> = Vec::new();
        let mut next_id = 1u64;
        for i in 0..6u64 {
            plug_in(&n, next_id, i < 4, i % 2 == 0);
            ids.push(next_id);
            next_id += 1;
        }
        let mut reporter = FailureReporter {
            seed,
            step: 0,
            command: "",
        };

        for step in 0..iterations {
            reporter.step = step;
            let slot = a.below(ids.len() as u64) as usize;
            let id = ids[slot];
            // Handshake messages and the most common ones come back more
            // often: they open the paths of the others.
            let v = if a.one_in(5) {
                a.below(2)
            } else {
                a.below(VARIANTS)
            };
            reporter.command = "(generation)";
            let (m, valid) = message(v, &mut a, &n, &mut known, &mut miner);
            // What the decoder would refuse never reaches `handle`.
            if m.frame(n.magic).len() > HEADER_LEN + MAX_PAYLOAD {
                tally.oversized += 1;
                continue;
            }
            let cmd = m.command();
            reporter.command = cmd;
            let (before, established) = {
                let g = n.shared.lock().unwrap();
                (
                    g.chain.tip_id(),
                    g.peers.get(&id).map(|p| p.handshaked).unwrap_or(false),
                )
            };
            let block = match &m {
                Message::Block(b) => Some(b.header),
                _ => None,
            };

            let start = Instant::now();
            let keep = n.handle(id, m);
            let elapsed = start.elapsed();

            let e = tally.messages.entry(cmd).or_default();
            e.0 += 1;
            e.1 = e.1.max(elapsed);
            let context = format!("seed {seed:#x}, step {step}, `{cmd}`");
            assert!(
                elapsed < HANDLE_THRESHOLD,
                "{context}: handle took {elapsed:?}"
            );
            check_invariants(&n, &context, step % 64 == 0);
            if keep {
                // A kept peer is below the threshold: otherwise a penalty was
                // counted without anyone disconnecting.
                let score = n.shared.lock().unwrap().peers.get(&id).map(|p| p.ban_score);
                assert!(
                    score.unwrap_or(0) < BAN_THRESHOLD,
                    "{context}: peer {id} kept with a score of {score:?}"
                );
            }

            // The chain only advances on a genuinely valid block, and such a
            // block coming from an established peer is always adopted.
            let after = n.tip_id();
            if valid && established {
                let h = block.expect("valid block");
                assert_eq!(after, h.block_id(), "{context}: valid block rejected");
                tally.valid_blocks += 1;
                known.active.push(after);
                let cb = n.with_chain(|c| c.block_by_id(&after).map(|b| b.transactions[0].txid()));
                known.coinbases.extend(cb);
            } else if valid {
                assert_eq!(after, before, "{context}: block adopted from a stranger");
            } else if after != before {
                // A mutation can leave a block valid: in regtest the target is
                // easy. The tip is then only allowed to move if the adopted
                // block passes checks redone here, outside the chain's code
                // path.
                assert!(established, "{context}: block adopted from a stranger");
                let b = n
                    .with_chain(|c| c.block_by_id(&after))
                    .expect("body of the tip");
                independently_valid(&b, before, &context);
                tally.valid_blocks += 1;
                known.active.push(after);
                known.coinbases.push(b.transactions[0].txid());
            }

            // A disconnected peer is replaced by a newcomer, established or
            // not: that is what an attacker who reconnects would do.
            if !keep {
                tally.drops += 1;
                n.disconnect(id);
                plug_in(&n, next_id, a.one_in(2), a.one_in(2));
                ids[slot] = next_id;
                next_id += 1;
            }

            // From time to time, maintenance runs as if a minute had passed:
            // body deadlines, re-requests, disconnections.
            if step % 256 == 255 {
                reporter.command = "(maintenance)";
                if let Some(past) =
                    Instant::now().checked_sub(BODY_TIMEOUT + Duration::from_secs(1))
                {
                    let mut g = n.shared.lock().unwrap();
                    for p in g.peers.values_mut() {
                        for t in p.requested_bodies.values_mut() {
                            *t = past;
                        }
                    }
                }
                n.maintain_peers();
                check_invariants(
                    &n,
                    &format!("seed {seed:#x}, step {step}, maintenance"),
                    false,
                );
                for id in ids.iter_mut() {
                    if !n.shared.lock().unwrap().peers.contains_key(id) {
                        tally.drops += 1;
                        plug_in(&n, next_id, a.one_in(2), a.one_in(2));
                        *id = next_id;
                        next_id += 1;
                    }
                }
            }
        }

        // --- Honest progress after the storm: a handshake completed the
        // normal way, then a valid block adopted.
        reporter.command = "honest sync";
        plug_in(&n, next_id, false, false);
        let honest = next_id;
        let height = n.height();
        assert!(n.handle(
            honest,
            Message::Version {
                version: PROTOCOL_VERSION,
                timestamp: unix_now(),
                nonce: 0x5eed_0000_0000_0001,
                user_agent: "honest".into(),
                start_height: height + 1,
            }
        ));
        assert!(n.handle(honest, Message::VerAck));
        let b = n
            .with_chain(|c| {
                c.mine_block(
                    Hash256([7u8; 32]),
                    SchemeId::LamportOts,
                    &[],
                    c.tip().time + 1,
                    5_000_000,
                )
            })
            .expect("regtest mining");
        let bid = b.header.block_id();
        assert!(n.handle(honest, Message::Block(Box::new(b))));
        assert_eq!(
            n.tip_id(),
            bid,
            "seed {seed:#x}: the node no longer synchronizes an honest peer"
        );
        assert_eq!(n.height(), height + 1);
        check_invariants(&n, "end", true);
        drop(reporter);
        n.shutdown();
    }

    #[test]
    fn handler_fuzz() {
        let iterations = env_u64("Q21_FUZZ_ITERATIONS").unwrap_or(6_000);
        let seeds = env_u64("Q21_FUZZ_SEEDS").unwrap_or(3);
        let first = env_u64("Q21_FUZZ_SEED").unwrap_or(0x51_2100);
        let start = Instant::now();
        let mut tally = Tally::default();
        for k in 0..seeds {
            campaign(first.wrapping_add(k), iterations, &mut tally);
        }
        let total: u64 = tally.messages.values().map(|(c, _)| *c).sum();
        eprintln!(
            "handler fuzz: {seeds} seed(s) from {first:#x}, \
             {total} messages, {} valid blocks adopted, {} disconnections, \
             {} discarded as larger than a frame, in {:?}",
            tally.valid_blocks,
            tally.drops,
            tally.oversized,
            start.elapsed()
        );
        for (cmd, (c, max)) in &tally.messages {
            eprintln!("  {cmd:<12} {c:>9} messages, handle max {max:?}");
        }
    }
}

/// Targeted tests that came out of the review of the handlers.
#[cfg(test)]
mod tests_handler_review {
    use super::*;
    use crate::chain::genesis_block;
    use crate::wire::NetAddr;

    const NETWORK: Network = Network::Regtest;

    fn node() -> Node {
        Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)))
    }

    fn anonymous_peer(n: &Node, id: u64) -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let stream = TcpStream::connect(listener.local_addr().unwrap()).expect("socket");
        let addr = stream.peer_addr().unwrap();
        let now = Instant::now();
        n.shared.lock().unwrap().peers.insert(
            id,
            Peer {
                addr,
                writer: Arc::new(Mutex::new(stream)),
                outbound: false,
                snapshot_bucket: TokenBucket::new(now),
                tx_bucket: TokenBucket::for_transactions(now),
                cmpct_bucket: TokenBucket::for_compact_announcements(now),
                headers_bucket: TokenBucket::for_header_requests(now),
                addr_bucket: TokenBucket::for_addresses(now),
                expected_headers: 0,
                requested_bodies: HashMap::new(),
                bodies_to_request: VecDeque::new(),
                more_expected: false,
                version_received: false,
                version_sent: false,
                handshaked: false,
                ban_score: 0,
                start_height: 0,
                pending: HashMap::new(),
                consecutive_orphans: 0,
                last_received: now,
                pending_ping: None,
                connected_at: now,
            },
        );
        listener
    }

    /// A thousand addresses from all-distinct /16 groups, starting at `start`.
    fn group_batch(start: u32) -> Vec<NetAddr> {
        (0..crate::wire::MAX_ADDR as u32)
            .map(|i| {
                let g = start + i;
                NetAddr {
                    ip: [11 + (g >> 8) as u8 % 100, g as u8, 1, 1],
                    port: 21021,
                    last_seen: 1,
                }
            })
            .collect()
    }

    /// An `Addr` pushed before the handshake is not read.
    ///
    /// With the address book full, each address from a new group makes us scan
    /// the five hundred twelve groups to evict one: nearly eight milliseconds of
    /// global lock for sixteen kibibytes received, with neither bucket nor
    /// introduction. A single anonymous connection thus held the lock almost
    /// continuously.
    #[test]
    fn an_addr_before_the_handshake_is_not_read() {
        let n = node();
        let _e = anonymous_peer(&n, 9);
        let mut worst = Duration::ZERO;
        for k in 0..8u32 {
            let start = Instant::now();
            assert!(n.handle(9, Message::Addr(group_batch(k * 1000))));
            worst = worst.max(start.elapsed());
        }
        eprintln!("anonymous addr: handle max {worst:?}");
        assert_eq!(
            n.address_count(),
            0,
            "an anonymous connection wrote into the address book"
        );
    }

    fn establish(n: &Node, id: u64) {
        let mut g = n.shared.lock().unwrap();
        let p = g.peers.get_mut(&id).unwrap();
        p.version_received = true;
        p.handshaked = true;
    }

    /// Suspicion refuted: `consecutive_orphans += 1` cannot overflow. The third
    /// unconnected batch disconnects the peer; the counter never goes beyond
    /// three on a live connection.
    #[test]
    fn the_orphan_counter_disconnects_before_any_overflow() {
        let n = node();
        let _e = anonymous_peer(&n, 9);
        establish(&n, 9);
        let header = n.with_chain(|c| c.tip());
        let mut foreign = header;
        foreign.prev_block = Hash256([0xab; 32]);
        for i in 1..=3u32 {
            n.shared
                .lock()
                .unwrap()
                .peers
                .get_mut(&9)
                .unwrap()
                .expected_headers = 1;
            let kept = n.handle(9, Message::Headers(vec![foreign]));
            assert_eq!(kept, i < 3, "batch {i}");
        }
    }

    /// Suspicions refuted: extreme indices and chunk numbers, on a known block
    /// and an absent snapshot, neither panic nor serve anything.
    #[test]
    fn extreme_indices_serve_nothing() {
        let n = node();
        let _e = anonymous_peer(&n, 9);
        establish(&n, 9);
        let tip = n.tip_id();
        assert!(n.handle(
            9,
            Message::GetBlockTxn {
                block: tip,
                indices: vec![u32::MAX, u32::MAX - 1, 1, 0],
            }
        ));
        for index in [0, 1, u32::MAX - 1, u32::MAX] {
            assert!(n.handle(9, Message::GetSnapshotChunk { index }));
        }
        assert_eq!(crate::fast_sync::chunk(&[1, 2, 3], u32::MAX), &[] as &[u8]);
    }

    /// Suspicion refuted: a compact announcement whose prefilled index is
    /// `u32::MAX`, or whose total count exceeds the bound, is rejected by the
    /// reconstruction without out-of-bounds indexing or oversized allocation.
    #[test]
    fn an_absurd_reconstruction_is_rejected_without_panicking() {
        let g = genesis_block(NETWORK);
        let mut c = CompactBlock::from_block(&g, 1);
        c.prefilled[0].0 = u32::MAX;
        assert!(Reconstruction::from_compact(&c, &HashMap::new()).is_err());
        let mut c = CompactBlock::from_block(&g, 1);
        c.short_ids = vec![0; crate::compact::MAX_TX_PER_BLOCK];
        assert!(matches!(
            Reconstruction::from_compact(&c, &HashMap::new()),
            Err(crate::compact::CompactError::TooManyTransactions(_))
        ));
        let mut c = CompactBlock::from_block(&g, 1);
        c.prefilled.push((0, g.transactions[0].clone()));
        // Index zero twice: one slot stays empty, and finalization says so
        // instead of panicking.
        let r = Reconstruction::from_compact(&c, &HashMap::new()).expect("accepted shape");
        assert!(r.finish().is_err());
    }

    /// Acts as if every requested body had been requested more than
    /// [`BODY_TIMEOUT`] ago: the deadline is replayed without waiting a minute.
    fn age_requests(n: &Node) {
        let past = Instant::now()
            .checked_sub(BODY_TIMEOUT + Duration::from_secs(1))
            .expect("monotonic clock advanced enough");
        let mut g = n.shared.lock().unwrap();
        for p in g.peers.values_mut() {
            for t in p.requested_bodies.values_mut() {
                *t = past;
            }
        }
    }

    /// An honest peer is never punished for a body someone else invented.
    ///
    /// An anonymous connection announces sixteen invented block identifiers.
    /// They are requested, never delivered; at the deadline, the request was
    /// made again to the first established peer — an honest one, which cannot
    /// deliver what does not exist, and in turn lost fifty points. Two rounds
    /// were enough to disconnect it, and the attacker only had to reconnect to
    /// start over: enough to drain a node of its honest peers.
    #[test]
    fn an_honest_peer_is_not_punished_for_invented_bodies() {
        let n = node();
        let _h = anonymous_peer(&n, 1);
        establish(&n, 1);
        for round in 0..2u64 {
            let attacker = 100 + round;
            let _e = anonymous_peer(&n, attacker);
            // Established: an anonymous `inv` is no longer read at all
            // (0.3.2), and it is the re-request itself that is tested here.
            establish(&n, attacker);
            let invented: Vec<InvItem> = (0..MAX_BODIES_IN_FLIGHT as u8)
                .map(|i| InvItem {
                    kind: InvKind::CompactBlock,
                    hash: Hash256([i ^ (round as u8 * 0x40) ^ 0x80; 32]),
                })
                .collect();
            assert!(n.handle(attacker, Message::Inv(invented)));
            // First deadline: the announcer withholds, the request is made
            // again.
            age_requests(&n);
            n.maintain_peers();
            // Second deadline: the peer the request was made to does not
            // deliver.
            age_requests(&n);
            n.maintain_peers();
            n.disconnect(attacker);
        }
        let g = n.shared.lock().unwrap();
        let honest = g.peers.get(&1);
        assert!(
            honest.is_some(),
            "the honest peer was disconnected for bodies the attacker invented"
        );
        assert_eq!(
            honest.unwrap().ban_score,
            0,
            "the honest peer was penalized for invented bodies"
        );
    }

    /// Counter-test: a real withheld body is always requested again from
    /// another peer, as a full block, and adopted when it arrives.
    #[test]
    fn a_withheld_body_is_requested_again_and_adopted() {
        let n = node();
        let listener = anonymous_peer(&n, 1);
        establish(&n, 1);
        let (mut honest_side, _) = listener.accept().expect("accept");
        let _ = honest_side.set_read_timeout(Some(Duration::from_secs(5)));
        let block = n
            .with_chain(|c| {
                c.mine_block(
                    Hash256([3u8; 32]),
                    crate::sig::SchemeId::LamportOts,
                    &[],
                    c.tip().time + 1,
                    5_000_000,
                )
            })
            .expect("regtest mining");
        let bid = block.header.block_id();
        let _e = anonymous_peer(&n, 2);
        establish(&n, 2);
        assert!(n.handle(
            2,
            Message::Inv(vec![InvItem {
                kind: InvKind::CompactBlock,
                hash: bid,
            }])
        ));
        age_requests(&n);
        n.maintain_peers();
        // The honest peer receives the re-request.
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let request = loop {
            match Message::parse(&buffer, n.magic) {
                Ok((Message::GetData(v), _)) => break v,
                Ok((_, k)) => {
                    buffer.drain(..k);
                }
                Err(WireError::Incomplete) => {
                    let k = honest_side.read(&mut chunk).expect("read");
                    assert!(k > 0, "connection closed without a re-request");
                    buffer.extend_from_slice(&chunk[..k]);
                }
                Err(e) => panic!("unreadable frame: {e:?}"),
            }
        };
        assert_eq!(
            request,
            vec![InvItem {
                kind: InvKind::Block,
                hash: bid,
            }]
        );
        assert!(n.handle(1, Message::Block(Box::new(block))));
        assert_eq!(n.tip_id(), bid, "the re-requested body was not adopted");
        assert_eq!(n.shared.lock().unwrap().peers[&1].ban_score, 0);
    }

    /// The same `Addr`, after the handshake, is read as before.
    #[test]
    fn an_addr_after_the_handshake_is_read() {
        let n = node();
        let _e = anonymous_peer(&n, 9);
        {
            let mut g = n.shared.lock().unwrap();
            let p = g.peers.get_mut(&9).unwrap();
            p.version_received = true;
            p.handshaked = true;
        }
        assert!(n.handle(9, Message::Addr(group_batch(0))));
        assert_eq!(n.address_count(), crate::addr::MAX_GROUPS);
    }
}
